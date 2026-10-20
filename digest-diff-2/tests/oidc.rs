//! Login against a mock OIDC provider that signs real ID tokens.

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::Key;
use chrono::{Duration, Utc};
use clap::Parser;
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
    CoreRsaPrivateSigningKey,
};
use openidconnect::{
    Audience, EmptyAdditionalClaims, IssuerUrl, JsonWebKeyId, Nonce, PrivateSigningKey,
    StandardClaims, SubjectIdentifier,
};
use rsa::RsaPrivateKey;
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use serde_json::json;
use tower::ServiceExt;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

use digest_diff_2::config::Config;
use digest_diff_2::db::Db;
use digest_diff_2::web::auth::{AuthMode, SESSION_COOKIE, Session};
use digest_diff_2::web::{AppState, router};

const CLIENT_ID: &str = "digest_diff_2";

struct Idp {
    server: MockServer,
    key: CoreRsaPrivateSigningKey,
}

impl Idp {
    async fn start() -> Idp {
        let server = MockServer::start().await;
        let pem = RsaPrivateKey::new(&mut rand08::rngs::OsRng, 2048)
            .unwrap()
            .to_pkcs1_pem(LineEnding::LF)
            .unwrap();
        let key =
            CoreRsaPrivateSigningKey::from_pem(&pem, Some(JsonWebKeyId::new("k1".into()))).unwrap();
        let issuer = server.uri();
        Mock::given(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            })))
            .mount(&server)
            .await;
        Mock::given(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(CoreJsonWebKeySet::new(vec![key.as_verification_key()])),
            )
            .mount(&server)
            .await;
        Idp { server, key }
    }

    /// Answers the next code exchange with an ID token for `nonce`.
    async fn issue(&self, nonce: &str) {
        let now = Utc::now();
        let claims = CoreIdTokenClaims::new(
            IssuerUrl::new(self.server.uri()).unwrap(),
            vec![Audience::new(CLIENT_ID.into())],
            now + Duration::minutes(5),
            now,
            StandardClaims::new(SubjectIdentifier::new("user-1".into())),
            EmptyAdditionalClaims {},
        )
        .set_nonce(Some(Nonce::new(nonce.into())));
        let id_token = CoreIdToken::new(
            claims,
            &self.key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .unwrap();
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "at",
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": id_token.to_string(),
            })))
            .mount(&self.server)
            .await;
    }
}

async fn app(idp: &Idp, key: &Key) -> Router {
    let cfg = Config::try_parse_from([
        "digest_diff_2",
        "--oidc-issuer",
        &idp.server.uri(),
        "--oidc-client-id",
        CLIENT_ID,
    ])
    .unwrap();
    let auth = AuthMode::from_config(&cfg.auth, &cfg.public_url, false).unwrap();
    let db = Db::memory().unwrap();
    let manager = digest_diff_2::jobs::Manager::new(
        db.clone(),
        std::sync::Arc::new(digest_diff_2::scanner::DemoEngine),
        3600,
        std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();
    router(AppState::new(cfg, db, manager, auth, key.clone(), None))
}

fn set_cookie(res: &axum::response::Response, name: &str) -> Option<String> {
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
        .find(|c| c.starts_with(&format!("{name}=")))
}

/// Runs `/auth/login` then `/auth/callback`, returning the callback
/// response. `tamper` replaces the `state` sent back by the provider.
async fn login(idp: &Idp, key: &Key, tamper: Option<&str>) -> axum::response::Response {
    let app = app(idp, key).await;
    let res = app
        .clone()
        .oneshot(
            Request::get("/auth/login?next=/diff?demo=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let authorize = url::Url::parse(res.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let param = |name: &str| {
        authorize
            .query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    };
    assert!(param("code_challenge").is_some(), "PKCE is used");
    idp.issue(&param("nonce").unwrap()).await;
    let login_cookie = set_cookie(&res, "digest_diff_2_login").expect("login cookie");
    let state = tamper
        .map(str::to_string)
        .unwrap_or_else(|| param("state").unwrap());
    app.oneshot(
        Request::get(format!("/auth/callback?code=c&state={state}"))
            .header(header::COOKIE, login_cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
}

fn session(res: &axum::response::Response, key: &Key) -> Session {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        set_cookie(res, SESSION_COOKIE).unwrap().parse().unwrap(),
    );
    let jar = PrivateCookieJar::from_headers(&headers, key.clone());
    serde_json::from_str(jar.get(SESSION_COOKIE).unwrap().value()).unwrap()
}

#[tokio::test]
async fn login_creates_a_session_and_returns_to_the_page() {
    let (idp, key) = (Idp::start().await, Key::generate());
    let res = login(&idp, &key, None).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers()[header::LOCATION], "/diff?demo=1");
    let s = session(&res, &key);
    assert_eq!(s.sub, "user-1");
    // No groups claim: a household member, not an admin.
    assert!(!s.admin);
}

#[tokio::test]
async fn a_mismatched_state_is_refused() {
    let (idp, key) = (Idp::start().await, Key::generate());
    let res = login(&idp, &key, Some("forged")).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(set_cookie(&res, SESSION_COOKIE).is_none());
}
