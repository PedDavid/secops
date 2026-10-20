//! OIDC login, encrypted session cookies, the `User`/`Admin` extractors and
//! CSRF tokens.

use axum::extract::{FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;
use tracing::{debug, info, warn};

use super::{AppError, AppState};
use crate::config::AuthConfig;

pub const SESSION_COOKIE: &str = "digest_diff_2_session";
const LOGIN_COOKIE: &str = "digest_diff_2_login";
const LOGIN_TTL_SECS: i64 = 600;
const CSRF_HEADER: &str = "x-csrf-token";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    pub sub: String,
    pub name: String,
    pub admin: bool,
    pub csrf: String,
    /// Unix seconds after which the session is invalid.
    pub exp: i64,
}

impl Session {
    pub fn is_expired(&self, now: Timestamp) -> bool {
        now.as_second() >= self.exp
    }

    pub fn check_csrf(
        &self,
        headers: &HeaderMap,
        form_token: Option<&str>,
    ) -> Result<(), AppError> {
        let provided = headers
            .get(CSRF_HEADER)
            .and_then(|v| v.to_str().ok())
            .or(form_token)
            .unwrap_or_default();
        if constant_time_eq(provided.as_bytes(), self.csrf.as_bytes()) {
            Ok(())
        } else {
            Err(AppError::Forbidden("invalid or missing CSRF token".into()))
        }
    }
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub enum AuthMode {
    Oidc(Box<Oidc>),
    /// Everyone is an admin. Development and demo only.
    InsecureDev {
        csrf: String,
    },
}

pub struct Oidc {
    issuer: IssuerUrl,
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    redirect: RedirectUrl,
    scopes: Vec<String>,
    admin_claim: String,
    admin_value: String,
    http: reqwest::Client,
    client: OnceCell<OidcClient>,
    /// The discovered `userinfo_endpoint`, if the provider has one.
    userinfo_url: std::sync::OnceLock<Option<String>>,
}

impl AuthMode {
    pub fn from_config(
        cfg: &AuthConfig,
        public_url: &url::Url,
        force_dev: bool,
    ) -> anyhow::Result<Self> {
        if cfg.insecure_dev_auth || force_dev {
            warn!("insecure dev auth enabled: every visitor is an admin");
            return Ok(AuthMode::InsecureDev {
                csrf: random_token(),
            });
        }
        let (Some(issuer), Some(client_id)) = (&cfg.oidc_issuer, &cfg.oidc_client_id) else {
            anyhow::bail!(
                "OIDC is required: set --oidc-issuer and --oidc-client-id (or --insecure-dev-auth for local development)"
            );
        };
        let client_secret = match &cfg.oidc_client_secret_file {
            Some(path) => Some(ClientSecret::new(
                std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?
                    .trim()
                    .to_string(),
            )),
            None => None,
        };
        let redirect = format!(
            "{}/auth/callback",
            public_url.as_str().trim_end_matches('/')
        );
        let http = reqwest::Client::builder()
            // Following redirects exposes the client to SSRF.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(15))
            .build()?;
        Ok(AuthMode::Oidc(Box::new(Oidc {
            issuer: IssuerUrl::new(issuer.as_str().trim_end_matches('/').to_string())?,
            client_id: ClientId::new(client_id.clone()),
            client_secret,
            redirect: RedirectUrl::new(redirect)?,
            scopes: cfg
                .oidc_scopes
                .split_whitespace()
                .filter(|s| *s != "openid")
                .map(str::to_string)
                .collect(),
            admin_claim: cfg.admin_claim.clone(),
            admin_value: cfg.admin_value.clone(),
            http,
            client: OnceCell::new(),
            userinfo_url: std::sync::OnceLock::new(),
        })))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct HttpError(String);

async fn http_call(
    client: reqwest::Client,
    request: openidconnect::HttpRequest,
) -> Result<openidconnect::HttpResponse, HttpError> {
    let request = reqwest::Request::try_from(request).map_err(|e| HttpError(e.to_string()))?;
    let response = client
        .execute(request)
        .await
        .map_err(|e| HttpError(e.to_string()))?;
    let mut builder = axum::http::Response::builder().status(response.status());
    for (name, value) in response.headers() {
        builder = builder.header(name, value);
    }
    let body = response
        .bytes()
        .await
        .map_err(|e| HttpError(e.to_string()))?;
    builder
        .body(body.to_vec())
        .map_err(|e| HttpError(e.to_string()))
}

impl Oidc {
    /// The claims the userinfo endpoint returns for this access token, if the
    /// provider has one and it answers with plain JSON.
    async fn userinfo_claims(&self, access_token: &str) -> Option<serde_json::Value> {
        let url = self.userinfo_url.get()?.as_deref()?;
        let response = self
            .http
            .get(url)
            .bearer_auth(access_token)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .and_then(|r| r.error_for_status());
        match response {
            Ok(r) => r.json().await.ok(),
            Err(e) => {
                warn!(error = %e, "userinfo request failed");
                None
            }
        }
    }

    async fn client(&self) -> Result<&OidcClient, AppError> {
        self.client
            .get_or_try_init(|| async {
                let http = self.http.clone();
                let metadata = CoreProviderMetadata::discover_async(self.issuer.clone(), &|r| {
                    http_call(http.clone(), r)
                })
                .await
                .map_err(|e| AppError::Upstream(format!("OIDC discovery failed: {e}")))?;
                info!(issuer = %self.issuer.as_str(), "OIDC provider discovered");
                let _ = self
                    .userinfo_url
                    .set(metadata.userinfo_endpoint().map(|u| u.url().to_string()));
                Ok(CoreClient::from_provider_metadata(
                    metadata,
                    self.client_id.clone(),
                    self.client_secret.clone(),
                )
                .set_redirect_uri(self.redirect.clone()))
            })
            .await
    }
}

/// Transient state between `/auth/login` and `/auth/callback`.
#[derive(Serialize, Deserialize)]
struct LoginState {
    state: String,
    nonce: String,
    pkce_verifier: String,
    next: String,
    exp: i64,
}

#[derive(Deserialize)]
pub struct LoginQuery {
    next: Option<String>,
}

/// Only same-site relative paths are accepted as redirect targets.
pub fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(n) if n.starts_with('/') && !n.starts_with("//") && !n.contains('\\') => n.to_string(),
        _ => "/".to_string(),
    }
}

fn cookie(
    state: &AppState,
    name: &'static str,
    value: String,
    max_age_secs: i64,
) -> Cookie<'static> {
    Cookie::build((name, value))
        .path("/")
        .http_only(true)
        .secure(state.inner.cfg.public_url.scheme() == "https")
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(max_age_secs))
        .build()
}

pub async fn login(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(q): Query<LoginQuery>,
) -> Result<Response, AppError> {
    let next = safe_next(q.next.as_deref());
    let oidc = match &state.inner.auth {
        AuthMode::InsecureDev { .. } => return Ok(Redirect::to(&next).into_response()),
        AuthMode::Oidc(oidc) => oidc,
    };
    let client = oidc.client().await?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge);
    for scope in &oidc.scopes {
        request = request.add_scope(Scope::new(scope.clone()));
    }
    let (url, csrf, nonce) = request.url();
    let now = Timestamp::now().as_second();
    let login_state = LoginState {
        state: csrf.secret().clone(),
        nonce: nonce.secret().clone(),
        pkce_verifier: verifier.secret().clone(),
        next,
        exp: now + LOGIN_TTL_SECS,
    };
    let value =
        serde_json::to_string(&login_state).map_err(|e| AppError::Internal(e.to_string()))?;
    let jar = jar.add(cookie(&state, LOGIN_COOKIE, value, LOGIN_TTL_SECS));
    Ok((jar, Redirect::to(url.as_str())).into_response())
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

pub async fn callback(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    let AuthMode::Oidc(oidc) = &state.inner.auth else {
        return Ok(Redirect::to("/").into_response());
    };
    if let Some(error) = q.error {
        let detail = q.error_description.unwrap_or_default();
        return Err(AppError::Unauthorized(format!(
            "login failed: {error} {detail}"
        )));
    }
    let login: LoginState = jar
        .get(LOGIN_COOKIE)
        .and_then(|c| serde_json::from_str(c.value()).ok())
        .ok_or_else(|| AppError::Unauthorized("login expired, try again".into()))?;
    let jar = jar.remove(Cookie::build(LOGIN_COOKIE).path("/"));
    let now = Timestamp::now();
    if now.as_second() > login.exp {
        return Err(AppError::Unauthorized("login expired, try again".into()));
    }
    let returned_state = q.state.unwrap_or_default();
    if !constant_time_eq(returned_state.as_bytes(), login.state.as_bytes()) {
        return Err(AppError::Unauthorized("login state mismatch".into()));
    }
    let code = q
        .code
        .ok_or_else(|| AppError::Unauthorized("missing authorization code".into()))?;

    let client = oidc.client().await?;
    let http = oidc.http.clone();
    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|e| AppError::Internal(e.to_string()))?
        .set_pkce_verifier(PkceCodeVerifier::new(login.pkce_verifier.clone()))
        .request_async(&|r| http_call(http.clone(), r))
        .await
        .map_err(|e| AppError::Unauthorized(format!("token exchange failed: {e}")))?;
    let id_token = token
        .id_token()
        .ok_or_else(|| AppError::Unauthorized("provider returned no ID token".into()))?;
    let claims = id_token
        .claims(
            &client.id_token_verifier(),
            &Nonce::new(login.nonce.clone()),
        )
        .map_err(|e| AppError::Unauthorized(format!("invalid ID token: {e}")))?;

    // The signature was verified above, so reading extra claims from the
    // payload directly is safe.
    let raw_claims = decode_jwt_payload(&id_token.to_string()).unwrap_or_default();
    let mut admin_source =
        claim_contains(&raw_claims, &oidc.admin_claim, &oidc.admin_value).then_some("ID token");
    // Keycloak puts client roles only in the access token and userinfo by
    // default, so look there too. The access token is not verified: it came
    // in the same TLS response as the verified ID token, so no new party is
    // trusted. An opaque (non-JWT) access token is skipped.
    let access_token = token.access_token().secret();
    if admin_source.is_none()
        && let Some(userinfo) = oidc.userinfo_claims(access_token).await
        && claim_contains(&userinfo, &oidc.admin_claim, &oidc.admin_value)
    {
        admin_source = Some("userinfo");
    }
    if admin_source.is_none()
        && let Some(payload) = decode_jwt_payload(access_token)
        && claim_contains(&payload, &oidc.admin_claim, &oidc.admin_value)
    {
        admin_source = Some("access token");
    }
    let admin = admin_source.is_some();
    debug!(
        claim = %oidc.admin_claim,
        source = admin_source.unwrap_or("none"),
        "admin claim lookup"
    );
    let name = claims
        .preferred_username()
        .map(|u| u.to_string())
        .or_else(|| claims.email().map(|e| e.to_string()))
        .or_else(|| {
            claims
                .name()
                .and_then(|n| n.get(None))
                .map(|n| n.to_string())
        })
        .unwrap_or_else(|| claims.subject().to_string());
    let ttl = state.inner.cfg.auth.session_ttl.as_secs();
    let session = Session {
        sub: claims.subject().to_string(),
        name: name.clone(),
        admin,
        csrf: random_token(),
        exp: now.as_second() + ttl,
    };
    info!(user = %name, admin, "login");
    let value = serde_json::to_string(&session).map_err(|e| AppError::Internal(e.to_string()))?;
    let jar = jar.add(cookie(&state, SESSION_COOKIE, value, ttl));
    Ok((jar, Redirect::to(&login.next)).into_response())
}

pub async fn logout(
    jar: PrivateCookieJar,
    user: User,
    headers: HeaderMap,
    axum::Form(form): axum::Form<CsrfForm>,
) -> Result<Response, AppError> {
    user.0.check_csrf(&headers, form.csrf.as_deref())?;
    let jar = jar.remove(Cookie::build(SESSION_COOKIE).path("/"));
    Ok((jar, Redirect::to("/")).into_response())
}

#[derive(Deserialize, Default)]
pub struct CsrfForm {
    #[serde(rename = "_csrf")]
    pub csrf: Option<String>,
}

fn decode_jwt_payload(jwt: &str) -> Option<serde_json::Value> {
    let payload = jwt.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Checks a claim (dot-separated path, e.g. `realm_access.roles`) for a
/// value; the claim may be a string or an array of strings.
pub fn claim_contains(claims: &serde_json::Value, path: &str, value: &str) -> bool {
    let mut current = claims;
    for part in path.split('.') {
        match current.get(part) {
            Some(v) => current = v,
            None => return false,
        }
    }
    match current {
        serde_json::Value::String(s) => s == value,
        serde_json::Value::Array(items) => items.iter().any(|i| i.as_str() == Some(value)),
        _ => false,
    }
}

/// A logged-in user. Rejects with a redirect to the login page.
pub struct User(pub Session);

/// A logged-in admin. Rejects with 403 for non-admins.
pub struct Admin(pub Session);

pub enum AuthRejection {
    Login(String),
    HtmxLogin(String),
    Forbidden,
    Internal,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        match self {
            AuthRejection::Login(next) => {
                Redirect::to(&format!("/auth/login?next={}", urlencode(&next))).into_response()
            }
            AuthRejection::HtmxLogin(next) => (
                StatusCode::UNAUTHORIZED,
                [(
                    "HX-Redirect",
                    format!("/auth/login?next={}", urlencode(&next)),
                )],
            )
                .into_response(),
            AuthRejection::Forbidden => {
                AppError::Forbidden("this page needs admin rights".into()).into_response()
            }
            AuthRejection::Internal => AppError::Internal("session error".into()).into_response(),
        }
    }
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

impl FromRequestParts<AppState> for User {
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let now = Timestamp::now();
        if let AuthMode::InsecureDev { csrf } = &state.inner.auth {
            return Ok(User(Session {
                sub: "dev".into(),
                name: "dev-admin".into(),
                admin: true,
                csrf: csrf.clone(),
                exp: now.as_second() + 3600,
            }));
        }
        let jar =
            PrivateCookieJar::<axum_extra::extract::cookie::Key>::from_request_parts(parts, state)
                .await
                .map_err(|_| AuthRejection::Internal)?;
        let session: Option<Session> = jar
            .get(SESSION_COOKIE)
            .and_then(|c| serde_json::from_str(c.value()).ok());
        match session {
            Some(s) if !s.is_expired(now) => Ok(User(s)),
            _ => {
                let next = parts
                    .uri
                    .path_and_query()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_else(|| "/".into());
                if parts.headers.contains_key("hx-request") {
                    // Send htmx back to the page the fragment belongs to.
                    let page = parts
                        .headers
                        .get("hx-current-url")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|u| url::Url::parse(u).ok())
                        .map(|u| {
                            u[url::Position::BeforePath..url::Position::AfterQuery].to_string()
                        })
                        .unwrap_or(next);
                    Err(AuthRejection::HtmxLogin(page))
                } else {
                    Err(AuthRejection::Login(next))
                }
            }
        }
    }
}

impl FromRequestParts<AppState> for Admin {
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let User(session) = User::from_request_parts(parts, state).await?;
        if session.admin {
            Ok(Admin(session))
        } else {
            Err(AuthRejection::Forbidden)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keycloak_client_roles_are_found_in_a_jwt_payload() {
        let payload = URL_SAFE_NO_PAD.encode(
            json!({"resource_access": {"digest_diff_2": {"roles": ["admin"]}}}).to_string(),
        );
        let jwt = format!("e30.{payload}.sig");
        let claims = decode_jwt_payload(&jwt).unwrap();
        assert!(claim_contains(
            &claims,
            "resource_access.digest_diff_2.roles",
            "admin"
        ));
        // An opaque access token is not a JWT and is skipped.
        assert!(decode_jwt_payload("opaque-token").is_none());
    }

    #[test]
    fn claims_are_matched_by_path() {
        let claims = json!({
            "groups": ["users", "digest_diff_2-admins"],
            "role": "admin",
            "realm_access": {"roles": ["x", "keys-admin"]}
        });
        assert!(claim_contains(&claims, "groups", "digest_diff_2-admins"));
        assert!(!claim_contains(&claims, "groups", "admins"));
        assert!(claim_contains(&claims, "role", "admin"));
        assert!(claim_contains(&claims, "realm_access.roles", "keys-admin"));
        assert!(!claim_contains(&claims, "missing.path", "x"));
    }

    #[test]
    fn next_must_be_relative() {
        assert_eq!(safe_next(Some("/keys/a?x=1")), "/keys/a?x=1");
        assert_eq!(safe_next(Some("//evil.example")), "/");
        assert_eq!(safe_next(Some("https://evil.example")), "/");
        assert_eq!(safe_next(Some("/\\evil.example")), "/");
        assert_eq!(safe_next(None), "/");
    }

    #[test]
    fn csrf_check() {
        let s = Session {
            sub: "a".into(),
            name: "a".into(),
            admin: true,
            csrf: "token".into(),
            exp: 1,
        };
        let mut headers = HeaderMap::new();
        assert!(s.check_csrf(&headers, Some("token")).is_ok());
        assert!(s.check_csrf(&headers, Some("nope")).is_err());
        assert!(s.check_csrf(&headers, None).is_err());
        headers.insert(CSRF_HEADER, "token".parse().unwrap());
        assert!(s.check_csrf(&headers, None).is_ok());
    }
}
