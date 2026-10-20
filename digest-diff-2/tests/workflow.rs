use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use axum_extra::extract::cookie::Key;
use clap::Parser;
use digest_diff_2::{
    config::Config,
    db::Db,
    jobs::Manager,
    model::{Pair, Report},
    scanner::{DemoEngine, Engine},
    web::{self, AppState, auth::AuthMode},
};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;
fn pair() -> Pair {
    Pair {
        old: format!("alpine@sha256:{}", "a".repeat(64)),
        new: format!("alpine@sha256:{}", "b".repeat(64)),
    }
}
async fn state() -> AppState {
    let cfg = Config::try_parse_from(["test", "--demo"]).unwrap();
    let db = Db::memory().unwrap();
    let jobs = Manager::new(
        db.clone(),
        Arc::new(DemoEngine),
        3600,
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    let auth = AuthMode::from_config(&cfg.auth, &cfg.public_url, true).unwrap();
    AppState::new(
        cfg,
        db,
        jobs,
        auth,
        Key::generate(),
        Some("test-api-token-that-is-at-least-32-characters".into()),
    )
}
async fn text(r: axum::response::Response) -> String {
    String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}
#[tokio::test]
async fn complete_workflow_and_partial_results() {
    let s = state().await;
    let p = pair();
    let app = web::router(s.clone());
    let route = format!("/jobs?{}", p.query());
    let denied = app
        .clone()
        .oneshot(
            Request::post(&route)
                .header("Origin", "http://localhost:8080")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let res = app
        .clone()
        .oneshot(
            Request::post(&route)
                .header(
                    "Authorization",
                    "Bearer test-api-token-that-is-at-least-32-characters",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let job = s.inner.jobs.start(p.clone()).await.unwrap();
    assert_eq!(job.id, p.id());
    let res = app
        .clone()
        .oneshot(
            Request::get(format!("/diff?{}", p.query()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(text(res).await.contains("every 2s"));
    let mut partial_seen = false;
    for _ in 0..80 {
        let job = s.inner.db.get(&p.id()).await.unwrap().unwrap();
        if job.packages_ready && job.pending() {
            partial_seen = true;
            let res = app
                .clone()
                .oneshot(
                    Request::get(format!("/comparisons/{}/fragment", p.id()))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let html = text(res).await;
            assert!(html.contains("openssl"));
            assert!(html.contains("still pending"));
        }
        if job.state == "completed" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }
    assert!(partial_seen);
    let job = s.inner.db.get(&p.id()).await.unwrap().unwrap();
    assert_eq!(job.state, "completed");
    let res = app
        .clone()
        .oneshot(
            Request::get(format!("/diff.json?{}", p.query()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let report: Report = serde_json::from_str(&text(res).await).unwrap();
    assert_eq!(report.vulnerabilities.unwrap().resolved.len(), 1);
    let res = app
        .clone()
        .oneshot(
            Request::get(format!("/diff?{}", p.query()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.headers()["x-frame-options"], "DENY");
    let html = text(res).await;
    assert!(html.contains("https://www.cve.org/CVERecord?id=CVE-2025-12345"));
    assert!(!html.contains("every 2s"));
    let ops = web::ops_router(s.clone());
    let res = ops
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(
        text(res)
            .await
            .contains("digest_diff_comparisons_completed_total 1")
    );
}
#[tokio::test]
async fn protected_ui_and_api() {
    let cfg = Config::try_parse_from([
        "test",
        "--oidc-issuer",
        "https://idp.example.com",
        "--oidc-client-id",
        "digest-diff",
    ])
    .unwrap();
    let db = Db::memory().unwrap();
    let jobs = Manager::new(
        db.clone(),
        Arc::new(DemoEngine),
        3600,
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    let auth = AuthMode::from_config(&cfg.auth, &cfg.public_url, false).unwrap();
    let s = AppState::new(cfg, db, jobs, auth, Key::generate(), None);
    let app = web::router(s.clone());
    let res = app
        .clone()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let res = app
        .clone()
        .oneshot(
            Request::get(format!("/jobs?{}", pair().query()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = app
        .clone()
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = web::ops_router(s)
        .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}
#[tokio::test]
async fn restart_marks_unfinished_jobs_but_preserves_inventory() {
    let s = state().await;
    let mut job = s.inner.jobs.start(pair()).await.unwrap();
    job.state = "running".into();
    job.packages_ready = true;
    job.result = Some(Report::default());
    let path =
        std::env::temp_dir().join(format!("digest-diff-recovery-{}.db", rand::random::<u64>()));
    let db = Db::open(&path).unwrap();
    db.save(&job).await.unwrap();
    drop(db);
    let db = Db::open(&path).unwrap();
    db.recover().await.unwrap();
    let recovered = db.get(&job.id).await.unwrap().unwrap();
    assert_eq!(recovered.state, "failed");
    assert!(recovered.packages_ready);
    assert!(recovered.result.is_some());
    drop(db);
    let _ = std::fs::remove_file(path);
}
struct Slow;
#[async_trait::async_trait]
impl Engine for Slow {
    fn fingerprint(&self) -> String {
        "slow".into()
    }
    async fn compare(&self, _: &Pair, _: &digest_diff_2::jobs::Progress) -> anyhow::Result<Report> {
        std::future::pending().await
    }
}
#[tokio::test]
async fn timeout_and_queue_backpressure() {
    let db = Db::memory().unwrap();
    let m = Manager::new(
        db.clone(),
        Arc::new(Slow),
        3600,
        std::time::Duration::from_millis(100),
    )
    .await
    .unwrap();
    let p = pair();
    let first = m.start(p.clone()).await.unwrap();
    assert_eq!(m.start(p).await.unwrap().id, first.id);
    let mut busy = false;
    for i in 0..12 {
        let p = Pair {
            old: format!("image{i}@sha256:{}", "a".repeat(64)),
            new: pair().new,
        };
        if matches!(
            m.start(p).await,
            Err(digest_diff_2::jobs::SubmitError::Busy)
        ) {
            busy = true;
            break;
        }
    }
    assert!(busy);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert_eq!(db.get(&first.id).await.unwrap().unwrap().state, "failed");
}

#[tokio::test]
async fn report_login_redirect_keeps_image_query() {
    let cfg = Config::try_parse_from([
        "test",
        "--oidc-issuer",
        "https://idp.example.com",
        "--oidc-client-id",
        "digest-diff",
    ])
    .unwrap();
    let db = Db::memory().unwrap();
    let jobs = Manager::new(
        db.clone(),
        Arc::new(DemoEngine),
        3600,
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    let auth = AuthMode::from_config(&cfg.auth, &cfg.public_url, false).unwrap();
    let app = web::router(AppState::new(cfg, db, jobs, auth, Key::generate(), None));
    let response = app
        .oneshot(
            Request::get(format!("/comparisons/{}/fragment", pair().id()))
                .header("HX-Request", "true")
                .header(
                    "HX-Current-URL",
                    format!("http://localhost:8080/diff?{}", pair().query()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let redirect = response.headers()["hx-redirect"].to_str().unwrap();
    let url = url::Url::parse(&format!("http://localhost:8080{redirect}")).unwrap();
    let next = url
        .query_pairs()
        .find(|(k, _)| k == "next")
        .unwrap()
        .1
        .to_string();
    assert_eq!(next, format!("/diff?{}", pair().query()));
}

#[tokio::test]
async fn private_badges_are_not_shared_cacheable() {
    let s = state().await;
    let app = web::router(s);
    let response = app
        .oneshot(
            Request::get(format!("/badge?{}", pair().query()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "private, no-store");
}
