use digest_diff_2::{
    config::Config,
    db::Db,
    jobs::Manager,
    scanner::{DemoEngine, Engine, Scanner},
    web::{self, AppState, auth::AuthMode},
};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::load();
    let filter = EnvFilter::try_from_env("DIGEST_DIFF_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info"));
    if cfg.log_json {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init()
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init()
    }
    let db = if cfg.demo {
        Db::memory()?
    } else {
        Db::open(&cfg.data_dir.join("digest-diff.db"))?
    };
    let auth = AuthMode::from_config(
        &cfg.auth,
        &cfg.public_url,
        cfg.demo && cfg.auth.oidc_issuer.is_none(),
    )?;
    let key = web::load_cookie_key(cfg.auth.cookie_key_file.as_deref())?;
    let token = cfg
        .api_token_file
        .as_ref()
        .map(std::fs::read_to_string)
        .transpose()?
        .map(|s| s.trim().to_owned());
    if let Some(t) = &token {
        anyhow::ensure!(t.len() >= 32, "API token must be at least 32 characters")
    }
    let engine: Arc<dyn Engine> = if cfg.demo {
        Arc::new(DemoEngine)
    } else {
        Arc::new(
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                Scanner::new(cfg.data_dir.join("cache"), cfg.allowed_registries.clone()),
            )
            .await??,
        )
    };
    let manager = Manager::new(
        db.clone(),
        engine,
        cfg.scan_ttl.as_secs(),
        std::time::Duration::from_secs(cfg.scan_timeout.as_secs() as u64),
    )
    .await?;
    let state = AppState::new(cfg.clone(), db, manager, auth, key, token);
    if cfg.demo {
        state
            .inner
            .jobs
            .start(digest_diff_2::model::Pair {
                old: format!("postgres:18@sha256:{}", "a".repeat(64)),
                new: format!("postgres:18@sha256:{}", "b".repeat(64)),
            })
            .await?;
    }
    let ui = tokio::net::TcpListener::bind(cfg.listen).await?;
    let ops = tokio::net::TcpListener::bind(cfg.metrics_listen).await?;
    tracing::info!(ui=%cfg.listen,ops=%cfg.metrics_listen,"listening");
    tokio::select! {r=axum::serve(ui,web::router(state.clone())).with_graceful_shutdown(shutdown())=>r?,r=axum::serve(ops,web::ops_router(state)).with_graceful_shutdown(shutdown())=>r?};
    Ok(())
}
async fn shutdown() {
    let ctrl = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {_=ctrl=>{},_=term=>{}}
}
