pub mod auth;
use crate::{
    config::Config,
    db::Db,
    jobs::{Job, Manager, SubmitError},
    model::Pair,
};
use askama::Template;
use auth::{Admin, AuthMode, Session, User};
use axum::{
    Form, Json, Router,
    body::Body,
    extract::{FromRef, FromRequestParts, Path as WebPath, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{CookieJar, Key};
use rust_embed::RustEmbed;
use serde::Deserialize;
use std::{path::Path, sync::Arc};
use tower_http::trace::TraceLayer;
#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<Inner>,
}
pub struct Inner {
    pub cfg: Config,
    pub db: Db,
    pub jobs: Manager,
    pub auth: AuthMode,
    pub cookie_key: Key,
    pub api_token: Option<String>,
    pub asset_version: String,
}
impl AppState {
    pub fn new(
        cfg: Config,
        db: Db,
        jobs: Manager,
        auth: AuthMode,
        cookie_key: Key,
        api_token: Option<String>,
    ) -> Self {
        let joined = Assets::iter()
            .filter_map(|f| Assets::get(&f))
            .flat_map(|a| a.data.to_vec())
            .collect::<Vec<_>>();
        Self {
            inner: Arc::new(Inner {
                cfg,
                db,
                jobs,
                auth,
                cookie_key,
                api_token,
                asset_version: crate::model::hash(&hex::encode(joined))[..12].into(),
            }),
        }
    }
}
impl FromRef<AppState> for Key {
    fn from_ref(s: &AppState) -> Key {
        s.inner.cookie_key.clone()
    }
}
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    Upstream(String),
    #[error("{0}")]
    Internal(String),
    #[error("scan queue is full; retry shortly")]
    Busy,
}
#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage<'a> {
    status: u16,
    message: &'a str,
}
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let code = match &self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Busy => StatusCode::SERVICE_UNAVAILABLE,
            Self::Upstream(_) => StatusCode::BAD_GATEWAY,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let message = if code.is_server_error() && !matches!(self, Self::Busy) {
            tracing::error!(error=%self,"request failed");
            "The request failed. Check service logs.".into()
        } else {
            self.to_string()
        };
        let body = ErrorPage {
            status: code.as_u16(),
            message: &message,
        }
        .render()
        .unwrap_or(message);
        let mut r = (code, Html(body)).into_response();
        if code == StatusCode::SERVICE_UNAVAILABLE {
            r.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
        }
        r
    }
}
impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e.to_string())
    }
}
impl From<askama::Error> for AppError {
    fn from(e: askama::Error) -> Self {
        Self::Internal(e.to_string())
    }
}
impl From<SubmitError> for AppError {
    fn from(e: SubmitError) -> Self {
        match e {
            SubmitError::Busy => Self::Busy,
            SubmitError::Other(e) => e.into(),
        }
    }
}
#[derive(RustEmbed)]
#[folder = "assets/"]
struct Assets;
async fn asset(WebPath(path): WebPath<String>) -> Response {
    match Assets::get(&path) {
        Some(f) => (
            [
                (
                    header::CONTENT_TYPE,
                    mime_guess::from_path(&path)
                        .first_or_octet_stream()
                        .to_string(),
                ),
                (
                    header::CACHE_CONTROL,
                    "public, max-age=31536000, immutable".into(),
                ),
            ],
            Body::from(f.data.into_owned()),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
struct Layout {
    title: String,
    user: String,
    csrf: String,
    admin: bool,
    dev_auth: bool,
    dark: bool,
    palette: String,
    appearance: String,
    asset_version: String,
    demo: bool,
}
fn layout(s: &AppState, user: &Session, cookies: &CookieJar, title: &str) -> Layout {
    let palette: String = cookies
        .get("digest_diff_palette")
        .map(|c| c.value())
        .filter(|p| ["neutral", "blue", "green", "orange", "violet"].contains(p))
        .unwrap_or("neutral")
        .into();
    let appearance = cookies
        .get("digest_diff_appearance")
        .map(|c| c.value())
        .filter(|m| ["minimal", "accent", "full"].contains(m))
        .unwrap_or(if palette == "neutral" {
            "minimal"
        } else {
            "accent"
        })
        .into();
    Layout {
        appearance,
        title: title.into(),
        user: user.name.clone(),
        csrf: user.csrf.clone(),
        admin: user.admin,
        dev_auth: matches!(s.inner.auth, AuthMode::InsecureDev { .. }),
        dark: cookies
            .get("digest_diff_theme")
            .is_some_and(|c| c.value() == "dark"),
        palette,
        asset_version: s.inner.asset_version.clone(),
        demo: s.inner.cfg.demo,
    }
}
fn view_job(s: &AppState, mut job: Job) -> Job {
    if job.state == "completed" && !job.fresh(s.inner.jobs.ttl, &s.inner.jobs.fingerprint) {
        job.state = "stale".into();
    }
    job
}
#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage {
    layout: Layout,
    jobs: Vec<Job>,
    query: String,
}
#[derive(Template)]
#[template(path = "comparison.html")]
struct ComparisonPage {
    layout: Layout,
    job: Job,
}
#[derive(Template)]
#[template(path = "partials/comparison.html")]
struct ComparisonFragment {
    job: Job,
    csrf: String,
    admin: bool,
}
#[derive(Deserialize, Default)]
struct Search {
    #[serde(default)]
    q: String,
}
async fn index(
    State(s): State<AppState>,
    User(user): User,
    cookies: CookieJar,
    Query(q): Query<Search>,
) -> Result<Html<String>, AppError> {
    if q.q.len() > 256 {
        return Err(AppError::BadRequest(
            "Search is limited to 256 characters".into(),
        ));
    }
    let query = q.q.to_lowercase();
    let jobs = s
        .inner
        .db
        .recent()
        .await?
        .into_iter()
        .map(|j| view_job(&s, j))
        .filter(|j| {
            format!("{} {}", j.pair.old, j.pair.new)
                .to_lowercase()
                .contains(&query)
        })
        .collect();
    Ok(Html(
        IndexPage {
            layout: layout(&s, &user, &cookies, "Comparisons"),
            jobs,
            query: q.q,
        }
        .render()?,
    ))
}
#[derive(Deserialize)]
struct CompareForm {
    old: String,
    new: String,
    _csrf: Option<String>,
}
async fn create(
    State(s): State<AppState>,
    Admin(user): Admin,
    headers: HeaderMap,
    Form(f): Form<CompareForm>,
) -> Result<Redirect, AppError> {
    user.check_csrf(&headers, f._csrf.as_deref())?;
    let pair = Pair {
        old: f.old,
        new: f.new,
    };
    pair.validate().map_err(AppError::BadRequest)?;
    s.inner.jobs.start(pair.clone()).await?;
    Ok(Redirect::to(&format!("/diff?{}", pair.query())))
}
#[derive(Deserialize)]
struct DiffQuery {
    old: String,
    new: String,
    #[serde(default)]
    fragment: Option<String>,
}
fn pair(q: DiffQuery) -> Result<Pair, AppError> {
    let p = Pair {
        old: q.old,
        new: q.new,
    };
    p.validate().map_err(AppError::BadRequest)?;
    Ok(p)
}
fn blank_job(s: &AppState, pair: Pair) -> Job {
    Job {
        id: pair.id(),
        pair,
        state: "not_scanned".into(),
        stage: "not_scanned".into(),
        packages_ready: false,
        submitted_at: 0,
        updated_at: 0,
        finished_at: None,
        error: None,
        result: None,
        fingerprint: s.inner.jobs.fingerprint.clone(),
    }
}
async fn comparison(
    State(s): State<AppState>,
    User(user): User,
    cookies: CookieJar,
    Query(q): Query<DiffQuery>,
) -> Result<Response, AppError> {
    let fragment = q.fragment.as_deref() == Some("1");
    let p = pair(q)?;
    let job = s
        .inner
        .db
        .get(&p.id())
        .await?
        .unwrap_or_else(|| blank_job(&s, p));
    let job = view_job(&s, job);
    if fragment {
        return fragment_response(job, &user);
    }
    Ok(Html(
        ComparisonPage {
            layout: layout(&s, &user, &cookies, "Digest comparison"),
            job,
        }
        .render()?,
    )
    .into_response())
}
fn fragment_response(job: Job, user: &Session) -> Result<Response, AppError> {
    Ok(Html(
        ComparisonFragment {
            job,
            csrf: user.csrf.clone(),
            admin: user.admin,
        }
        .render()?,
    )
    .into_response())
}
async fn fragment(
    State(s): State<AppState>,
    User(user): User,
    WebPath(id): WebPath<String>,
) -> Result<Response, AppError> {
    let j = s
        .inner
        .db
        .get(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("Comparison not found".into()))?;
    fragment_response(view_job(&s, j), &user)
}
fn valid_api(s: &AppState, h: &HeaderMap) -> bool {
    let Some(expected) = &s.inner.api_token else {
        return false;
    };
    h.get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .is_some_and(|provided| auth::constant_time_eq(expected.as_bytes(), provided.as_bytes()))
}
pub struct ApiCaller {
    session: Option<Session>,
}
impl FromRequestParts<AppState> for ApiCaller {
    type Rejection = Response;
    async fn from_request_parts(parts: &mut Parts, s: &AppState) -> Result<Self, Response> {
        if valid_api(s, &parts.headers) {
            return Ok(Self { session: None });
        }
        if parts.headers.contains_key(header::AUTHORIZATION) {
            return Err(StatusCode::UNAUTHORIZED.into_response());
        }
        match User::from_request_parts(parts, s).await {
            Ok(User(session)) => Ok(Self {
                session: Some(session),
            }),
            Err(_) => Err(StatusCode::UNAUTHORIZED.into_response()),
        }
    }
}
async fn get_job(
    State(s): State<AppState>,
    _caller: ApiCaller,
    Query(p): Query<Pair>,
) -> Result<Response, AppError> {
    p.validate().map_err(AppError::BadRequest)?;
    Ok(match s.inner.db.get(&p.id()).await? {
        Some(j) => Json(view_job(&s, j)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"state":"not_scanned"})),
        )
            .into_response(),
    })
}
async fn submit_job(
    State(s): State<AppState>,
    caller: ApiCaller,
    headers: HeaderMap,
    Query(p): Query<Pair>,
) -> Result<Response, AppError> {
    if let Some(u) = caller.session {
        if !u.admin {
            return Err(AppError::Forbidden(
                "Submitting comparisons requires admin rights".into(),
            ));
        }
        u.check_csrf(&headers, None)?;
    }
    p.validate().map_err(AppError::BadRequest)?;
    let j = s.inner.jobs.start(p).await?;
    let status = if j.state == "completed" {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    Ok((status, Json(j)).into_response())
}
async fn json_report(
    State(s): State<AppState>,
    caller: ApiCaller,
    Query(p): Query<Pair>,
) -> Result<Response, AppError> {
    p.validate().map_err(AppError::BadRequest)?;
    let mut job = s.inner.db.get(&p.id()).await?;
    if job
        .as_ref()
        .is_none_or(|j| !j.pending() && !j.fresh(s.inner.jobs.ttl, &s.inner.jobs.fingerprint))
    {
        if caller.session.is_some() {
            return Err(AppError::BadRequest(
                "Submit the comparison with POST /jobs first".into(),
            ));
        }
        job = Some(s.inner.jobs.start(p.clone()).await?);
    }
    let mut j = job.expect("job submitted");
    while j.pending() {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        j = s
            .inner
            .db
            .get(&j.id)
            .await?
            .ok_or_else(|| AppError::NotFound("Comparison was removed".into()))?;
    }
    if j.state != "completed" {
        return Err(AppError::Upstream(
            "Comparison failed; inspect GET /jobs".into(),
        ));
    }
    Ok(Json(j.result).into_response())
}
async fn badge(
    State(s): State<AppState>,
    caller: Result<ApiCaller, Response>,
    Query(p): Query<Pair>,
) -> Result<Response, AppError> {
    if !s.inner.cfg.public_badges && caller.is_err() {
        return Err(AppError::Unauthorized("Login required".into()));
    }
    p.validate().map_err(AppError::BadRequest)?;
    let job = s.inner.db.get(&p.id()).await?;
    let text = match job {
        Some(j) => {
            if j.state == "completed" {
                if j.fresh(s.inner.jobs.ttl, &s.inner.jobs.fingerprint) {
                    j.summary()
                } else {
                    "stale".into()
                }
            } else {
                j.state
            }
        }
        None => "not scanned".into(),
    };
    let escaped = text
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;");
    let width = 120 + text.chars().count() * 7;
    let cache_control = if s.inner.cfg.public_badges {
        "max-age=15, must-revalidate"
    } else {
        "private, no-store"
    };
    Ok(([(header::CONTENT_TYPE,"image/svg+xml"),(header::CACHE_CONTROL,cache_control)],format!(r##"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="24" role="img" aria-label="digest diff: {escaped}"><rect width="100%" height="24" rx="4" fill="#334155"/><text x="10" y="16" fill="white" font-family="sans-serif" font-size="12">digest diff: {escaped}</text></svg>"##)).into_response())
}
async fn headers(req: Request, next: Next) -> Response {
    let asset = req.uri().path().starts_with("/assets/");
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY,HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    if !asset && !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    r
}
async fn origin(State(s): State<AppState>, req: Request, next: Next) -> Response {
    if !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS)
        && !valid_api(&s, req.headers())
        && req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            != Some(s.inner.cfg.public_origin().as_str())
    {
        return AppError::Forbidden("Cross-origin request rejected".into()).into_response();
    }
    next.run(req).await
}
pub fn router(s: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/comparisons", post(create))
        .route("/comparisons/{id}/fragment", get(fragment))
        .route("/diff", get(comparison))
        .route("/diff.json", get(json_report))
        .route("/jobs", get(get_job).post(submit_job))
        .route("/badge", get(badge))
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/logout", post(auth::logout))
        .route("/assets/{*path}", get(asset))
        .layer(middleware::from_fn_with_state(s.clone(), origin))
        .layer(middleware::from_fn(headers))
        .layer(axum::extract::DefaultBodyLimit::max(16384))
        .layer(TraceLayer::new_for_http().make_span_with(
            |req: &Request| tracing::info_span!("http",method=%req.method(),path=%req.uri().path()),
        ))
        .with_state(s)
}
pub fn ops_router(s: AppState) -> Router {
    let metrics = s.inner.jobs.metrics.clone();
    let db = s.inner.db.clone();
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route(
            "/readyz",
            get(move || {
                let db = db.clone();
                async move {
                    if db.ping().await {
                        (StatusCode::OK, "ready\n")
                    } else {
                        (StatusCode::SERVICE_UNAVAILABLE, "database unavailable\n")
                    }
                }
            }),
        )
        .route(
            "/metrics",
            get(move || {
                let m = metrics.clone();
                async move {
                    (
                        [(
                            header::CONTENT_TYPE,
                            "application/openmetrics-text; version=1.0.0; charset=utf-8",
                        )],
                        m.encode(),
                    )
                }
            }),
        )
}
pub fn load_cookie_key(path: Option<&Path>) -> anyhow::Result<Key> {
    use base64::Engine as _;
    match path {
        None => {
            tracing::warn!("no cookie key file: sessions do not survive restart");
            Ok(Key::generate())
        }
        Some(p) => {
            let raw = std::fs::read(p)?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(String::from_utf8_lossy(&raw).trim())
                .ok()
                .filter(|v| v.len() >= 64)
                .unwrap_or(raw);
            Key::try_from(bytes.as_slice())
                .map_err(|_| anyhow::anyhow!("cookie key must contain at least 64 bytes"))
        }
    }
}
