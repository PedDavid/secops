use clap::{CommandFactory, Parser};
use jiff::SignedDuration;
use std::{net::SocketAddr, path::PathBuf};
use url::Url;
fn duration(s: &str) -> Result<SignedDuration, String> {
    crate::duration::parse(s).map_err(|e| e.to_string())
}
#[derive(Parser, Debug, Clone)]
#[command(
    version,
    about = "Container digest comparisons, built on the homelab application foundation"
)]
pub struct Config {
    #[arg(long, env = "DIGEST_DIFF_LISTEN", default_value = "0.0.0.0:8080")]
    pub listen: SocketAddr,
    #[arg(
        long,
        env = "DIGEST_DIFF_METRICS_LISTEN",
        default_value = "0.0.0.0:9090"
    )]
    pub metrics_listen: SocketAddr,
    #[arg(
        long,
        env = "DIGEST_DIFF_PUBLIC_URL",
        default_value = "http://localhost:8080"
    )]
    pub public_url: Url,
    #[arg(long, env = "DIGEST_DIFF_DATA_DIR", default_value = "/data")]
    pub data_dir: PathBuf,
    #[arg(long,env="DIGEST_DIFF_SCAN_TTL",default_value="6h",value_parser=duration)]
    pub scan_ttl: SignedDuration,
    #[arg(long,env="DIGEST_DIFF_SCAN_TIMEOUT",default_value="15m",value_parser=duration)]
    pub scan_timeout: SignedDuration,
    #[arg(long, env = "DIGEST_DIFF_DEMO")]
    pub demo: bool,
    #[arg(long, env = "DIGEST_DIFF_LOG_JSON")]
    pub log_json: bool,
    /// Token file for Renovate's API calls. Never supplied in a URL.
    #[arg(long, env = "DIGEST_DIFF_API_TOKEN_FILE")]
    pub api_token_file: Option<PathBuf>,
    #[arg(long, env = "DIGEST_DIFF_PUBLIC_BADGES")]
    pub public_badges: bool,
    #[arg(
        long,
        env = "DIGEST_DIFF_ALLOWED_REGISTRIES",
        value_delimiter = ',',
        default_value = "docker.io,registry-1.docker.io,ghcr.io,quay.io,gcr.io,mcr.microsoft.com"
    )]
    pub allowed_registries: Vec<String>,
    #[command(flatten)]
    pub auth: AuthConfig,
}
#[derive(clap::Args, Debug, Clone)]
pub struct AuthConfig {
    #[arg(long, env = "DIGEST_DIFF_OIDC_ISSUER")]
    pub oidc_issuer: Option<Url>,
    #[arg(long, env = "DIGEST_DIFF_OIDC_CLIENT_ID")]
    pub oidc_client_id: Option<String>,
    #[arg(long, env = "DIGEST_DIFF_OIDC_CLIENT_SECRET_FILE")]
    pub oidc_client_secret_file: Option<PathBuf>,
    #[arg(
        long,
        env = "DIGEST_DIFF_OIDC_SCOPES",
        default_value = "profile email groups"
    )]
    pub oidc_scopes: String,
    #[arg(long, env = "DIGEST_DIFF_ADMIN_CLAIM", default_value = "groups")]
    pub admin_claim: String,
    #[arg(
        long,
        env = "DIGEST_DIFF_ADMIN_VALUE",
        default_value = "digest-diff-admins"
    )]
    pub admin_value: String,
    #[arg(long,env="DIGEST_DIFF_SESSION_TTL",default_value="8h",value_parser=duration)]
    pub session_ttl: SignedDuration,
    #[arg(long, env = "DIGEST_DIFF_COOKIE_KEY_FILE")]
    pub cookie_key_file: Option<PathBuf>,
    #[arg(long, env = "DIGEST_DIFF_INSECURE_DEV_AUTH")]
    pub insecure_dev_auth: bool,
}
impl Config {
    pub fn load() -> Self {
        let cfg = Self::parse();
        if let Err(e) = cfg.check() {
            Self::command()
                .error(clap::error::ErrorKind::ArgumentConflict, e)
                .exit()
        };
        cfg
    }
    pub fn check(&self) -> Result<(), String> {
        if !matches!(self.public_url.scheme(), "http" | "https")
            || self.public_url.path() != "/"
            || self.public_url.query().is_some()
            || self.public_url.fragment().is_some()
        {
            return Err("public URL must be an http(s) origin".into());
        }
        for d in [self.scan_ttl, self.scan_timeout, self.auth.session_ttl] {
            if d.as_secs() <= 0 {
                return Err("durations must be positive".into());
            }
        }
        Ok(())
    }
    pub fn public_origin(&self) -> String {
        self.public_url.origin().ascii_serialization()
    }
}
