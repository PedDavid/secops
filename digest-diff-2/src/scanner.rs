use crate::{
    jobs::Progress,
    model::{self, Finding, Package, Pair, Report, hash},
};
use anyhow::{Context, bail};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Stdio,
};
#[async_trait::async_trait]
pub trait Engine: Send + Sync {
    fn fingerprint(&self) -> String;
    async fn compare(&self, pair: &Pair, progress: &Progress) -> anyhow::Result<Report>;
}
pub struct Scanner {
    dir: PathBuf,
    syft: String,
    grype: String,
    registries: Vec<String>,
}
impl Scanner {
    pub async fn new(dir: PathBuf, registries: Vec<String>) -> anyhow::Result<Self> {
        tokio::fs::create_dir_all(&dir).await?;
        let syft = tool_version("syft").await?;
        let grype = tool_version("grype").await?;
        atomic(&dir.join("syft.json"), b"{}").await?;
        atomic(&dir.join("grype.json"),&serde_json::to_vec(&json!({"db":{"cache-dir":dir.join("grype-db"),"auto-update":false,"validate-by-hash-on-start":true,"validate-age":true,"max-allowed-built-age":"120h"}}))?).await?;
        Ok(Self {
            dir,
            syft,
            grype,
            registries,
        })
    }
    pub fn registry(reference: &str) -> &str {
        let head = reference.split('/').next().unwrap_or_default();
        if reference.contains('/')
            && (head.contains('.') || head.contains(':') || head == "localhost")
        {
            head
        } else {
            "docker.io"
        }
    }
    async fn tool(&self, name: &str, args: &[String]) -> anyhow::Result<Vec<u8>> {
        let mut a = vec![
            "--config".into(),
            self.dir
                .join(format!("{name}.json"))
                .to_string_lossy()
                .into_owned(),
        ];
        a.extend_from_slice(args);
        run(name, &a).await
    }
    async fn sbom(&self, reference: &str) -> anyhow::Result<(PathBuf, Vec<Package>)> {
        anyhow::ensure!(
            self.registries
                .iter()
                .any(|r| r == Self::registry(reference)),
            "registry is not allowed by deployment configuration"
        );
        let path = self.dir.join("sboms").join(format!(
            "{}.json",
            hash(&format!("{reference}|linux/amd64|{}", self.syft))
        ));
        let raw = match tokio::fs::read(&path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.tool(
                    "syft",
                    &[
                        "scan".into(),
                        format!("registry:{reference}"),
                        "--platform".into(),
                        "linux/amd64".into(),
                        "-o".into(),
                        "syft-json".into(),
                    ],
                )
                .await?
            }
            Err(e) => return Err(e.into()),
        };
        let doc: Value = serde_json::from_slice(&raw)?;
        let artifacts = doc
            .get("artifacts")
            .and_then(Value::as_array)
            .context("Syft output missing artifacts")?;
        let packages = artifacts
            .iter()
            .map(|p| serde_json::from_value(p.clone()))
            .collect::<Result<Vec<Package>, _>>()?;
        atomic(&path, &raw).await?;
        Ok((path, packages))
    }
    async fn findings(&self, sbom: &Path, db_id: &str) -> anyhow::Result<Vec<Finding>> {
        let path = self.dir.join("findings").join(format!(
            "{}.json",
            hash(&format!("{}|{db_id}|{}|v2", sbom.display(), self.grype))
        ));
        if let Ok(raw) = tokio::fs::read(&path).await
            && let Ok(fs) = serde_json::from_slice(&raw)
        {
            return Ok(fs);
        }
        let raw = self
            .tool(
                "grype",
                &[
                    format!("sbom:{}", sbom.display()),
                    "-o".into(),
                    "json".into(),
                ],
            )
            .await?;
        let fs = parse_findings(&raw)?;
        atomic(&path, &serde_json::to_vec(&fs)?).await?;
        Ok(fs)
    }
}
#[async_trait::async_trait]
impl Engine for Scanner {
    fn fingerprint(&self) -> String {
        format!("{}|{}|linux/amd64|v2", self.syft, self.grype)
    }
    async fn compare(&self, pair: &Pair, progress: &Progress) -> anyhow::Result<Report> {
        progress.update("inventory_old", None).await?;
        let (a, old) = self.sbom(&pair.old).await?;
        progress.update("inventory_new", None).await?;
        let (b, new) = self.sbom(&pair.new).await?;
        let mut r = model::packages(&old, &new);
        progress.update("database", Some(r.clone())).await?;
        self.tool("grype", &["db".into(), "update".into()]).await?;
        let status: Value = serde_json::from_slice(
            &self
                .tool(
                    "grype",
                    &["db".into(), "status".into(), "-o".into(), "json".into()],
                )
                .await?,
        )?;
        anyhow::ensure!(
            status["valid"] == true && status["built"].is_string(),
            "vulnerability database is not valid"
        );
        let db_id = hash(&format!(
            "{}|{}|{}",
            status["built"], status["from"], status["schemaVersion"]
        ));
        progress.update("vulnerabilities_old", None).await?;
        let old = self.findings(&a, &db_id).await?;
        progress.update("vulnerabilities_new", None).await?;
        let new = self.findings(&b, &db_id).await?;
        r.vulnerabilities = Some(model::vulnerabilities(old, new));
        r.scan = Some(
            json!({"platform":"linux/amd64","syft_version":self.syft,"grype_version":self.grype,"database":status,"database_id":db_id,"scanned_at":jiff::Timestamp::now().to_string()}),
        );
        Ok(r)
    }
}
async fn tool_version(name: &str) -> anyhow::Result<String> {
    let v: Value =
        serde_json::from_slice(&run(name, &["version".into(), "-o".into(), "json".into()]).await?)?;
    Ok(v["version"]
        .as_str()
        .context("missing scanner version")?
        .into())
}
async fn run(name: &str, args: &[String]) -> anyhow::Result<Vec<u8>> {
    let mut cmd = tokio::process::Command::new(name);
    cmd.args(args).kill_on_drop(true).stdin(Stdio::null());
    for (k, _) in std::env::vars_os() {
        if let Some(k) = k.to_str()
            && (k.starts_with("GRYPE_") || k.starts_with("SYFT_"))
        {
            cmd.env_remove(k);
        }
    }
    let out = cmd
        .env("GRYPE_CHECK_FOR_APP_UPDATE", "false")
        .env("SYFT_CHECK_FOR_APP_UPDATE", "false")
        .output()
        .await
        .with_context(|| format!("starting {name}"))?;
    if !out.status.success() {
        bail!(
            "{name} failed: {}",
            String::from_utf8_lossy(&out.stderr[..out.stderr.len().min(4096)])
        )
    }
    Ok(out.stdout)
}
async fn atomic(path: &Path, raw: &[u8]) -> anyhow::Result<()> {
    tokio::fs::create_dir_all(path.parent().context("missing cache parent")?).await?;
    let tmp = path.with_extension(format!("{}.tmp", rand::random::<u64>()));
    tokio::fs::write(&tmp, raw).await?;
    if let Err(e) = tokio::fs::rename(&tmp, path).await {
        let _ = tokio::fs::remove_file(tmp).await;
        return Err(e.into());
    }
    Ok(())
}
pub fn parse_findings(raw: &[u8]) -> anyhow::Result<Vec<Finding>> {
    let doc: Value = serde_json::from_slice(raw)?;
    let matches = doc["matches"]
        .as_array()
        .context("Grype output missing matches")?;
    let mut fs = vec![];
    let mut seen = BTreeSet::new();
    for m in matches {
        let v = &m["vulnerability"];
        let a: &Value = &m["artifact"];
        anyhow::ensure!(
            v["id"].is_string() && v["severity"].is_string(),
            "Grype match missing vulnerability identity/severity"
        );
        anyhow::ensure!(
            ["name", "version", "type"]
                .iter()
                .all(|k| a[*k].is_string()),
            "Grype match missing package identity"
        );
        let field = |v: &Value, k: &str| v[k].as_str().unwrap_or_default().to_owned();
        let f = Finding {
            id: field(v, "id"),
            url: field(v, "dataSource"),
            namespace: field(v, "namespace"),
            package: field(a, "name"),
            kind: field(a, "type"),
            version: field(a, "version"),
            severity: field(v, "severity"),
            fix_state: field(&v["fix"], "state"),
            fix_versions: serde_json::from_value(v["fix"]["versions"].clone()).unwrap_or_default(),
        };
        if seen.insert((f.identity(), f.version.clone())) {
            fs.push(f)
        }
    }
    Ok(fs)
}
pub struct DemoEngine;
#[async_trait::async_trait]
impl Engine for DemoEngine {
    fn fingerprint(&self) -> String {
        "demo-v2".into()
    }
    async fn compare(&self, _: &Pair, progress: &Progress) -> anyhow::Result<Report> {
        progress.update("inventory_old", None).await?;
        tokio::time::sleep(std::time::Duration::from_millis(350)).await;
        progress.update("inventory_new", None).await?;
        let p = |name: &str, v: &str| Package {
            name: name.into(),
            version: v.into(),
            kind: "deb".into(),
        };
        let mut r = model::packages(
            &[p("openssl", "3.0.15"), p("curl", "8.10.0")],
            &[
                p("openssl", "3.0.16"),
                p("curl", "8.11.0"),
                p("ca-certificates", "20261001"),
            ],
        );
        progress.update("database", Some(r.clone())).await?;
        tokio::time::sleep(std::time::Duration::from_millis(900)).await;
        r.vulnerabilities = Some(model::Vulnerabilities {
            resolved: vec![Finding {
                id: "CVE-2025-12345".into(),
                package: "openssl".into(),
                version: "3.0.15".into(),
                severity: "High".into(),
                fix_state: "fixed".into(),
                fix_versions: vec!["3.0.16".into()],
                ..Default::default()
            }],
            ..Default::default()
        });
        r.scan = Some(
            json!({"platform":"linux/amd64","syft_version":"demo","grype_version":"demo","scanned_at":"2026-10-19T12:00:00Z","database":{"demo":true}}),
        );
        Ok(r)
    }
}
