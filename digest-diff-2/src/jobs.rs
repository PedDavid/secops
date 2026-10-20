use crate::{
    db::Db,
    model::{Pair, Report},
    scanner::Engine,
};
use prometheus_client::{
    encoding::text::encode,
    metrics::{
        counter::Counter,
        gauge::Gauge,
        histogram::{Histogram, exponential_buckets},
    },
    registry::Registry,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    #[serde(flatten)]
    pub pair: Pair,
    pub state: String,
    pub stage: String,
    pub packages_ready: bool,
    pub submitted_at: i64,
    pub updated_at: i64,
    pub finished_at: Option<i64>,
    pub error: Option<String>,
    pub result: Option<Report>,
    pub fingerprint: String,
}
impl Job {
    pub fn fresh(&self, ttl: i64, fingerprint: &str) -> bool {
        self.state == "completed"
            && self.fingerprint == fingerprint
            && self
                .finished_at
                .is_some_and(|t| jiff::Timestamp::now().as_second() - t < ttl)
    }
    pub fn stage_label(&self) -> &str {
        if self.state == "stale" {
            return "Report is due for refresh";
        }
        match self.stage.as_str() {
            "inventory_old" => "Reading original image packages",
            "inventory_new" => "Reading updated image packages",
            "database" => "Updating vulnerability database",
            "vulnerabilities_old" => "Checking original image vulnerabilities",
            "vulnerabilities_new" => "Checking updated image vulnerabilities",
            "completed" => "Comparison complete",
            _ => "Waiting for the scanner",
        }
    }
    pub fn summary(&self) -> String {
        match &self.result {
            Some(r) => match &r.vulnerabilities {
                Some(v) => format!(
                    "{} introduced · {} resolved",
                    v.introduced.len(),
                    v.resolved.len()
                ),
                None => format!(
                    "{} package changes",
                    r.changed.len() + r.added.len() + r.removed.len()
                ),
            },
            None => "Awaiting inventory".into(),
        }
    }
    pub fn pending(&self) -> bool {
        matches!(self.state.as_str(), "queued" | "running")
    }
}
#[derive(Clone)]
pub struct Progress {
    pub db: Db,
    pub job: Arc<Mutex<Job>>,
}
impl Progress {
    pub async fn update(&self, stage: &str, report: Option<Report>) -> anyhow::Result<()> {
        let mut j = self.job.lock().await;
        j.stage = stage.into();
        j.updated_at = jiff::Timestamp::now().as_second();
        if let Some(r) = report {
            j.packages_ready = true;
            j.result = Some(r)
        }
        self.db.save(&j).await
    }
}
pub struct Metrics {
    registry: Registry,
    pub completed: Counter,
    pub failed: Counter,
    pub active: Gauge,
    pub queued: Gauge,
    pub duration: Histogram,
}
impl Default for Metrics {
    fn default() -> Self {
        let mut r = Registry::default();
        let completed = Counter::default();
        let failed = Counter::default();
        let active = Gauge::default();
        let queued = Gauge::default();
        let duration = Histogram::new(exponential_buckets(1., 2., 12));
        r.register(
            "digest_diff_comparisons_completed",
            "Completed comparisons",
            completed.clone(),
        );
        r.register(
            "digest_diff_comparisons_failed",
            "Failed comparisons",
            failed.clone(),
        );
        r.register("digest_diff_scans_active", "Running scans", active.clone());
        r.register("digest_diff_scans_queued", "Queued scans", queued.clone());
        r.register(
            "digest_diff_scan_duration_seconds",
            "Comparison running time",
            duration.clone(),
        );
        Self {
            registry: r,
            completed,
            failed,
            active,
            queued,
            duration,
        }
    }
}
impl Metrics {
    pub fn encode(&self) -> String {
        let mut s = String::new();
        encode(&mut s, &self.registry).expect("metrics encoding");
        s
    }
}
#[derive(Clone)]
pub struct Manager {
    pub db: Db,
    tx: mpsc::Sender<Job>,
    submit: Arc<Mutex<()>>,
    pub metrics: Arc<Metrics>,
    pub fingerprint: String,
    pub ttl: i64,
}
#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("scan queue is full; retry shortly")]
    Busy,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
impl Manager {
    pub async fn new(
        db: Db,
        engine: Arc<dyn Engine>,
        ttl: i64,
        timeout: std::time::Duration,
    ) -> anyhow::Result<Self> {
        db.recover().await?;
        let (tx, mut rx) = mpsc::channel::<Job>(8);
        let metrics = Arc::new(Metrics::default());
        let m = Self {
            db: db.clone(),
            tx,
            submit: Arc::new(Mutex::new(())),
            metrics: metrics.clone(),
            fingerprint: engine.fingerprint(),
            ttl,
        };
        tokio::spawn(async move {
            while let Some(mut job) = rx.recv().await {
                metrics.queued.dec();
                metrics.active.set(1);
                let start = std::time::Instant::now();
                job.state = "running".into();
                let progress = Progress {
                    db: db.clone(),
                    job: Arc::new(Mutex::new(job)),
                };
                let outcome = async {
                    progress.update("inventory_old", None).await?;
                    let pair = progress.job.lock().await.pair.clone();
                    engine.compare(&pair, &progress).await
                };
                let outcome = match tokio::time::timeout(timeout, outcome).await {
                    Ok(r) => r,
                    Err(_) => Err(anyhow::anyhow!("scan timed out")),
                };
                let mut job = progress.job.lock().await;
                let now = jiff::Timestamp::now().as_second();
                job.updated_at = now;
                job.finished_at = Some(now);
                match outcome {
                    Ok(report) => {
                        job.state = "completed".into();
                        job.stage = "completed".into();
                        job.packages_ready = true;
                        job.result = Some(report);
                        metrics.completed.inc();
                    }
                    Err(e) => {
                        tracing::error!(job=%job.id,error=%e,"comparison failed");
                        job.state = "failed".into();
                        job.error = Some("Scan failed. Check service logs and retry.".into());
                        metrics.failed.inc();
                    }
                }
                if let Err(e) = db.save(&job).await {
                    tracing::error!(error=%e,"cannot persist scan outcome")
                }
                metrics.active.set(0);
                metrics.duration.observe(start.elapsed().as_secs_f64());
            }
        });
        Ok(m)
    }
    pub async fn start(&self, pair: Pair) -> Result<Job, SubmitError> {
        let _guard = self.submit.lock().await;
        let id = pair.id();
        if let Some(j) = self.db.get(&id).await?
            && (j.pending() || j.fresh(self.ttl, &self.fingerprint))
        {
            return Ok(j);
        }
        // Reserve capacity before persisting so a rejected request cannot erase an old report.
        let permit = self
            .tx
            .clone()
            .try_reserve_owned()
            .map_err(|_| SubmitError::Busy)?;
        let now = jiff::Timestamp::now().as_second();
        let j = Job {
            id,
            pair,
            state: "queued".into(),
            stage: "queued".into(),
            packages_ready: false,
            submitted_at: now,
            updated_at: now,
            finished_at: None,
            error: None,
            result: None,
            fingerprint: self.fingerprint.clone(),
        };
        self.db.save(&j).await?;
        self.metrics.queued.inc();
        permit.send(j.clone());
        Ok(j)
    }
}
