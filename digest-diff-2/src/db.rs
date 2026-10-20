use crate::jobs::Job;
use rusqlite::{Connection, OptionalExtension};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}
impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let c = Connection::open(path)?;
        c.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(c)
    }
    pub fn memory() -> anyhow::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }
    fn init(c: Connection) -> anyhow::Result<Self> {
        c.busy_timeout(std::time::Duration::from_secs(5))?;
        c.pragma_update(None, "temp_store", "MEMORY")?;
        let v: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
        anyhow::ensure!(v <= 1, "database schema is newer than this application");
        c.execute_batch("CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, updated_at INTEGER NOT NULL, document TEXT NOT NULL); PRAGMA user_version=1;")?;
        Ok(Self {
            conn: Arc::new(Mutex::new(c)),
        })
    }
    async fn call<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> anyhow::Result<T> + Send + 'static,
    ) -> anyhow::Result<T> {
        let c = self.conn.clone();
        tokio::task::spawn_blocking(move || f(&mut c.lock().unwrap_or_else(|e| e.into_inner())))
            .await?
    }
    pub async fn get(&self, id: &str) -> anyhow::Result<Option<Job>> {
        let id = id.to_string();
        self.call(move |c| {
            let doc: Option<String> = c
                .query_row("SELECT document FROM jobs WHERE id=?1", [id], |r| r.get(0))
                .optional()?;
            doc.map(|s| serde_json::from_str(&s).map_err(Into::into))
                .transpose()
        })
        .await
    }
    pub async fn save(&self, job: &Job) -> anyhow::Result<()> {
        let j = job.clone();
        self.call(move|c|{c.execute("INSERT INTO jobs VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at,document=excluded.document",rusqlite::params![j.id,j.updated_at,serde_json::to_string(&j)?])?;Ok(())}).await
    }
    pub async fn recent(&self) -> anyhow::Result<Vec<Job>> {
        self.call(|c| {
            let mut q =
                c.prepare("SELECT document FROM jobs ORDER BY updated_at DESC,id LIMIT 50")?;
            let rows = q.query_map([], |r| r.get::<_, String>(0))?;
            rows.map(|r| Ok(serde_json::from_str(&r?)?)).collect()
        })
        .await
    }
    pub async fn recover(&self) -> anyhow::Result<()> {
        self.call(|c| {
            let mut query = c.prepare("SELECT document FROM jobs")?;
            let docs = query
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            drop(query);
            let tx = c.transaction()?;
            for doc in docs {
                let mut job: Job = serde_json::from_str(&doc)?;
                if matches!(job.state.as_str(), "queued" | "running") {
                    job.state = "failed".into();
                    job.error = Some(
                        "Interrupted by a restart. Retry to resume using cached inventories."
                            .into(),
                    );
                    job.updated_at = jiff::Timestamp::now().as_second();
                    tx.execute(
                        "UPDATE jobs SET document=?2,updated_at=?3 WHERE id=?1",
                        rusqlite::params![job.id, serde_json::to_string(&job)?, job.updated_at],
                    )?;
                }
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }
    pub async fn ping(&self) -> bool {
        self.call(|c| {
            let _: i64 = c.query_row("SELECT 1", [], |r| r.get(0))?;
            Ok(())
        })
        .await
        .is_ok()
    }
}
