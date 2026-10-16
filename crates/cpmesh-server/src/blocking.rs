use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

static PASSWORD_WORKERS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(4)));
static MAIL_WORKERS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(4)));
static PASSWORD_QUEUE: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(64)));
static MAIL_QUEUE: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(64)));

#[derive(Clone, Copy, Debug)]
pub enum Work {
    Password,
    Mail,
}

/// The permit stays with the blocking job even when the HTTP request is cancelled.
pub async fn run<T: Send + 'static>(
    kind: Work,
    job: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let queued = Instant::now();
    let queue = match kind {
        Work::Password => PASSWORD_QUEUE.clone(),
        Work::Mail => MAIL_QUEUE.clone(),
    };
    let _admission = queue.try_acquire_owned().map_err(|_| {
        tracing::warn!(?kind, "Blocking work admission limit reached");
        "service busy; retry shortly".to_string()
    })?;
    let workers = match kind {
        Work::Password => PASSWORD_WORKERS.clone(),
        Work::Mail => MAIL_WORKERS.clone(),
    };
    let permit = tokio::time::timeout(Duration::from_secs(30), workers.acquire_owned())
        .await
        .map_err(|_| {
            tracing::warn!(?kind, "Blocking work queue deadline exceeded");
            "service busy; retry shortly".to_string()
        })?
        .map_err(|e| format!("worker pool unavailable: {e}"))?;
    tracing::debug!(
        ?kind,
        queued_ms = queued.elapsed().as_millis(),
        "Blocking work admitted"
    );
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let started = Instant::now();
        let result = job();
        tracing::debug!(
            ?kind,
            duration_ms = started.elapsed().as_millis(),
            "Blocking work finished"
        );
        result
    })
    .await
    .map_err(|e| format!("blocking work failed: {e}"))?
}
