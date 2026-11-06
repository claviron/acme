use std::path::Path;
use std::time::{Duration, SystemTime};

use claviron::runtime::AppState;
use claviron::tasks::{TaskResult, task};
use tokio::fs;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::acme_config;

/// Remove ACME challenge files older than the given age (default 60 minutes).
/// Safe to call periodically (idempotent). If ACME is not configured, it no-ops.
#[task(
    name = "acme_gc",
    scope = "workers",
    dispatch = "one",
    crate_path = "claviron",
    config = "timing: { kind: interval, every: 1h, skip_on_boot: true }\nattempts: 1\nsilent: false\n"
)]
pub async fn acme_challenge_gc(
    state: AppState,
    _cancel: CancellationToken, // runtime: claviron::tasks::TaskRuntime,
) -> TaskResult<()> {
    let Some(cfg) = acme_config(&state)? else {
        debug!("acme_gc: acme.yaml missing; skipping");
        return Ok(());
    };
    if cfg.challenges_dir().as_os_str().is_empty() {
        debug!("acme_gc: no file challenge storage configured; skipping");
        return Ok(());
    }
    let dir = cfg.challenges_dir().clone();
    let now = SystemTime::now();
    let max_age = Duration::from_secs(3600); // 60 minutes
    let cutoff = now.checked_sub(max_age).unwrap_or(SystemTime::UNIX_EPOCH);
    //
    // debug!(
    //     slot = runtime.slot(),
    //     ?runtime.run_mode,
    //     process_id = runtime.process_id,
    //     "🟣 acme gc running"
    // );

    let mut read_dir = read_challenge_dir(&dir).await?;

    let mut removed = 0usize;
    while let Ok(Some(entry)) = read_dir.next_entry().await {
        let path = entry.path();
        // Only consider plain files
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(e) => {
                debug!(path = %path.display(), err = ?e, "metadata failed");
                continue;
            }
        };
        if !meta.is_file() {
            continue;
        }
        let modified = match meta.modified() {
            Ok(m) => m,
            Err(e) => {
                debug!(path = %path.display(), err = ?e, "modified() failed");
                continue;
            }
        };
        if modified <= cutoff {
            match fs::remove_file(&path).await {
                Ok(()) => {
                    removed += 1;
                    debug!(path = %path.display(), "🔸 removed stale ACME challenge");
                }
                Err(e) => {
                    warn!(path = %path.display(), err = ?e, "failed to remove stale ACME challenge");
                }
            }
        }
    }

    if removed > 0 {
        info!(count = removed, dir = %dir.display(), "ACME cleanup completed");
    } else {
        debug!(dir = %dir.display(), "ACME cleanup: nothing to remove");
    }

    Ok(())
}

async fn read_challenge_dir(dir: &Path) -> std::io::Result<fs::ReadDir> {
    fs::read_dir(dir).await.map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "failed to read ACME challenge directory '{}': {error}",
                dir.display()
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_challenge_directory_is_an_io_error() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("current time follows Unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "claviron-acme-missing-challenges-{}-{unique}",
            std::process::id()
        ));
        let error = read_challenge_dir(&dir)
            .await
            .expect_err("the test challenge directory must not exist");

        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(error.to_string().contains(dir.to_string_lossy().as_ref()));
    }
}
