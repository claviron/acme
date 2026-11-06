use claviron::runtime::AppState;
use claviron::tasks::{TaskResult, task};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use super::acme_config;
use crate::AcmeError;

#[task(name = "acme_renew", scope = "master", crate_path = "claviron")]
pub async fn acme_renew(
    state: AppState,
    _token: CancellationToken,
) -> TaskResult<()> {
    use crate::AcmeStore;
    use crate::actions::database::renew_cert_from_db;
    const CONCURRENT_TASK_COUNT: usize = 2;

    let Some(acme_cfg) = acme_config(&state)? else {
        debug!("acme_renew: acme.yaml missing; skipping");
        return Ok(());
    };

    use claviron::db::DbService;
    let db_service =
        state.registry_ref().resolve::<DbService>().ok_or_else(|| {
            claviron::tasks::Error::other(
                "acme_renew: DbService not registered",
            )
        })?;
    // Through HostingService: the store it opens announces its writes where
    // the database does not (SQLite).
    let hosting = state
        .registry_ref()
        .resolve::<claviron::hosting::HostingService>()
        .ok_or_else(|| {
            claviron::tasks::Error::other(
                "acme_renew: HostingService not registered",
            )
        })?
        .store()
        .map_err(|error| {
            claviron::tasks::Error::other(format!("acme_renew: {error}"))
        })?;
    let acme_store = AcmeStore::open(&db_service).map_err(|error| {
        claviron::tasks::Error::other(format!("acme_renew: {error}"))
    })?;

    let days_before_expiry = acme_cfg.renew_before as i64;

    debug!(
        "🔍 acme_renew: Retrieving certificates expiring within {} days",
        days_before_expiry
    );

    let threshold = time::OffsetDateTime::now_utc()
        + time::Duration::days(days_before_expiry);
    let certs = hosting
        .acme_certificates(true, Some(threshold))
        .await
        .map_err(|e| {
            claviron::tasks::Error::other(format!(
                "acme_renew: db query failed: {e}"
            ))
        })?;

    if certs.is_empty() {
        debug!("🔹 acme_renew: no certificates are due to renew");
        return Ok(());
    }

    use std::sync::Arc;

    use futures::stream::{FuturesUnordered, StreamExt};
    use tokio::sync::Semaphore;

    let sem = Arc::new(Semaphore::new(CONCURRENT_TASK_COUNT));
    let mut tasks = FuturesUnordered::new();

    for cert in certs {
        let sem = sem.clone();
        let hosting = hosting.clone();
        let acme_store = acme_store.clone();
        let cfg = acme_cfg.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap(); // limit
            let cn = cert.certificate.cn.clone();
            match renew_cert_from_db(&acme_store, &hosting, &cfg, cert, true)
                .await
            {
                Ok(_) => Ok(cn),
                Err(err) => Err(RenewalError { cn, source: err }),
            }
        }));
    }

    while let Some(res) = tasks.next().await {
        match res {
            Ok(Ok(cn)) => {
                info!("✅ acme_renew: renewed certificate `{}`", cn);
            }
            Ok(Err(err)) => error!("acme_renew: {}", err),
            Err(join_err) => {
                error!("❌ acme_renew: a renewal task panicked: {join_err}")
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
struct RenewalError {
    cn: String,
    source: AcmeError,
}

impl std::fmt::Display for RenewalError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        write!(
            f,
            "certificate renewal failed cn={} source={}",
            self.cn, self.source
        )
    }
}

impl std::error::Error for RenewalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
