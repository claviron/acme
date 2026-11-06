mod cleanup;
mod renew;

use std::sync::Arc;

use claviron::runtime::AppState;

use crate::config::AcmeConfig;
use crate::provider::AcmeProvider;

/// The configuration `AcmeProvider` currently holds, as Congif last applied
/// it; `None` while there is no `acme.yaml`. Tasks read the snapshot the
/// service owns rather than the file.
pub(crate) fn acme_config(
    state: &AppState
) -> claviron::tasks::TaskResult<Option<Arc<AcmeConfig>>> {
    let provider =
        state.registry_ref().resolve::<AcmeProvider>().ok_or_else(|| {
            claviron::tasks::Error::other("AcmeService is not registered")
        })?;
    Ok(provider.snapshot())
}
