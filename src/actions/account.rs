use std::fs;

use tracing::error;

use crate::account::{ACCOUNT_FILE_NAME, Account};
use crate::clients::{AccountClient, acme_client};
use crate::cryptex::keys;
use crate::error::AcmeError;

pub async fn new_account(account: &mut Account) -> Result<(), AcmeError> {
    // Account key path (shared for both staging/prod unless configured otherwise)

    let key_path = &account.key_path;
    // parent() gives an Option<&Path>
    let Some(key_dir) = key_path.parent() else {
        return Err(AcmeError::from(
            "Account key path does not have a parent directory",
        ));
    };
    let json_path = key_dir.join(ACCOUNT_FILE_NAME);

    if key_dir.exists() {
        return Err(AcmeError::from("Account key directory already exists!"));
    }

    let (key, jwk) = keys::generate_acme_key_with_jwk(&account.alg)?;

    let http_client = acme_client()?;

    let client = AccountClient::with_client(http_client, &account.url);

    let url = client.register_account(&key, &jwk).await.map_err(|e| {
        error!("Failed to register ACME account: {:?}", e);
        AcmeError::RegistrationFailed(e.to_string())
    })?;

    account.jwk = jwk;
    account.url = url;
    account.tos_agreed = true;

    fs::create_dir_all(key_dir).map_err(|e| {
        AcmeError::io_error(
            "Failed to create account key directory",
            key_dir,
            e,
        )
    })?;

    fs::write(key_path, &key).map_err(|e| {
        AcmeError::io_error("Failed to write account key file", key_path, e)
    })?;

    // Persist account metadata alongside the key
    let acct_json = serde_json::to_string_pretty(&account)?;
    fs::write(&json_path, acct_json).map_err(|e| {
        AcmeError::io_error(
            "Failed to write account metadata file",
            &json_path,
            e,
        )
    })?;
    Ok(())
}
