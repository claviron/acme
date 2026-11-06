use std::path::Path;

use crate::AcmeError;

/// Owns one exclusively created HTTP-01 file until validation ends or the
/// requesting future is dropped. All operations use the pinned directory,
/// including cleanup: replacing a parent path cannot redirect them.
pub(super) struct Challenge {
    #[cfg(unix)]
    directory: std::fs::File,
    #[cfg(unix)]
    token: String,
}

impl Challenge {
    pub(super) async fn create(
        directory: &Path,
        token: &str,
        authorization: String,
    ) -> Result<Self, AcmeError> {
        // RFC 8555 section 8.3: base64url alphabet, without padding. In
        // particular, no path separators, dots, percent escapes or NULs.
        if !valid_token(token) {
            return Err(AcmeError::InvalidChallengeToken);
        }

        let directory = directory.to_owned();
        let token = token.to_owned();
        // The blocking job owns the guard before writing. If cancellation
        // drops its result, the guard cleans up after that job finishes too.
        tokio::task::spawn_blocking(move || {
            Self::create_at(&directory, token, authorization)
        })
        .await
        .map_err(|error| AcmeError::Unexpected(error.to_string()))?
    }

    #[cfg(unix)]
    fn create_at(
        directory: &Path,
        token: String,
        authorization: String,
    ) -> Result<Self, AcmeError> {
        use std::io::Write;

        use rustix::fs::{Mode, OFlags, open, openat};

        let path = directory.join(&token);
        let directory = open(
            directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(std::fs::File::from)
        .map_err(|error| {
            AcmeError::io_error(
                "Failed to open challenge directory",
                &path,
                error.into(),
            )
        })?;
        // Match File::create's 0666 permission request, subject to umask.
        // Exclusive creation rejects regular files, hard links and symlinks;
        // NOFOLLOW also makes the final-component policy explicit.
        let file = openat(
            &directory,
            token.as_str(),
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC,
            Mode::RUSR
                | Mode::WUSR
                | Mode::RGRP
                | Mode::WGRP
                | Mode::ROTH
                | Mode::WOTH,
        )
        .map_err(|error| {
            AcmeError::io_error(
                "Failed to create challenge file",
                &path,
                error.into(),
            )
        })?;
        let owned = Self { directory, token };
        std::fs::File::from(file).write_all(authorization.as_bytes()).map_err(
            |error| {
                AcmeError::io_error(
                    "Failed to write challenge file",
                    &path,
                    error,
                )
            },
        )?;
        Ok(owned)
    }

    #[cfg(not(unix))]
    fn create_at(
        directory: &Path,
        _token: String,
        _authorization: String,
    ) -> Result<Self, AcmeError> {
        Err(AcmeError::io_error(
            "Directory-relative challenge creation is unavailable",
            directory,
            std::io::Error::from(std::io::ErrorKind::Unsupported),
        ))
    }
}

impl Drop for Challenge {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Err(error) = rustix::fs::unlinkat(
            &self.directory,
            self.token.as_str(),
            rustix::fs::AtFlags::empty(),
        ) && error != rustix::io::Errno::NOENT
        {
            tracing::warn!(token = %self.token, %error, "Failed to remove owned ACME challenge file");
        }
    }
}

#[cfg(all(test, unix))]
#[path = "../../tests/unit/challenge.rs"]
mod tests;

pub(crate) fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
        })
}
