use std::borrow::Cow;
use std::str::FromStr;

use claviron::ssl::Algorithm;
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use time::{OffsetDateTime, UtcOffset};

use crate::AcmeError;

#[derive(Clone, Debug)]
pub struct AcmeAccount {
    pub id: i32,
    pub name: String,
    pub url: String,
    pub issuer_id: i32,
    pub private_key: String,
    pub jwk: Value,
    pub algorithm: Algorithm,
    pub email: String,
    pub organization: String,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
    pub is_default: bool,
}

/// Storage-neutral account input used by operator tools when importing a
/// file-backed ACME account into the shared hosting database.
#[derive(Clone, Debug)]
pub struct NewAcmeAccount {
    pub name: String,
    pub url: String,
    pub private_key: String,
    pub jwk: Value,
    pub algorithm: Algorithm,
    pub email: String,
    pub organization: String,
    pub is_default: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum AcmeOperation {
    Create,
    Renew,
}

impl AcmeOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Renew => "renew",
        }
    }
}

/// ACME accounts and the operation log, in the same database as the hosting
/// data (certificates refer to accounts): roma's PostgreSQL `hosting` schema,
/// or, with the `sqlite` feature, an SQLite file with the tables named
/// `hosting_<table>`.
#[derive(Clone)]
pub struct AcmeStore {
    pool: Pool,
}

#[derive(Clone)]
enum Pool {
    Postgres(PgPool),
    #[cfg(feature = "sqlite")]
    Sqlite(sqlx::SqlitePool),
}

/// One statement on whichever backend the store holds; the SQL is
/// PostgreSQL's and [`sqlite`] rewrites what SQLite spells differently.
macro_rules! run {
    ($store:expr, query, $sql:expr, [$($bind:expr),* $(,)?], execute) => {
        match &$store.pool {
            Pool::Postgres(pool) => sqlx::query(sqlx::AssertSqlSafe($sql))
                $(.bind($bind))*
                .execute(pool)
                .await
                .map(|done| done.rows_affected()),
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(sqlite($sql)))
                $(.bind($bind))*
                .execute(pool)
                .await
                .map(|done| done.rows_affected())
        }
    };
    ($store:expr, $query:ident $(::<$($ty:ty),*>)?, $sql:expr, [$($bind:expr),* $(,)?], $fetch:ident) => {
        match &$store.pool {
            Pool::Postgres(pool) => sqlx::$query $(::<_, $($ty),*>)?(sqlx::AssertSqlSafe($sql))
                $(.bind($bind))*
                .$fetch(pool)
                .await,
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(pool) => sqlx::$query $(::<_, $($ty),*>)?(sqlx::AssertSqlSafe(sqlite($sql)))
                $(.bind($bind))*
                .$fetch(pool)
                .await
        }
    };
}

/// PostgreSQL's spelling as SQLite reads it: `hosting_<table>` for
/// `hosting.<table>`, UTC text for `NOW()`, and no enum cast (SQLite keeps
/// the operation type as checked text).
#[cfg_attr(not(feature = "sqlite"), allow(dead_code))]
fn sqlite(sql: &'static str) -> Cow<'static, str> {
    Cow::Owned(
        sql.replace("::hosting.acme_operation_type", "")
            .replace("hosting.", "hosting_")
            .replace("NOW()", "strftime('%Y-%m-%dT%H:%M:%SZ', 'now')"),
    )
}

/// UTC, whole seconds: how both backends hold a timestamp, and the only form
/// SQLite's text comparison orders right.
fn stored(at: OffsetDateTime) -> OffsetDateTime {
    let at = at.to_offset(UtcOffset::UTC);
    at.replace_nanosecond(0).unwrap_or(at)
}

impl AcmeStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool: Pool::Postgres(pool) }
    }

    #[cfg(feature = "sqlite")]
    pub fn sqlite(pool: sqlx::SqlitePool) -> Self {
        Self { pool: Pool::Sqlite(pool) }
    }

    /// The store on the connection `db.yaml`'s `hosting:` names, where the
    /// certificates these accounts issued are.
    pub fn open(db: &claviron::db::DbService) -> Result<Self, AcmeError> {
        let profile = db.hosting_profile();
        match db.profile(&profile).map_err(AcmeError::Database)? {
            #[cfg(feature = "postgres")]
            claviron::db::Pool::Postgres(pool) => Ok(Self::new(pool)),
            #[cfg(feature = "sqlite")]
            claviron::db::Pool::Sqlite(pool) => Ok(Self::sqlite(pool)),
            #[allow(unreachable_patterns)]
            _ => Err(AcmeError::Database(format!(
                "`{profile}`: ACME data is not kept on this backend in this build"
            ))),
        }
    }

    pub async fn default_account(
        &self
    ) -> Result<Option<AcmeAccount>, AcmeError> {
        run!(
            self,
            query_as::<AcmeAccountRow>,
            "SELECT id, name, url, issuer_id, private_key, jwk,
                    algorithm, email, organization, created_at,
                    last_used_at, is_default
               FROM hosting.acme_accounts
              WHERE is_default = TRUE
              LIMIT 1",
            [],
            fetch_optional
        )
        .map_err(AcmeError::database)?
        .map(TryInto::try_into)
        .transpose()
    }

    pub async fn account_by_id(
        &self,
        id: i32,
    ) -> Result<Option<AcmeAccount>, AcmeError> {
        run!(
            self,
            query_as::<AcmeAccountRow>,
            "SELECT id, name, url, issuer_id, private_key, jwk,
                    algorithm, email, organization, created_at,
                    last_used_at, is_default
               FROM hosting.acme_accounts
              WHERE id = $1
              LIMIT 1",
            [id],
            fetch_optional
        )
        .map_err(AcmeError::database)?
        .map(TryInto::try_into)
        .transpose()
    }

    pub async fn account_by_url(
        &self,
        url: &str,
    ) -> Result<Option<AcmeAccount>, AcmeError> {
        run!(
            self,
            query_as::<AcmeAccountRow>,
            "SELECT id, name, url, issuer_id, private_key, jwk,
                    algorithm, email, organization, created_at,
                    last_used_at, is_default
               FROM hosting.acme_accounts
              WHERE url = $1
              LIMIT 1",
            [url],
            fetch_optional
        )
        .map_err(AcmeError::database)?
        .map(TryInto::try_into)
        .transpose()
    }

    pub async fn insert_account(
        &self,
        account: NewAcmeAccount,
    ) -> Result<AcmeAccount, AcmeError> {
        let issuer_id = run!(
            self,
            query_scalar::<i32>,
            "SELECT id
               FROM hosting.acme_issuers
              WHERE is_default = TRUE
              LIMIT 1",
            [],
            fetch_optional
        )
        .map_err(AcmeError::database)?
        .ok_or_else(|| AcmeError::from("default ACME issuer not found"))?;

        let row = run!(
            self,
            query_as::<AcmeAccountRow>,
            "INSERT INTO hosting.acme_accounts
                (name, url, issuer_id, private_key, jwk, algorithm,
                 email, organization, created_at, is_default)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), $9)
             RETURNING id, name, url, issuer_id, private_key, jwk,
                       algorithm, email, organization, created_at,
                       last_used_at, is_default",
            [
                account.name,
                account.url,
                issuer_id,
                account.private_key,
                account.jwk,
                account.algorithm.to_string(),
                account.email,
                account.organization,
                account.is_default
            ],
            fetch_one
        )
        .map_err(AcmeError::database)?;

        row.try_into()
    }

    /// Open an operation's log row. One pending row per CN and operation
    /// type: a second attempt while one runs is refused by the database.
    /// Whoever opens a row closes it with [`finish_log`](Self::finish_log)
    /// on every way out.
    pub async fn insert_pending_log(
        &self,
        cn: &str,
        operation: AcmeOperation,
        aliases: Option<Value>,
    ) -> Result<i32, AcmeError> {
        run!(
            self,
            query_scalar::<i32>,
            "INSERT INTO hosting.acme_logs
                (cn, operation_type, attempted_at, status, error_message,
                 acme_account_id, duration_seconds, aliases, created_at)
             VALUES ($1, $2::hosting.acme_operation_type, NOW(), 'pending', NULL,
                     NULL, NULL, $3, NOW())
             RETURNING id",
            [cn, operation.as_str(), aliases],
            fetch_one
        )
        .map_err(AcmeError::database)
    }

    /// Close a log row: `success` without an error message, `failed` with
    /// one. The account is unknown when an attempt failed before one was
    /// chosen.
    pub async fn finish_log(
        &self,
        id: i32,
        account_id: Option<i32>,
        duration_seconds: i32,
        error_message: Option<&str>,
    ) -> Result<(), AcmeError> {
        let status = if error_message.is_some() { "failed" } else { "success" };
        run!(
            self,
            query,
            "UPDATE hosting.acme_logs
                SET status = $2, error_message = $3, acme_account_id = $4,
                    duration_seconds = $5
              WHERE id = $1",
            [id, status, error_message, account_id, duration_seconds],
            execute
        )
        .map_err(AcmeError::database)?;
        Ok(())
    }

    /// Whether `operation` on `cn` succeeded since `cutoff`.
    pub async fn succeeded_since(
        &self,
        cn: &str,
        operation: AcmeOperation,
        cutoff: OffsetDateTime,
    ) -> Result<bool, AcmeError> {
        run!(
            self,
            query_scalar::<bool>,
            "SELECT EXISTS (
                SELECT 1 FROM hosting.acme_logs
                 WHERE cn = $1 AND operation_type = $2::hosting.acme_operation_type
                   AND status = 'success' AND created_at >= $3
             )",
            [cn, operation.as_str(), stored(cutoff)],
            fetch_one
        )
        .map_err(AcmeError::database)
    }

    /// How many times `operation` on `cn` failed since `cutoff`.
    pub async fn failures_since(
        &self,
        cn: &str,
        operation: AcmeOperation,
        cutoff: OffsetDateTime,
    ) -> Result<i64, AcmeError> {
        run!(
            self,
            query_scalar::<i64>,
            "SELECT COUNT(*) FROM hosting.acme_logs
              WHERE cn = $1 AND operation_type = $2::hosting.acme_operation_type
                AND status = 'failed' AND created_at >= $3",
            [cn, operation.as_str(), stored(cutoff)],
            fetch_one
        )
        .map_err(AcmeError::database)
    }
}

#[derive(FromRow)]
struct AcmeAccountRow {
    id: i32,
    name: String,
    url: String,
    issuer_id: i32,
    private_key: String,
    jwk: Value,
    algorithm: String,
    email: String,
    organization: String,
    created_at: OffsetDateTime,
    last_used_at: Option<OffsetDateTime>,
    is_default: bool,
}

impl TryFrom<AcmeAccountRow> for AcmeAccount {
    type Error = AcmeError;

    fn try_from(row: AcmeAccountRow) -> Result<Self, Self::Error> {
        let algorithm = Algorithm::from_str(&row.algorithm).map_err(|_| {
            AcmeError::from(format!(
                "invalid ACME algorithm '{}'",
                row.algorithm
            ))
        })?;
        Ok(Self {
            id: row.id,
            name: row.name,
            url: row.url,
            issuer_id: row.issuer_id,
            private_key: row.private_key,
            jwk: row.jwk,
            algorithm,
            email: row.email,
            organization: row.organization,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
            is_default: row.is_default,
        })
    }
}
