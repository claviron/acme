CREATE TABLE hosting_acme_accounts (
    id INTEGER PRIMARY KEY, name TEXT, url TEXT, issuer_id INTEGER,
    private_key TEXT, jwk TEXT, algorithm TEXT, email TEXT, organization TEXT,
    created_at TEXT, last_used_at TEXT, is_default BOOLEAN
);
CREATE TABLE hosting_acme_logs (
    id INTEGER PRIMARY KEY, cn TEXT, operation_type TEXT, attempted_at TEXT,
    status TEXT, error_message TEXT, acme_account_id INTEGER,
    duration_seconds INTEGER, aliases TEXT, created_at TEXT
);
CREATE TABLE hosting_certificate_issuers (
    id INTEGER PRIMARY KEY, name TEXT UNIQUE, kind TEXT,
    acme_account_id INTEGER UNIQUE, ca_certificate_id INTEGER
);
CREATE TABLE hosting_certificates (
    id INTEGER PRIMARY KEY, issuer_id INTEGER, cn TEXT UNIQUE, kind TEXT,
    certs_der BLOB, key_der BLOB, expires_at TEXT, issued_at TEXT,
    updated_at TEXT, enabled BOOLEAN, revoked_at TEXT
);
CREATE TABLE hosting_cert_aliases (
    id INTEGER PRIMARY KEY, cert_id INTEGER, hostname TEXT, created_at TEXT,
    UNIQUE(cert_id, hostname)
);
CREATE TABLE hosting_certificate_server (
    certificate_id INTEGER, server_id INTEGER, created_at TEXT,
    PRIMARY KEY(certificate_id, server_id)
);
