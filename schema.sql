-- Timestamps are UTC text in the form YYYY-MM-DDTHH:MM:SSZ.
-- Application code maintains created_at and updated_at. There are no update triggers.
-- security_events stores event metadata only. It must never store passwords,
-- password hashes, session tokens, or other authentication secrets.
-- is_blocked distinguishes an explicitly blocked account from one that is only
-- waiting for its first temporary credential.
-- deleted_at removes an account from use while preserving ownership and audit history.
-- sessions.credential_kind records whether the session used a temporary credential.
-- sessions store a SHA-256 digest of the session identifier, never the identifier.

CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (
        name IN ('administrator', 'manager', 'editor', 'employee', 'reader')
    ),
    description TEXT NOT NULL CHECK (length(trim(description)) > 0)
);

CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (
        name IN (
            'users.manage',
            'security.manage',
            'dossiers.read_declassified',
            'dossiers.read_classified',
            'dossiers.read_doom_level',
            'dossiers.read_own_drafts',
            'dossiers.create',
            'dossiers.edit_own',
            'dossiers.submit_own',
            'dossiers.review',
            'dossiers.declassify',
            'incidents.create',
            'incidents.read_own',
            'incidents.read_submitted'
        )
    ),
    description TEXT NOT NULL CHECK (length(trim(description)) > 0)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE RESTRICT,
    FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (length(trim(username)) > 0),
    password_hash TEXT CHECK (password_hash IS NULL OR length(password_hash) > 0),
    role_id INTEGER NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0, 1)),
    is_blocked INTEGER NOT NULL DEFAULT 0 CHECK (is_blocked IN (0, 1)),
    must_change_password INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    password_changed_at TEXT,
    deleted_at TEXT,
    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    password_hash TEXT NOT NULL CHECK (length(password_hash) > 0),
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS temporary_passwords (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    password_hash TEXT NOT NULL CHECK (length(password_hash) > 0),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    session_token_hash TEXT NOT NULL UNIQUE CHECK (length(session_token_hash) > 0),
    created_at TEXT NOT NULL,
    last_activity_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    credential_kind TEXT NOT NULL DEFAULT 'password' CHECK (
        credential_kind IN ('password', 'temporary')
    ),
    temporary_password_id INTEGER,
    role_id_at_creation INTEGER,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT,
    FOREIGN KEY (temporary_password_id) REFERENCES temporary_passwords (id)
        ON DELETE RESTRICT,
    FOREIGN KEY (role_id_at_creation) REFERENCES roles (id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS forbidden_words (
    id INTEGER PRIMARY KEY,
    word TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (length(trim(word)) > 0),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY CHECK (length(trim(key)) > 0),
    value TEXT NOT NULL CHECK (length(value) > 0)
);

CREATE TABLE IF NOT EXISTS dossiers (
    id TEXT PRIMARY KEY CHECK (id GLOB 'DV-[0-9][0-9][0-9]'),
    title TEXT NOT NULL CHECK (length(trim(title)) > 0),
    organization TEXT NOT NULL CHECK (
        organization IN ('SHIELD', 'HYDRA', 'SWORD', 'UNKNOWN')
    ),
    classification TEXT NOT NULL CHECK (
        classification IN (
            'DECLASSIFIED',
            'INTERNAL',
            'SECRET',
            'TOP_SECRET',
            'DOOM_LEVEL'
        )
    ),
    status TEXT NOT NULL CHECK (
        status IN (
            'DRAFT', 'PENDING', 'SUBMITTED', 'APPROVED', 'REJECTED', 'DECLASSIFIED'
        )
    ),
    file_name TEXT NOT NULL UNIQUE CHECK (file_name = id || '.json'),
    created_by INTEGER,
    approved_by INTEGER,
    source_incident_id INTEGER,
    submitted_at TEXT,
    reviewed_at TEXT,
    rejection_reason TEXT CHECK (
        rejection_reason IS NULL OR length(trim(rejection_reason)) > 0
    ),
    declassified_by INTEGER,
    declassified_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE RESTRICT,
    FOREIGN KEY (approved_by) REFERENCES users (id) ON DELETE RESTRICT,
    FOREIGN KEY (source_incident_id) REFERENCES incident_reports (id)
        ON DELETE RESTRICT,
    FOREIGN KEY (declassified_by) REFERENCES users (id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS incident_reports (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL CHECK (length(trim(title)) > 0),
    description TEXT NOT NULL CHECK (length(trim(description)) > 0),
    created_by INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (length(trim(status)) > 0),
    created_at TEXT NOT NULL,
    FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    event_type TEXT NOT NULL CHECK (length(trim(event_type)) > 0),
    description TEXT NOT NULL CHECK (length(trim(description)) > 0),
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_users_role_id ON users (role_id);
CREATE INDEX IF NOT EXISTS idx_password_history_user_created
    ON password_history (user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_temporary_passwords_user_id
    ON temporary_passwords (user_id);
CREATE INDEX IF NOT EXISTS idx_temporary_passwords_expires_at
    ON temporary_passwords (expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_dossiers_organization ON dossiers (organization);
CREATE INDEX IF NOT EXISTS idx_dossiers_classification ON dossiers (classification);
CREATE INDEX IF NOT EXISTS idx_dossiers_status ON dossiers (status);
CREATE INDEX IF NOT EXISTS idx_dossiers_created_by ON dossiers (created_by);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dossiers_source_incident
    ON dossiers (source_incident_id) WHERE source_incident_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_incident_reports_created_by ON incident_reports (created_by);
CREATE INDEX IF NOT EXISTS idx_incident_reports_status ON incident_reports (status);
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events (user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events (event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events (created_at);

CREATE TRIGGER IF NOT EXISTS prevent_admin_username_change
BEFORE UPDATE OF username ON users
FOR EACH ROW
WHEN OLD.username = 'ADMIN' AND NEW.username <> 'ADMIN'
BEGIN
    SELECT RAISE(ABORT, 'The permanent ADMIN account cannot be renamed.');
END;

CREATE TRIGGER IF NOT EXISTS prevent_admin_delete
BEFORE DELETE ON users
FOR EACH ROW
WHEN OLD.username = 'ADMIN'
BEGIN
    SELECT RAISE(ABORT, 'The permanent ADMIN account cannot be deleted.');
END;
