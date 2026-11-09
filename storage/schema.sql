CREATE TABLE IF NOT EXISTS vault_metadata (
    id INTEGER PRIMARY KEY,
    salt_kek BLOB NOT NULL,
    encrypted_dek BLOB NOT NULL,
    nonce_kek BLOB NOT NULL,
    kdf_algorithm TEXT NOT NULL,
    time_cost INTEGER NOT NULL,
    memory_cost INTEGER NOT NULL,
    parallelism INTEGER NOT NULL,
    hash_len INTEGER NOT NULL DEFAULT 32
);

CREATE TABLE IF NOT EXISTS vault_entries (
    id INTEGER PRIMARY KEY,
    encrypted_data BLOB NOT NULL,
    nonce BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);