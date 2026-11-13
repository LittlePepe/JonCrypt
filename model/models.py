from dataclasses import dataclass


@dataclass
class KeyDerivationData:
    salt_kek: bytes
    kek: bytes

@dataclass
class KeyManagerData:
    nonce_kek: bytes
    encrypted_dek: bytes

@dataclass
class EncryptedData:
    nonce: bytes
    ciphertext: bytes

@dataclass(frozen=True)
class KdfParams:
    time_cost: int
    memory_cost: int
    parallelism: int
    hash_len: int

@dataclass(frozen=True)
class VaultHeader:
    format_major: int
    format_minor: int
    flags: int
    kdf_id: int
    kdf_params: KdfParams
    salt: bytes
    cipher_id: int
    dek_nonce: bytes
    wrapped_dek: bytes
    payload_nonce: bytes
    payload_len: int

@dataclass(frozen=True)
class CredentialEntry:
    id: int
    link: str
    password: str
    created_at: int
    updated_at: int | None


@dataclass
class VaultPayload:
    schema_version: int
    next_id: int
    entries: list[CredentialEntry]