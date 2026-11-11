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

@dataclass
class KdfParams:
    time_cost: int
    memory_cost: int
    parallelism: int
    hash_len: int
    frozen: bool



