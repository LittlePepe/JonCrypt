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