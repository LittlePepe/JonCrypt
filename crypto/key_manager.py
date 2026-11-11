import secrets
from crypto.kdf import KeyDerivation
from crypto.cryptation import Cryptation
from model.models import KeyManagerData

class KeyManager:
    def __init__(self, key_derivation: KeyDerivation, default_kdf_params=None):

        self.key_derivation = key_derivation
        self.key_derivation_data = self.key_derivation.derive_kek()
        self.kek = self.key_derivation_data.kek


    def create_dek(self) -> bytes:
        return secrets.token_bytes(32)
    
    def encrypt_dek(self, dek: bytes, aad: bytes | None = None) -> KeyManagerData:
        encrypted_data = Cryptation.encrypt(self.kek,dek, aad)
        
        return KeyManagerData(
            nonce_kek=encrypted_data.nonce, 
            encrypted_dek=encrypted_data.ciphertext
        )

    def decrypt_dek(self, data: KeyManagerData, aad: bytes | None = None) -> bytes:
        return Cryptation.decrypt(self.kek,data.nonce_kek,data.encrypted_dek, aad)