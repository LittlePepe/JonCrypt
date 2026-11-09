import argon2
import secrets 
from model.models import KeyDerivationData


class KeyDerivation:

    def __init__(self, senha_mestre: bytes, salt_kek: bytes | None = None):

        self.senha_mestre = senha_mestre
        self.salt_kek = (salt_kek if salt_kek is not None else secrets.token_bytes(16)) # Gerar 16 bytes
        self.nonce_kek = secrets.token_bytes(12) # Gerar 12 bytes

    def derive_kek(self) -> KeyDerivationData:

        kek = argon2.low_level.hash_secret_raw(
            secret=self.senha_mestre,
            salt=self.salt_kek,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=argon2.low_level.Type.ID
        )

        return KeyDerivationData(salt_kek=self.salt_kek, kek=kek)
