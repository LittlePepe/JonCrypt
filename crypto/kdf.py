import argon2
import secrets 
from model.models import KdfParams, KeyDerivationData


class KeyDerivation:

    def __init__(self, senha_mestre: bytes, default_kdf_params: KdfParams | None = None, salt_kek: bytes | None = None):

        self.senha_mestre = senha_mestre
        self.default_kdf_params = default_kdf_params
        self.salt_kek = (salt_kek if salt_kek is not None else secrets.token_bytes(16)) # Gerar 16 bytes
        

    def derive_kek(self) -> KeyDerivationData:

        kek = argon2.low_level.hash_secret_raw(
            secret=self.senha_mestre,
            salt=self.salt_kek,
            time_cost=self.default_kdf_params.time_cost,
            memory_cost=self.default_kdf_params.memory_cost,
            parallelism=self.default_kdf_params.parallelism,
            hash_len=self.default_kdf_params.hash_len,
            type=argon2.low_level.Type.ID
        )

        return KeyDerivationData(salt_kek=self.salt_kek, kek=kek)
