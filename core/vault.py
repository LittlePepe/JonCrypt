from crypto.kdf import KeyDerivation
from crypto.key_manager import KeyManager
from storage.vault_repository import VaultRepository
from model.models import KdfParams, KeyManagerData

class InicializationVault:

    DEFAULT_KDF_PARAMS = KdfParams(
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        hash_len=32,
        frozen=True
    )
        
    def __init__(self, senha_mestre: bytes, repository: VaultRepository):
        self.senha_mestre = senha_mestre
        self.default_kdf_params = self.DEFAULT_KDF_PARAMS
        self.repository = repository


    def create_vault(self):

        # Inicializar derivação | KDF
        kdf = KeyDerivation(self.senha_mestre, default_kdf_params=self.default_kdf_params)

        # Inicializar gerenciamento de chaves | DEK
        key_manager = KeyManager(kdf) 

        # Gerar DEK | DEK
        dek = key_manager.create_dek()

        # Encapsular DEK utilizando KEK | DEK -> AES-GCM
        encrypted_dek = key_manager.encrypt_dek(dek)

        # Salvar metadados DB | DEK
        self.repository.save_metadata(
            salt_kek=kdf.salt_kek,
            encrypted_dek=encrypted_dek.encrypted_dek,
            nonce_kek=encrypted_dek.nonce_kek,
            kdf_algorithm="Argon2id",
            kdf_parameters={
                "time_cost": self.default_kdf_params.time_cost,
                "memory_cost": self.default_kdf_params.memory_cost,
                "parallelism": self.default_kdf_params.parallelism,
                "hash_len": self.default_kdf_params.hash_len
            }
        )

        return dek

    def unlock_vault(self):
        metadados = self.repository.get_metadados()
        salt_kek = metadados[0][1]
        nonce_kek = metadados[0][3]
        encrypted_dek = metadados [0][2]

        kdf_params = KdfParams(
            time_cost=metadados[0][5],
            memory_cost=metadados[0][6],
            parallelism=metadados[0][7],
            hash_len=metadados[0][8]
        )

        # Inicializar derivação | KDF
        kdf = KeyDerivation(self.senha_mestre,default_kdf_params=kdf_params, salt_kek=salt_kek)
        # Inicializar gerenciamento de chaves | DEK
        key_manager = KeyManager(kdf)
        
        key_manager_data = KeyManagerData(nonce_kek=nonce_kek, encrypted_dek=encrypted_dek)

        recovered_dek = key_manager.decrypt_dek(key_manager_data)

        return recovered_dek
