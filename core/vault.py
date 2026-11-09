from crypto.kdf import KeyDerivation
from crypto.key_manager import KeyManager
from storage.vault_repository import VaultRepository
from model.models import KeyManagerData

class InicializationKey:
    def __init__(self, senha_mestre: bytes, repository: VaultRepository):
        self.senha_mestre = senha_mestre
        self.repository = repository


    def create_vault(self):

        # Inicializar derivação | KDF
        kdf = KeyDerivation(self.senha_mestre)

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
                "time_cost": 3,
                "memory_cost": 65536,
                "parallelism": 4,
                "hash_len": 32
            }
        )

        return True

    def unlock_vault(self):
        metadados = self.repository.get_metadados()
        salt_kek = metadados[0][1]
        nonce_kek = metadados[0][3]
        encrypted_dek = metadados [0][2]

        # Inicializar derivação | KDF
        kdf = KeyDerivation(self.senha_mestre, salt_kek)
        # Inicializar gerenciamento de chaves | DEK
        key_manager = KeyManager(kdf)
        
        key_manager_data = KeyManagerData(nonce_kek=nonce_kek, encrypted_dek=encrypted_dek)

        recovered_dek = key_manager.decrypt_dek(key_manager_data)
        
        return recovered_dek
