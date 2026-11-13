from crypto.kdf import KeyDerivation
from crypto.key_manager import KeyManager
import dataclasses
from storage.svault_repository import SvaultRepository
from storage.svault_format import FORMAT_MAJOR, FORMAT_MINOR, KDF_ARGON2ID, CIPHER_AES256GCM, NONCE_LEN, WRAPPED_DEK_LEN, kdf_section
from model.models import KdfParams, KeyManagerData, VaultHeader, VaultPayload

class InicializationVault:

    def __init__(self, senha_mestre: bytes, repository: SvaultRepository):
        self.senha_mestre = senha_mestre
        self.repository = repository


    def create_vault(self):

        # Inicializar derivação | KDF
        kdf = KeyDerivation(self.senha_mestre)

        # Inicializar gerenciamento de chaves | DEK
        key_manager = KeyManager(kdf) 

        # Gerar DEK | DEK
        dek = key_manager.create_dek()

        # Header provisório (dek_nonce, wrapped_dek e payload ainda não existem)
        header = VaultHeader(
            format_major=FORMAT_MAJOR,
            format_minor=FORMAT_MINOR,
            flags=0,
            kdf_id=KDF_ARGON2ID,
            kdf_params=KdfParams,
            salt=kdf.salt_kek,
            cipher_id=CIPHER_AES256GCM,
            dek_nonce=bytes(NONCE_LEN),
            wrapped_dek=bytes(WRAPPED_DEK_LEN),
            payload_nonce=bytes(NONCE_LEN),
            payload_len=0,
        )

        # Encapsular DEK utilizando KEK + Header (AAD) | DEK -> AES-GCM
        encrypted_dek = key_manager.encrypt_dek(dek, aad=kdf_section(header))

        # Header Definitivo com DEK
        header = dataclasses.replace(
            header,
            dek_nonce=encrypted_dek.nonce_kek,
            wrapped_dek=encrypted_dek.encrypted_dek,
        )

        # Payload
        payload = VaultPayload(schema_version=1, next_id=1, entries=[])
        self.repository.create(header, payload, dek)

        return dek, header

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
