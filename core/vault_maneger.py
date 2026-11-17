from crypto.kdf import KeyDerivation
from crypto.dek import KeyManager
import dataclasses
from storage.svault_repository import SvaultRepository
from storage.svault_format import FORMAT_MAJOR, FORMAT_MINOR, KDF_ARGON2ID, CIPHER_AES256GCM, NONCE_LEN, WRAPPED_DEK_LEN, kdf_section
from model.models import KeyManagerData, VaultHeader, VaultPayload


class VaultManager:

    def __init__(self, repository: SvaultRepository):
        self.repository = repository


    def create_vault(self, master_key: bytes):

        # Inicializar derivação | KDF
        kdf = KeyDerivation(master_key)

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
            kdf_params=kdf.default_kdf_params,
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

        return dek, header, payload

    def unlock_vault(self, master_key: bytes):
        metadados = self.repository.read_header()
        
        salt_kek = metadados.salt
        nonce_dek = metadados.dek_nonce
        encrypted_dek = metadados.wrapped_dek

        # Inicializar derivação | KDF
        kdf = KeyDerivation(master_key, salt_kek=salt_kek)
        # Inicializar gerenciamento de chaves | DEK
        key_manager = KeyManager(kdf)
        
        key_manager_data = KeyManagerData(nonce_kek=nonce_dek, encrypted_dek=encrypted_dek)

        recovered_dek = key_manager.decrypt_dek(data=key_manager_data, aad=kdf_section(metadados))

        header, payload = self.repository.load(recovered_dek)
        return recovered_dek, header, payload
