from crypto.cryptation import Cryptation
from storage.vault_repository import VaultRepository

class credentialManager:
    def __init__(self, recovered_dek: bytes, reference: str, data: bytes, repository: VaultRepository):
        self.recovered_dek = recovered_dek
        self.reference = reference
        self.repository = repository
        self.data = data

    def encrypt_credential(self):
        encrypted_password = Cryptation.encrypt(
            self.recovered_dek,
            self.data
        )
        
        self.repository.save_credential(
            encrypted_password=encrypted_password.ciphertext,
            nonce=encrypted_password.nonce,
            link=self.reference
        )

        return True

    def decrypt_credential(self, id: int):
        credential = self.repository.get_credential(credential_id=id)
        encrypted_data = credential[0][1]
        nonce = credential[0][3]

        decrypted_data = Cryptation.decrypt(
            self.recovered_dek,
            nonce,
            encrypted_data
        )
        return decrypted_data.decode('utf-8')
