from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
from model.models import EncryptedData

class Cryptation:

    @staticmethod
    def encrypt(key: bytes, data: bytes) -> EncryptedData:

        nonce = secrets.token_bytes(12)

        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, data, None)
        
        return EncryptedData(nonce=nonce, ciphertext=ciphertext)

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:

        cipher = AESGCM(key)

        return cipher.decrypt(nonce, ciphertext, None)
