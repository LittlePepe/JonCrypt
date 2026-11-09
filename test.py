
from crypto.kdf import KeyDerivation
from crypto.key_manager import KeyManager
from crypto.cryptation import Cryptation
from storage.vault_repository import VaultRepository

# Senha mestre | Input
senha_mestre = b"MinhaSenhaMestre123!"

# Local banco de dados
repository = VaultRepository("data/joncrypt.db")

# Inicializar derivação | KDF
kdf = KeyDerivation(senha_mestre)

# Inicializar gerenciamento de chaves | DEK
key_manager = KeyManager(kdf) 

# Gerar DEK | DEK
dek = key_manager.create_dek()

# Encapsular DEK utilizando KEK | DEK -> AES-GCM
encrypted_dek = key_manager.encrypt_dek(dek)

# Salvar metadados DB | DEK
repository.save_metadata(
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

# Recuperar |  DEK
recovered_dek = key_manager.decrypt_dek(encrypted_dek)

# Testar criptografia de uma credencial | Input
senha_site = b"MinhaSenhaDoSite123!"

# Criptografar credencial | AES-GCM
encrypted_password = Cryptation.encrypt(
    recovered_dek,
    senha_site
)

# Descriptografar credencial | AES-GCM
decrypted_password = Cryptation.decrypt(
    recovered_dek,
    encrypted_password.nonce,
    encrypted_password.ciphertext
)

print("DEK original:", dek.hex())
print("DEK recuperada:", recovered_dek.hex())
print("Senha recuperada:", decrypted_password.decode())
