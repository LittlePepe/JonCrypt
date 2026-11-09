from storage.DataManager import DatabaseManager
from storage.vault_repository import VaultRepository
from core.vault import InicializationKey
from crypto.cryptation import Cryptation

# Inicializar banco de dados
db_manager = DatabaseManager("data/joncrypt.db")
db_manager.initialize_database()

try:
    # Inicializar Repository
    repository = VaultRepository(db_manager)

    # Senha mestre (temporária para testes)
    senha_mestre = b"MinhaSenhaMestre123!"

    # Inicializar gerenciamento do cofre
    vault = InicializationKey(senha_mestre, repository)

    # Verificar existência do cofre
    if repository.vault_exists():

        print("Cofre existente. Realizando desbloqueio...")
        recovered_dek = vault.unlock_vault()

    else:

        print("Nenhum cofre encontrado. Criando novo cofre...")
        recovered_dek = vault.create_vault()

    # Testar criptografia de uma credencial
    senha_site = b"MinhaSenhaDoSite123!"

    encrypted_password = Cryptation.encrypt(
        recovered_dek,
        senha_site
    )

    # Descriptografar credencial
    decrypted_password = Cryptation.decrypt(
        recovered_dek,
        encrypted_password.nonce,
        encrypted_password.ciphertext
    )

    print("DEK recuperada:", recovered_dek.hex())
    print("Senha recuperada:", decrypted_password.decode())

finally:
    # Fechar conexão com banco
    db_manager.close()