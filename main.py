from storage.data_maneger import DatabaseManager
from storage.vault_repository import VaultRepository
from core.vault import InicializationVault
from core.validation_maneger import ValidationManager
from core.credential_manager import credentialManager

# Inicializar banco de dados
db_manager = DatabaseManager("data/joncrypt.db")
db_manager.initialize_database()

try:
    # Inicializar Repository
    repository = VaultRepository(db_manager)

    # Senha mestre (temporária para testes)
    senha_mestre = b"MinhaSenhaMestre123!"

    # Inicializar gerenciamento do cofre
    vault = InicializationVault(senha_mestre, repository)

    # Inicializar inicializar/validação do cofre
    validation_vault = ValidationManager(vault)

    recovered_dek = validation_vault.validate_vault()

    # Testar criptografia de uma credencial
    senha_site = b"SenhaSite123!"
    reference = "https://www.exemplo.com"

    # Inicializar gerenciador de credenciais
    credential_manager = credentialManager(recovered_dek, reference, senha_site, repository)
    credential_manager.encrypt_credential()

    # Testar descriptografia de uma credencial
    decrypted_password = credential_manager.decrypt_credential(id=1)
    print(f"Senha descriptografada: {decrypted_password}")

finally:
    # Fechar conexão com banco
    db_manager.close()