from core.credential_manager import credentialManager
from core.validation_maneger import ValidationManager
from core.vault import InicializationVault
from model.errors import VaultError
from storage.svault_repository import SvaultRepository

# Repositório do cofre (arquivo .svault)
repository = SvaultRepository("data/joncrypt.svault")

# Senha mestre (temporária para testes)
senha_mestre = b"MinhaSenhaMestre123!"

vault = InicializationVault(senha_mestre, repository)
validation_vault = ValidationManager(vault)

try:
    dek, header, payload = validation_vault.validate_vault()
except VaultError as erro:
    print(f"Não foi possível abrir o cofre: {erro}")
    raise SystemExit(1)

credential_manager = credentialManager(dek, header, payload, repository)

# Testar gravação de uma credencial
credential_manager.add_credential("https://www.exemplo.com", "SenhaSite123!")

# Testar leitura de uma credencial
credencial = credential_manager.get_credential(1)
print(f"Senha recuperada: {credencial.password}")