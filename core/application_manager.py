from core.credential_manager import credentialManager
from core.validation_maneger import ValidationManager
from core.vault_maneger import VaultManager
from model.errors import VaultError
from storage.svault_repository import SvaultRepository
from ui.consolemenu import ConsoleMenu



class ApplicationManager:

    def start_vault():
        repository = SvaultRepository("data/joncrypt.svault")

        menu = ConsoleMenu()
        menu.inicialization_display()

        master_key = menu.get_masterkey()

        vault = VaultManager(master_key, repository)
        validation_vault = ValidationManager(vault)

        try:
            dek, header, payload = validation_vault.validate_vault()

        except VaultError as erro:
            print(f"Não foi possível abrir o cofre: {erro}")
            raise SystemExit(1)

        credential_manager = credentialManager(dek=dek, header=header, payload=payload, repository=repository)

        # Testar gravação de uma credencial
        credential_manager.add_credential("https://www.exemplo.com", "SenhaSite123!")

        # Testar leitura de uma credencial
        print(credential_manager.payload.entries)

    