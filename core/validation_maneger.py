
class ValidationManager:
    def __init__(self, vault):
        self.vault = vault

    def validate_vault(self):
        # Verificar existência do cofre
        if self.vault.repository.vault_exists():
            print("Cofre existente. Realizando desbloqueio...")
            recovered_dek = self.vault.unlock_vault()
        else:
            print("Nenhum cofre encontrado. Criando novo cofre...")
            recovered_dek = self.vault.create_vault()

        return recovered_dek 
        