
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
        
    def get_masterkey(self):
        while True:
            master_key = input("Input a master key:")

            if self.validate_masterkey(master_key):
                return master_key
            return "Weak Password"
    
    def validate_masterkey(self, master_key):
        
        caracteres = '!@#$%&'
  
        has_leight = len(master_key) >= 10
        has_caracter = any(char in caracteres for char in master_key)

        return has_leight, has_caracter