
class VaultError(Exception):
    def __init__(self):
        pass

    #Arquivo Malformatado
    def VaultFormatError(self):
        return "Vault format is invalid. Please check the vault file."

    #Versão Desconhecida
    def UnsupportedVersionError(self):
        return "Vault version is not supported. Please update the application."

    # Dados adulterados
    def IntegrityError(self):
        return "Vault integrity check failed. The vault may be corrupted or tampered with."

    #Senha Incorreta
    def InvalidPasswordError(self):
        return "The provided password is incorrect. Please try again."