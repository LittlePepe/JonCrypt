
class ConsoleMenu:
    def __init__(self, opcao: int):
        self.opcao = opcao

    def exibir_menu(self):
        print("Menu:")
        print("1. Opção 1")
        print("2. Opção 2")
        print("3. Opção 3")
        print("4. Sair")