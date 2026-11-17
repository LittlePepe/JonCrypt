from art import tprint


class ConsoleMenu:

    def display_menu(self):
        print("1. Consult")
        print("2. Register a new credential")
        print("3. Change the master key")
        print("4. Exit")

    def get_option(self):
        return input("Select an option: ")


    def execute_option(self, option):
        if option == "1":
            print("Consulting credentials")

        elif option == "2":
            print("Registering credential")

        elif option == "3":
            print("Changing master key")

        elif option == "4":
            print("Exiting")

        else:
            print("Invalid option!")

    def inicialization_display(self):
        tprint("Jon Look", font="small")
        print("============== inicializando ==============")
