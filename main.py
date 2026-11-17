from ui.consolemenu import ConsoleMenu

menu = ConsoleMenu()
menu.inicialization_display()
menu.display_menu()

option = menu.get_option()
menu.execute_option(option)