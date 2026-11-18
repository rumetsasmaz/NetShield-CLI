from netshield import config, theme
from netshield.modules import ALL_MODULES
from netshield.theme import ask, paint, say

BANNER = r"""
 _   _  _____ _____ _____ _   _ _____ _____ _     _____    _____ _     _____
| \ | ||  ___|_   _/  ___| | | |_   _|  ___| |   |  _  \  /  __ \ |   |_   _|
|  \| || |__   | | \ `--.| |_| | | | | |__ | |   | | | |  | /  \/ |     | |
| . ` ||  __|  | |  `--. \  _  | | | |  __|| |   | | | |  | |   | |     | |
| |\  || |___  | | /\__/ / | | | _| |_| |___| |___| |/ /   | \__/\ |_____| |_
\_| \_/\____/  \_/ \____/\_| |_/\___/\____/\_____/___/     \____/\_____/\___/
"""


def print_menu(modules):
    say("title", "\n--- NetShield-CLI ---")
    for number, module in enumerate(modules, start=1):
        say("menu", f"{number}. {module.name}")
    say("exit", f"{len(modules) + 1}. Exit")


def main():
    theme.set_theme(config.load().get("theme", "default"))
    modules = ALL_MODULES
    print(paint("banner", BANNER))

    while True:
        print_menu(modules)
        choice = ask(f"\nSelect an option (1-{len(modules) + 1}):")

        if choice == str(len(modules) + 1):
            say("exit", "\nExiting... Goodbye!")
            break
        if not choice.isdigit() or not 1 <= int(choice) <= len(modules):
            say("error", "\n[!] Invalid choice, try again.")
            continue

        try:
            modules[int(choice) - 1].run()
        except (KeyboardInterrupt, EOFError):
            say("warn", "\n[!] Cancelled.")


if __name__ == "__main__":
    main()
