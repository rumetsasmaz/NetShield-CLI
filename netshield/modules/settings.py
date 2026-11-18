from netshield import config, theme
from netshield.base import BaseModule
from netshield.theme import ask, say


class ThemeModule(BaseModule):
    name = "Change Theme"
    description = "Pick a colour theme (saved for next time)"

    def run(self):
        names = theme.available_themes()
        for index, name in enumerate(names, start=1):
            marker = " (current)" if name == theme.current_theme() else ""
            say("menu", f"  {index}. {name}{marker}")
        choice = ask("Theme number or name:").lower()
        if choice.isdigit() and 1 <= int(choice) <= len(names):
            choice = names[int(choice) - 1]
        if not theme.set_theme(choice):
            say("error", "[-] Unknown theme.")
            return
        settings = config.load()
        settings["theme"] = choice
        saved = config.save(settings)
        say("ok", f"[+] Theme set to '{choice}'" + ("" if saved else " (could not be saved)"))
