"""Central place for colours, glyphs and safe terminal output.

Every module imports its colours from here instead of defining its own.
"""

import sys

from colorama import Fore, Style, init

init(autoreset=True)

# Raw service banners can contain characters that the Windows console code
# page (e.g. cp1254) cannot encode. Never crash on printing.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

RESET = Style.RESET_ALL

# role -> colour. Roles are what modules ask for; themes decide the colour.
THEMES = {
    "default": {
        "banner": Fore.CYAN, "title": Fore.CYAN, "menu": Fore.GREEN,
        "prompt": Fore.YELLOW, "ok": Fore.GREEN, "error": Fore.RED,
        "warn": Fore.YELLOW, "info": Fore.BLUE, "exit": Fore.RED,
        "dim": Fore.WHITE,
    },
    "matrix": {
        "banner": Fore.GREEN, "title": Fore.GREEN, "menu": Fore.GREEN,
        "prompt": Fore.LIGHTGREEN_EX, "ok": Fore.LIGHTGREEN_EX,
        "error": Fore.RED, "warn": Fore.YELLOW, "info": Fore.GREEN,
        "exit": Fore.GREEN, "dim": Fore.GREEN,
    },
    "hacker": {
        "banner": Fore.RED, "title": Fore.RED, "menu": Fore.WHITE,
        "prompt": Fore.LIGHTRED_EX, "ok": Fore.GREEN, "error": Fore.LIGHTRED_EX,
        "warn": Fore.YELLOW, "info": Fore.RED, "exit": Fore.RED,
        "dim": Fore.WHITE,
    },
    "ocean": {
        "banner": Fore.LIGHTBLUE_EX, "title": Fore.LIGHTCYAN_EX,
        "menu": Fore.CYAN, "prompt": Fore.LIGHTYELLOW_EX, "ok": Fore.LIGHTGREEN_EX,
        "error": Fore.LIGHTRED_EX, "warn": Fore.LIGHTYELLOW_EX,
        "info": Fore.LIGHTBLUE_EX, "exit": Fore.LIGHTRED_EX, "dim": Fore.BLUE,
    },
    "mono": {role: "" for role in (
        "banner", "title", "menu", "prompt", "ok", "error", "warn",
        "info", "exit", "dim")},
}

_current = "default"


def available_themes():
    return list(THEMES)


def set_theme(name):
    """Switch theme. Returns False (and changes nothing) for unknown names."""
    global _current
    if name not in THEMES:
        return False
    _current = name
    return True


def current_theme():
    return _current


def paint(role, text):
    """Wrap text in the colour of the given role for the active theme."""
    colour = THEMES[_current].get(role, "")
    return f"{colour}{text}{RESET}" if colour else str(text)


def say(role, text=""):
    print(paint(role, text))


def ask(text):
    """Prompt the user with the themed 'prompt' colour."""
    return input(paint("prompt", text) + " ").strip()
