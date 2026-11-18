"""Tiny JSON settings file (currently only the theme)."""

import json
from pathlib import Path

CONFIG_PATH = Path.home() / ".netshield" / "config.json"


def load():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as file:
            data = json.load(file)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def save(data):
    try:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)
        return True
    except OSError:
        return False
