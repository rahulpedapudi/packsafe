import tomllib
from pathlib import Path

from .defaults import DEFAULT_CONFIG


class Config:
    def __init__(self, config_path: Path):
        self.config_path = config_path

    def load(self):
        if self.config_path.exists():
            with open(self.config_path, "rb") as f:
                return tomllib.load(f)
        return None

    def save_default_config(self):
        if not self.config_path.exists():
            self.config_path.write_text(DEFAULT_CONFIG, encoding="utf-8")
