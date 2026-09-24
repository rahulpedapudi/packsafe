import os
import sys
from pathlib import Path

from ..config import settings


def get_cache_path(app_name: str = settings.APP_NAME):
    """Returns the platform-specific cache directory"""
    if sys.platform == "win32":
        base_dir = Path(
            os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
        )
        return base_dir / app_name / "Cache"
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / app_name
    else:
        base_dir = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))

        return base_dir / app_name


def get_app_path(app_name: str = settings.APP_NAME) -> Path:
    return Path.home() / f".{app_name}"
