from pathlib import Path


class Settings:
    # app config
    APP_NAME: str = "packsafe"
    APP_ROOT: Path = Path.home() / f".{APP_NAME}"
    APP_CONFIG: Path = APP_ROOT / "config.toml"
    APP_CACHE: Path = APP_ROOT / "cache.db"

    # sources
    PYPI_BASE_URL: str = "https://pypi.org/pypi"
    OSV_BASE_URL: str = "https://api.osv.dev/v1/query"

    # local database
    DATABASE_URL: str = str(APP_CACHE)


settings = Settings()
