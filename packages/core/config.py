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
    CISA_FEED_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    GITHUB_URL: str = "https://api.github.com/repos"
    DEPS_URL: str = "https://api.deps.dev/v3"
    EPSS_BASE_URL: str = "https://api.first.org/data/v1/epss"

    # local database
    DATABASE_URL: str = str(APP_CACHE)


settings = Settings()

