import os
from pathlib import Path


class Settings:
    # app config
    APP_NAME: str = "packsafe"
    APP_ROOT: Path = Path.home() / f".{APP_NAME}"
    APP_CONFIG: Path = APP_ROOT / "config.toml"
    APP_CACHE: Path = APP_ROOT / "cache.db"

    # sources
    PYPI_BASE_URL: str = "https://pypi.org/pypi"
    PYPI_STATS_URL: str = "http://localhost:8000"
    OSV_BASE_URL: str = "https://api.osv.dev/v1/query"
    CISA_FEED_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    GITHUB_URL: str = "https://api.github.com/repos"
    DEPS_URL: str = "https://api.deps.dev/v3"
    EPSS_BASE_URL: str = "https://api.first.org/data/v1/epss"

    # local database
    DATABASE_URL: str = str(APP_CACHE)

    # PackSafe's own service. Hosts the endpoints the CLI cannot serve itself: BigQuery
    # download stats, and natural-language explanations. Note the provider API key is
    # deliberately absent here - that stays on the server, and a CLI that asks for it
    # would be asking users to paste a third-party credential into a terminal.
    EXPLAIN_API_URL: str = "http://localhost:8000"

    def __post_init__(self) -> None:
        # Only the service endpoints honour the environment. Every upstream default stays
        # a literal: a registry URL is not something a user should be able to redirect at
        # the scoring engine by exporting a variable.
        for attr, var in (
            ("PYPI_STATS_URL", "PACKSAFE_PYPI_STATS_URL"),
            ("EXPLAIN_API_URL", "PACKSAFE_EXPLAIN_URL"),
        ):
            override = os.getenv(var)
            if override:
                setattr(self, attr, override.rstrip("/"))


settings = Settings()
