from pydantic import BaseModel


class VersionDownloadStat(BaseModel):
    version: str
    download_count: int


class StatsResponse(BaseModel):
    package_name: str
    version: str | None = None
    stats: list[VersionDownloadStat]
