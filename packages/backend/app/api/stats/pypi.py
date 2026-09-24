from app.schemas.pypi import StatsResponse
from app.services.pypi_service import get_stats
from fastapi import APIRouter

pypi_router = APIRouter()


@pypi_router.get("/{package}", response_model=StatsResponse)
def get_package_stats(
    package: str,
    version: str | None = None,
    interval: int = 30,
):
    return get_stats(package, version, interval)
