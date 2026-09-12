import asyncio
import httpx
from ..models import PackageMetadata, EcosystemType
from ..config import settings
from .helpers import parse_deps


async def fetch_pypi_metadata(package_name: str) -> PackageMetadata:
    """
    Fetches PyPI package metadata.

    Args:
        package_name (str): The name of the package to fetch metadata for.

    Returns:
        PackageMetadata: The metadata of the package.

    Example:
        >>> asyncio.run(fetch_pypi_metadata("jsonschema"))
    """

    async with httpx.AsyncClient() as client:
        res = await client.get(f"{settings.pypi_base_url}/{package_name}/json")

        res.raise_for_status()
        data = res.json()

        info = data.get("info", {})

        version = info.get("version")
        description = info.get("summary", None)
        project_urls = info.get("project_urls", None)
        dependencies = info.get("requires_dist", None)

        # latest release
        last_release_date = data["releases"][version][0]["upload_time"]

        parsed_dependencies = parse_deps(dependencies)

        return PackageMetadata(
            name=package_name,
            version=version,
            description=description,
            project_urls=project_urls,
            ecosystem=EcosystemType.pypi,
            raw_deps=dependencies,
            dependencies=parsed_dependencies,
            last_release_date=last_release_date,
        )


# i need to use google bigquery cuz pypistats is deprecated
async def fetch_pypi_stats(package_name: str):
    ...

if __name__ == "__main__":
    print(asyncio.run(fetch_pypi_metadata("jsonschema")).model_dump_json(indent=2))
