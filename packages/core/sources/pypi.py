from datetime import datetime

import httpx

from ..config import settings
from ..models.package import PackageMetadata, PackageRequest
from .helpers import parse_deps


class PyPIRegistry:
    # same signature as PackageRegistry's exists() method
    def exists(self, package: PackageRequest) -> tuple[bool, PackageMetadata | None]:
        try:
            response = httpx.get(
                f"{settings.pypi_base_url}/{package.name}/json", timeout=5
            )

            if response.status_code == 200:
                return (True, self.extract_metadata(response.json()))
            else:
                return (False, None)

        except httpx.HTTPError as e:
            raise httpx.HTTPError(f"Could not fetch the data from pypi: {e}")

    def extract_metadata(self, data: dict) -> PackageMetadata:
        info = data.get("info", {})
        version = info.get("version")
        description = info.get("summary", None)
        project_urls = info.get("project_urls", None)
        dependencies = info.get("requires_dist", None)

        releases = data.get("releases", {})

        # Collect all valid ISO upload timestamps across all releases & artifacts
        all_upload_times: list[datetime] = []

        for release_files in releases.values():
            for file_info in release_files:
                upload_time_str = file_info.get(
                    "upload_time_iso_8601"
                ) or file_info.get("upload_time")
                if upload_time_str:
                    # Replace 'Z' with '+00:00' for standard ISO parsing in Python 3.11+
                    clean_time = upload_time_str.replace("Z", "+00:00")
                    all_upload_times.append(datetime.fromisoformat(clean_time))

        # Safely compute initial and last release dates
        initial_release_date = min(all_upload_times) if all_upload_times else None

        # Try getting the specific upload time for `version` first; fallback to overall max date
        last_release_date = None
        if version and version in releases and releases[version]:
            version_files = releases[version]
            upload_time_str = version_files[0].get(
                "upload_time_iso_8601"
            ) or version_files[0].get("upload_time")
            if upload_time_str:
                last_release_date = datetime.fromisoformat(upload_time_str)

        if not last_release_date and all_upload_times:
            last_release_date = max(all_upload_times)

        parsed_dependencies = parse_deps(dependencies)

        return PackageMetadata(
            version=version,
            description=description,
            project_urls=project_urls,
            raw_deps=dependencies,
            dependencies=parsed_dependencies,
            last_release_date=last_release_date,
            initial_release_date=initial_release_date,
        )
