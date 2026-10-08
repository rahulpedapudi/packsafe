from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from packsafe_core.config import settings
from packsafe_core.exceptions import RegistryAPIError
from packsafe_core.models.package import EcosystemType, PackageRequest
from packsafe_core.sources.pypi import PyPIRegistry


@pytest.fixture
def pypi_registry():
    return PyPIRegistry()


@pytest.fixture
def mock_downloads_api():
    """Isolates the pypistats lookup so extract_metadata never touches the network.

    extract_metadata awaits _fetch_downloads, which opens its own AsyncClient and hits
    settings.PYPI_STATS_URL. Unpatched it would attempt a real connection (and the
    failure is swallowed by a broad except, so the suite would still pass).
    """
    with patch("packsafe_core.sources.pypi.httpx.AsyncClient") as mock_client_class:
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"stats": [{"download_count": 1234}]}
        mock_client.get.return_value = mock_response
        yield mock_client


@pytest.fixture
def mock_pypi_response_full():
    now = datetime.now(UTC)
    return {
        "info": {
            "name": "testpkg",
            "version": "1.2.3",
            "package_url": "https://pypi.org/project/testpkg/",
            "project_urls": {
                "Source": "https://github.com/test/testpkg",
                "Documentation": "https://testpkg.readthedocs.io",
            },
            "author": "Jane Doe, John Smith",
            "maintainer_email": "jane@example.com",
            "license": "MIT",
        },
        "releases": {
            "1.0.0": [
                {
                    "url": "https://files.pythonhosted.org/packages/1.0.0/testpkg-1.0.0.tar.gz",
                    "upload_time_iso_8601": (now - timedelta(days=400)).isoformat(),
                    "digests": {"sha256": "hash100"},
                }
            ],
            "1.2.0": [
                {
                    "url": "https://files.pythonhosted.org/packages/1.2.0/testpkg-1.2.0.tar.gz",
                    "upload_time": (now - timedelta(days=100)).isoformat(),
                    "digests": {"sha256": "hash120"},
                }
            ],
            "1.2.3": [
                {
                    "url": "https://files.pythonhosted.org/packages/1.2.3/testpkg-1.2.3.whl",
                    "upload_time_iso_8601": (now - timedelta(days=10)).isoformat(),
                    "digests": {"sha256": "hash123"},
                }
            ],
        },
    }


class TestPyPIRegistry:
    @pytest.mark.asyncio
    @patch("packsafe_core.sources.pypi.httpx.AsyncClient")
    async def test_exists_success_full(
        self, mock_client_class, pypi_registry, mock_pypi_response_full
    ):
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_pypi_response_full
        mock_client.get.return_value = mock_response

        req = PackageRequest(name="testpkg", version="1.2.3")
        exists, metadata = await pypi_registry.exists(req)

        assert exists is True
        assert metadata is not None

        identity, reg_ev, prov, dist_url = metadata
        assert identity.name == "testpkg"
        assert identity.ecosystem == EcosystemType.pypi
        assert identity.version == "1.2.3"
        assert identity.repository_url == "https://github.com/test/testpkg"
        assert identity.archive_hash == "hash123"

        assert reg_ev.status == "AVAILABLE"
        assert reg_ev.declared_license == "MIT"
        assert (
            reg_ev.maintainer_count == 3
        )  # "Jane Doe", "John Smith", "jane@example.com"
        assert reg_ev.latest_version == "1.2.3"

        # 1 year ago was 365 days. 1.0.0 is 400 days (not in 1y). 1.2.0 is 100 days (in 1y). 1.2.3 is 10 days (in 1y)
        assert reg_ev.release_count_1y == 2
        # 3 months ago is 90 days. 1.2.3 is 10 days (in 3m)
        assert reg_ev.release_count_3m == 1

        assert (
            dist_url
            == "https://files.pythonhosted.org/packages/1.2.3/testpkg-1.2.3.whl"
        )
        assert prov.source == "registry"

        # Verify network call. extract_metadata also queries pypistats for download
        # counts, so the metadata request is matched rather than being the only call.
        mock_client.get.assert_any_call(
            f"{settings.PYPI_BASE_URL}/testpkg/json", timeout=5
        )

    @pytest.mark.asyncio
    @patch("packsafe_core.sources.pypi.httpx.AsyncClient")
    async def test_exists_not_found(self, mock_client_class, pypi_registry):
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_client.get.return_value = mock_response

        req = PackageRequest(name="unknownpkg")
        exists, metadata = await pypi_registry.exists(req)

        assert exists is False
        assert metadata is None

    @pytest.mark.asyncio
    @patch("packsafe_core.sources.pypi.httpx.AsyncClient")
    async def test_exists_http_error(self, mock_client_class, pypi_registry):
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client.get.side_effect = httpx.HTTPError("Network failure")

        req = PackageRequest(name="errorpkg")
        # exists() translates httpx's own error hierarchy into a PackSafe exception,
        # so the transport error is re-raised as RegistryAPIError.
        with pytest.raises(
            RegistryAPIError, match="Could not fetch the data from pypi"
        ):
            await pypi_registry.exists(req)

    def test_extract_repository_url(self, pypi_registry):
        assert pypi_registry._extract_repository_url({"Source": "url1"}) == "url1"
        assert pypi_registry._extract_repository_url({"Repository": "url2"}) == "url2"
        assert pypi_registry._extract_repository_url({"Code": "url3"}) == "url3"
        assert pypi_registry._extract_repository_url({"Source Code": "url4"}) == "url4"
        assert pypi_registry._extract_repository_url({"Homepage": "url5"}) == "url5"
        assert pypi_registry._extract_repository_url({"Other": "url6"}) is None
        assert pypi_registry._extract_repository_url({}) is None

    @pytest.mark.asyncio
    async def test_extract_metadata_minimal_missing(
        self, pypi_registry, mock_downloads_api
    ):
        # Empty dictionary response
        identity, reg_ev, prov, dist_url = await pypi_registry.extract_metadata(
            "minpkg", None, {}
        )

        assert identity.name == "minpkg"
        assert identity.version == "1.0.0"  # Default fallback
        assert identity.repository_url is None
        assert identity.archive_hash is None

        assert reg_ev.declared_license == "UNKNOWN"
        assert reg_ev.release_count_1y is None
        assert reg_ev.release_count_3m is None
        assert reg_ev.days_since_last_release is None
        assert reg_ev.project_maturity_days is None
        assert reg_ev.maintainer_count is None
        assert reg_ev.published_at is None

        assert dist_url is None

    @pytest.mark.asyncio
    async def test_extract_metadata_bad_date(self, pypi_registry, mock_downloads_api):
        data = {"releases": {"1.0": [{"upload_time_iso_8601": "invalid-date-string"}]}}
        # Should not crash
        identity, reg_ev, prov, dist_url = await pypi_registry.extract_metadata(
            "bad-date-pkg", "1.0", data
        )
        assert reg_ev.release_count_1y is None
        assert reg_ev.published_at is None

    @pytest.mark.asyncio
    async def test_extract_metadata_no_dist_url(
        self, pypi_registry, mock_downloads_api
    ):
        data = {
            "releases": {
                "1.0": [
                    {
                        "url": "https://example.com/file.zip",
                        "digests": {"sha256": "abc"},
                    }
                ]
            }
        }
        identity, reg_ev, prov, dist_url = await pypi_registry.extract_metadata(
            "nodistpkg", "1.0", data
        )
        assert dist_url is None
        assert identity.archive_hash is None

    @pytest.mark.parametrize(
        "maintainer_str, expected_count",
        [
            ("jane@example.com", 1),
            ("Jane, John", 2),
            ("Jane; John / Jim \n Jack", 4),
            ("", None),
        ],
    )
    @pytest.mark.asyncio
    async def test_extract_metadata_maintainers(
        self, pypi_registry, mock_downloads_api, maintainer_str, expected_count
    ):
        data = {"info": {"maintainer": maintainer_str}}
        _, reg_ev, _, _ = await pypi_registry.extract_metadata("pkg", "1.0", data)
        assert reg_ev.maintainer_count == expected_count

    @pytest.mark.parametrize(
        "pkg_name", ["fastapi", "django", "numpy", "pandas", "requests"]
    )
    @pytest.mark.asyncio
    @patch("packsafe_core.sources.pypi.httpx.AsyncClient")
    async def test_various_packages_mock(
        self, mock_client_class, pypi_registry, pkg_name
    ):
        # Just ensure the flow works for varied names, using a simple valid response
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"name": pkg_name, "version": "1.0"}}
        mock_client.get.return_value = mock_response

        req = PackageRequest(name=pkg_name)
        exists, metadata = await pypi_registry.exists(req)
        assert exists is True
        assert metadata[0].name == pkg_name
