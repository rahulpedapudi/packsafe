from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from packsafe_core.models.evidence import EvidenceStatus
from packsafe_core.models.package import EcosystemType, PackageIdentity, PackageRequest
from packsafe_core.pipeline.context import AnalysisContext
from packsafe_core.pipeline.stages.archive import ArchiveStage
from packsafe_core.sources.archive import ArchiveCollector, ExtractedArchive
from packsafe_core.sources.safe_archive import ArchiveSecurityError


class TestArchive:
    @pytest.fixture
    def mock_collector(self):
        collector = AsyncMock(spec=ArchiveCollector)
        return collector

    @pytest.fixture
    def stage(self, mock_collector):
        return ArchiveStage(collector=mock_collector)

    @pytest.fixture
    def context(self):
        ctx = AnalysisContext(
            request=PackageRequest(
                name="testpkg", version="1.0.0", ecosystem=EcosystemType.pypi
            )
        )
        ctx.package = PackageIdentity(
            name="testpkg",
            version="1.0.0",
            ecosystem=EcosystemType.pypi,
            distribution_url="https://example.com/dist.tar.gz",
            archive_hash="somehash",
        )
        return ctx

    @pytest.mark.asyncio
    async def test_archive_instantiation(self, stage):
        assert stage is not None

    @pytest.mark.asyncio
    async def test_archive_not_pypi(self, stage, context):
        context.package = PackageIdentity(
            name="testpkg",
            version="1.0.0",
            ecosystem=EcosystemType.npm,
            distribution_url="https://example.com/dist.tar.gz",
            archive_hash="somehash",
        )
        await stage.execute(context)

        # default is untouched
        stage.collector.collect.assert_not_called()

    @pytest.mark.asyncio
    async def test_archive_no_dist_url(self, stage, context):
        context.package = PackageIdentity(
            name="testpkg",
            version="1.0.0",
            ecosystem=EcosystemType.pypi,
            distribution_url=None,
            archive_hash="somehash",
        )
        await stage.execute(context)

        # default is untouched
        stage.collector.collect.assert_not_called()

    @pytest.mark.asyncio
    async def test_archive_successful(self, stage, mock_collector, context, tmp_path):
        # Mock archive
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        (extract_dir / "setup.py").touch()
        (extract_dir / "LICENSE").touch()

        mock_archive = MagicMock(spec=ExtractedArchive)
        mock_archive.extract_dir = extract_dir
        mock_archive.files = (Path("setup.py"), Path("LICENSE"))
        mock_archive.sha256 = "actualhash"
        mock_archive.size_bytes = 100
        mock_collector.collect.return_value = mock_archive

        await stage.execute(context)

        assert context.static_analysis.status == EvidenceStatus.AVAILABLE
        assert context.static_analysis.archive_sha256 == "actualhash"
        assert context.license_file_found is True

        mock_archive.cleanup.assert_called_once()
        mock_collector.aclose.assert_called_once()

        # Provenance should be appended
        assert any(
            p.source == "archive" and p.source_url == "https://example.com/dist.tar.gz"
            for p in context.provenance
        )

    @pytest.mark.asyncio
    async def test_archive_dangerous_files(
        self, stage, mock_collector, context, tmp_path
    ):
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        (extract_dir / "bad.pth").touch()
        (extract_dir / "native.so").touch()

        mock_archive = MagicMock(spec=ExtractedArchive)
        mock_archive.extract_dir = extract_dir
        mock_archive.files = (Path("bad.pth"), Path("native.so"))
        mock_archive.sha256 = "actualhash"
        mock_archive.size_bytes = 200
        mock_collector.collect.return_value = mock_archive

        await stage.execute(context)

        assert context.static_analysis.status == EvidenceStatus.AVAILABLE
        assert len(context.static_analysis.findings) >= 2
        finding_types = [f.finding_type for f in context.static_analysis.findings]
        assert "SUSPICIOUS_INSTALL_BEHAVIOR" in finding_types

    @pytest.mark.asyncio
    async def test_archive_security_error(self, stage, mock_collector, context):
        mock_collector.collect.side_effect = ArchiveSecurityError("malicious archive")

        await stage.execute(context)

        assert context.static_analysis.status == EvidenceStatus.MISSING

    @pytest.mark.asyncio
    async def test_archive_exception(self, stage, mock_collector, context):
        mock_collector.collect.side_effect = Exception("network failure")

        await stage.execute(context)

        assert context.static_analysis.status == EvidenceStatus.MISSING
