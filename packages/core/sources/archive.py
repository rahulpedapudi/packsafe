"""Async archive downloader with streaming SHA-256 verification and safe extraction."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .safe_archive import ArchiveSecurityError, SafeArchiveExtractor

logger = logging.getLogger(__name__)

CHUNK_SIZE = 65536


@dataclass
class ExtractedArchive:
    """A downloaded, verified and extracted distribution archive.

    The temporary directory is owned by this handle: call :meth:`cleanup` when the
    extracted files are no longer needed, ideally from a ``finally`` block.
    """

    files: tuple[Path, ...] = ()
    sha256: str = ""
    size_bytes: int = 0
    extract_dir: Path | None = None
    _temp_dir: Path | None = field(default=None, repr=False)

    @property
    def file_count(self) -> int:
        return len(self.files)

    def cleanup(self) -> None:
        """Removes the temporary directory. Safe to call more than once."""
        if self._temp_dir is None:
            return
        shutil.rmtree(self._temp_dir, ignore_errors=True)
        self._temp_dir = None
        self.extract_dir = None


class ArchiveCollector:
    """Downloads package distribution archives, verifies their bytes, extracts them safely."""

    MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50 MB

    def __init__(
        self,
        extractor: SafeArchiveExtractor | None = None,
        timeout: tuple[float, float] = (5.0, 15.0),
        max_retries: int = 2,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.extractor = extractor or SafeArchiveExtractor()
        self.timeout = httpx.Timeout(
            connect=timeout[0], read=timeout[1], write=10.0, pool=10.0
        )
        self.max_retries = max_retries
        self._client = client
        self._owns_client = client is None

    def _get_client(self) -> httpx.AsyncClient:
        """Lazily create one shared client so connections are pooled and reused."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True
            )
            self._owns_client = True
        return self._client

    async def aclose(self) -> None:
        """Close the underlying client only if this collector created it."""
        if self._client is not None and self._owns_client and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

    async def __aenter__(self) -> ArchiveCollector:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    # --------------------------------------------------------------- internals

    def _archive_kind(self, url: str, archive_path: Path) -> str:
        """Pick the extraction strategy from the URL, falling back to magic bytes.

        PyPI distribution URLs carry the extension, but a query string would defeat a
        naive endswith() check, and the temp file is written without an extension.
        """
        base = url.split("?", 1)[0].split("#", 1)[0].lower()
        if base.endswith((".zip", ".whl")):
            return "zip"
        if base.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar")):
            return "tar"

        if zipfile.is_zipfile(archive_path):
            return "zip"
        try:
            if tarfile.is_tarfile(archive_path):
                return "tar"
        except OSError:
            pass
        return "tar"

    def _extract(self, archive_path: Path, extract_dir: Path, kind: str) -> list[Path]:
        if kind == "zip":
            return self.extractor.extract_zip(archive_path, extract_dir)
        return self.extractor.extract_tar(archive_path, extract_dir)

    def _total_extracted_size(self, files: list[Path]) -> int:
        total = 0
        for f in files:
            try:
                total += f.stat().st_size
            except OSError:
                continue  # raced with cleanup or an unreadable entry
        return total

    async def _download_to_disk(
        self, download_url: str, archive_path: Path
    ) -> str:
        """Stream the archive to disk, hashing the exact bytes received.

        Returns the hex SHA-256 of the downloaded bytes.
        """
        client = self._get_client()
        hasher = hashlib.sha256()
        total_bytes = 0

        async with client.stream("GET", download_url) as resp:
            if resp.status_code != 200:
                raise ArchiveSecurityError(
                    f"Failed to download archive from {download_url}: "
                    f"HTTP {resp.status_code}"
                )

            content_length = resp.headers.get("Content-Length")
            if content_length and int(content_length) > self.MAX_DOWNLOAD_BYTES:
                raise ArchiveSecurityError(
                    "Content-Length exceeds maximum archive limit "
                    f"({content_length} > {self.MAX_DOWNLOAD_BYTES} bytes)."
                )

            with open(archive_path, "wb") as f:
                async for chunk in resp.aiter_bytes(CHUNK_SIZE):
                    total_bytes += len(chunk)
                    if total_bytes > self.MAX_DOWNLOAD_BYTES:
                        raise ArchiveSecurityError(
                            "Download exceeded maximum archive limit "
                            f"({self.MAX_DOWNLOAD_BYTES} bytes)."
                        )
                    hasher.update(chunk)
                    f.write(chunk)

        return hasher.hexdigest()

    # ------------------------------------------------------------------- public

    async def collect(
        self,
        download_url: str,
        expected_sha256: str | None = None,
    ) -> ExtractedArchive:
        """Download, verify and safely extract a distribution archive.

        The returned handle owns a temporary directory; call ``cleanup()`` on it.
        Raises :class:`ArchiveSecurityError` if the archive is oversized, unsafe, or
        does not match ``expected_sha256``.
        """
        temp_dir = Path(tempfile.mkdtemp(prefix="packsafe_pkg_"))
        archive_path = temp_dir / "distribution_archive"
        extract_dir = temp_dir / "extracted"

        try:
            calculated_sha = await self._download_with_retry(
                download_url, archive_path
            )

            if expected_sha256 and expected_sha256.lower() != calculated_sha.lower():
                logger.warning(
                    "Archive SHA-256 mismatch for %s: expected %s, got %s.",
                    download_url,
                    expected_sha256,
                    calculated_sha,
                )
                raise ArchiveSecurityError(
                    f"Archive SHA-256 mismatch! Expected {expected_sha256}, "
                    f"got {calculated_sha}."
                )

            extract_dir.mkdir(parents=True, exist_ok=True)
            kind = self._archive_kind(download_url, archive_path)
            # Extraction is CPU/IO bound: keep it off the event loop.
            extracted = await asyncio.to_thread(
                self._extract, archive_path, extract_dir, kind
            )
            size_bytes = await asyncio.to_thread(self._total_extracted_size, extracted)

            return ExtractedArchive(
                files=tuple(extracted),
                sha256=calculated_sha,
                size_bytes=size_bytes,
                extract_dir=extract_dir,
                _temp_dir=temp_dir,
            )

        except BaseException:
            # Never leak a temp dir, including on cancellation.
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    async def _download_with_retry(
        self, download_url: str, archive_path: Path
    ) -> str:
        last_error: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                return await self._download_to_disk(download_url, archive_path)
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429 and attempt < self.max_retries:
                    retry_after = float(
                        e.response.headers.get("Retry-After", 1.0 + attempt * 2)
                    )
                    await asyncio.sleep(min(retry_after, 5.0))
                    continue
                raise
            except (httpx.TimeoutException, httpx.NetworkError) as e:
                last_error = e
                logger.debug(
                    "Archive download error on attempt %s for %s: %s",
                    attempt,
                    download_url,
                    e,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(0.5 * (2**attempt))
                    continue
                raise

        raise ArchiveSecurityError(
            f"Failed to download archive after {self.max_retries} retries: "
            f"{download_url}"
        ) from last_error