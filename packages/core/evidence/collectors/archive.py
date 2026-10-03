# """Archive downloader and safe extractor with SHA-256 byte verification."""

# from __future__ import annotations

# import hashlib
# import logging

# # from packsafe.analysis.safe_archive import SafeArchiveExtractor, ArchiveSecurityError
# import shutil
# import tempfile
# import time
# from pathlib import Path

# import httpx

# logger = logging.getLogger(__name__)


# class ArchiveCollector:
#     """Safely downloads package distribution archives, hashes them, and extracts them."""

#     MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50 MB limit

#     def __init__(
#         self,
#         extractor: SafeArchiveExtractor | None = None,
#         timeout: tuple[float, float] = (5.0, 15.0),
#         max_retries: int = 2,
#         client: httpx.Client | None = None,
#     ) -> None:
#         self.extractor = extractor or SafeArchiveExtractor()
#         self.timeout = httpx.Timeout(
#             connect=timeout[0], read=timeout[1], write=10.0, pool=10.0
#         )
#         self.max_retries = max_retries
#         self._client = client

#     def _get_client(self) -> httpx.Client:
#         if self._client is not None:
#             return self._client
#         return httpx.Client(timeout=self.timeout, follow_redirects=True)

#     @staticmethod
#     def cleanup(temp_dir: Path) -> None:
#         """Safely removes temporary extraction directory."""
#         if temp_dir.exists() and temp_dir.is_dir():
#             shutil.rmtree(temp_dir, ignore_errors=True)

#     def download_and_extract(
#         self,
#         download_url: str,
#         expected_sha256: str | None = None,
#     ) -> tuple[list[Path], str, Path]:
#         """Downloads an archive, hashes the exact bytes, and safely extracts it.

#         Returns (extracted_file_paths, calculated_sha256, temp_dir).
#         """
#         client = self._get_client()
#         temp_dir = Path(tempfile.mkdtemp(prefix="packsafe_pkg_"))
#         archive_path = temp_dir / "distribution_archive"

#         for attempt in range(self.max_retries + 1):
#             hasher = hashlib.sha256()
#             total_bytes = 0
#             try:
#                 with client.stream("GET", download_url) as resp:
#                     if resp.status_code == 429:
#                         retry_after = float(
#                             resp.headers.get("Retry-After", 1.0 + attempt * 2)
#                         )
#                         time.sleep(min(retry_after, 5.0))
#                         continue
#                     elif resp.status_code >= 500:
#                         time.sleep(0.5 * (2**attempt))
#                         continue
#                     elif resp.status_code != 200:
#                         self.cleanup(temp_dir)
#                         raise ValueError(
#                             f"Failed to download archive from {download_url}: HTTP {resp.status_code}"
#                         )

#                     # Header length validation
#                     content_length = resp.headers.get("Content-Length")
#                     if content_length and int(content_length) > self.MAX_DOWNLOAD_BYTES:
#                         self.cleanup(temp_dir)
#                         raise ArchiveSecurityError(
#                             f"Content-Length exceeds maximum archive limit ({self.MAX_DOWNLOAD_BYTES} bytes)."
#                         )

#                     with open(archive_path, "wb") as f:
#                         for chunk in resp.iter_bytes(chunk_size=65536):
#                             total_bytes += len(chunk)
#                             if total_bytes > self.MAX_DOWNLOAD_BYTES:
#                                 self.cleanup(temp_dir)
#                                 raise ArchiveSecurityError(
#                                     f"Download exceeded maximum archive limit ({self.MAX_DOWNLOAD_BYTES} bytes)."
#                                 )
#                             hasher.update(chunk)
#                             f.write(chunk)

#                     calculated_sha = hasher.hexdigest()
#                     if (
#                         expected_sha256
#                         and expected_sha256.lower() != calculated_sha.lower()
#                     ):
#                         self.cleanup(temp_dir)
#                         raise ArchiveSecurityError(
#                             f"Archive SHA-256 mismatch! Expected {expected_sha256}, got {calculated_sha}."
#                         )

#                     extract_dir = temp_dir / "extracted"
#                     extract_dir.mkdir(parents=True, exist_ok=True)

#                     # Determine archive type
#                     if download_url.endswith(".zip") or download_url.endswith(".whl"):
#                         extracted = self.extractor.extract_zip(
#                             archive_path, extract_dir
#                         )
#                     else:
#                         extracted = self.extractor.extract_tar(
#                             archive_path, extract_dir
#                         )

#                     return extracted, calculated_sha, temp_dir

#             except (httpx.TimeoutException, httpx.NetworkError) as e:
#                 logger.debug(f"Archive download error on attempt {attempt}: {e}")
#                 if attempt < self.max_retries:
#                     time.sleep(0.5 * (2**attempt))
#                 else:
#                     self.cleanup(temp_dir)
#                     raise

#         self.cleanup(temp_dir)
#         raise ValueError(
#             f"Failed to download archive after {self.max_retries} retries: {download_url}"
#         )

#     def extract_from_bytes(
#         self,
#         data: bytes,
#         archive_name: str = "package.tar.gz",
#     ) -> tuple[list[Path], str, Path]:
#         """Safely extracts in-memory archive bytes, hashing before write."""
#         if len(data) > self.MAX_DOWNLOAD_BYTES:
#             raise ArchiveSecurityError(
#                 f"Data exceeds maximum archive limit ({self.MAX_DOWNLOAD_BYTES} bytes)."
#             )

#         sha256 = hashlib.sha256(data).hexdigest()
#         temp_dir = Path(tempfile.mkdtemp(prefix="packsafe_mem_"))
#         archive_path = temp_dir / archive_name

#         with open(archive_path, "wb") as f:
#             f.write(data)

#         extract_dir = temp_dir / "extracted"
#         extract_dir.mkdir(parents=True, exist_ok=True)

#         if archive_name.endswith(".zip") or archive_name.endswith(".whl"):
#             extracted = self.extractor.extract_zip(archive_path, extract_dir)
#         else:
#             extracted = self.extractor.extract_tar(archive_path, extract_dir)

#         return extracted, sha256, temp_dir
