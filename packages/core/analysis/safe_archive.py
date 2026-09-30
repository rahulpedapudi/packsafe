"""Safe archive extraction boundary preventing Zip-Slip, bombs, and symlink attacks."""

from __future__ import annotations

import os
import tarfile
import zipfile
from pathlib import Path
from typing import BinaryIO


class ArchiveSecurityError(ValueError):
    """Raised when an archive violates safety limits or exhibits path traversal."""
    pass


class SafeArchiveExtractor:
    """Safely extracts zip or tarball archives into an isolated temporary directory."""

    def __init__(
        self,
        max_total_size_bytes: int = 50 * 1024 * 1024,  # 50 MB
        max_file_size_bytes: int = 10 * 1024 * 1024,   # 10 MB
        max_file_count: int = 2000,
        max_compression_ratio: float = 10.0,
    ) -> None:
        self.max_total_size = max_total_size_bytes
        self.max_file_size = max_file_size_bytes
        self.max_file_count = max_file_count
        self.max_compression_ratio = max_compression_ratio

    def extract_zip(self, zip_path: Path, dest_dir: Path) -> list[Path]:
        """Safely extracts a zip file."""
        extracted_paths: list[Path] = []
        archive_size = zip_path.stat().st_size
        total_extracted_size = 0
        file_count = 0

        dest_dir_resolved = dest_dir.resolve()

        with zipfile.ZipFile(zip_path, "r") as zf:
            infolist = zf.infolist()
            if len(infolist) > self.max_file_count:
                raise ArchiveSecurityError(f"Archive exceeds maximum file count ({len(infolist)} > {self.max_file_count}).")

            for member in infolist:
                file_count += 1
                if member.file_size > self.max_file_size:
                    raise ArchiveSecurityError(f"File '{member.filename}' exceeds max size limit ({member.file_size} > {self.max_file_size}).")

                total_extracted_size += member.file_size
                if total_extracted_size > self.max_total_size:
                    raise ArchiveSecurityError("Archive exceeds maximum uncompressed size limit (50 MB).")

                if archive_size > 0 and (total_extracted_size / archive_size) > self.max_compression_ratio:
                    raise ArchiveSecurityError("Archive exceeds maximum safe compression ratio (potential zip bomb).")

                # Path traversal prevention (Zip-Slip)
                target_path = (dest_dir / member.filename).resolve()
                try:
                    if not target_path.is_relative_to(dest_dir_resolved):
                        raise ArchiveSecurityError(f"Path traversal detected in archive member: '{member.filename}'.")
                except ValueError:
                    raise ArchiveSecurityError(f"Path traversal detected in archive member: '{member.filename}'.")

                # Extract safely
                zf.extract(member, dest_dir)
                extracted_paths.append(target_path)

        return extracted_paths

    def extract_tar(self, tar_path: Path, dest_dir: Path) -> list[Path]:
        """Safely extracts a tar / tar.gz / tar.bz2 archive."""
        extracted_paths: list[Path] = []
        archive_size = tar_path.stat().st_size
        total_extracted_size = 0
        file_count = 0

        dest_dir_resolved = dest_dir.resolve()

        with tarfile.open(tar_path, "r:*") as tf:
            members = tf.getmembers()
            if len(members) > self.max_file_count:
                raise ArchiveSecurityError(f"Archive exceeds maximum file count ({len(members)} > {self.max_file_count}).")

            for member in members:
                file_count += 1
                if member.size > self.max_file_size:
                    raise ArchiveSecurityError(f"File '{member.name}' exceeds max size limit.")

                total_extracted_size += member.size
                if total_extracted_size > self.max_total_size:
                    raise ArchiveSecurityError("Archive exceeds maximum uncompressed size limit (50 MB).")

                # Symlink / Hardlink attack check
                if member.issym() or member.islnk():
                    link_target = (dest_dir / member.linkname).resolve()
                    try:
                        if not link_target.is_relative_to(dest_dir_resolved):
                            continue  # Skip unsafe symlink
                    except ValueError:
                        continue

                # Path traversal check
                target_path = (dest_dir / member.name).resolve()
                try:
                    if not target_path.is_relative_to(dest_dir_resolved):
                        raise ArchiveSecurityError(f"Path traversal detected in archive member: '{member.name}'.")
                except ValueError:
                    raise ArchiveSecurityError(f"Path traversal detected in archive member: '{member.name}'.")

                # Python 3.12+ safe tar extraction filter
                try:
                    tf.extract(member, dest_dir, filter="data")
                except TypeError:
                    tf.extract(member, dest_dir)

                extracted_paths.append(target_path)

        return extracted_paths
