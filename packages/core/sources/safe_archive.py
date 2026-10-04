"""Safe archive extraction boundary preventing Zip-Slip, bombs, and symlink attacks.

Pure stdlib and side-effect free, so it is trivially testable against hostile archives.
Every limit below is enforced *before* a single byte is written to disk.
"""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path


class ArchiveSecurityError(ValueError):
    """Raised when an archive violates safety limits or exhibits path traversal."""


class SafeArchiveExtractor:
    """Safely extracts zip or tarball archives into an isolated temporary directory.

    Enforces four independent limits (count, per-file size, cumulative uncompressed
    size, compression ratio) plus a containment check on every resolved member path.
    """

    def __init__(
        self,
        max_total_size_bytes: int = 50 * 1024 * 1024,  # 50 MB
        max_file_size_bytes: int = 10 * 1024 * 1024,  # 10 MB
        max_file_count: int = 2000,
        max_compression_ratio: float = 10.0,
    ) -> None:
        self.max_total_size = max_total_size_bytes
        self.max_file_size = max_file_size_bytes
        self.max_file_count = max_file_count
        self.max_compression_ratio = max_compression_ratio

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _contains(dest_dir_resolved: Path, candidate: Path) -> bool:
        """True when candidate resolves inside dest_dir. Never raises."""
        try:
            return candidate.is_relative_to(dest_dir_resolved)
        except (ValueError, OSError):
            return False

    def _resolve_member(
        self, dest_dir: Path, dest_dir_resolved: Path, name: str
    ) -> Path:
        """Resolve a member path and reject anything escaping the destination."""
        target = (dest_dir / name).resolve()
        if not self._contains(dest_dir_resolved, target):
            raise ArchiveSecurityError(
                f"Path traversal detected in archive member: '{name}'."
            )
        return target

    def _accumulate(
        self, extracted_size: int, member_name: str, member_size: int
    ) -> int:
        """Apply the per-file and cumulative size limits, returning the new total."""
        if member_size > self.max_file_size:
            raise ArchiveSecurityError(
                f"File '{member_name}' exceeds max size limit "
                f"({member_size} > {self.max_file_size})."
            )
        total = extracted_size + member_size
        if total > self.max_total_size:
            raise ArchiveSecurityError(
                "Archive exceeds maximum uncompressed size limit "
                f"({total} > {self.max_total_size} bytes)."
            )
        return total

    def _check_ratio(
        self, archive_size: int, total_extracted: int, archive_path: Path
    ) -> None:
        """Reject implausible expansion (zip-bomb heuristic).

        Only meaningful once a meaningful amount has been extracted, otherwise tiny
        archives fail on rounding.
        """
        if archive_size <= 0 or total_extracted <= 0:
            return
        if total_extracted < 1024 * 1024:  # under 1 MB extracted, not conclusive
            return
        ratio = total_extracted / archive_size
        if ratio > self.max_compression_ratio:
            raise ArchiveSecurityError(
                f"Archive '{archive_path.name}' exceeds maximum safe compression "
                f"ratio ({ratio:.1f}:1 > {self.max_compression_ratio}:1, potential "
                "zip bomb)."
            )

    # --------------------------------------------------------------------- zip

    def extract_zip(self, zip_path: Path, dest_dir: Path) -> list[Path]:
        """Safely extracts a zip/wheel file. Returns regular files only."""
        extracted_paths: list[Path] = []
        archive_size = zip_path.stat().st_size
        dest_dir_resolved = dest_dir.resolve()

        with zipfile.ZipFile(zip_path, "r") as zf:
            members = [m for m in zf.infolist() if not m.is_dir()]
            if len(members) > self.max_file_count:
                raise ArchiveSecurityError(
                    f"Archive exceeds maximum file count "
                    f"({len(members)} > {self.max_file_count})."
                )

            total_extracted_size = 0
            for member in members:
                total_extracted_size = self._accumulate(
                    total_extracted_size, member.filename, member.file_size
                )
                self._check_ratio(archive_size, total_extracted_size, zip_path)

                target_path = self._resolve_member(
                    dest_dir, dest_dir_resolved, member.filename
                )
                zf.extract(member, dest_dir)
                if target_path.is_file():
                    extracted_paths.append(target_path)

        return extracted_paths

    # --------------------------------------------------------------------- tar

    def _tar_link_escapes(
        self, dest_dir: Path, dest_dir_resolved: Path, member: tarfile.TarInfo
    ) -> bool:
        """True when a symlink/hardlink points outside the destination.

        Tar link targets are relative to the directory holding the link, not to the
        extraction root, so resolution must use the link's own parent.
        """
        link_parent = (dest_dir / member.name).parent
        try:
            link_target = (link_parent / member.linkname).resolve()
        except (ValueError, OSError):
            return True
        return not self._contains(dest_dir_resolved, link_target)

    def extract_tar(self, tar_path: Path, dest_dir: Path) -> list[Path]:
        """Safely extracts a tar / tar.gz / tar.bz2 / tar.xz archive.

        Returns regular files only; unsafe symlinks and hardlinks are skipped.
        """
        extracted_paths: list[Path] = []
        archive_size = tar_path.stat().st_size
        dest_dir_resolved = dest_dir.resolve()

        with tarfile.open(tar_path, "r:*") as tf:
            members = tf.getmembers()
            if len(members) > self.max_file_count:
                raise ArchiveSecurityError(
                    f"Archive exceeds maximum file count "
                    f"({len(members)} > {self.max_file_count})."
                )

            total_extracted_size = 0
            for member in members:
                total_extracted_size = self._accumulate(
                    total_extracted_size, member.name, member.size
                )
                self._check_ratio(archive_size, total_extracted_size, tar_path)

                if member.issym() or member.islnk():
                    if self._tar_link_escapes(dest_dir, dest_dir_resolved, member):
                        continue  # skip links pointing outside the sandbox

                if not (member.isfile() or member.isdir()):
                    continue  # skip devices, FIFOs, sockets

                target_path = self._resolve_member(
                    dest_dir, dest_dir_resolved, member.name
                )

                # Python 3.12+ 'data' filter is the authoritative defense: it blocks
                # absolute paths, '..' escapes, escaping links, and strips setuid bits.
                try:
                    tf.extract(member, dest_dir, filter="data")
                except TypeError:  # pragma: no cover - Python < 3.12
                    tf.extract(member, dest_dir)

                if target_path.is_file():
                    extracted_paths.append(target_path)

        return extracted_paths
