"""The installed PackSafe version, resolved from package metadata.

Read from the installed distribution rather than hardcoded, so there is exactly one
place a version is written: the ``project.version`` in pyproject.toml. A constant here
would drift from the published artifact, which is precisely the kind of drift that makes
a security tool's self-report untrustworthy.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

#: Used when the package is run from a source checkout that was never installed.
UNKNOWN_VERSION = "0.1.0+unknown"

#: The distribution name on PyPI. Must match ``project.name`` in pyproject.toml: the
#: import package is ``packsafe_cli``, but importlib.metadata keys off the distribution.
DISTRIBUTION = "packsafe"


def get_version() -> str:
    """Returns the installed version, or a clearly-marked fallback if unavailable."""
    try:
        return version(DISTRIBUTION)
    except PackageNotFoundError:
        return UNKNOWN_VERSION


def version_info() -> str:
    """The version line shown by ``--version``."""
    return f"packsafe {get_version()}"
