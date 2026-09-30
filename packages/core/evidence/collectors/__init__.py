"""Evidence collectors package."""

from packsafe.evidence.collectors.pypi import PyPICollector
from packsafe.evidence.collectors.npm import NpmCollector
from packsafe.evidence.collectors.osv import OSVCollector
from packsafe.evidence.collectors.github import GitHubCollector

__all__ = [
    "PyPICollector",
    "NpmCollector",
    "OSVCollector",
    "GitHubCollector",
]
