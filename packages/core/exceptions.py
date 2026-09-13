class PackageAnalysisError(Exception):
    """Base exception for package analysis failures."""


class PackageNotFoundError(PackageAnalysisError):
    """Raised when the package does not exist on the registry."""

    def __init__(self, package_name: str, ecosystem: str):
        self.package_name = package_name
        self.ecosystem = ecosystem
        super().__init__(f"Package '{package_name}' not found in {ecosystem}.")


class RegistryAPIError(PackageAnalysisError):
    """Raised when the registry returns a 5xx or connection fails."""

    def __init__(self, message: str, status_code: int | None = None):
        self.status_code = status_code
        super().__init__(message)


class InvalidPackageDataError(PackageAnalysisError):
    """Raised when payload parsing fails due to unexpected format."""
