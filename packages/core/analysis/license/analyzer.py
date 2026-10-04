"""License compliance and SPDX analyzer.

Strictly isolated from the five core security categories.
"""

from __future__ import annotations

from ...models.evidence import LicenseEvidence

OSI_APPROVED = {
    "MIT",
    "APACHE-2.0",
    "BSD-2-CLAUSE",
    "BSD-3-CLAUSE",
    "ISC",
    "PYTHON-2.0",
    "GPL-2.0",
    "GPL-3.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "AGPL-3.0",
    "MPL-2.0",
    "CC0-1.0",
    "UNLICENSE",
}

COPYLEFT_LICENSES = {
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-3.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "SSPL-1.0",
}


class LicenseAnalyzer:
    """Analyzes package license identifiers and copyleft characteristics."""

    def normalize_spdx(self, raw_license: str | None) -> str:
        if not raw_license or raw_license.strip().upper() in ("UNKNOWN", "NONE", ""):
            return "UNKNOWN"

        clean = raw_license.strip().upper()
        if "MIT" in clean:
            return "MIT"
        elif "APACHE" in clean:
            return "Apache-2.0"
        elif "BSD" in clean and "3" in clean:
            return "BSD-3-Clause"
        elif "BSD" in clean:
            return "BSD-2-Clause"
        elif "ISC" in clean:
            return "ISC"
        elif "AGPL" in clean:
            return "AGPL-3.0"
        elif "GPL" in clean and "3" in clean:
            return "GPL-3.0"
        elif "GPL" in clean:
            return "GPL-2.0"
        elif "UNLICENSE" in clean:
            return "Unlicense"
        elif "CC0" in clean:
            return "CC0-1.0"
        return raw_license.strip()

    def analyze(
        self, raw_license: str | None, license_file_found: bool = True
    ) -> LicenseEvidence:
        spdx = self.normalize_spdx(raw_license)
        spdx_upper = spdx.upper()

        is_osi = spdx_upper in OSI_APPROVED
        is_copyleft = spdx_upper in COPYLEFT_LICENSES

        return LicenseEvidence(
            declared_license=raw_license,
            spdx_id=spdx,
            is_osi_approved=is_osi,
            is_copyleft=is_copyleft,
            license_file_present=license_file_found,
            status="AVAILABLE" if raw_license else "MISSING",
        )
