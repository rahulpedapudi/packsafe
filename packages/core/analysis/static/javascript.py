"""JavaScript and npm static package analyzer."""

from __future__ import annotations

import json
import re
from pathlib import Path
from packsafe.evidence.models import StaticAnalysisFindingItem


class JavaScriptStaticAnalyzer:
    """Safely analyzes npm package files and JS/TS source code without execution."""

    def analyze_package_json(self, package_json_path: Path) -> list[StaticAnalysisFindingItem]:
        findings: list[StaticAnalysisFindingItem] = []
        try:
            data = json.loads(package_json_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return findings

        scripts = data.get("scripts", {})
        suspicious_hooks = ["preinstall", "install", "postinstall", "prepare"]

        for hook in suspicious_hooks:
            cmd = scripts.get(hook)
            if cmd:
                # Check for curl, wget, bash, sh, powershell, python execution in install hooks
                if re.search(r"(curl|wget|powershell|bash|sh|cmd\.exe|node\s+-e|python)", cmd, re.IGNORECASE):
                    findings.append(StaticAnalysisFindingItem(
                        finding_type="SUSPICIOUS_INSTALL_BEHAVIOR",
                        severity="CRITICAL",
                        confidence=0.92,
                        title=f"Suspicious {hook} lifecycle script hook",
                        description=f"Package executes external shell command during installation: {cmd}",
                        evidence_snippet=f'"{hook}": "{cmd}"',
                        file_path="package.json",
                        line_number=1,
                    ))
                else:
                    findings.append(StaticAnalysisFindingItem(
                        finding_type="SUSPICIOUS_INSTALL_BEHAVIOR",
                        severity="MEDIUM",
                        confidence=0.70,
                        title=f"Package contains {hook} script",
                        description=f"Automated installation lifecycle hook defined: {cmd}",
                        evidence_snippet=f'"{hook}": "{cmd}"',
                        file_path="package.json",
                        line_number=1,
                    ))

        return findings

    def analyze_js_file(self, file_path: Path) -> list[StaticAnalysisFindingItem]:
        findings: list[StaticAnalysisFindingItem] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings

        rel_path = file_path.name

        # 1. Process execution: child_process, execSync, spawnSync
        if re.search(r"(\bchild_process\b|execSync|spawnSync|require\(['\"]child_process['\"]\)|\bspawn\s*\()", content):
            findings.append(StaticAnalysisFindingItem(
                finding_type="SHELL_PROCESS_EXECUTION",
                severity="HIGH",
                confidence=0.80,
                title="Process execution call in JavaScript",
                description="Use of child_process or exec/spawn in JavaScript source",
                evidence_snippet="child_process invocation",
                file_path=rel_path,
                line_number=1,
            ))

        # 2. Dynamic execution: eval, Function, vm
        if re.search(r"(\beval\s*\(|new\s+Function\s*\(|vm\.runIn)", content):
            findings.append(StaticAnalysisFindingItem(
                finding_type="DYNAMIC_CODE_EXECUTION",
                severity="HIGH",
                confidence=0.85,
                title="Dynamic JavaScript code execution",
                description="Use of eval or new Function constructor",
                evidence_snippet="eval / new Function",
                file_path=rel_path,
                line_number=1,
            ))

        # 3. Environment and Credential Access with heuristic matching
        sensitive_patterns = r"(\.ssh/id_rsa|private[_-]?key|process\.env\.[A-Za-z0-9_]*(secret|password|passwd|api[_-]?key|credential|token|auth)|(AWS_SECRET|AWS_ACCESS_KEY|GITHUB_TOKEN|SECRET_KEY|API_KEY|AUTH_TOKEN|PRIVATE_KEY|MY_COMPANY_TOKEN|INTERNAL_API_KEY|SERVICE_PASSWORD|CUSTOM_SECRET|AUTH_CREDENTIAL))"
        if re.search(sensitive_patterns, content, re.IGNORECASE):
            findings.append(StaticAnalysisFindingItem(
                finding_type="CREDENTIAL_SECRET_ACCESS",
                severity="HIGH",
                confidence=0.80,
                title="Sensitive credential or token reference in JavaScript",
                description="Source code references sensitive credentials or authentication secret keys",
                evidence_snippet="sensitive credential key reference",
                file_path=rel_path,
                line_number=1,
            ))
        elif re.search(r"\bprocess\.env\b", content):
            findings.append(StaticAnalysisFindingItem(
                finding_type="ENVIRONMENT_VARIABLE_ACCESS",
                severity="LOW",
                confidence=0.25,
                title="Environment variable access in JavaScript",
                description="Access to standard process.env configuration",
                evidence_snippet="process.env access",
                file_path=rel_path,
                line_number=1,
            ))

        return findings
