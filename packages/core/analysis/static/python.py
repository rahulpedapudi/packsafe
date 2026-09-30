"""Python static AST and source code analyzer with contextual threat correlation."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from packsafe.evidence.models import StaticAnalysisFindingItem


class PythonStaticAnalyzer:
    """Safely analyzes Python source files via AST parsing without code execution."""

    SENSITIVE_ENV_KEYS = {
        "aws_secret_access_key", "aws_access_key_id", "ssh_key", "github_token",
        "api_key", "secret_key", "password", "passwd", "token", "auth_token", "private_key",
        "credential", "auth_credential", "secret", "internal_api_key",
    }

    def analyze_file(self, file_path: Path) -> list[StaticAnalysisFindingItem]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []
        return self.analyze_code(content, filename=file_path.name)

    def analyze_code(self, content: str, filename: str = "module.py") -> list[StaticAnalysisFindingItem]:
        findings: list[StaticAnalysisFindingItem] = []
        rel_path = filename
        is_setup = rel_path in ("setup.py", "setup.cfg", "__init__.py")

        try:
            tree = ast.parse(content, filename=filename)
        except SyntaxError:
            return findings

        has_outbound_network = False
        has_sensitive_credential_access = False
        has_remote_download = False
        has_process_exec = False
        credential_snippet = ""
        exec_snippet = ""

        for node in ast.walk(tree):
            line_no = getattr(node, "lineno", 0)

            # 1. Subprocess / Shell execution
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                # Check if it is a benign attribute call like platform.system()
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "platform":
                    pass
                elif func_name in ("Popen", "run", "call", "check_call", "check_output", "system", "spawn", "fork"):
                    # Avoid matching non-os object methods for run/call/system unless os/subprocess or bare name
                    is_subproc = False
                    if isinstance(node.func, ast.Name):
                        is_subproc = True
                    elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        if node.func.value.id in ("os", "subprocess", "posix"):
                            is_subproc = True

                    if is_subproc:
                        has_process_exec = True
                        exec_snippet = f"{func_name}() at line {line_no}"
                    if is_setup:
                        findings.append(StaticAnalysisFindingItem(
                            finding_type="SUSPICIOUS_INSTALL_BEHAVIOR",
                            severity="CRITICAL",
                            confidence=0.90,
                            title="Process execution during installation",
                            description=f"Invocation of process execution '{func_name}' inside package setup script",
                            evidence_snippet=exec_snippet,
                            file_path=rel_path,
                            line_number=line_no,
                        ))
                    else:
                        findings.append(StaticAnalysisFindingItem(
                            finding_type="SHELL_PROCESS_EXECUTION",
                            severity="MEDIUM",
                            confidence=0.60,
                            title="Subprocess execution detected",
                            description=f"Invocation of process execution '{func_name}'",
                            evidence_snippet=exec_snippet,
                            file_path=rel_path,
                            line_number=line_no,
                        ))

                # 2. Dynamic execution: eval / exec / compile / __import__
                elif isinstance(node.func, ast.Name) and func_name in ("eval", "exec", "compile", "__import__"):
                    if func_name in ("eval", "exec"):
                        findings.append(StaticAnalysisFindingItem(
                            finding_type="DYNAMIC_CODE_EXECUTION",
                            severity="HIGH" if is_setup else "MEDIUM",
                            confidence=0.85 if is_setup else 0.70,
                            title="Dynamic code execution detected",
                            description=f"Use of dynamic evaluation function '{func_name}'",
                            evidence_snippet=f"{func_name}() at line {line_no}",
                            file_path=rel_path,
                            line_number=line_no,
                        ))
                    elif func_name == "compile":
                        # Builtin compile() without eval/exec is often used for templates/code generation
                        findings.append(StaticAnalysisFindingItem(
                            finding_type="DYNAMIC_CODE_EXECUTION",
                            severity="LOW",
                            confidence=0.30,  # Below 0.50 threshold to avoid false-positive gate trigger
                            title="Code compilation detected",
                            description="Use of Python compile() builtin",
                            evidence_snippet=f"compile() at line {line_no}",
                            file_path=rel_path,
                            line_number=line_no,
                        ))
                    elif func_name == "__import__":
                        # Builtin __import__() is commonly used for lazy loading or backward compatibility
                        findings.append(StaticAnalysisFindingItem(
                            finding_type="DYNAMIC_CODE_EXECUTION",
                            severity="LOW",
                            confidence=0.30,  # Below 0.50 threshold to avoid false-positive gate trigger
                            title="Dynamic module import detected",
                            description="Use of __import__() for dynamic module loading",
                            evidence_snippet=f"__import__() at line {line_no}",
                            file_path=rel_path,
                            line_number=line_no,
                        ))

                # 3. Network requests / remote downloads
                elif func_name in ("urlopen", "urlretrieve", "get", "post", "connect", "Socket", "send"):
                    has_outbound_network = True
                    if func_name == "urlretrieve":
                        has_remote_download = True

                    if is_setup:
                        findings.append(StaticAnalysisFindingItem(
                            finding_type="REMOTE_CODE_DOWNLOAD" if func_name == "urlretrieve" else "SUSPICIOUS_INSTALL_BEHAVIOR",
                            severity="CRITICAL" if func_name == "urlretrieve" else "HIGH",
                            confidence=0.90 if func_name == "urlretrieve" else 0.75,
                            title="Network call inside setup script",
                            description=f"Network request '{func_name}' during installation",
                            evidence_snippet=f"{func_name}() at line {line_no}",
                            file_path=rel_path,
                            line_number=line_no,
                        ))

            # 4. Environment variable access
            if isinstance(node, ast.Subscript):
                if isinstance(node.value, ast.Attribute) and node.value.attr == "environ":
                    # Check what key is being accessed
                    key_str = ""
                    if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                        key_str = node.slice.value.lower()
                    
                    is_sensitive = any(sk in key_str for sk in self.SENSITIVE_ENV_KEYS)
                    if is_sensitive:
                        has_sensitive_credential_access = True
                        credential_snippet = f"os.environ['{key_str}'] at line {line_no}"
                    else:
                        findings.append(StaticAnalysisFindingItem(
                            finding_type="ENVIRONMENT_VARIABLE_ACCESS",
                            severity="LOW",
                            confidence=0.30,
                            title="Environment variable access",
                            description=f"Reading os.environ['{key_str}']",
                            evidence_snippet=f"os.environ['{key_str}'] at line {line_no}",
                            file_path=rel_path,
                            line_number=line_no,
                        ))

        # 5. Check direct file references to secrets (.ssh, .aws)
        if re.search(r"(\.ssh/id_rsa|\.aws/credentials|\.bash_history)", content):
            has_sensitive_credential_access = True
            credential_snippet = "Direct credential path reference (.ssh / .aws)"

        # 6. Contextual Threat Correlation:
        # Credential Access + Outbound Network -> Credential Exfiltration Gate trigger
        # Correlated exfiltration vs disjoint co-occurrence
        has_correlated_exfiltration = False
        
        # Check scope correlation: inspect functions and module scope
        scopes = [tree] + [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for scope in scopes:
            scope_has_cred = False
            scope_has_net = False
            for n in ast.walk(scope):
                if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Attribute) and n.value.attr == "environ":
                    if isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str):
                        k = n.slice.value.lower()
                        if any(sk in k for sk in self.SENSITIVE_ENV_KEYS):
                            scope_has_cred = True
                elif isinstance(n, ast.Call):
                    fn = n.func.id if isinstance(n.func, ast.Name) else (n.func.attr if isinstance(n.func, ast.Attribute) else "")
                    if fn in ("urlopen", "urlretrieve", "get", "post", "connect", "Socket", "send"):
                        scope_has_net = True
            if scope_has_cred and scope_has_net:
                has_correlated_exfiltration = True
                break

        if is_setup and has_sensitive_credential_access and has_outbound_network:
            has_correlated_exfiltration = True

        if has_sensitive_credential_access:
            if has_correlated_exfiltration:
                findings.append(StaticAnalysisFindingItem(
                    finding_type="CREDENTIAL_SECRET_ACCESS",
                    severity="CRITICAL",
                    confidence=0.92,
                    title="Credential harvesting and outbound transmission",
                    description="Source code accesses sensitive credentials/tokens combined with outbound network communication in the same execution scope.",
                    evidence_snippet=f"{credential_snippet} + network transmission",
                    file_path=rel_path,
                    line_number=1,
                ))
            else:
                findings.append(StaticAnalysisFindingItem(
                    finding_type="CREDENTIAL_SECRET_ACCESS",
                    severity="HIGH",
                    confidence=0.70,  # Below 0.85 gate threshold for unconfirmed cross-function co-occurrence
                    title="Sensitive credential path access",
                    description="Source code accesses sensitive credentials or tokens without confirmed exfiltration in the same execution path.",
                    evidence_snippet=credential_snippet,
                    file_path=rel_path,
                    line_number=1,
                ))

        # Remote payload download + execution -> Remote Payload Execution Gate trigger
        if has_remote_download and has_process_exec:
            findings.append(StaticAnalysisFindingItem(
                finding_type="REMOTE_PAYLOAD_EXECUTION",
                severity="CRITICAL",
                confidence=0.92,
                title="Remote payload download and execution",
                description="Source code downloads remote binary/payload and executes it.",
                evidence_snippet=f"{exec_snippet} following remote download",
                file_path=rel_path,
                line_number=1,
            ))

        # 7. Regex checks for Base64 unpacking combined with dynamic execution
        if re.search(r"(exec|eval)\s*\(\s*base64\.(b64decode|decodebytes)", content) or (
            re.search(r"base64\.(b64decode|decodebytes)", content) and (has_process_exec or (has_outbound_network and is_setup))
        ):
            findings.append(StaticAnalysisFindingItem(
                finding_type="OBFUSCATION_PATTERNS",
                severity="HIGH" if has_process_exec else "MEDIUM",
                confidence=0.85 if has_process_exec else 0.65,
                title="Obfuscated payload decoding detected",
                description="Use of base64 decoding to unpack dynamic executable payload",
                evidence_snippet="base64 decode into execution context",
                file_path=rel_path,
                line_number=1,
            ))

        return findings
