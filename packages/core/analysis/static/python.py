"""Python static AST and source code analyzer with contextual threat correlation."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from ...models.static_analysis import StaticAnalysisFindingItem


class PythonStaticAnalyzer:
    """Safely analyzes Python source files via AST parsing without code execution."""

    SENSITIVE_ENV_KEYS = {
        "aws_secret_access_key", "aws_access_key_id", "ssh_key", "github_token",
        "api_key", "secret_key", "password", "passwd", "token", "auth_token", "private_key",
        "credential", "auth_credential", "secret", "internal_api_key",
    }

    # Function and method names that indicate process execution.
    PROCESS_EXEC_NAMES = frozenset({
        "Popen", "run", "call", "check_call", "check_output",
        "system", "spawn", "fork",
    })

    # Modules whose methods may legitimately be named like process execution.
    PROCESS_EXEC_MODULES = frozenset({"os", "subprocess", "posix"})

    # Network-capable call names.
    NETWORK_NAMES = frozenset({
        "urlopen", "urlretrieve", "get", "post", "connect", "Socket", "send",
    })

    DYNAMIC_EXEC_NAMES = frozenset({"eval", "exec", "compile", "__import__"})

    def analyze_file(self, file_path: Path) -> list[StaticAnalysisFindingItem]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        return self.analyze_code(content, filename=file_path.name)

    def analyze_code(self, content: str, filename: str = "module.py") -> list[StaticAnalysisFindingItem]:
        findings: list[StaticAnalysisFindingItem] = []
        rel_path = filename
        # 'setup.py' only. '__init__.py' is a re-export shim in the overwhelming
        # majority of packages, so treating it as an install script produced a large
        # volume of CRITICAL findings that tripped GATE-INSTALL-MALWARE (BLOCK).
        is_setup = rel_path == "setup.py"

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
                func_name = self._resolve_callable_name(node)

                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "platform":
                    pass
                elif func_name in self.PROCESS_EXEC_NAMES:
                    # Avoid matching non-os object methods for run/call/system unless os/subprocess or bare name
                    is_subproc = False
                    if isinstance(node.func, ast.Name):
                        is_subproc = True
                    elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        if node.func.value.id in self.PROCESS_EXEC_MODULES:
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
                elif isinstance(node.func, ast.Name) and func_name in self.DYNAMIC_EXEC_NAMES:
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
                            description=f"Use of __import__() for dynamic module loading",
                            evidence_snippet=f"__import__() at line {line_no}",
                            file_path=rel_path,
                            line_number=line_no,
                        ))

                # 3. Network requests / remote downloads
                elif func_name in self.NETWORK_NAMES:
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
                    key_str = self._extract_subscript_key(node)
                    if key_str:
                        self._record_env_access(
                            key_str,
                            line_no,
                            rel_path,
                            findings,
                        )
                        if self._is_sensitive_key(key_str):
                            has_sensitive_credential_access = True
                            credential_snippet = (
                                f"os.environ['{key_str}'] at line {line_no}"
                            )

            # 4b. os.environ.get(...) / os.getenv(...) read the same store but are
            # Call nodes, not Subscript nodes, so a Subscript-only match missed the
            # most common way to read a secret in modern code.
            if isinstance(node, ast.Call):
                env_key = self._extract_env_call_key(node)
                if env_key is not None:
                    self._record_env_access(
                        env_key,
                        getattr(node, "lineno", 0),
                        rel_path,
                        findings,
                    )
                    if self._is_sensitive_key(env_key):
                        has_sensitive_credential_access = True
                        credential_snippet = f"{env_key} at line {getattr(node, 'lineno', 0)}"

        # 5. Check direct file references to secrets (.ssh, .aws)
        if re.search(r"(\.ssh/id_rsa|\.aws/credentials|\.bash_history)", content):
            has_sensitive_credential_access = True
            credential_snippet = "Direct credential path reference (.ssh / .aws)"

        # 6. Contextual Threat Correlation:
        # Credential Access + Outbound Network -> Credential Exfiltration Gate trigger
        # Correlated exfiltration vs disjoint co-occurrence
        has_correlated_exfiltration = self._has_correlated_exfiltration(tree)

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

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _resolve_callable_name(node: ast.Call) -> str:
        """Best-effort name of the callee: attribute name or bare identifier."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    @staticmethod
    def _extract_subscript_key(node: ast.Subscript) -> str:
        """Return the string key of a constant subscript, else empty string."""
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            return node.slice.value.lower()
        return ""

    @classmethod
    def _extract_env_call_key(cls, node: ast.Call) -> str | None:
        """Return the environment key read by os.getenv(k) / os.environ.get(k).

        Returns None when the call is not an environment read or the key is dynamic.
        """
        if not isinstance(node.func, ast.Attribute):
            return None

        is_getenv = (
            node.func.attr == "getenv"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
        )
        is_environ_get = (
            node.func.attr == "get"
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "environ"
        )
        if not (is_getenv or is_environ_get):
            return None

        if not node.args:
            return None
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value.lower()
        return None

    @classmethod
    def _is_sensitive_key(cls, key: str) -> bool:
        return any(sk in key for sk in cls.SENSITIVE_ENV_KEYS)

    @classmethod
    def _record_env_access(
        cls,
        key: str,
        line_no: int,
        rel_path: str,
        findings: list[StaticAnalysisFindingItem],
    ) -> None:
        """Emit the benign LOW finding for a non-sensitive environment read."""
        if cls._is_sensitive_key(key):
            return
        findings.append(
            StaticAnalysisFindingItem(
                finding_type="ENVIRONMENT_VARIABLE_ACCESS",
                severity="LOW",
                confidence=0.30,
                title="Environment variable access",
                description=f"Reading environment variable '{key}'",
                evidence_snippet=f"os.environ['{key}'] at line {line_no}",
                file_path=rel_path,
                line_number=line_no,
            )
        )

    @staticmethod
    def _nested_function_node_ids(scope: ast.AST) -> set[int]:
        """Ids of every node belonging to a function nested *inside* scope.

        The scope node itself is never excluded, so passing a function in still walks
        its own body. ``ast.walk`` cannot be pruned, so the subtrees to exclude are
        collected first and then skipped by identity.
        """
        skip: set[int] = set()
        for n in ast.walk(scope):
            if n is scope:
                continue
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                skip.update(id(child) for child in ast.walk(n))
        return skip

    @classmethod
    def _scope_credential_and_network(
        cls, scope: ast.AST, descend_into_functions: bool
    ) -> tuple[bool, bool]:
        """Returns (credential_access, network_call) within one scope.

        When ``descend_into_functions`` is False, function bodies nested inside scope
        are excluded, so module scope reflects only import-time statements.
        """
        excluded = (
            frozenset()
            if descend_into_functions
            else cls._nested_function_node_ids(scope)
        )

        scope_has_cred = False
        scope_has_net = False

        for n in ast.walk(scope):
            if id(n) in excluded:
                continue

            if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Attribute) and n.value.attr == "environ":
                key = cls._extract_subscript_key(n)
                if key and cls._is_sensitive_key(key):
                    scope_has_cred = True
            elif isinstance(n, ast.Call):
                if cls._extract_env_call_key(n) and cls._is_sensitive_key(
                    cls._extract_env_call_key(n) or ""
                ):
                    scope_has_cred = True
                elif cls._resolve_callable_name(n) in cls.NETWORK_NAMES:
                    scope_has_net = True

        return scope_has_cred, scope_has_net

    @classmethod
    def _has_correlated_exfiltration(cls, tree: ast.AST) -> bool:
        """True when credential access and a network call share one execution scope.

        Each function is evaluated on its own, and the module body is evaluated
        separately from function bodies, so unrelated helpers in the same file do not
        correlate with each other.
        """
        functions = [
            n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
        ]

        for func in functions:
            cred, net = cls._scope_credential_and_network(
                func, descend_into_functions=False
            )
            if cred and net:
                return True

        cred, net = cls._scope_credential_and_network(
            tree, descend_into_functions=False
        )
        return cred and net