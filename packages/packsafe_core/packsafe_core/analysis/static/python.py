"""Python static AST and source code analyzer with contextual threat correlation."""

from __future__ import annotations

import ast
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from ...models.static_analysis import StaticAnalysisFindingItem


@dataclass(frozen=True)
class NetworkContext:
    """Per-file import facts needed to tell a network call from a same-named local one.

    Narrowing the network match to qualified receivers would otherwise have silently
    stopped recognizing two common shapes: a function imported straight out of a network
    module (``from requests import get``) and a module alias (``import requests as r``).
    Both are common in real malware, so both must stay detectable.

    Attributes:
        receivers: Names bound to a client instance, e.g. ``client = httpx.Client()``.
        bare_names: Functions imported from a network module, e.g. ``get`` above.
        aliases: Local module alias mapped back to its real root, e.g. ``{'r': 'requests'}``.
    """

    receivers: frozenset[str] = frozenset()
    bare_names: frozenset[str] = frozenset()
    aliases: Mapping[str, str] = MappingProxyType({})


EMPTY_NETWORK_CONTEXT = NetworkContext()


class PythonStaticAnalyzer:
    """Safely analyzes Python source files via AST parsing without code execution."""

    SENSITIVE_ENV_KEYS = {
        "aws_secret_access_key",
        "aws_access_key_id",
        "ssh_key",
        "github_token",
        "api_key",
        "secret_key",
        "password",
        "passwd",
        "token",
        "auth_token",
        "private_key",
        "credential",
        "auth_credential",
        "secret",
        "internal_api_key",
    }

    # Function and method names that indicate process execution.
    PROCESS_EXEC_NAMES = frozenset(
        {
            "Popen",
            "run",
            "call",
            "check_call",
            "check_output",
            "system",
            "spawn",
            "fork",
        }
    )

    # Modules whose methods may legitimately be named like process execution.
    PROCESS_EXEC_MODULES = frozenset({"os", "subprocess", "posix"})

    # Bare, module-level functions whose name is unambiguously a network operation.
    # Anything ambiguous (get, post, send, connect) is excluded on purpose: those names
    # are shared with dict/queue/env access, and matching them by name alone reported
    # os.environ.get() as "outbound network", which hard-blocked every official API SDK.
    NETWORK_BARE_CALLS = frozenset({"urlopen", "urlretrieve", "urlcleanup"})

    # Receiver roots whose method calls are network operations. Matched against the root
    # name of the receiver expression, so requests.get(), requests.api.get(),
    # requests.Session().get() and httpx.Client().post() are all recognized.
    NETWORK_RECEIVER_ROOTS = frozenset(
        {
            "requests",
            "httpx",
            "aiohttp",
            "urllib",
            "urllib2",
            "urllib3",
            "socket",
            "socketserver",
            "http",
            "httplib",
            "http.client",
            "ftplib",
            "smtplib",
            "poplib",
            "imaplib",
            "telnetlib",
            "pycurl",
            "websockets",
            "websocket",
            "grpc",
            "paramiko",
        }
    )

    # Constructors whose result is a network client, so a name bound to one of these can
    # be treated as a network receiver: ``client = httpx.Client(); client.post(...)``.
    NETWORK_CLIENT_CONSTRUCTORS = frozenset(
        {
            "Client",
            "AsyncClient",
            "Session",
            "ClientSession",
            "socket",
            "HTTPConnection",
            "HTTPSConnection",
            "HTTPConnectionPool",
            "PoolManager",
            "URLopener",
            "FancyURLopener",
        }
    )

    # Method names that are network operations when invoked on a network receiver.
    NETWORK_METHODS = frozenset(
        {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "head",
            "options",
            "request",
            "send",
            "sendall",
            "sendto",
            "recv",
            "connect",
            "urlopen",
            "open",
        }
    )

    DYNAMIC_EXEC_NAMES = frozenset({"eval", "exec", "compile", "__import__"})

    def analyze_file(self, file_path: Path) -> list[StaticAnalysisFindingItem]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        return self.analyze_code(content, filename=file_path.name)

    def analyze_code(
        self, content: str, filename: str = "module.py"
    ) -> list[StaticAnalysisFindingItem]:
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
        # Real source locations for the file-level findings raised below. A finding pinned
        # to line 1 is unactionable for anyone reviewing the package.
        credential_line = 0
        network_line = 0
        exec_line = 0
        net_ctx = self._collect_network_context(tree)

        for node in ast.walk(tree):
            line_no = getattr(node, "lineno", 0)

            # 1. Subprocess / Shell execution
            if isinstance(node, ast.Call):
                func_name = self._resolve_callable_name(node)

                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "platform"
                ):
                    pass
                elif func_name in self.PROCESS_EXEC_NAMES:
                    # Avoid matching non-os object methods for run/call/system unless os/subprocess or bare name
                    is_subproc = False
                    if isinstance(node.func, ast.Name):
                        is_subproc = True
                    elif isinstance(node.func, ast.Attribute) and isinstance(
                        node.func.value, ast.Name
                    ):
                        if node.func.value.id in self.PROCESS_EXEC_MODULES:
                            is_subproc = True

                    if is_subproc:
                        has_process_exec = True
                        exec_snippet = f"{func_name}() at line {line_no}"
                        exec_line = line_no
                    if is_setup:
                        findings.append(
                            StaticAnalysisFindingItem(
                                finding_type="SUSPICIOUS_INSTALL_BEHAVIOR",
                                severity="CRITICAL",
                                confidence=0.90,
                                title="Process execution during installation",
                                description=f"Invocation of process execution '{func_name}' inside package setup script",
                                evidence_snippet=exec_snippet,
                                file_path=rel_path,
                                line_number=line_no,
                            )
                        )
                    else:
                        findings.append(
                            StaticAnalysisFindingItem(
                                finding_type="SHELL_PROCESS_EXECUTION",
                                severity="MEDIUM",
                                confidence=0.60,
                                title="Subprocess execution detected",
                                description=f"Invocation of process execution '{func_name}'",
                                evidence_snippet=exec_snippet,
                                file_path=rel_path,
                                line_number=line_no,
                            )
                        )

                # 2. Dynamic execution: eval / exec / compile / __import__
                elif (
                    isinstance(node.func, ast.Name)
                    and func_name in self.DYNAMIC_EXEC_NAMES
                ):
                    if func_name in ("eval", "exec"):
                        findings.append(
                            StaticAnalysisFindingItem(
                                finding_type="DYNAMIC_CODE_EXECUTION",
                                severity="HIGH" if is_setup else "MEDIUM",
                                confidence=0.85 if is_setup else 0.70,
                                title="Dynamic code execution detected",
                                description=f"Use of dynamic evaluation function '{func_name}'",
                                evidence_snippet=f"{func_name}() at line {line_no}",
                                file_path=rel_path,
                                line_number=line_no,
                            )
                        )
                    elif func_name == "compile":
                        # Builtin compile() without eval/exec is often used for templates/code generation
                        findings.append(
                            StaticAnalysisFindingItem(
                                finding_type="DYNAMIC_CODE_EXECUTION",
                                severity="LOW",
                                confidence=0.30,  # Below 0.50 threshold to avoid false-positive gate trigger
                                title="Code compilation detected",
                                description="Use of Python compile() builtin",
                                evidence_snippet=f"compile() at line {line_no}",
                                file_path=rel_path,
                                line_number=line_no,
                            )
                        )
                    elif func_name == "__import__":
                        # Builtin __import__() is commonly used for lazy loading or backward compatibility
                        findings.append(
                            StaticAnalysisFindingItem(
                                finding_type="DYNAMIC_CODE_EXECUTION",
                                severity="LOW",
                                confidence=0.30,  # Below 0.50 threshold to avoid false-positive gate trigger
                                title="Dynamic module import detected",
                                description="Use of __import__() for dynamic module loading",
                                evidence_snippet=f"__import__() at line {line_no}",
                                file_path=rel_path,
                                line_number=line_no,
                            )
                        )

                # 3. Network requests / remote downloads
                elif network_label := self._classify_network_call(node, net_ctx):
                    has_outbound_network = True
                    if network_line == 0:
                        network_line = line_no
                    is_urlretrieve = network_label.endswith("urlretrieve")
                    if is_urlretrieve:
                        has_remote_download = True

                    if is_setup:
                        findings.append(
                            StaticAnalysisFindingItem(
                                finding_type="REMOTE_CODE_DOWNLOAD"
                                if is_urlretrieve
                                else "SUSPICIOUS_INSTALL_BEHAVIOR",
                                severity="CRITICAL" if is_urlretrieve else "HIGH",
                                confidence=0.90 if is_urlretrieve else 0.75,
                                title="Network call inside setup script",
                                description=f"Network request '{network_label}' during installation",
                                evidence_snippet=f"{network_label}() at line {line_no}",
                                file_path=rel_path,
                                line_number=line_no,
                            )
                        )

            # 4. Environment variable access
            if isinstance(node, ast.Subscript):
                if (
                    isinstance(node.value, ast.Attribute)
                    and node.value.attr == "environ"
                ):
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
                            credential_line = line_no

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
                        credential_snippet = (
                            f"{env_key} at line {getattr(node, 'lineno', 0)}"
                        )
                        credential_line = getattr(node, "lineno", 0)

        # 5. Check direct file references to secrets (.ssh, .aws)
        if re.search(r"(\.ssh/id_rsa|\.aws/credentials|\.bash_history)", content):
            has_sensitive_credential_access = True
            credential_snippet = "Direct credential path reference (.ssh / .aws)"
            credential_line = self._first_match_line(
                content, r"\.ssh/id_rsa|\.aws/credentials|\.bash_history"
            )

        # 6. Contextual Threat Correlation:
        # Credential Access + Outbound Network -> Credential Exfiltration Gate trigger
        # Correlated exfiltration vs disjoint co-occurrence
        has_correlated_exfiltration = self._has_correlated_exfiltration(tree, net_ctx)

        if is_setup and has_sensitive_credential_access and has_outbound_network:
            has_correlated_exfiltration = True

        if has_sensitive_credential_access:
            if has_correlated_exfiltration:
                # Anchor on the credential read: that is the line a reviewer needs, and
                # the transmission is described in the snippet.
                findings.append(
                    StaticAnalysisFindingItem(
                        finding_type="CREDENTIAL_SECRET_ACCESS",
                        severity="CRITICAL",
                        confidence=0.92,
                        title="Credential harvesting and outbound transmission",
                        description="Source code accesses sensitive credentials/tokens combined with outbound network communication in the same execution scope.",
                        evidence_snippet=(
                            f"{credential_snippet} + outbound network"
                            + (f" (line {network_line})" if network_line else "")
                        ),
                        file_path=rel_path,
                        line_number=credential_line or 1,
                    )
                )
            else:
                findings.append(
                    StaticAnalysisFindingItem(
                        finding_type="CREDENTIAL_SECRET_ACCESS",
                        severity="HIGH",
                        confidence=0.70,  # Below 0.85 gate threshold for unconfirmed cross-function co-occurrence
                        title="Sensitive credential path access",
                        description="Source code accesses sensitive credentials or tokens without confirmed exfiltration in the same execution path.",
                        evidence_snippet=credential_snippet,
                        file_path=rel_path,
                        line_number=credential_line or 1,
                    )
                )

        # Remote payload download + execution -> Remote Payload Execution Gate trigger
        if has_remote_download and has_process_exec:
            findings.append(
                StaticAnalysisFindingItem(
                    finding_type="REMOTE_PAYLOAD_EXECUTION",
                    severity="CRITICAL",
                    confidence=0.92,
                    title="Remote payload download and execution",
                    description="Source code downloads remote binary/payload and executes it.",
                    evidence_snippet=f"{exec_snippet} following remote download",
                    file_path=rel_path,
                    line_number=exec_line or network_line or 1,
                )
            )

        # 7. Regex checks for Base64 unpacking combined with dynamic execution
        if re.search(
            r"(exec|eval)\s*\(\s*base64\.(b64decode|decodebytes)", content
        ) or (
            re.search(r"base64\.(b64decode|decodebytes)", content)
            and (has_process_exec or (has_outbound_network and is_setup))
        ):
            findings.append(
                StaticAnalysisFindingItem(
                    finding_type="OBFUSCATION_PATTERNS",
                    severity="HIGH" if has_process_exec else "MEDIUM",
                    confidence=0.85 if has_process_exec else 0.65,
                    title="Obfuscated payload decoding detected",
                    description="Use of base64 decoding to unpack dynamic executable payload",
                    evidence_snippet="base64 decode into execution context",
                    file_path=rel_path,
                    line_number=self._first_match_line(
                        content,
                        r"(exec|eval)\s*\(\s*base64\.(b64decode|decodebytes)"
                        r"|base64\.(b64decode|decodebytes)",
                    )
                    or 1,
                )
            )

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

    @staticmethod
    def _first_match_line(content: str, pattern: str) -> int:
        """1-based line number of the first regex match, or 0 when there is none."""
        match = re.search(pattern, content)
        if match is None:
            return 0
        return content.count("\n", 0, match.start()) + 1

    # ------------------------------------------------------------- network calls

    @staticmethod
    def _root_name(node: ast.AST) -> str:
        """Root identifier of a dotted expression: ``a.b.c(...)`` -> ``'a'``.

        Walks down ``.value`` chains and takes the first plain Name. A call in the middle
        (``httpx.Client().get``) resolves to the module that produced it, which is what
        the receiver allowlist is keyed on.
        """
        current = node
        while True:
            if isinstance(current, ast.Name):
                return current.id
            if isinstance(current, ast.Attribute):
                current = current.value
                continue
            if isinstance(current, ast.Call):
                current = current.func
                continue
            if isinstance(current, ast.Subscript):
                current = current.value
                continue
            return ""

    @classmethod
    def _collect_network_context(cls, tree: ast.AST) -> NetworkContext:
        """Gathers the import and binding facts needed to classify network calls.

        Covers ``import requests``, ``import requests as r``, ``from requests import
        get``, ``client = httpx.Client()`` and ``with aiohttp.ClientSession() as s``.
        """
        receivers: set[str] = set()
        bare_names: set[str] = set()
        aliases: dict[str, str] = {}

        def canonical(name: str) -> str:
            return aliases.get(name, name)

        def bind(target: ast.AST) -> None:
            if isinstance(target, ast.Name):
                receivers.add(target.id)

        def is_client_constructor(value: ast.AST) -> bool:
            if not isinstance(value, ast.Call):
                return False
            func = value.func
            if isinstance(func, ast.Attribute):
                return (
                    func.attr in cls.NETWORK_CLIENT_CONSTRUCTORS
                    and canonical(cls._root_name(func)) in cls.NETWORK_RECEIVER_ROOTS
                )
            if isinstance(func, ast.Name):
                # ``client = requests()``
                return canonical(func.id) in cls.NETWORK_RECEIVER_ROOTS
            return False

        # Imports first: the alias table has to be complete before constructors are
        # classified, since ``import httpx as h; client = h.Client()`` depends on it.
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    aliases[alias.asname or root] = root
            elif isinstance(node, ast.ImportFrom):
                if node.level or not node.module:
                    continue
                if node.module.split(".")[0] not in cls.NETWORK_RECEIVER_ROOTS:
                    continue
                for alias in node.names:
                    if alias.name != "*":
                        bare_names.add(alias.asname or alias.name)

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if is_client_constructor(node.value):
                    for target in node.targets:
                        bind(target)
            elif isinstance(node, ast.AnnAssign):
                if is_client_constructor(node.value):
                    bind(node.target)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None and is_client_constructor(
                        item.context_expr
                    ):
                        bind(item.optional_vars)

        return NetworkContext(
            receivers=frozenset(receivers),
            bare_names=frozenset(bare_names),
            aliases=MappingProxyType(dict(aliases)),
        )

    @classmethod
    def _is_environ_receiver(cls, node: ast.AST) -> bool:
        """True for an ``os.environ``-style receiver, i.e. an environment store access."""
        return isinstance(node, ast.Attribute) and node.attr == "environ"

    @classmethod
    def _classify_network_call(
        cls,
        node: ast.Call,
        ctx: NetworkContext = EMPTY_NETWORK_CONTEXT,
    ) -> str | None:
        """Returns a label when the call is a network operation, else None.

        An environment read is classified as an environment read and never as network: it
        is the credential *source*, not the transmission. Letting it fall through to the
        network branch is what made a plain config read look like exfiltration.
        """
        func = node.func

        # Bare call: either an unambiguously network function, or one imported from a
        # network module whose name is itself a network operation
        # (``from requests import get``). The name still has to look like a network
        # operation, otherwise ``from urllib.parse import urlsplit`` would classify pure
        # string parsing as a transmission.
        if isinstance(func, ast.Name):
            name = func.id
            if name in cls.NETWORK_BARE_CALLS:
                return name
            if name in ctx.bare_names and name in cls.NETWORK_METHODS:
                return name
            return None

        if not isinstance(func, ast.Attribute):
            return None

        method = func.attr
        if method not in cls.NETWORK_METHODS:
            return None

        receiver = func.value
        if cls._is_environ_receiver(receiver):
            return None

        root = cls._root_name(receiver)
        if not root:
            return None

        canonical = ctx.aliases.get(root, root)
        if (
            canonical in cls.NETWORK_RECEIVER_ROOTS
            or root in ctx.receivers
            or canonical in ctx.receivers
        ):
            return f"{root}.{method}"

        return None

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
        cls,
        scope: ast.AST,
        descend_into_functions: bool,
        net_ctx: NetworkContext = EMPTY_NETWORK_CONTEXT,
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

            if (
                isinstance(n, ast.Subscript)
                and isinstance(n.value, ast.Attribute)
                and n.value.attr == "environ"
            ):
                key = cls._extract_subscript_key(n)
                if key and cls._is_sensitive_key(key):
                    scope_has_cred = True
            elif isinstance(n, ast.Call):
                env_key = cls._extract_env_call_key(n)
                if env_key is not None:
                    # An environment read is terminal: it is the credential source, and
                    # must never also be counted as the outbound transmission. It used to
                    # fall through to the network branch, where its ``.get`` matched the
                    # bare name 'get', so a config read satisfied both halves of the
                    # exfiltration correlation.
                    if cls._is_sensitive_key(env_key):
                        scope_has_cred = True
                elif cls._classify_network_call(n, net_ctx):
                    scope_has_net = True

        return scope_has_cred, scope_has_net

    @classmethod
    def _has_correlated_exfiltration(
        cls,
        tree: ast.AST,
        net_ctx: NetworkContext | None = None,
    ) -> bool:
        """True when credential access and a network call share one execution scope.

        Each function is evaluated on its own, and the module body is evaluated
        separately from function bodies, so unrelated helpers in the same file do not
        correlate with each other.
        """
        if net_ctx is None:
            net_ctx = cls._collect_network_context(tree)

        functions = [
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
        ]

        for func in functions:
            cred, net = cls._scope_credential_and_network(
                func, descend_into_functions=False, net_ctx=net_ctx
            )
            if cred and net:
                return True

        cred, net = cls._scope_credential_and_network(
            tree,
            descend_into_functions=False,
            net_ctx=net_ctx,
        )
        return cred and net
