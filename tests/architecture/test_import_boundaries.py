"""Executable, ratcheted import-boundary contract for :mod:`evoom_guard`.

This is deliberately an AST gate rather than an import-time smoke test.  It sees
imports hidden inside functions, imports guarded by ``TYPE_CHECKING``, relative
imports, wildcard imports, and the two dynamic-import forms used by Python's
standard library.  The committed baseline records existing architectural debt;
it is not an allow-list for adding more debt.

When a violation is removed, this test fails on purpose until the baseline is
reviewed and its ceiling is lowered.  That makes architectural improvement an
explicit, auditable ratchet instead of silently leaving stale exceptions behind.
"""

from __future__ import annotations

import ast
import importlib.util
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = ROOT / "evoom_guard"
BASELINE_PATH = Path(__file__).with_name("import_boundary_baseline.json")
BASELINE_FORMAT = "evoom-guard-import-boundary-baseline-1"
INTERNAL_PACKAGE = "evoom_guard"

VIOLATION_KINDS = (
    "cycle_edges",
    "cross_package_private_imports",
    "wildcard_imports",
    "unresolved_dynamic_imports",
    "layer_violations",
    "unclassified_modules",
)

# ADR-0001's arrow describes increasingly high-level layers.  Imports may point
# to the same or a lower layer, never from a lower layer to a higher layer.  A
# name is considered extracted only when it is a real package (has __init__.py),
# so same-named compatibility monoliths such as workspace.py are not mislabeled.
LAYER_GROUPS: tuple[tuple[str, ...], ...] = (
    ("domain",),
    ("policy", "candidate", "workspace"),
    ("execution", "isolation"),
    ("verifiers",),
    ("application",),
    ("evidence",),
    ("finalizer", "admission"),
    ("api", "cli", "integrations"),
)
LAYER_RANK = {
    package_name: rank
    for rank, package_names in enumerate(LAYER_GROUPS)
    for package_name in package_names
}


@dataclass(frozen=True, order=True)
class ImportFact:
    """One internal import observed in source, including execution context."""

    source: str
    target: str | None
    symbol: str
    kind: str
    scope: str
    type_checking: bool
    line: int
    wildcard: bool = False
    unresolved: bool = False


@dataclass(frozen=True)
class Analysis:
    """Deterministic result returned by the AST scanner."""

    modules: tuple[str, ...]
    internal_edges: tuple[tuple[str, str], ...]
    facts: tuple[ImportFact, ...]
    violations: Mapping[str, tuple[str, ...]]
    locations: Mapping[tuple[str, str], tuple[int, ...]]


def _module_for_path(package_root: Path, path: Path) -> str:
    relative = path.relative_to(package_root)
    parts = list(relative.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join((package_root.name, *parts)) if parts else package_root.name


def _discover_modules(package_root: Path) -> tuple[dict[str, Path], frozenset[str]]:
    modules: dict[str, Path] = {}
    package_modules: set[str] = set()
    for path in sorted(package_root.rglob("*.py")):
        module = _module_for_path(package_root, path)
        if module in modules:
            raise AssertionError(f"duplicate Python module discovered: {module}")
        modules[module] = path
        if path.name == "__init__.py":
            package_modules.add(module)
    return modules, frozenset(package_modules)


def _source_package(source: str, package_modules: frozenset[str]) -> str:
    if source in package_modules:
        return source
    return source.rpartition(".")[0]


def _resolve_relative(module: str | None, level: int, package: str) -> str:
    if level == 0:
        return module or ""
    relative_name = "." * level + (module or "")
    try:
        return importlib.util.resolve_name(relative_name, package)
    except (ImportError, ValueError):
        # Syntax may be valid while the requested level escapes the package.
        # Preserve a deterministic marker so the caller can reject it.
        return relative_name


def _known_target(name: str, modules: frozenset[str]) -> str | None:
    if not (name == INTERNAL_PACKAGE or name.startswith(f"{INTERNAL_PACKAGE}.")):
        return None
    candidate = name
    while candidate:
        if candidate in modules:
            return candidate
        candidate = candidate.rpartition(".")[0]
    # Retain an internal-but-missing target.  Normal Python tests will report the
    # missing module too; keeping it here prevents the architecture graph from
    # silently treating it as third-party.
    return name


def _contains_type_checking(
    node: ast.AST, type_checking_names: frozenset[str], typing_aliases: frozenset[str]
) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in type_checking_names:
            return True
        if (
            isinstance(child, ast.Attribute)
            and child.attr == "TYPE_CHECKING"
            and isinstance(child.value, ast.Name)
            and child.value.id in typing_aliases
        ):
            return True
    return False


def _type_checking_polarity(
    node: ast.AST, type_checking_names: frozenset[str], typing_aliases: frozenset[str]
) -> bool | None:
    if isinstance(node, ast.Name) and node.id in type_checking_names:
        return True
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "TYPE_CHECKING"
        and isinstance(node.value, ast.Name)
        and node.value.id in typing_aliases
    ):
        return True
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        polarity = _type_checking_polarity(node.operand, type_checking_names, typing_aliases)
        return None if polarity is None else not polarity
    return None


class _AliasCollector(ast.NodeVisitor):
    """Collect aliases needed to recognize TYPE_CHECKING and importlib calls."""

    def __init__(self) -> None:
        self.type_checking_names: set[str] = {"TYPE_CHECKING"}
        self.typing_aliases: set[str] = set()
        self.importlib_aliases: set[str] = set()
        self.import_module_names: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "typing":
                self.typing_aliases.add(alias.asname or "typing")
            elif alias.name == "importlib":
                self.importlib_aliases.add(alias.asname or "importlib")

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level == 0 and node.module == "typing":
            for alias in node.names:
                if alias.name == "TYPE_CHECKING":
                    self.type_checking_names.add(alias.asname or alias.name)
        if node.level == 0 and node.module == "importlib":
            for alias in node.names:
                if alias.name == "import_module":
                    self.import_module_names.add(alias.asname or alias.name)


class _ImportVisitor(ast.NodeVisitor):
    def __init__(
        self,
        *,
        source: str,
        modules: frozenset[str],
        package_modules: frozenset[str],
        aliases: _AliasCollector,
    ) -> None:
        self.source = source
        self.modules = modules
        self.source_package = _source_package(source, package_modules)
        self.type_checking_names = frozenset(aliases.type_checking_names)
        self.typing_aliases = frozenset(aliases.typing_aliases)
        self.importlib_aliases = frozenset(aliases.importlib_aliases)
        self.import_module_names = frozenset(aliases.import_module_names)
        self.scope_depth = 0
        self.type_checking_depth = 0
        self.facts: list[ImportFact] = []

    @property
    def scope(self) -> str:
        return "local" if self.scope_depth else "module"

    @property
    def in_type_checking(self) -> bool:
        return self.type_checking_depth > 0

    def _append(
        self,
        *,
        target: str | None,
        symbol: str,
        kind: str,
        line: int,
        wildcard: bool = False,
        unresolved: bool = False,
    ) -> None:
        self.facts.append(
            ImportFact(
                source=self.source,
                target=target,
                symbol=symbol,
                kind=kind,
                scope=self.scope,
                type_checking=self.in_type_checking,
                line=line,
                wildcard=wildcard,
                unresolved=unresolved,
            )
        )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            target = _known_target(alias.name, self.modules)
            if target is not None:
                self._append(
                    target=target,
                    symbol=alias.name.rpartition(".")[2],
                    kind="import",
                    line=node.lineno,
                )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = _resolve_relative(node.module, node.level, self.source_package)
        for alias in node.names:
            candidate = f"{base}.{alias.name}" if base else alias.name
            target = _known_target(candidate, self.modules)
            if target not in self.modules:
                target = _known_target(base, self.modules)
            if target is not None:
                self._append(
                    target=target,
                    symbol=alias.name,
                    kind="from",
                    line=node.lineno,
                    wildcard=alias.name == "*",
                )

    def visit_Call(self, node: ast.Call) -> None:
        dynamic_kind: str | None = None
        if isinstance(node.func, ast.Name):
            if node.func.id == "__import__":
                dynamic_kind = "dynamic-__import__"
            elif node.func.id in self.import_module_names:
                dynamic_kind = "dynamic-import_module"
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "import_module"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.importlib_aliases
        ):
            dynamic_kind = "dynamic-import_module"

        if dynamic_kind is not None:
            self._visit_dynamic_call(node, dynamic_kind)
        self.generic_visit(node)

    def _visit_dynamic_call(self, node: ast.Call, kind: str) -> None:
        if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(
            node.args[0].value, str
        ):
            self._append(
                target=None,
                symbol="<non-literal>",
                kind=kind,
                line=node.lineno,
                unresolved=True,
            )
            return

        requested = node.args[0].value
        resolved = requested
        if requested.startswith("."):
            package = self.source_package
            if kind == "dynamic-import_module":
                package_arg: ast.AST | None = node.args[1] if len(node.args) > 1 else None
                for keyword in node.keywords:
                    if keyword.arg == "package":
                        package_arg = keyword.value
                if isinstance(package_arg, ast.Constant) and isinstance(package_arg.value, str):
                    package = package_arg.value
            try:
                resolved = importlib.util.resolve_name(requested, package)
            except (ImportError, ValueError):
                self._append(
                    target=None,
                    symbol=requested,
                    kind=kind,
                    line=node.lineno,
                    unresolved=True,
                )
                return

        target = _known_target(resolved, self.modules)
        if target is not None:
            self._append(target=target, symbol=resolved, kind=kind, line=node.lineno)

    def visit_If(self, node: ast.If) -> None:
        polarity = _type_checking_polarity(
            node.test, self.type_checking_names, self.typing_aliases
        )
        contains_marker = _contains_type_checking(
            node.test, self.type_checking_names, self.typing_aliases
        )
        self.visit(node.test)
        self._visit_statements(
            node.body,
            type_checking=polarity is True or (polarity is None and contains_marker),
        )
        self._visit_statements(
            node.orelse,
            type_checking=polarity is False or (polarity is None and contains_marker),
        )

    def _visit_statements(self, statements: Sequence[ast.stmt], *, type_checking: bool) -> None:
        if type_checking:
            self.type_checking_depth += 1
        try:
            for statement in statements:
                self.visit(statement)
        finally:
            if type_checking:
                self.type_checking_depth -= 1

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # Defaults and decorators execute in the enclosing scope.  Function bodies
        # execute locally and are the imports the architectural gate must not miss.
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        if node.returns is not None:
            self.visit(node.returns)
        self.scope_depth += 1
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.scope_depth -= 1


def _scan_imports(
    modules: Mapping[str, Path], package_modules: frozenset[str]
) -> tuple[ImportFact, ...]:
    module_names = frozenset(modules)
    facts: list[ImportFact] = []
    for source, path in sorted(modules.items()):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            raise AssertionError(f"cannot parse {path}: {exc}") from exc
        aliases = _AliasCollector()
        aliases.visit(tree)
        visitor = _ImportVisitor(
            source=source,
            modules=module_names,
            package_modules=package_modules,
            aliases=aliases,
        )
        visitor.visit(tree)
        facts.extend(visitor.facts)
    return tuple(
        sorted(
            facts,
            key=lambda fact: (
                fact.source,
                fact.target or "",
                fact.symbol,
                fact.kind,
                fact.scope,
                fact.type_checking,
                fact.line,
                fact.wildcard,
                fact.unresolved,
            ),
        )
    )


def _strongly_connected_components(
    modules: Iterable[str], edges: Iterable[tuple[str, str]]
) -> tuple[tuple[str, ...], ...]:
    graph: dict[str, set[str]] = {module: set() for module in modules}
    for source, target in edges:
        if source in graph and target in graph:
            graph[source].add(target)

    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    components: list[tuple[str, ...]] = []

    def connect(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)

        for target in sorted(graph[node]):
            if target not in indices:
                connect(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[target])

        if lowlinks[node] == indices[node]:
            component: list[str] = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == node:
                    break
            components.append(tuple(sorted(component)))

    for module in sorted(graph):
        if module not in indices:
            connect(module)
    return tuple(sorted(components))


def _layer_name(module: str, package_modules: frozenset[str]) -> str | None:
    parts = module.split(".")
    if len(parts) < 2:
        return None
    candidate = f"{INTERNAL_PACKAGE}.{parts[1]}"
    if candidate not in package_modules:
        return None
    return parts[1] if parts[1] in LAYER_RANK else None


def _architectural_component(module: str, package_modules: frozenset[str]) -> str:
    """Return the nearest real first-level package, or the flat module itself."""

    parts = module.split(".")
    candidate = ".".join(parts[:2]) if len(parts) >= 2 else module
    return candidate if candidate in package_modules else module


def _fact_context(fact: ImportFact) -> str:
    return f"{fact.kind}:{fact.scope}:{'type-checking' if fact.type_checking else 'runtime'}"


def analyze_package(package_root: Path) -> Analysis:
    modules_by_name, package_modules = _discover_modules(package_root)
    facts = _scan_imports(modules_by_name, package_modules)
    edges = tuple(
        sorted(
            {
                (fact.source, fact.target)
                for fact in facts
                if fact.target in modules_by_name
            }
        )
    )
    components = _strongly_connected_components(modules_by_name, edges)
    component_by_module: dict[str, tuple[str, ...]] = {}
    for component in components:
        if len(component) > 1:
            for module in component:
                component_by_module[module] = component

    cycle_edges = {
        f"{source} -> {target}"
        for source, target in edges
        if source == target
        or (source in component_by_module and target in component_by_module[source])
    }
    private_contexts: dict[tuple[str, str, str], set[str]] = {}
    for fact in facts:
        if (
            fact.target is None
            or fact.target == fact.source
            or fact.kind != "from"
            or not fact.symbol.startswith("_")
            # Dunder metadata such as __version__ is an intentionally exported
            # Python convention, not a private implementation symbol.
            or (fact.symbol.startswith("__") and fact.symbol.endswith("__"))
            or _architectural_component(fact.source, package_modules)
            == _architectural_component(fact.target, package_modules)
        ):
            continue
        private_contexts.setdefault((fact.source, fact.target, fact.symbol), set()).add(
            _fact_context(fact)
        )
    private_imports = {
        " | ".join((*key, f"contexts={','.join(sorted(contexts))}"))
        for key, contexts in private_contexts.items()
    }
    wildcard_imports = {
        " | ".join((fact.source, fact.target or "<unresolved>", _fact_context(fact)))
        for fact in facts
        if fact.wildcard
    }
    unresolved_dynamic = {
        " | ".join((fact.source, fact.kind, fact.symbol, _fact_context(fact)))
        for fact in facts
        if fact.unresolved
    }
    layer_violations: set[str] = set()
    for source, target in edges:
        source_layer = _layer_name(source, package_modules)
        target_layer = _layer_name(target, package_modules)
        if source_layer is None or target_layer is None:
            continue
        if LAYER_RANK[source_layer] < LAYER_RANK[target_layer]:
            layer_violations.add(
                " | ".join((source, target, f"{source_layer}->{target_layer}"))
            )
    unclassified_modules = {
        module
        for module in modules_by_name
        if module != INTERNAL_PACKAGE and _layer_name(module, package_modules) is None
    }

    locations: dict[tuple[str, str], set[int]] = {}
    for fact in facts:
        if fact.target is not None:
            locations.setdefault((fact.source, fact.target), set()).add(fact.line)

    violations: dict[str, tuple[str, ...]] = {
        "cycle_edges": tuple(sorted(cycle_edges)),
        "cross_package_private_imports": tuple(sorted(private_imports)),
        "wildcard_imports": tuple(sorted(wildcard_imports)),
        "unresolved_dynamic_imports": tuple(sorted(unresolved_dynamic)),
        "layer_violations": tuple(sorted(layer_violations)),
        "unclassified_modules": tuple(sorted(unclassified_modules)),
    }
    return Analysis(
        modules=tuple(sorted(modules_by_name)),
        internal_edges=edges,
        facts=facts,
        violations=violations,
        locations={key: tuple(sorted(lines)) for key, lines in sorted(locations.items())},
    )


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_baseline(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise AssertionError(f"invalid architecture baseline {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AssertionError("architecture baseline must be a JSON object")
    return value


def validate_baseline(baseline: Mapping[str, Any]) -> list[str]:
    problems: list[str] = []
    expected_top_level = {"format", "package", "policy", "ratchet_history", "violations"}
    actual_top_level = set(baseline)
    if actual_top_level != expected_top_level:
        problems.append(
            "baseline top-level keys differ: "
            f"missing={sorted(expected_top_level - actual_top_level)!r} "
            f"extra={sorted(actual_top_level - expected_top_level)!r}"
        )
    if baseline.get("format") != BASELINE_FORMAT:
        problems.append(f"baseline format must be {BASELINE_FORMAT!r}")
    if baseline.get("package") != INTERNAL_PACKAGE:
        problems.append(f"baseline package must be {INTERNAL_PACKAGE!r}")

    policy = baseline.get("policy")
    expected_policy = {
        "full_ast": True,
        "include_local_imports": True,
        "include_type_checking_imports": True,
        "resolve_relative_imports": True,
        "inspect_dynamic_imports": ["__import__", "importlib.import_module"],
        "reject_internal_wildcards": True,
        "reject_new_cross_package_private_imports": True,
        "reject_new_cycle_edges": True,
        "reject_new_unclassified_modules": True,
        "layer_order": [list(group) for group in LAYER_GROUPS],
    }
    if policy != expected_policy:
        problems.append("baseline policy does not match the executable AST policy")

    raw_violations = baseline.get("violations")
    if not isinstance(raw_violations, dict) or set(raw_violations) != set(VIOLATION_KINDS):
        problems.append(f"violations must contain exactly {list(VIOLATION_KINDS)!r}")
        raw_violations = {}
    for kind in VIOLATION_KINDS:
        entries = raw_violations.get(kind)
        if not isinstance(entries, list) or not all(isinstance(item, str) for item in entries):
            problems.append(f"violations.{kind} must be a list of strings")
        elif entries != sorted(set(entries)):
            problems.append(f"violations.{kind} must be sorted and duplicate-free")

    history = baseline.get("ratchet_history")
    if not isinstance(history, list) or not history:
        problems.append("ratchet_history must be a non-empty list")
        return problems

    previous: dict[str, int] | None = None
    for expected_revision, entry in enumerate(history, start=1):
        if not isinstance(entry, dict) or set(entry) != {"revision", "ceilings"}:
            problems.append(f"ratchet_history[{expected_revision - 1}] has invalid shape")
            continue
        if entry.get("revision") != expected_revision:
            problems.append("ratchet revisions must be consecutive integers starting at 1")
        ceilings = entry.get("ceilings")
        if not isinstance(ceilings, dict) or set(ceilings) != set(VIOLATION_KINDS):
            problems.append(f"ratchet revision {expected_revision} has invalid ceiling keys")
            continue
        if not all(type(ceilings[kind]) is int and ceilings[kind] >= 0 for kind in VIOLATION_KINDS):
            problems.append(f"ratchet revision {expected_revision} ceilings must be integers >= 0")
            continue
        current = {kind: ceilings[kind] for kind in VIOLATION_KINDS}
        if previous is not None:
            raised = {
                kind: (previous[kind], current[kind])
                for kind in VIOLATION_KINDS
                if current[kind] > previous[kind]
            }
            if raised:
                problems.append(
                    f"ratchet revision {expected_revision} raises ceilings: {raised!r}; "
                    "ceilings may only decrease"
                )
        previous = current

    if previous is not None:
        for kind in VIOLATION_KINDS:
            entries = raw_violations.get(kind, [])
            if isinstance(entries, list) and previous[kind] != len(entries):
                problems.append(
                    f"latest ceiling for {kind} is {previous[kind]}, "
                    f"but baseline records {len(entries)} violations"
                )
    return problems


def compare_with_baseline(analysis: Analysis, baseline: Mapping[str, Any]) -> list[str]:
    problems = validate_baseline(baseline)
    if problems:
        return problems
    raw_violations = baseline["violations"]
    assert isinstance(raw_violations, dict)
    for kind in VIOLATION_KINDS:
        expected = set(raw_violations[kind])
        actual = set(analysis.violations[kind])
        added = sorted(actual - expected)
        removed = sorted(expected - actual)
        if added:
            problems.append(
                f"{kind}: {len(added)} new violation(s) exceed the ratchet:\n  + "
                + "\n  + ".join(added)
            )
        if removed:
            problems.append(
                f"{kind}: {len(removed)} recorded violation(s) are gone; preserve the "
                "improvement by removing them from the baseline and appending a ratchet "
                "revision with a lower ceiling:\n  - "
                + "\n  - ".join(removed)
            )
    return problems


def test_repository_import_boundaries_match_ratcheted_baseline() -> None:
    analysis = analyze_package(PACKAGE_ROOT)
    baseline = load_baseline(BASELINE_PATH)
    problems = compare_with_baseline(analysis, baseline)
    assert not problems, "\n\n".join(problems)


def _write_package(tmp_path: Path, files: Mapping[str, str]) -> Path:
    package = tmp_path / INTERNAL_PACKAGE
    for relative, content in files.items():
        path = package / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return package


def _baseline_for(analysis: Analysis) -> dict[str, Any]:
    ceilings = {kind: len(analysis.violations[kind]) for kind in VIOLATION_KINDS}
    return {
        "format": BASELINE_FORMAT,
        "package": INTERNAL_PACKAGE,
        "policy": {
            "full_ast": True,
            "include_local_imports": True,
            "include_type_checking_imports": True,
            "resolve_relative_imports": True,
            "inspect_dynamic_imports": ["__import__", "importlib.import_module"],
            "reject_internal_wildcards": True,
            "reject_new_cross_package_private_imports": True,
            "reject_new_cycle_edges": True,
            "reject_new_unclassified_modules": True,
            "layer_order": [list(group) for group in LAYER_GROUPS],
        },
        "ratchet_history": [{"revision": 1, "ceilings": ceilings}],
        "violations": {kind: list(analysis.violations[kind]) for kind in VIOLATION_KINDS},
    }


def test_ast_scanner_covers_local_type_checking_relative_dynamic_and_star(
    tmp_path: Path,
) -> None:
    package = _write_package(
        tmp_path,
        {
            "__init__.py": "",
            "a.py": (
                "from typing import TYPE_CHECKING\n"
                "import importlib as loader\n"
                "if TYPE_CHECKING:\n"
                "    from .b import _typed\n"
                "def load():\n"
                "    from .b import public\n"
                "    return loader.import_module('.b', package='evoom_guard')\n"
                "from .b import *\n"
                "name = 'evoom_guard.b'\n"
                "loader.import_module(name)\n"
            ),
            "b.py": "from .a import load\n_typed = 1\npublic = 2\n",
        },
    )
    analysis = analyze_package(package)

    facts = analysis.facts
    assert any(
        fact.source == "evoom_guard.a"
        and fact.target == "evoom_guard.b"
        and fact.scope == "local"
        for fact in facts
    )
    assert any(fact.symbol == "_typed" and fact.type_checking for fact in facts)
    assert any(fact.kind == "dynamic-import_module" and not fact.unresolved for fact in facts)
    assert any(fact.kind == "dynamic-import_module" and fact.unresolved for fact in facts)
    assert analysis.violations["wildcard_imports"]
    assert {
        "evoom_guard.a -> evoom_guard.b",
        "evoom_guard.b -> evoom_guard.a",
    } <= set(analysis.violations["cycle_edges"])


def test_relative_import_from_package_init_resolves_to_submodule(tmp_path: Path) -> None:
    package = _write_package(
        tmp_path,
        {
            "__init__.py": "from . import child\n",
            "child.py": "VALUE = 1\n",
        },
    )
    analysis = analyze_package(package)
    assert ("evoom_guard", "evoom_guard.child") in analysis.internal_edges


def test_self_import_is_a_cycle(tmp_path: Path) -> None:
    package = _write_package(
        tmp_path,
        {"__init__.py": "", "a.py": "from evoom_guard.a import VALUE\nVALUE = 1\n"},
    )
    analysis = analyze_package(package)
    assert analysis.violations["cycle_edges"] == (
        "evoom_guard.a -> evoom_guard.a",
    )


def test_documented_layer_order_rejects_lower_to_higher_import(tmp_path: Path) -> None:
    package = _write_package(
        tmp_path,
        {
            "__init__.py": "",
            "domain/__init__.py": "",
            "domain/model.py": "from evoom_guard.application import pipeline\n",
            "application/__init__.py": "",
            "application/pipeline.py": "VALUE = 1\n",
        },
    )
    analysis = analyze_package(package)
    assert analysis.violations["layer_violations"] == (
        "evoom_guard.domain.model | evoom_guard.application.pipeline | domain->application",
    )
    assert analysis.violations["unclassified_modules"] == ()


def test_new_flat_module_exceeds_unclassified_module_ratchet(tmp_path: Path) -> None:
    package = _write_package(
        tmp_path,
        {"__init__.py": "", "legacy.py": "VALUE = 1\n"},
    )
    baseline = _baseline_for(analyze_package(package))

    _write_package(tmp_path, {"new_flat.py": "VALUE = 2\n"})
    analysis = analyze_package(package)
    problems = compare_with_baseline(analysis, baseline)

    assert "evoom_guard.new_flat" in analysis.violations["unclassified_modules"]
    assert any(
        "unclassified_modules" in problem
        and "new violation" in problem
        and "evoom_guard.new_flat" in problem
        for problem in problems
    )


def test_new_unknown_package_exceeds_unclassified_module_ratchet(tmp_path: Path) -> None:
    package = _write_package(
        tmp_path,
        {"__init__.py": "", "legacy.py": "VALUE = 1\n"},
    )
    baseline = _baseline_for(analyze_package(package))

    _write_package(
        tmp_path,
        {
            "experimental/__init__.py": "",
            "experimental/feature.py": "VALUE = 2\n",
        },
    )
    analysis = analyze_package(package)
    problems = compare_with_baseline(analysis, baseline)

    assert {
        "evoom_guard.experimental",
        "evoom_guard.experimental.feature",
    } <= set(analysis.violations["unclassified_modules"])
    assert any(
        "unclassified_modules" in problem
        and "new violation" in problem
        and "evoom_guard.experimental.feature" in problem
        for problem in problems
    )


def test_transitional_record_verification_package_remains_explicit_debt() -> None:
    analysis = analyze_package(PACKAGE_ROOT)
    assert {
        "evoom_guard.record_verification",
        "evoom_guard.record_verification.isolation",
        "evoom_guard.record_verification.report",
    } <= set(analysis.violations["unclassified_modules"])


def test_ratchet_rejects_added_and_removed_violations(tmp_path: Path) -> None:
    clean_package = _write_package(
        tmp_path / "clean",
        {"__init__.py": "", "a.py": "VALUE = 1\n", "b.py": "VALUE = 2\n"},
    )
    debt_package = _write_package(
        tmp_path / "debt",
        {
            "__init__.py": "",
            "a.py": "from .b import _private\n",
            "b.py": "_private = 1\n",
        },
    )
    clean = analyze_package(clean_package)
    debt = analyze_package(debt_package)

    clean_baseline = _baseline_for(clean)
    debt_baseline = _baseline_for(debt)
    assert any("new violation" in item for item in compare_with_baseline(debt, clean_baseline))
    assert any("are gone" in item for item in compare_with_baseline(clean, debt_baseline))


def test_ratchet_history_may_only_lower_ceilings(tmp_path: Path) -> None:
    package = _write_package(
        tmp_path,
        {"__init__.py": "", "a.py": "VALUE = 1\n"},
    )
    baseline = _baseline_for(analyze_package(package))
    raised = {kind: 0 for kind in VIOLATION_KINDS}
    raised["cycle_edges"] = 1
    baseline["ratchet_history"].append({"revision": 2, "ceilings": raised})
    baseline["violations"]["cycle_edges"] = ["evoom_guard.a -> evoom_guard.a"]
    problems = validate_baseline(baseline)
    assert any("ceilings may only decrease" in problem for problem in problems)


@pytest.mark.parametrize(
    "source",
    (
        "from evoom_guard.missing import *\n",
        "def load(name):\n    return __import__(name)\n",
    ),
)
def test_new_opaque_import_mechanisms_are_violations(tmp_path: Path, source: str) -> None:
    package = _write_package(tmp_path, {"__init__.py": "", "a.py": source})
    analysis = analyze_package(package)
    assert analysis.violations["wildcard_imports"] or analysis.violations[
        "unresolved_dynamic_imports"
    ]
