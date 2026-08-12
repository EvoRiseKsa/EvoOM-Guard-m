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
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
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
# so same-named compatibility monoliths such as evidence.py are not mislabeled.
LAYER_GROUPS: tuple[tuple[str, ...], ...] = (
    ("foundation",),
    ("domain",),
    ("policy", "candidate", "workspace"),
    ("execution", "isolation"),
    ("verifiers", "runners"),
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
# Stable public modules may retain historical flat import paths when the whole
# module has one documented semantic owner.  Classify only those exact modules;
# mixed compatibility facades remain explicit architectural debt until their
# responsibilities are separated.
FLAT_MODULE_LAYERS = {
    "evoom_guard.adapters": "runners",
    "evoom_guard.contracts": "foundation",
    "evoom_guard.strict_json": "foundation",
    "evoom_guard.patch_applier": "candidate",
    "evoom_guard.patchmin": "candidate",
    "evoom_guard.candidate_runner": "isolation",
    "evoom_guard.runtime_identity": "workspace",
    "evoom_guard.pack_manifest": "verifiers",
    "evoom_guard.artifact_admission": "admission",
    "evoom_guard.artifact_digest_admission": "admission",
    "evoom_guard.change_attempt_observation": "evidence",
    "evoom_guard.evidence": "evidence",
    "evoom_guard.evidence_bundle": "evidence",
    "evoom_guard.maintenance_bindings": "finalizer",
    "evoom_guard.release_source_finalizer": "finalizer",
    "evoom_guard.release_source_finalizer_v2": "finalizer",
    "evoom_guard.release_source_producer_receipt_v2": "finalizer",
    "evoom_guard.signing": "evidence",
    "evoom_guard.verdict_contract_v1_11": "domain",
    "evoom_guard.verdict_contract_v1_12": "domain",
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
    if module in FLAT_MODULE_LAYERS:
        return FLAT_MODULE_LAYERS[module]
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


def _analyze_package_uncached(package_root: Path) -> Analysis:
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


def _freeze_analysis(analysis: Analysis) -> Analysis:
    """Detach and freeze the two mapping-backed parts of an analysis result."""

    return Analysis(
        modules=analysis.modules,
        internal_edges=analysis.internal_edges,
        facts=analysis.facts,
        violations=MappingProxyType(dict(analysis.violations)),
        locations=MappingProxyType(dict(analysis.locations)),
    )


@lru_cache(maxsize=1)
def _repository_analysis() -> Analysis:
    """Return one immutable architecture snapshot for this test process."""

    return _freeze_analysis(_analyze_package_uncached(PACKAGE_ROOT))


def analyze_package(package_root: Path) -> Analysis:
    """Analyze a package, caching only the immutable checked-out source tree."""

    if package_root == PACKAGE_ROOT:
        return _repository_analysis()
    return _analyze_package_uncached(package_root)


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


def test_repository_analysis_snapshot_is_process_cached_and_immutable() -> None:
    first = analyze_package(PACKAGE_ROOT)
    second = analyze_package(PACKAGE_ROOT)

    assert first is second
    with pytest.raises(TypeError):
        first.violations["cycle_edges"] = ()  # type: ignore[index]
    with pytest.raises(TypeError):
        first.locations[("source", "target")] = ()  # type: ignore[index]


def test_repository_import_boundaries_match_ratcheted_baseline() -> None:
    analysis = analyze_package(PACKAGE_ROOT)
    baseline = load_baseline(BASELINE_PATH)
    problems = compare_with_baseline(analysis, baseline)
    assert not problems, "\n\n".join(problems)


def test_guard_uses_only_public_cross_package_contracts() -> None:
    """Prevent Guard from coupling back to private verifier implementation."""

    module = "evoom_guard.guard"
    analysis = analyze_package(PACKAGE_ROOT)
    private_imports = tuple(
        violation
        for violation in analysis.violations["cross_package_private_imports"]
        if violation.startswith(f"{module} | ")
    )
    assert private_imports == ()


def test_domain_verification_contracts_are_classified_and_dependency_free() -> None:
    """Keep the first Stage-3 slice independent of every higher layer."""

    analysis = analyze_package(PACKAGE_ROOT)
    domain_modules = {
        "evoom_guard.domain",
        "evoom_guard.domain.verdict",
        "evoom_guard.domain.verification",
    }
    assert domain_modules.issubset(analysis.modules)
    assert domain_modules.isdisjoint(
        analysis.violations["unclassified_modules"]
    )
    assert not any(
        violation.startswith("evoom_guard.domain")
        for violation in analysis.violations["cross_package_private_imports"]
    )
    for module in (
        "evoom_guard.domain.verdict",
        "evoom_guard.domain.verification",
    ):
        assert {
            target
            for source, target in analysis.internal_edges
            if source == module
        } == set()


def test_flat_foundation_and_verification_owners_are_classified_and_closed() -> None:
    """Classify only cohesive flat contracts whose dependency direction is closed."""

    analysis = analyze_package(PACKAGE_ROOT)
    expected_layers = {
        "evoom_guard.contracts": "foundation",
        "evoom_guard.strict_json": "foundation",
        "evoom_guard.runtime_identity": "workspace",
        "evoom_guard.pack_manifest": "verifiers",
    }

    assert {
        module: FLAT_MODULE_LAYERS.get(module) for module in expected_layers
    } == expected_layers
    for module in expected_layers:
        assert module in analysis.modules
        assert module not in analysis.violations["unclassified_modules"]
        assert {
            target
            for source, target in analysis.internal_edges
            if source == module and target != module
        } == set()
        assert not any(
            violation.startswith(f"{module} |")
            for violation in analysis.violations["cross_package_private_imports"]
        )


def test_flat_evidence_admission_and_finalizer_owners_follow_declared_layers() -> None:
    """Classify cohesive stable paths without hiding their dependency closure."""

    analysis = analyze_package(PACKAGE_ROOT)
    expected_layers = {
        "evoom_guard.artifact_admission": "admission",
        "evoom_guard.artifact_digest_admission": "admission",
        "evoom_guard.evidence": "evidence",
        "evoom_guard.evidence_bundle": "evidence",
        "evoom_guard.maintenance_bindings": "finalizer",
        "evoom_guard.release_source_finalizer": "finalizer",
        "evoom_guard.release_source_finalizer_v2": "finalizer",
        "evoom_guard.release_source_producer_receipt_v2": "finalizer",
        "evoom_guard.signing": "evidence",
    }
    expected_dependencies = {
        "evoom_guard.artifact_admission": {
            "evoom_guard.evidence_bundle",
            "evoom_guard.signing",
            "evoom_guard.trusted_finalizer",
        },
        "evoom_guard.artifact_digest_admission": {
            "evoom_guard.evidence_bundle",
            "evoom_guard.signing",
            "evoom_guard.trusted_finalizer",
        },
        "evoom_guard.evidence": {
            "evoom_guard.candidate",
            "evoom_guard.execution",
            "evoom_guard.policy.harness",
            "evoom_guard.verifiers.harness_policy",
            "evoom_guard.verifiers.repo_verifier",
            "evoom_guard.workspace",
            "evoom_guard.workspace.repository",
        },
        "evoom_guard.evidence_bundle": {
            "evoom_guard.record_verifier",
            "evoom_guard.signing",
            "evoom_guard.strict_json",
        },
        "evoom_guard.maintenance_bindings": {
            "evoom_guard.evidence_bundle",
        },
        "evoom_guard.release_source_finalizer": {
            "evoom_guard.evidence_bundle",
            "evoom_guard.finalizer_derivation",
            "evoom_guard.record_verifier",
            "evoom_guard.signing",
        },
        "evoom_guard.release_source_finalizer_v2": {
            "evoom_guard.maintenance_bindings",
        },
        "evoom_guard.release_source_producer_receipt_v2": {
            "evoom_guard.maintenance_bindings",
        },
        "evoom_guard.signing": set(),
    }

    assert {
        module: FLAT_MODULE_LAYERS.get(module) for module in expected_layers
    } == expected_layers
    for module, expected in expected_dependencies.items():
        assert module in analysis.modules
        assert module not in analysis.violations["unclassified_modules"]
        assert {
            target
            for source, target in analysis.internal_edges
            if source == module and target != module
        } == expected
        assert not any(
            violation.startswith(f"{module} |")
            for violation in analysis.violations["layer_violations"]
        )


def test_artifact_provider_v3_is_a_closed_admission_layer() -> None:
    """Keep provider-specific V3 above existing evidence and V2 primitives."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.admission.artifact_provider_v3"

    assert module in analysis.modules
    assert module not in analysis.violations["unclassified_modules"]
    assert {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    } == {
        "evoom_guard.artifact_digest_admission",
        "evoom_guard.evidence_bundle",
        "evoom_guard.github_attestation",
        "evoom_guard.strict_json",
    }
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["layer_violations"]
    )
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_guard_reads_semantics_from_domain_and_schema_from_versioned_contracts() -> None:
    """Keep generic semantics separate from versioned wire ownership."""

    analysis = analyze_package(PACKAGE_ROOT)
    for contract in (
        "evoom_guard.verdict_contract_v1_11",
        "evoom_guard.verdict_contract_v1_12",
    ):
        contract_facts = tuple(
            fact
            for fact in analysis.facts
            if fact.source == "evoom_guard.guard" and fact.target == contract
        )
        assert tuple(fact.symbol for fact in contract_facts) == ("SCHEMA_VERSION",)
    assert (
        "evoom_guard.guard",
        "evoom_guard.domain.verdict",
    ) in analysis.internal_edges


def test_workspace_package_is_classified_and_dependency_free() -> None:
    """The atomic module-to-package move must remove real legacy debt."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.workspace"

    assert module in analysis.modules
    assert module not in analysis.violations["unclassified_modules"]
    assert {
        target for source, target in analysis.internal_edges if source == module
    } == set()
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_candidate_tree_has_one_dependency_free_workspace_owner() -> None:
    """Snapshot intake must not absorb policy, execution, or verdict work."""

    analysis = analyze_package(PACKAGE_ROOT)
    owner = "evoom_guard.workspace.candidate_tree"

    assert owner in analysis.modules
    assert owner not in analysis.violations["unclassified_modules"]
    assert {
        target
        for source, target in analysis.internal_edges
        if source == owner and target != owner
    } == set()
    assert ("evoom_guard.guard", owner) in analysis.internal_edges
    assert not any(
        violation.startswith(f"{owner} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_cli_captures_candidate_tree_compatibility_through_public_snapshot() -> None:
    """The CLI must not import Guard's historical private error class."""

    analysis = analyze_package(PACKAGE_ROOT)
    guard_facts = tuple(
        fact
        for fact in analysis.facts
        if fact.source == "evoom_guard.cli"
        and fact.target == "evoom_guard.guard"
        and fact.symbol
        in {
            "_UnverifiableChangedPathsError",
            "blocks_from_dirs",
            "serialize_candidate_blocks",
            "snapshot_candidate_tree_compatibility",
        }
    )

    assert tuple(fact.symbol for fact in guard_facts) == (
        "snapshot_candidate_tree_compatibility",
    )
    assert not any(
        violation.startswith("evoom_guard.cli | evoom_guard.guard |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_repository_workspace_has_one_dependency_free_owner() -> None:
    """Repository copying/cleanup must not depend on verifier orchestration."""

    analysis = analyze_package(PACKAGE_ROOT)
    owner = "evoom_guard.workspace.repository"

    assert owner in analysis.modules
    assert owner not in analysis.violations["unclassified_modules"]
    assert {
        target
        for source, target in analysis.internal_edges
        if source == owner and target != owner
    } == set()
    assert ("evoom_guard.verifiers.repo_verifier", owner) in analysis.internal_edges
    assert not any(
        violation.startswith(f"{owner} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_repository_workspace_lifetime_is_dependency_free() -> None:
    """Workspace-path bookkeeping must not absorb verifier or cleanup effects."""

    analysis = analyze_package(PACKAGE_ROOT)
    owner = "evoom_guard.workspace.repository_lifetime"

    assert owner in analysis.modules
    assert owner not in analysis.violations["unclassified_modules"]
    assert {
        target
        for source, target in analysis.internal_edges
        if source == owner and target != owner
    } == set()
    assert (
        "evoom_guard.verifiers.repo_verifier",
        owner,
    ) in analysis.internal_edges
    assert not any(
        violation.startswith(f"{owner} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_repository_cleanup_effect_owner_is_dependency_free() -> None:
    """Cleanup effect coordination must not absorb verifier orchestration."""

    analysis = analyze_package(PACKAGE_ROOT)
    owner = "evoom_guard.verifiers.repo_cleanup"

    assert owner in analysis.modules
    assert owner not in analysis.violations["unclassified_modules"]
    assert {
        target
        for source, target in analysis.internal_edges
        if source == owner and target != owner
    } == set()
    assert (
        "evoom_guard.verifiers.repo_verifier",
        owner,
    ) in analysis.internal_edges
    assert not any(
        violation.startswith(f"{owner} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_cli_package_is_classified_and_preserves_the_console_surface() -> None:
    """The CLI facade and parser owner must retain the public entry point."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.cli"
    parser_module = "evoom_guard.cli.parser"
    cli_path = PACKAGE_ROOT / "cli" / "__init__.py"
    parser_path = PACKAGE_ROOT / "cli" / "parser.py"

    assert modules[module] == cli_path
    assert modules[parser_module] == parser_path
    assert module not in analysis.violations["unclassified_modules"]
    assert parser_module not in analysis.violations["unclassified_modules"]
    tree = ast.parse(cli_path.read_text(encoding="utf-8"))
    functions = {
        node.name for node in tree.body if isinstance(node, ast.FunctionDef)
    }
    assert {"build_parser", "main"} <= functions
    parser_tree = ast.parse(parser_path.read_text(encoding="utf-8"))
    parser_functions = {
        node.name for node in parser_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert parser_functions == {"build_parser"}
    assert {
        target
        for source, target in analysis.internal_edges
        if source == parser_module and target != parser_module
    } == set()
    assert 'evo-guard = "evoom_guard.cli:main"' in (
        ROOT / "pyproject.toml"
    ).read_text(encoding="utf-8")


def test_cli_guard_command_has_one_typed_owner_and_no_runtime_internal_imports() -> None:
    """The bounded command owner must receive effects only through its facade."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.cli"
    owner_module = "evoom_guard.cli.guard_command"
    facade_path = PACKAGE_ROOT / "cli" / "__init__.py"
    owner_path = PACKAGE_ROOT / "cli" / "guard_command.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (
        facade_module,
        owner_module,
    ) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
    owner_functions = {
        node.name for node in owner_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert owner_functions == {"execute_guard_command"}
    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name for node in facade_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert {"cmd_guard", "_guard_command_services"} <= facade_functions


def test_cli_diagnostic_commands_have_one_stdlib_owner_and_public_facades() -> None:
    """Diagnostic and pack inspection logic belongs to one injected owner."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.cli"
    owner_module = "evoom_guard.cli.diagnostic_commands"
    facade_path = PACKAGE_ROOT / "cli" / "__init__.py"
    owner_path = PACKAGE_ROOT / "cli" / "diagnostic_commands.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
    owner_functions = {
        node.name for node in owner_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert owner_functions == {
        "build_doctor_report",
        "execute_doctor",
        "execute_pack_doctor",
        "execute_version",
        "validate_pack",
    }
    import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert import_roots <= {
        "__future__",
        "argparse",
        "collections",
        "dataclasses",
        "typing",
    }
    owner_classes = {
        node.name for node in owner_tree.body if isinstance(node, ast.ClassDef)
    }
    assert owner_classes == {"DoctorServices", "PackValidationServices"}

    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name for node in facade_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert {
        "cmd_doctor",
        "cmd_pack_doctor",
        "cmd_version",
        "doctor_report",
        "validate_pack",
    } <= facade_functions


def test_cli_init_command_has_one_stdlib_owner_and_public_facades() -> None:
    """Initialization owns templates and sequencing but receives every effect."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.cli"
    owner_module = "evoom_guard.cli.init_command"
    facade_path = PACKAGE_ROOT / "cli" / "__init__.py"
    owner_path = PACKAGE_ROOT / "cli" / "init_command.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module and fact.target is not None and not fact.type_checking
    } == set()

    owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
    owner_functions = {node.name for node in owner_tree.body if isinstance(node, ast.FunctionDef)}
    assert owner_functions == {
        "execute_init_command",
        "infer_default_policy_path",
        "render_private_workflow",
        "render_public_workflow",
        "validate_github_actions_credential_key",
    }
    import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert import_roots <= {
        "__future__",
        "argparse",
        "collections",
        "dataclasses",
        "typing",
    }
    owner_classes = {node.name for node in owner_tree.body if isinstance(node, ast.ClassDef)}
    assert owner_classes == {
        "InitCommandServices",
        "InitPathServices",
        "_DumpJson",
        "_JoinPath",
        "_MakeDirectories",
        "_OpenText",
    }

    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {node.name for node in facade_tree.body if isinstance(node, ast.FunctionDef)}
    assert {
        "_default_policy_path",
        "_github_actions_credential_key",
        "_init_command_services",
        "_workflow_yaml",
        "_workflow_yaml_private",
        "cmd_init",
    } <= facade_functions


def test_cli_signing_keygen_has_one_stdlib_owner_and_public_facade() -> None:
    """Key generation owns sequencing but receives its signing effect."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.cli"
    owner_module = "evoom_guard.cli.signing_commands"
    facade_path = PACKAGE_ROOT / "cli" / "__init__.py"
    owner_path = PACKAGE_ROOT / "cli" / "signing_commands.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
    owner_functions = {
        node.name for node in owner_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert owner_functions == {"execute_keygen"}
    owner_classes = {
        node.name for node in owner_tree.body if isinstance(node, ast.ClassDef)
    }
    assert owner_classes == {"KeygenServices"}
    import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert import_roots <= {
        "__future__",
        "argparse",
        "collections",
        "dataclasses",
    }

    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name for node in facade_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert "cmd_keygen" in facade_functions
    keygen_facade = next(
        node
        for node in facade_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "cmd_keygen"
    )
    assert not any(
        isinstance(node, (ast.For, ast.If, ast.Match, ast.Try, ast.While))
        for node in ast.walk(keygen_facade)
    )


def test_cli_artifact_admission_v1_has_one_stdlib_owner_and_public_facades() -> None:
    """Artifact Admission V1 sequencing has one effect-injected owner."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.cli"
    owner_module = "evoom_guard.cli.artifact_admission_commands"
    facade_path = PACKAGE_ROOT / "cli" / "__init__.py"
    owner_path = PACKAGE_ROOT / "cli" / "artifact_admission_commands.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
    owner_functions = {
        node.name for node in owner_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert owner_functions == {
        "execute_seal_artifact_admission",
        "execute_verify_artifact_admission",
    }
    owner_classes = {
        node.name for node in owner_tree.body if isinstance(node, ast.ClassDef)
    }
    assert owner_classes == {
        "SealArtifactAdmissionServices",
        "VerifyArtifactAdmissionServices",
        "_ArtifactSubject",
        "_InspectedArtifactBinding",
        "_ReadExternalObject",
        "_SealArtifactAdmission",
        "_SealedArtifactBinding",
        "_VerifiedArtifactBinding",
        "_VerifyArtifactAdmission",
    }
    import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert import_roots <= {
        "__future__",
        "argparse",
        "collections",
        "dataclasses",
        "typing",
    }

    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name: node
        for node in facade_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    for name in (
        "cmd_seal_artifact_admission",
        "cmd_verify_artifact_admission",
    ):
        facade = facade_functions[name]
        assert not any(
            isinstance(node, (ast.For, ast.If, ast.Match, ast.Try, ast.While))
            for node in ast.walk(facade)
        )


def test_cli_artifact_digest_v2_has_one_stdlib_owner_and_public_facades() -> None:
    """Artifact Digest Admission V2 has one effect-injected owner."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.cli"
    owner_module = "evoom_guard.cli.artifact_digest_admission_commands"
    facade_path = PACKAGE_ROOT / "cli" / "__init__.py"
    owner_path = PACKAGE_ROOT / "cli" / "artifact_digest_admission_commands.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
    owner_functions = {
        node.name for node in owner_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert owner_functions == {
        "execute_seal_artifact_digest_admission",
        "execute_verify_artifact_digest_admission",
    }
    owner_classes = {
        node.name for node in owner_tree.body if isinstance(node, ast.ClassDef)
    }
    assert owner_classes == {
        "SealArtifactDigestAdmissionServices",
        "VerifyArtifactDigestAdmissionServices",
        "_AsDictValue",
        "_InspectedArtifactDigestBinding",
        "_ReadExternalObject",
        "_SealArtifactDigestAdmission",
        "_SealedArtifactDigestBinding",
        "_VerifiedArtifactDigestBinding",
        "_VerifyArtifactDigestAdmission",
    }
    import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert import_roots <= {
        "__future__",
        "argparse",
        "collections",
        "dataclasses",
        "typing",
    }

    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name: node
        for node in facade_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    for name in (
        "cmd_seal_artifact_digest_admission",
        "cmd_verify_artifact_digest_admission",
    ):
        facade = facade_functions[name]
        assert not any(
            isinstance(node, (ast.For, ast.If, ast.Match, ast.Try, ast.While))
            for node in ast.walk(facade)
        )


def test_cli_github_attestation_receipts_have_one_stdlib_owner() -> None:
    """Receipt orchestration has one owner and a structurally offline verifier."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.cli"
    owner_module = "evoom_guard.cli.github_attestation_receipt_commands"
    facade_path = PACKAGE_ROOT / "cli" / "__init__.py"
    owner_path = PACKAGE_ROOT / "cli" / "github_attestation_receipt_commands.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
    owner_functions = {
        node.name for node in owner_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert owner_functions == {
        "execute_github_attestation_receipt",
        "execute_reverify_github_attestation_receipt",
        "execute_verify_github_attestation_receipt",
    }
    owner_classes = {
        node.name: node
        for node in owner_tree.body
        if isinstance(node, ast.ClassDef)
    }
    assert set(owner_classes) == {
        "CreateGitHubAttestationReceiptServices",
        "ReverifyGitHubAttestationReceiptServices",
        "VerifyGitHubAttestationReceiptServices",
        "_AsDictValue",
        "_CreateGitHubAttestationReceipt",
        "_CreatedGitHubAttestationReceipt",
        "_FreshGitHubAttestationVerification",
        "_GitHubAttestationPolicyKwargs",
        "_PolicyKwargsBuilder",
        "_ProviderIsolationBuilder",
        "_ReverifyGitHubAttestationReceipt",
        "_VerifiedGitHubAttestationReceipt",
        "_VerifyGitHubAttestationReceipt",
    }
    import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert import_roots <= {
        "__future__",
        "argparse",
        "collections",
        "dataclasses",
        "typing",
    }

    def service_fields(class_name: str) -> set[str]:
        return {
            node.target.id
            for node in owner_classes[class_name].body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
        }

    connected_fields = {
        "receipt_format",
        "github_error",
        "policy_kwargs_provider",
        "provider_isolation_provider",
        "machine_report_provider",
    }
    assert service_fields("CreateGitHubAttestationReceiptServices") == {
        *connected_fields,
        "create_github_attestation_receipt",
    }
    assert service_fields("ReverifyGitHubAttestationReceiptServices") == {
        *connected_fields,
        "reverify_github_attestation_receipt",
    }
    assert service_fields("VerifyGitHubAttestationReceiptServices") == {
        "receipt_format",
        "github_error",
        "verify_github_attestation_receipt",
        "policy_kwargs_provider",
        "machine_report_provider",
    }

    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name: node
        for node in facade_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    for name in (
        "cmd_github_attestation_receipt",
        "cmd_verify_github_attestation_receipt",
        "cmd_reverify_github_attestation_receipt",
    ):
        facade = facade_functions[name]
        assert not any(
            isinstance(node, (ast.For, ast.If, ast.Match, ast.Try, ast.While))
            for node in ast.walk(facade)
        )


def test_cli_github_attestation_admissions_have_two_bounded_state_machines() -> None:
    """Admission sealing and retained verification have one stdlib-only owner."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.cli"
    owner_module = "evoom_guard.cli.github_attestation_admission_commands"
    facade_path = PACKAGE_ROOT / "cli" / "__init__.py"
    owner_path = PACKAGE_ROOT / "cli" / "github_attestation_admission_commands.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_source = owner_path.read_text(encoding="utf-8")
    owner_tree = ast.parse(owner_source)
    owner_functions = {
        node.name: node
        for node in owner_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    assert set(owner_functions) == {
        "execute_seal_github_attestation_admission",
        "execute_verify_github_attestation_admission",
    }
    owner_classes = {
        node.name: node
        for node in owner_tree.body
        if isinstance(node, ast.ClassDef)
    }
    assert set(owner_classes) == {
        "SealGitHubAttestationAdmissionServices",
        "VerifyGitHubAttestationAdmissionServices",
        "_AsDictValue",
        "_CreatedGitHubAttestationReceipt",
        "_GitHubAttestationPolicyKwargs",
        "_InspectedAdmission",
        "_PolicyKwargsBuilder",
        "_ProviderIsolationBuilder",
        "_ReadExternalObject",
        "_SealGitHubAttestationAdmission",
        "_SealedAdmission",
        "_SealedGitHubAttestationAdmission",
        "_VerifiedAdmission",
        "_VerifiedGitHubAttestationReceipt",
        "_VerifiedGitHubAttestationAdmission",
        "_VerifyGitHubAttestationAdmission",
    }
    import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert import_roots <= {
        "__future__",
        "argparse",
        "collections",
        "dataclasses",
        "typing",
    }

    def service_fields(class_name: str) -> set[str]:
        return {
            node.target.id
            for node in owner_classes[class_name].body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
        }

    assert service_fields("SealGitHubAttestationAdmissionServices") == {
        "binding_format",
        "github_error",
        "signing_unavailable_error",
        "seal_github_attestation_admission",
        "read_external_object_provider",
        "policy_kwargs_provider",
        "provider_isolation_provider",
        "machine_report_provider",
    }
    assert service_fields("VerifyGitHubAttestationAdmissionServices") == {
        "binding_format",
        "github_error",
        "signing_unavailable_error",
        "verify_github_attestation_admission",
        "read_external_object_provider",
        "policy_kwargs_provider",
        "machine_report_provider",
    }

    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name: node
        for node in facade_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    verify_tree = owner_functions["execute_verify_github_attestation_admission"]
    seal_tree = owner_functions["execute_seal_github_attestation_admission"]

    def argument_attributes(function: ast.FunctionDef) -> set[str]:
        return {
            node.attr
            for node in ast.walk(function)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "args"
        }

    assert argument_attributes(seal_tree) == {
        "artifact",
        "expected_context",
        "expected_source",
        "finalizer_bundle",
        "finalizer_pub",
        "gh_executable",
        "out",
        "raw_output_out",
        "receipt_out",
        "sign_key",
        "timeout_seconds",
    }
    assert argument_attributes(verify_tree) == {
        "artifact",
        "binding",
        "expected_context",
        "expected_source",
        "finalizer_bundle",
        "finalizer_pub",
        "raw_output",
        "receipt",
        "trusted_pub",
    }
    policy_attributes = argument_attributes(
        facade_functions["_github_attestation_policy_kwargs"]
    )
    isolation_attributes = argument_attributes(
        facade_functions["_github_attestation_provider_isolation"]
    )
    assert argument_attributes(seal_tree) | policy_attributes | isolation_attributes == {
        "artifact",
        "cert_oidc_issuer",
        "expected_context",
        "expected_source",
        "finalizer_bundle",
        "finalizer_pub",
        "gh_executable",
        "gh_executable_sha256",
        "out",
        "provider_isolation_gid",
        "provider_isolation_uid",
        "raw_output_out",
        "receipt_out",
        "repo",
        "sign_key",
        "signer_digest",
        "signer_workflow",
        "source_digest",
        "source_ref",
        "timeout_seconds",
    }
    assert argument_attributes(verify_tree) | policy_attributes == {
        "artifact",
        "binding",
        "cert_oidc_issuer",
        "expected_context",
        "expected_source",
        "finalizer_bundle",
        "finalizer_pub",
        "raw_output",
        "receipt",
        "repo",
        "signer_digest",
        "signer_workflow",
        "source_digest",
        "source_ref",
        "trusted_pub",
    }
    verify_attributes = {
        node.attr for node in ast.walk(verify_tree) if isinstance(node, ast.Attribute)
    }
    assert verify_attributes.isdisjoint(
        {
            "force",
            "gh_executable",
            "gh_executable_sha256",
            "provider_isolation",
            "provider_isolation_gid",
            "provider_isolation_uid",
            "sign_key",
            "timeout_seconds",
        }
    )
    assert all(
        not isinstance(node, (ast.Import, ast.ImportFrom))
        for node in ast.walk(verify_tree)
    )
    for function in (seal_tree, verify_tree):
        assert isinstance(function.body[-2], ast.Expr)
        assert "machine_report_provider" in ast.unparse(function.body[-2])
        assert all(
            index < len(function.body) - 2
            for index, node in enumerate(function.body)
            if isinstance(node, ast.Try)
        )

    for name in (
        "cmd_seal_github_attestation_admission",
        "cmd_verify_github_attestation_admission",
    ):
        facade = facade_functions[name]
        assert not any(
            isinstance(node, (ast.For, ast.If, ast.Match, ast.Try, ast.While))
            for node in ast.walk(facade)
        )
        local_imports = {
            node.module
            for node in ast.walk(facade)
            if isinstance(node, ast.ImportFrom)
        }
        assert {
            "evoom_guard.artifact_digest_admission",
            "evoom_guard.github_attestation",
            "evoom_guard.signing",
        } <= local_imports


def test_cli_release_artifact_admission_has_bounded_online_and_offline_owners() -> None:
    """RAAE sealing and detached verification share one capability-bounded owner."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.cli"
    owner_module = "evoom_guard.cli.release_artifact_admission_commands"
    facade_path = PACKAGE_ROOT / "cli" / "__init__.py"
    owner_path = PACKAGE_ROOT / "cli" / "release_artifact_admission_commands.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_source = owner_path.read_text(encoding="utf-8")
    owner_tree = ast.parse(owner_source)
    owner_functions = {
        node.name: node
        for node in owner_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    assert set(owner_functions) == {
        "execute_seal_github_release_artifact_admission",
        "execute_verify_github_release_artifact_admission",
    }
    owner_classes = {
        node.name: node
        for node in owner_tree.body
        if isinstance(node, ast.ClassDef)
    }
    assert set(owner_classes) == {
        "SealGitHubReleaseArtifactAdmissionServices",
        "VerifyGitHubReleaseArtifactAdmissionServices",
        "_AsDictValue",
        "_BindRuntimeAdmitter",
        "_Environment",
        "_GitExecutablePin",
        "_InspectedReleaseArtifactAdmission",
        "_KeySeparation",
        "_NestedExpectations",
        "_PreflightPaths",
        "_ProviderIsolation",
        "_PublicKeyId",
        "_ReadExternalObject",
        "_SealReleaseArtifactAdmission",
        "_SealedReleaseArtifactAdmission",
        "_VerifiedReleaseArtifactAdmission",
        "_VerifyReleaseArtifactAdmission",
    }
    import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert import_roots <= {
        "__future__",
        "argparse",
        "collections",
        "dataclasses",
        "typing",
    }

    def service_fields(class_name: str) -> set[str]:
        return {
            node.target.id
            for node in owner_classes[class_name].body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
        }

    assert service_fields("SealGitHubReleaseArtifactAdmissionServices") == {
        "admission_format",
        "release_artifact_error",
        "github_error",
        "finalizer_error",
        "signing_unavailable_error",
        "bind_runtime_admitter",
        "seal_release_artifact_admission",
        "public_key_id",
        "git_executable_pin",
        "provider_isolation",
        "environment_provider",
        "preflight_provider",
        "nested_expectations_provider",
        "read_external_object_provider",
        "key_separation_provider",
        "machine_report_provider",
    }
    assert service_fields("VerifyGitHubReleaseArtifactAdmissionServices") == {
        "admission_format",
        "release_artifact_error",
        "signing_unavailable_error",
        "verify_release_artifact_admission",
        "nested_expectations_provider",
        "read_external_object_provider",
        "key_separation_provider",
        "machine_report_provider",
    }

    seal_tree = owner_functions[
        "execute_seal_github_release_artifact_admission"
    ]
    verify_tree = owner_functions[
        "execute_verify_github_release_artifact_admission"
    ]

    def argument_attributes(function: ast.FunctionDef) -> set[str]:
        return {
            node.attr
            for node in ast.walk(function)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "args"
        }

    assert argument_attributes(seal_tree) == {
        "admitter",
        "artifact",
        "builder",
        "expected_release_source_bootstrap_guard_sha",
        "expected_release_source_gh_executable_sha256",
        "expected_release_source_git_executable_sha256",
        "expected_release_source_provider_isolation_gid",
        "expected_release_source_provider_isolation_uid",
        "gh_executable",
        "gh_executable_sha256",
        "git_executable",
        "git_executable_sha256",
        "git_repository",
        "git_repository_bare",
        "out",
        "provider_isolation_gid",
        "provider_isolation_uid",
        "release_source_admission",
        "release_source_admission_v2_pub",
        "sign_key",
        "sign_pub",
        "timeout_seconds",
    }
    assert argument_attributes(verify_tree) == {
        "artifact",
        "bundle",
        "expected_admitter",
        "expected_builder",
        "expected_gh_executable_sha256",
        "expected_git_executable_sha256",
        "expected_provider_isolation_gid",
        "expected_provider_isolation_uid",
        "expected_release_source_bootstrap_guard_sha",
        "expected_release_source_gh_executable_sha256",
        "expected_release_source_git_executable_sha256",
        "expected_release_source_provider_isolation_gid",
        "expected_release_source_provider_isolation_uid",
        "release_source_admission_v2_pub",
        "trusted_pub",
    }
    verify_attributes = {
        node.attr for node in ast.walk(verify_tree) if isinstance(node, ast.Attribute)
    }
    assert verify_attributes.isdisjoint(
        {
            "environment_provider",
            "finalizer_error",
            "gh_executable",
            "git_executable",
            "git_executable_pin",
            "git_repository",
            "github_error",
            "preflight_provider",
            "private_key_path",
            "provider_isolation",
            "public_key_id",
            "seal_release_artifact_admission",
            "sign_key",
            "timeout_seconds",
        }
    )
    assert all(
        not isinstance(node, (ast.Import, ast.ImportFrom))
        for node in ast.walk(verify_tree)
    )

    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name: node
        for node in facade_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    for name in (
        "cmd_seal_github_release_artifact_admission",
        "cmd_verify_github_release_artifact_admission",
    ):
        facade = facade_functions[name]
        assert not any(
            isinstance(node, (ast.For, ast.If, ast.Match, ast.Try, ast.While))
            for node in ast.walk(facade)
        )
    seal_imports = {
        node.module
        for node in ast.walk(
            facade_functions["cmd_seal_github_release_artifact_admission"]
        )
        if isinstance(node, ast.ImportFrom)
    }
    verify_imports = {
        node.module
        for node in ast.walk(
            facade_functions["cmd_verify_github_release_artifact_admission"]
        )
        if isinstance(node, ast.ImportFrom)
    }
    assert seal_imports == {
        "evoom_guard.admission.release_artifact",
        "evoom_guard.finalizer_derivation",
        "evoom_guard.github_attestation",
        "evoom_guard.signing",
    }
    assert verify_imports == {
        "evoom_guard.admission.release_artifact",
        "evoom_guard.signing",
    }


def test_cli_release_source_finalizer_has_one_stdlib_owner_and_public_facades() -> None:
    """The four release-source adapters have one effect-injected owner."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.cli"
    owner_module = "evoom_guard.cli.release_source_finalizer_commands"
    facade_path = PACKAGE_ROOT / "cli" / "__init__.py"
    owner_path = PACKAGE_ROOT / "cli" / "release_source_finalizer_commands.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
    owner_functions = {
        node.name for node in owner_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert owner_functions == {
        "execute_derive_release_source_controls",
        "execute_release_source_handoff",
        "execute_seal_release_source_finalizer",
        "execute_verify_release_source_finalized",
    }
    owner_classes = {
        node.name for node in owner_tree.body if isinstance(node, ast.ClassDef)
    }
    assert {
        "DeriveReleaseSourceControlsServices",
        "ReleaseSourceHandoffServices",
        "SealReleaseSourceFinalizerServices",
        "VerifyReleaseSourceFinalizedServices",
    } <= owner_classes
    import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert import_roots <= {
        "__future__",
        "argparse",
        "collections",
        "dataclasses",
        "typing",
    }

    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name: node
        for node in facade_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    for name in (
        "cmd_release_source_handoff",
        "cmd_seal_release_source_finalizer",
        "cmd_verify_release_source_finalized",
        "cmd_derive_release_source_controls",
    ):
        facade = facade_functions[name]
        assert not any(
            isinstance(node, (ast.For, ast.If, ast.Match, ast.Try, ast.While))
            for node in ast.walk(facade)
        )


def test_cli_producer_receipts_have_one_stdlib_nonadmitting_owner() -> None:
    """Producer-receipt orchestration has one explicitly non-admitting owner."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.cli"
    owner_module = "evoom_guard.cli.release_source_producer_receipt_commands"
    facade_path = PACKAGE_ROOT / "cli" / "__init__.py"
    owner_path = (
        PACKAGE_ROOT / "cli" / "release_source_producer_receipt_commands.py"
    )

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
    owner_functions = {
        node.name for node in owner_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert owner_functions == {
        "execute_create_producer_receipt",
        "execute_reverify_producer_receipt",
        "execute_verify_producer_receipt",
    }
    owner_classes = {
        node.name: node
        for node in owner_tree.body
        if isinstance(node, ast.ClassDef)
    }
    assert set(owner_classes) == {
        "CreateProducerReceiptServices",
        "ReverifyProducerReceiptServices",
        "VerifyProducerReceiptServices",
        "_AttestedProducerReceipt",
        "_CreateProducerReceipt",
        "_CreatedGitHubReceipt",
        "_InspectedProducerReceipt",
        "_ProducerReceiptExternalInputs",
        "_ReadExternalObject",
        "_ReverifyProducerReceipt",
        "_VerifiedProducerReceipt",
        "_VerifyProducerReceipt",
    }
    import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert import_roots <= {
        "__future__",
        "argparse",
        "collections",
        "dataclasses",
        "typing",
    }

    def service_fields(class_name: str) -> set[str]:
        return {
            node.target.id
            for node in owner_classes[class_name].body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
        }

    assert service_fields("CreateProducerReceiptServices") == {
        "receipt_format",
        "producer_error",
        "create_producer_receipt",
        "read_external_object_provider",
        "absolute_path_provider",
        "machine_report_provider",
    }
    assert service_fields("VerifyProducerReceiptServices") == {
        "receipt_format",
        "producer_error",
        "verify_producer_receipt",
        "external_inputs_provider",
        "machine_report_provider",
    }
    assert service_fields("ReverifyProducerReceiptServices") == {
        "receipt_format",
        "producer_error",
        "reverify_producer_receipt",
        "external_inputs_provider",
        "read_external_object_provider",
        "machine_report_provider",
    }
    all_service_fields = set().union(
        service_fields("CreateProducerReceiptServices"),
        service_fields("VerifyProducerReceiptServices"),
        service_fields("ReverifyProducerReceiptServices"),
    )
    assert not (
        {
            "admission",
            "signing_key",
            "provider_isolation",
            "git_executable_pin",
            "gh_executable_pin",
        }
        & all_service_fields
    )

    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name: node
        for node in facade_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    facade_names = (
        "cmd_create_release_source_producer_receipt",
        "cmd_verify_release_source_producer_receipt",
        "cmd_reverify_attested_release_source_producer_receipt",
    )
    for name in facade_names:
        facade = facade_functions[name]
        assert not any(
            isinstance(node, (ast.For, ast.If, ast.Match, ast.Try, ast.While))
            for node in ast.walk(facade)
        )
        assert {
            node.module
            for node in ast.walk(facade)
            if isinstance(node, ast.ImportFrom)
        } == {"evoom_guard.release_source_producer_receipt"}


def test_cli_release_source_admissions_have_two_bounded_state_machines() -> None:
    """Connected source sealing and detached verification have one bounded owner."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.cli"
    owner_module = "evoom_guard.cli.release_source_admission_commands"
    facade_path = PACKAGE_ROOT / "cli" / "__init__.py"
    owner_path = PACKAGE_ROOT / "cli" / "release_source_admission_commands.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
    owner_functions = {
        node.name: node
        for node in owner_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    assert set(owner_functions) == {
        "execute_seal_release_source_admission",
        "execute_verify_release_source_admission",
    }
    owner_classes = {
        node.name: node
        for node in owner_tree.body
        if isinstance(node, ast.ClassDef)
    }
    assert set(owner_classes) == {
        "SealReleaseSourceAdmissionServices",
        "VerifyReleaseSourceAdmissionServices",
        "_GitExecutablePin",
        "_KeySeparation",
        "_Preflight",
        "_ProducerInputs",
        "_ProviderIsolation",
        "_PublicKeyId",
        "_ReadExternalObject",
        "_ReverifyProducerReceipt",
        "_SealReleaseSourceAdmission",
        "_SealedReleaseSourceAdmission",
        "_ValidateAdmitterRuntime",
        "_VerifiedBundle",
        "_VerifiedReleaseSourceAdmission",
        "_VerifyAdmitterWorkflow",
        "_VerifyReleaseSourceAdmission",
    }
    import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert import_roots <= {
        "__future__",
        "argparse",
        "collections",
        "dataclasses",
        "typing",
    }

    def service_fields(class_name: str) -> set[str]:
        return {
            node.target.id
            for node in owner_classes[class_name].body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
        }

    assert service_fields("SealReleaseSourceAdmissionServices") == {
        "admission_format",
        "environment_provider",
        "finalizer_error",
        "git_executable_pin",
        "github_error",
        "key_separation_provider",
        "machine_report_provider",
        "preflight_provider",
        "producer_inputs_provider",
        "producer_receipt_error",
        "provider_isolation",
        "public_key_id",
        "read_external_object_provider",
        "release_source_error",
        "reverify_producer_receipt",
        "seal_release_source_admission",
        "signing_unavailable_error",
        "validate_admitter_runtime",
        "verify_admitter_workflow",
    }
    verify_service_fields = service_fields("VerifyReleaseSourceAdmissionServices")
    assert verify_service_fields == {
        "admission_format",
        "key_separation_provider",
        "machine_report_provider",
        "read_external_object_provider",
        "release_source_error",
        "signing_unavailable_error",
        "verify_release_source_admission",
    }
    assert verify_service_fields.isdisjoint(
        {
            "environment_provider",
            "git_executable_pin",
            "preflight_provider",
            "producer_inputs_provider",
            "provider_isolation",
            "public_key_id",
            "reverify_producer_receipt",
            "seal_release_source_admission",
            "validate_admitter_runtime",
            "verify_admitter_workflow",
        }
    )

    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name: node
        for node in facade_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    seal_tree = owner_functions["execute_seal_release_source_admission"]
    verify_tree = owner_functions["execute_verify_release_source_admission"]

    def argument_attributes(function: ast.FunctionDef) -> set[str]:
        return {
            node.attr
            for node in ast.walk(function)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "args"
        }

    producer_attributes = argument_attributes(
        facade_functions["_producer_receipt_external_inputs"]
    )
    key_attributes = argument_attributes(
        facade_functions["_release_source_key_separation"]
    )
    preflight_attributes = argument_attributes(
        facade_functions["_preflight_release_source_admission_paths"]
    )
    assert argument_attributes(seal_tree) | producer_attributes | key_attributes | (
        preflight_attributes
    ) == {
        "admitter",
        "artifact_admission_v1_pub",
        "artifact_digest_admission_v2_pub",
        "bootstrap_guard_sha",
        "context",
        "force",
        "gh_executable",
        "gh_executable_sha256",
        "git_executable",
        "git_executable_sha256",
        "git_repository",
        "git_repository_bare",
        "github_policy",
        "github_raw_output_out",
        "github_receipt_out",
        "handoff",
        "out",
        "producer",
        "provider_isolation_gid",
        "provider_isolation_uid",
        "receipt",
        "release_source_finalizer_v1_pub",
        "sign_key",
        "sign_pub",
        "source",
        "timeout_seconds",
        "trusted_finalizer_pub",
        "verdict",
    }
    assert argument_attributes(verify_tree) | key_attributes == {
        "artifact_admission_v1_pub",
        "artifact_digest_admission_v2_pub",
        "bundle",
        "expected_admitter",
        "expected_bootstrap_guard_sha",
        "expected_context",
        "expected_gh_executable_sha256",
        "expected_git_executable_sha256",
        "expected_github_policy",
        "expected_producer",
        "expected_provider_isolation_gid",
        "expected_provider_isolation_uid",
        "expected_source",
        "release_source_finalizer_v1_pub",
        "trusted_finalizer_pub",
        "trusted_pub",
    }
    verify_attributes = {
        node.attr for node in ast.walk(verify_tree) if isinstance(node, ast.Attribute)
    }
    assert verify_attributes.isdisjoint(
        {
            "environment_provider",
            "force",
            "gh_executable",
            "git_executable",
            "git_repository",
            "github_raw_output_out",
            "github_receipt_out",
            "preflight_provider",
            "provider_isolation",
            "public_key_id",
            "sign_key",
            "sign_pub",
            "timeout_seconds",
        }
    )
    assert all(
        not isinstance(node, (ast.Import, ast.ImportFrom))
        for node in ast.walk(verify_tree)
    )
    for function in (seal_tree, verify_tree):
        assert isinstance(function.body[-2], ast.Expr)
        assert "machine_report_provider" in ast.unparse(function.body[-2])
        assert all(
            index < len(function.body) - 2
            for index, node in enumerate(function.body)
            if isinstance(node, ast.Try)
        )

    for name in (
        "cmd_seal_release_source_admission",
        "cmd_verify_release_source_admission",
    ):
        facade = facade_functions[name]
        assert not any(
            isinstance(node, (ast.For, ast.If, ast.Match, ast.Try, ast.While))
            for node in ast.walk(facade)
        )
    seal_imports = {
        node.module
        for node in ast.walk(
            facade_functions["cmd_seal_release_source_admission"]
        )
        if isinstance(node, ast.ImportFrom)
    }
    assert {
        "evoom_guard.admission.release_source",
        "evoom_guard.finalizer_derivation",
        "evoom_guard.github_attestation",
        "evoom_guard.release_source_producer_receipt",
        "evoom_guard.signing",
    } <= seal_imports
    verify_imports = {
        node.module
        for node in ast.walk(
            facade_functions["cmd_verify_release_source_admission"]
        )
        if isinstance(node, ast.ImportFrom)
    }
    assert verify_imports == {
        "evoom_guard.admission.release_source",
        "evoom_guard.signing",
    }


def test_guard_output_has_one_stdlib_owner_and_public_facades() -> None:
    """Output publication belongs to integrations while Guard keeps its API."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.guard"
    owner_module = "evoom_guard.integrations.guard_output"
    facade_path = PACKAGE_ROOT / "guard.py"
    owner_path = PACKAGE_ROOT / "integrations" / "guard_output.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
    owner_functions = {
        node.name for node in owner_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert {
        "render_report",
        "to_sarif",
        "write_json",
        "write_sarif",
    } <= owner_functions
    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name for node in facade_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert {
        "render_report",
        "to_sarif",
        "write_json",
        "write_sarif",
    } <= facade_functions


def test_cli_agent_change_commands_have_one_stdlib_owner_and_public_facades() -> None:
    """The five bounded adapters keep effects and import timing in the facade."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.cli"
    owner_module = "evoom_guard.cli.agent_change_commands"
    facade_path = PACKAGE_ROOT / "cli" / "__init__.py"
    owner_path = PACKAGE_ROOT / "cli" / "agent_change_commands.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
    owner_functions = {
        node.name for node in owner_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert owner_functions == {
        "execute_derive_agent_change_bindings",
        "execute_seal_agent_change_authorization",
        "execute_seal_agent_change_finalized",
        "execute_validate_agent_change_proposal",
        "execute_verify_agent_change_finalized",
    }
    import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert import_roots <= {
        "__future__",
        "argparse",
        "collections",
        "dataclasses",
        "typing",
    }
    owner_classes = {
        node.name for node in owner_tree.body if isinstance(node, ast.ClassDef)
    }
    assert {
        "DeriveBindingsServices",
        "SealAuthorizationServices",
        "SealFinalizedServices",
        "ValidateProposalServices",
        "VerifyFinalizedServices",
    } <= owner_classes

    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name for node in facade_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert {
        "cmd_derive_agent_change_bindings",
        "cmd_seal_agent_change_authorization",
        "cmd_seal_agent_change_finalized",
        "cmd_validate_agent_change_proposal",
        "cmd_verify_agent_change_finalized",
    } <= facade_functions


def test_cli_trusted_finalizer_commands_have_one_stdlib_owner_and_public_facades() -> None:
    """The Trusted Finalizer adapters keep effects and lookup timing in the facade."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.cli"
    owner_module = "evoom_guard.cli.trusted_finalizer_commands"
    facade_path = PACKAGE_ROOT / "cli" / "__init__.py"
    owner_path = PACKAGE_ROOT / "cli" / "trusted_finalizer_commands.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
    owner_functions = {
        node.name for node in owner_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert owner_functions == {
        "execute_derive_finalizer_bindings",
        "execute_finalizer_handoff",
        "execute_read_semantic_finalizer_record",
        "execute_seal_finalizer",
        "execute_verify_finalized",
        "execute_verify_finalizer_bindings",
    }
    import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert import_roots <= {
        "__future__",
        "argparse",
        "collections",
        "dataclasses",
        "typing",
    }
    owner_classes = {
        node.name for node in owner_tree.body if isinstance(node, ast.ClassDef)
    }
    assert {
        "DeriveBindingsServices",
        "FinalizerHandoffServices",
        "SealFinalizerServices",
        "SemanticRecordServices",
        "VerifyBindingsServices",
        "VerifyFinalizedServices",
    } <= owner_classes

    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name for node in facade_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert {
        "_read_semantic_finalizer_record",
        "cmd_derive_finalizer_bindings",
        "cmd_finalizer_handoff",
        "cmd_seal_finalizer",
        "cmd_verify_finalized",
        "cmd_verify_finalizer_bindings",
    } <= facade_functions


def test_cli_record_commands_have_one_stdlib_owner_and_public_facades() -> None:
    """The five record adapters keep effects and lookup timing in the facade."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.cli"
    owner_module = "evoom_guard.cli.record_commands"
    facade_path = PACKAGE_ROOT / "cli" / "__init__.py"
    owner_path = PACKAGE_ROOT / "cli" / "record_commands.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
    owner_functions = {
        node.name for node in owner_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert {
        "execute_bundle_evidence",
        "execute_finalize_record",
        "execute_verify_bundle",
        "execute_verify_record",
        "execute_verify_verdict",
    } <= owner_functions
    import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert import_roots <= {
        "__future__",
        "argparse",
        "collections",
        "dataclasses",
        "typing",
    }
    owner_classes = {
        node.name for node in owner_tree.body if isinstance(node, ast.ClassDef)
    }
    assert {
        "BundleEvidenceServices",
        "FinalizeRecordServices",
        "VerifyBundleServices",
        "VerifyRecordServices",
        "VerifyVerdictServices",
    } <= owner_classes

    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name for node in facade_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert {
        "cmd_bundle_evidence",
        "cmd_finalize_record",
        "cmd_verify_bundle",
        "cmd_verify_record",
        "cmd_verify_verdict",
    } <= facade_functions


def test_effective_policy_contracts_follow_public_layer_boundaries() -> None:
    """Policy construction may depend on domain values, never Guard internals."""

    analysis = analyze_package(PACKAGE_ROOT)
    assert (
        "evoom_guard.policy.effective",
        "evoom_guard.domain",
    ) in analysis.internal_edges
    assert (
        "evoom_guard.finalizer_derivation",
        "evoom_guard.policy",
    ) in analysis.internal_edges
    assert not any(
        violation.startswith(
            "evoom_guard.finalizer_derivation | evoom_guard.guard | _effective_policy"
        )
        for violation in analysis.violations["cross_package_private_imports"]
    )
    assert not any(
        source.startswith("evoom_guard.domain.")
        and target.startswith("evoom_guard.policy")
        for source, target in analysis.internal_edges
    )


def test_cli_change_attempt_observation_has_a_stdlib_owner_and_public_facade() -> None:
    """Observation orchestration stays injected and separate from CLI effects."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.cli"
    owner_module = "evoom_guard.cli.change_attempt_observation_commands"
    facade_path = PACKAGE_ROOT / "cli" / "__init__.py"
    owner_path = PACKAGE_ROOT / "cli" / "change_attempt_observation_commands.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
    owner_functions = {
        node.name for node in owner_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert owner_functions == {"execute_project_change_attempt_observation"}
    import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert import_roots <= {
        "__future__",
        "argparse",
        "collections",
        "dataclasses",
        "typing",
    }

    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name for node in facade_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert "cmd_project_change_attempt_observation" in facade_functions


def test_change_attempt_projection_has_a_closed_evidence_dependency_contract() -> None:
    """The public flat evidence projector must not absorb execution ownership."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.change_attempt_observation"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }

    assert dependencies == {
        "evoom_guard",
        "evoom_guard.domain.verdict",
        "evoom_guard.evidence_bundle",
        "evoom_guard.runtime_identity",
        "evoom_guard.signing",
        "evoom_guard.trusted_finalizer",
    }
    assert module not in analysis.violations["unclassified_modules"]
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_guard_request_is_a_dependency_closed_domain_contract() -> None:
    """The request aggregate may depend only on its peer policy value."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.domain.request"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }
    assert dependencies == {"evoom_guard.domain.policy"}
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_guard_request_preparation_has_only_its_public_domain_dependency() -> None:
    """Request preparation must not absorb execution or verifier ownership."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.application.request_preparation"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }

    assert dependencies == {"evoom_guard.domain"}
    assert ("evoom_guard.guard", module) in analysis.internal_edges
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_diff_verification_has_no_internal_effect_dependencies() -> None:
    """Diff sequencing consumes injected effects and imports no effect owner."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.application.diff_verification"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }

    assert dependencies == set()
    assert ("evoom_guard.guard", module) in analysis.internal_edges
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_repo_judgment_has_no_internal_effect_dependencies() -> None:
    """Initial repo judgment resolves every runtime owner through providers."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.application.repo_judgment"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }

    assert dependencies == set()
    assert module in analysis.modules
    assert module not in analysis.violations["unclassified_modules"]
    assert ("evoom_guard.guard", module) in analysis.internal_edges
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_repo_finalization_has_only_pipeline_and_domain_dependencies() -> None:
    """Finalization sequences injected effects without importing their owners."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.application.repo_finalization"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }

    assert dependencies == {
        "evoom_guard.application.pipeline",
        "evoom_guard.domain.decision",
        "evoom_guard.domain.evidence",
        "evoom_guard.domain.verdict",
    }
    assert ("evoom_guard.guard", module) in analysis.internal_edges
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_blackbox_finalization_has_only_application_and_domain_dependencies() -> None:
    """Post-cleanup finalization must not absorb judge/runtime ownership."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.application.blackbox_finalization"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }

    assert dependencies == set()
    assert ("evoom_guard.guard", module) in analysis.internal_edges
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_execution_evidence_contracts_follow_public_layer_boundaries() -> None:
    """Execution snapshots are pure domain values projected by the verifier."""

    analysis = analyze_package(PACKAGE_ROOT)
    domain_module = "evoom_guard.domain.execution"
    adapter_module = "evoom_guard.verifiers.repo_execution"

    assert {
        target
        for source, target in analysis.internal_edges
        if source == domain_module and target != domain_module
    } == set()
    assert {
        target
        for source, target in analysis.internal_edges
        if source == adapter_module and target != adapter_module
    } == {"evoom_guard.domain.execution"}
    assert not any(
        violation.startswith(f"{module} |")
        for module in (domain_module, adapter_module)
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_candidate_preflight_has_one_public_policy_dependency() -> None:
    """Candidate admission must not absorb execution or verdict ownership."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.verifiers.candidate_preflight"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }

    assert dependencies == {"evoom_guard.verifiers.harness_policy"}
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_repo_materialization_has_only_public_containment_dependencies() -> None:
    """The edit transaction may use candidate values and contained I/O only."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.verifiers.repo_materialization"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }

    assert dependencies == {
        "evoom_guard.candidate",
        "evoom_guard.workspace",
    }
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_repo_candidate_has_only_public_candidate_and_verdict_dependencies() -> None:
    """Candidate coordination must not absorb pack, execution, or cleanup owners."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.verifiers.repo_candidate"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }

    assert dependencies == {
        "evoom_guard.candidate",
        "evoom_guard.contracts",
    }
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_repo_pack_intake_has_only_the_public_pack_contract_dependency() -> None:
    """Pack intake may identify a snapshot but must not absorb its execution."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.verifiers.repo_pack_intake"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }

    assert dependencies == {"evoom_guard.pack_manifest"}
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_repo_pack_has_only_public_execution_and_evidence_dependencies() -> None:
    """Pack ownership must not absorb snapshot, identity, or cleanup orchestration."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.verifiers.repo_pack"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }

    assert dependencies == {
        "evoom_guard.contracts",
        "evoom_guard.domain.execution",
        "evoom_guard.domain.verification",
        "evoom_guard.execution",
        "evoom_guard.isolation",
    }
    assert (
        "evoom_guard.verifiers.repo_verifier",
        module,
    ) in analysis.internal_edges
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_repo_pack_continuity_depends_only_on_the_public_pack_contract() -> None:
    """Pack continuity must not absorb execution, JUnit, wire, or cleanup."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.verifiers.repo_pack_continuity"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }

    assert dependencies == {"evoom_guard.pack_manifest"}
    assert (
        "evoom_guard.verifiers.repo_verifier",
        module,
    ) in analysis.internal_edges
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_repo_setup_has_only_public_execution_and_fidelity_dependencies() -> None:
    """Setup policy must not absorb suite, pack, or verifier orchestration."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.verifiers.repo_setup"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }

    assert dependencies == {
        "evoom_guard.contracts",
        "evoom_guard.domain.execution",
        "evoom_guard.execution",
        "evoom_guard.isolation",
        "evoom_guard.verifiers.fidelity",
    }
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_repo_suite_has_only_public_execution_and_evidence_dependencies() -> None:
    """Suite ownership must not absorb pack, identity, or cleanup orchestration."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.verifiers.repo_suite"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }

    assert dependencies == {
        "evoom_guard.contracts",
        "evoom_guard.domain.execution",
        "evoom_guard.domain.verification",
        "evoom_guard.execution",
        "evoom_guard.isolation",
    }
    assert (
        "evoom_guard.verifiers.repo_verifier",
        module,
    ) in analysis.internal_edges
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_repo_runtime_continuity_has_only_identity_and_domain_dependencies() -> None:
    """Runtime continuity must not absorb execution, pack, or final composition."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.verifiers.repo_runtime_continuity"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }

    assert dependencies == {
        "evoom_guard.domain.evidence",
        "evoom_guard.runtime_identity",
    }
    assert (
        "evoom_guard.verifiers.repo_verifier",
        module,
    ) in analysis.internal_edges
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_blackbox_pack_has_only_public_execution_and_pack_dependencies() -> None:
    """Pack execution must not absorb facade, candidate, or cleanup ownership."""

    analysis = analyze_package(PACKAGE_ROOT)
    module = "evoom_guard.verifiers.blackbox_pack"
    dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }

    assert dependencies == {
        "evoom_guard.execution",
        "evoom_guard.pack_manifest",
    }
    assert ("evoom_guard.blackbox", module) in analysis.internal_edges
    assert not any(
        violation.startswith(f"{module} |")
        for violation in analysis.violations["cross_package_private_imports"]
    )


def test_blackbox_candidate_runtime_has_one_stdlib_owner_and_thin_facades() -> None:
    """Candidate observation/cleanup sequencing must depend only on injection."""

    modules, _ = _discover_modules(PACKAGE_ROOT)
    analysis = analyze_package(PACKAGE_ROOT)
    facade_module = "evoom_guard.blackbox"
    owner_module = "evoom_guard.verifiers.blackbox_candidate_runtime"
    facade_path = PACKAGE_ROOT / "blackbox.py"
    owner_path = PACKAGE_ROOT / "verifiers" / "blackbox_candidate_runtime.py"

    assert modules[owner_module] == owner_path
    assert owner_module not in analysis.violations["unclassified_modules"]
    assert (facade_module, owner_module) in analysis.internal_edges
    assert {
        fact.target
        for fact in analysis.facts
        if fact.source == owner_module
        and fact.target is not None
        and not fact.type_checking
    } == set()

    owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
    import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert import_roots <= {
        "__future__",
        "collections",
        "dataclasses",
        "typing",
    }
    assert {
        node.name
        for node in owner_tree.body
        if isinstance(node, ast.FunctionDef)
    } == {
        "attach_candidate_execution_evidence",
        "cleanup_candidate_containers",
    }

    facade_tree = ast.parse(facade_path.read_text(encoding="utf-8"))
    facade_functions = {
        node.name
        for node in facade_tree.body
        if isinstance(node, ast.FunctionDef)
    }
    facade_classes = {
        node.name
        for node in facade_tree.body
        if isinstance(node, ast.ClassDef)
    }
    assert {
        "_attach_candidate_execution_evidence",
        "_cleanup_candidate_containers",
        "_candidate_container_ids",
    } <= facade_functions
    assert "CandidateContainerCleanupError" in facade_classes


def test_release_source_admission_is_classified_and_uses_public_dependencies() -> None:
    """Prevent the first admission slice from inheriting flat-module debt."""

    module = "evoom_guard.admission.release_source"
    analysis = analyze_package(PACKAGE_ROOT)
    assert module in analysis.modules
    assert module not in analysis.violations["unclassified_modules"]
    private_imports = tuple(
        violation
        for violation in analysis.violations["cross_package_private_imports"]
        if violation.startswith(f"{module} | ")
    )
    assert private_imports == ()


def test_release_source_admission_internal_dependencies_are_exactly_allowlisted() -> None:
    """Freeze the V2 admission slice's internal dependency surface by module name."""

    module = "evoom_guard.admission.release_source"
    expected_dependencies = {
        "evoom_guard.evidence_bundle",
        "evoom_guard.finalizer_derivation",
        "evoom_guard.github_attestation",
        "evoom_guard.record_verifier",
        "evoom_guard.release_source_finalizer",
        "evoom_guard.release_source_producer_receipt",
        "evoom_guard.signing",
    }
    analysis = analyze_package(PACKAGE_ROOT)
    actual_dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }
    assert actual_dependencies == expected_dependencies


def test_release_artifact_admission_is_classified_and_uses_public_dependencies() -> None:
    """Keep the protected-main artifact admission slice out of flat-module debt."""

    module = "evoom_guard.admission.release_artifact"
    analysis = analyze_package(PACKAGE_ROOT)
    assert module in analysis.modules
    assert module not in analysis.violations["unclassified_modules"]
    private_imports = tuple(
        violation
        for violation in analysis.violations["cross_package_private_imports"]
        if violation.startswith(f"{module} | ")
    )
    assert private_imports == ()


def test_release_artifact_admission_dependencies_are_exactly_allowlisted() -> None:
    """Freeze the V1 release-artifact admission dependency surface."""

    module = "evoom_guard.admission.release_artifact"
    expected_dependencies = {
        "evoom_guard.admission.release_source",
        "evoom_guard.artifact_admission",
        "evoom_guard.evidence_bundle",
        "evoom_guard.finalizer_derivation",
        "evoom_guard.github_attestation",
        "evoom_guard.release_source_finalizer",
        "evoom_guard.signing",
    }
    analysis = analyze_package(PACKAGE_ROOT)
    actual_dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }
    assert actual_dependencies == expected_dependencies


def test_agent_change_admission_is_classified_and_uses_public_dependencies() -> None:
    """Keep Agent Change Admission inside the documented admission layer."""

    module = "evoom_guard.admission.agent_change"
    analysis = analyze_package(PACKAGE_ROOT)
    assert module in analysis.modules
    assert module not in analysis.violations["unclassified_modules"]
    private_imports = tuple(
        violation
        for violation in analysis.violations["cross_package_private_imports"]
        if violation.startswith(f"{module} | ")
    )
    assert private_imports == ()


def test_agent_change_admission_dependencies_are_exactly_allowlisted() -> None:
    """Freeze the candidate profile's intentionally small dependency surface."""

    module = "evoom_guard.admission.agent_change"
    expected_dependencies = {
        "evoom_guard.candidate.identity",
        "evoom_guard.evidence_bundle",
        "evoom_guard.finalizer_derivation",
        "evoom_guard.signing",
        "evoom_guard.trusted_finalizer",
        "evoom_guard.verifiers.harness_policy",
    }
    analysis = analyze_package(PACKAGE_ROOT)
    actual_dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == module and target != module
    }
    assert actual_dependencies == expected_dependencies


def test_admission_decision_modules_are_classified_and_use_public_dependencies() -> None:
    """Keep the proof-bound projection inside the documented admission layer."""

    modules = {
        "evoom_guard.admission.decision_envelope",
        "evoom_guard.admission.decision_sources",
    }
    analysis = analyze_package(PACKAGE_ROOT)
    assert modules <= set(analysis.modules)
    for module in modules:
        assert module not in analysis.violations["unclassified_modules"]
        private_imports = tuple(
            violation
            for violation in analysis.violations["cross_package_private_imports"]
            if violation.startswith(f"{module} | ")
        )
        assert private_imports == ()


def test_admission_decision_dependencies_are_exactly_allowlisted() -> None:
    """Freeze the deliberately small projection and proof-adapter surfaces."""

    expected = {
        "evoom_guard.admission.decision_envelope": {
            "evoom_guard.candidate.identity",
            "evoom_guard.evidence_bundle",
        },
        "evoom_guard.admission.decision_sources": {
            "evoom_guard.admission.agent_change",
            "evoom_guard.admission.decision_envelope",
            "evoom_guard.evidence_bundle",
            "evoom_guard.finalizer_derivation",
        },
    }
    analysis = analyze_package(PACKAGE_ROOT)
    for module, dependencies in expected.items():
        actual = {
            target
            for source, target in analysis.internal_edges
            if source == module and target != module
        }
        assert actual == dependencies


def test_runner_instrumentation_has_classified_owners_and_a_thin_facade() -> None:
    """Keep one class owner per runner behind two acyclic compatibility facades."""

    analysis = analyze_package(PACKAGE_ROOT)
    command = "evoom_guard.runners._command"
    class_owners = {
        "evoom_guard.runners.gotestsum": "GotestsumAdapter",
        "evoom_guard.runners.jest": "JestAdapter",
        "evoom_guard.runners.maven": "MavenAdapter",
        "evoom_guard.runners.mocha": "MochaAdapter",
        "evoom_guard.runners.node_test": "NodeTestAdapter",
        "evoom_guard.runners.pytest": "PytestAdapter",
        "evoom_guard.runners.rspec": "RspecAdapter",
        "evoom_guard.runners.shell": "ShellAdapter",
        "evoom_guard.runners.vitest": "VitestAdapter",
    }
    simple_owners = set(class_owners) - {"evoom_guard.runners.shell"}
    class_owner_modules = set(class_owners)
    owner_dependencies = {
        command: set(),
        "evoom_guard.runners.protocol": set(),
        **{module: {command} for module in simple_owners},
        "evoom_guard.runners.shell": {
            command,
            "evoom_guard.runners.protocol",
        },
        "evoom_guard.runners.adapters": {
            command,
            *class_owner_modules,
            "evoom_guard.runners.protocol",
        },
        "evoom_guard.runners.registry": {
            *class_owner_modules,
            "evoom_guard.runners.protocol",
        },
        "evoom_guard.runners": {
            *class_owner_modules,
            "evoom_guard.runners.protocol",
            "evoom_guard.runners.registry",
        },
    }
    for module, expected in owner_dependencies.items():
        assert module in analysis.modules
        assert module not in analysis.violations["unclassified_modules"]
        actual = {
            target
            for source, target in analysis.internal_edges
            if source == module and target != module
        }
        assert actual == expected

    facade = "evoom_guard.adapters"
    assert FLAT_MODULE_LAYERS[facade] == "runners"
    assert facade not in analysis.violations["unclassified_modules"]
    facade_dependencies = {
        target
        for source, target in analysis.internal_edges
        if source == facade and target != facade
    }
    assert facade_dependencies == {
        "evoom_guard.runners.adapters",
        "evoom_guard.runners.protocol",
        "evoom_guard.runners.registry",
    }
    assert not any(
        violation.startswith(f"{facade} | ")
        for violation in analysis.violations["layer_violations"]
    )
    assert not any(
        violation.startswith(f"{module} | ")
        for module in owner_dependencies
        for violation in analysis.violations["cross_package_private_imports"]
    )

    for module, class_name in class_owners.items():
        owner_path = PACKAGE_ROOT.joinpath(*module.split(".")[1:]).with_suffix(".py")
        owner_tree = ast.parse(owner_path.read_text(encoding="utf-8"))
        assert [
            node.name for node in owner_tree.body if isinstance(node, ast.ClassDef)
        ] == [class_name]

    combined_facade_tree = ast.parse(
        (PACKAGE_ROOT / "runners" / "adapters.py").read_text(encoding="utf-8")
    )
    assert not any(
        isinstance(node, (ast.ClassDef, ast.FunctionDef))
        for node in combined_facade_tree.body
    )

    facade_tree = ast.parse((PACKAGE_ROOT / "adapters.py").read_text(encoding="utf-8"))
    assert not any(isinstance(node, ast.ClassDef) for node in facade_tree.body)
    assert {
        node.name
        for node in facade_tree.body
        if isinstance(node, ast.FunctionDef)
    } == {"instrument_command"}


def test_flat_candidate_and_isolation_owners_have_ratcheted_shapes() -> None:
    """Ratchet structural evidence while leaving semantic ownership to review."""

    analysis = analyze_package(PACKAGE_ROOT)
    expected_layers = {
        "evoom_guard.patch_applier": "candidate",
        "evoom_guard.patchmin": "candidate",
        "evoom_guard.candidate_runner": "isolation",
    }
    expected_dependencies = {
        "evoom_guard.patch_applier": {"evoom_guard.candidate.patch"},
        "evoom_guard.patchmin": set(),
        "evoom_guard.candidate_runner": {
            "evoom_guard.execution",
            "evoom_guard.isolation.candidate",
            "evoom_guard.isolation.docker",
        },
    }

    assert {
        module: FLAT_MODULE_LAYERS.get(module) for module in expected_layers
    } == expected_layers
    for module, expected in expected_dependencies.items():
        assert module in analysis.modules
        assert module not in analysis.violations["unclassified_modules"]
        assert {
            target
            for source, target in analysis.internal_edges
            if source == module and target != module
        } == expected
        assert not any(
            violation.startswith(f"{module} | ")
            for violation in analysis.violations["layer_violations"]
        )
        assert not any(
            violation.startswith(f"{module} | ")
            for violation in analysis.violations["cross_package_private_imports"]
        )

    patch_facade_tree = ast.parse(
        (PACKAGE_ROOT / "patch_applier.py").read_text(encoding="utf-8")
    )
    assert not any(
        isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        for node in patch_facade_tree.body
    )
    patch_imports = {
        (node.module, alias.name, alias.asname)
        for node in patch_facade_tree.body
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    assert patch_imports == {
        ("evoom_guard.candidate.patch", "AmbiguousMatchError", "AmbiguousMatchError"),
        ("evoom_guard.candidate.patch", "NoMatchError", "NoMatchError"),
        ("evoom_guard.candidate.patch", "PatchError", "PatchError"),
        ("evoom_guard.candidate.patch", "apply_patch", "apply_patch"),
    }

    patchmin_tree = ast.parse(
        (PACKAGE_ROOT / "patchmin.py").read_text(encoding="utf-8")
    )
    patchmin_import_roots = {
        alias.name.partition(".")[0]
        for node in ast.walk(patchmin_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").partition(".")[0]
        for node in ast.walk(patchmin_tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert patchmin_import_roots <= {
        "__future__",
        "collections",
        "dataclasses",
        "fnmatch",
        "typing",
    }
    patchmin_exports = [
        ast.literal_eval(node.value)
        for node in patchmin_tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__all__"
            for target in node.targets
        )
    ]
    assert patchmin_exports == [
        [
            "BlastRadiusScore",
            "blast_radius_score",
            "minimize_patch",
            "RiskScore",
            "parse_unified_diff",
            "risk_score",
        ]
    ]
    assert {
        node.name
        for node in patchmin_tree.body
        if isinstance(
            node,
            (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
        )
    } == {
        "RiskScore",
        "minimize_patch",
        "parse_unified_diff",
        "_strip_diff_path",
        "_validated_precomputed_counts",
        "risk_score",
    }

    candidate_runner_tree = ast.parse(
        (PACKAGE_ROOT / "candidate_runner.py").read_text(encoding="utf-8")
    )
    assert {
        node.name
        for node in candidate_runner_tree.body
        if isinstance(node, ast.ClassDef)
    } == {"CandidateRunner"}
    assert {
        node.name
        for node in candidate_runner_tree.body
        if isinstance(node, ast.FunctionDef)
    } == {"_run_docker_control"}


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


def test_record_verification_helpers_have_classified_verifier_owners() -> None:
    analysis = analyze_package(PACKAGE_ROOT)
    removed_legacy_modules = {
        "evoom_guard.record_verification",
        "evoom_guard.record_verification.isolation",
        "evoom_guard.record_verification.report",
    }
    assert removed_legacy_modules.isdisjoint(analysis.modules)

    expected_dependencies = {
        "evoom_guard.verifiers.record_baseline_types": set(),
        "evoom_guard.verifiers.record_coverage_types": set(),
        "evoom_guard.verifiers.record_envelope_types": set(),
        "evoom_guard.verifiers.record_nested": {
            "evoom_guard.verdict_contract_v1_11",
            "evoom_guard.verifiers.junit_oracle",
        },
        "evoom_guard.verifiers.record_report": set(),
        "evoom_guard.verifiers.record_policy": set(),
        "evoom_guard.verifiers.record_isolation": {
            "evoom_guard.verifiers.record_report"
        },
    }
    for owner, expected in expected_dependencies.items():
        assert owner in analysis.modules
        assert owner not in analysis.violations["unclassified_modules"]
        assert {
            target
            for source, target in analysis.internal_edges
            if source == owner and target != owner
        } == expected
        assert not any(
            violation.startswith(f"{owner} |")
            for violation in analysis.violations["cross_package_private_imports"]
        )


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
