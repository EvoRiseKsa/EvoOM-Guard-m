"""Characterization of Guard's base/head candidate-tree contract.

These tests intentionally import through ``evoom_guard.guard``.  The facade,
its live provider lookup, exact serialization, and fail-closed diagnostics are
compatibility contracts while the owning implementation moves to
``evoom_guard.workspace``.
"""

from __future__ import annotations

import errno
import importlib
import inspect
from dataclasses import FrozenInstanceError
from dataclasses import fields as dataclass_fields
from pathlib import Path
from typing import Any

import pytest

from evoom_guard.workspace import candidate_tree

guard_module = importlib.import_module("evoom_guard.guard")


def test_candidate_tree_facade_value_shapes_are_frozen() -> None:
    assert guard_module._TreeEntry.__name__ == "_TreeEntry"
    assert guard_module._TreeEntry.__module__ == "evoom_guard.guard"
    assert (
        guard_module._UnverifiableChangedPathsError.__name__
        == "_UnverifiableChangedPathsError"
    )
    assert (
        guard_module._UnverifiableChangedPathsError.__module__
        == "evoom_guard.guard"
    )
    assert guard_module._TreeEntry.__bases__ == (object,)
    assert guard_module._TreeEntry.__mro__ == (
        guard_module._TreeEntry,
        object,
    )
    assert [field.name for field in dataclass_fields(guard_module._TreeEntry)] == [
        "full_path",
        "kind",
        "mode",
        "size",
        "link_target",
        "problem",
        "identity",
        "path_times",
    ]
    assert guard_module._TreeEntry.__annotations__ == {
        "full_path": "str",
        "kind": "str",
        "mode": "int | None",
        "size": "int | None",
        "link_target": "str | None",
        "problem": "str | None",
        "identity": "tuple[int, ...] | None",
        "path_times": "tuple[int, int] | None",
    }
    assert "__dataclass_fields__" in guard_module._TreeEntry.__dict__
    assert guard_module._TreeEntry.__init__.__qualname__ == "_TreeEntry.__init__"
    assert str(inspect.signature(guard_module._TreeEntry)) == (
        "(full_path: 'str', kind: 'str', mode: 'int | None', "
        "size: 'int | None', link_target: 'str | None' = None, "
        "problem: 'str | None' = None, identity: 'tuple[int, ...] | None' = None, "
        "path_times: 'tuple[int, int] | None' = None) -> None"
    )
    assert not issubclass(guard_module._TreeEntry, candidate_tree.TreeEntry)
    assert guard_module._TreeEntry is not candidate_tree.TreeEntry
    assert guard_module._UnverifiableChangedPathsError.__bases__ == (
        ValueError,
    )
    assert guard_module._UnverifiableChangedPathsError.__mro__ == (
        guard_module._UnverifiableChangedPathsError,
        ValueError,
        Exception,
        BaseException,
        object,
    )
    assert not issubclass(
        guard_module._UnverifiableChangedPathsError,
        candidate_tree.UnverifiableChangedPathsError,
    )
    assert (
        guard_module._UnverifiableChangedPathsError
        is not candidate_tree.UnverifiableChangedPathsError
    )
    entry = guard_module._TreeEntry(
        "tree/file.py",
        "regular",
        0o640,
        9,
        link_target=None,
        problem=None,
    )

    assert entry == guard_module._TreeEntry("tree/file.py", "regular", 0o640, 9)
    assert repr(entry) == (
        "_TreeEntry(full_path='tree/file.py', kind='regular', mode=416, "
        "size=9, link_target=None, problem=None, identity=None, "
        "path_times=None)"
    )
    with pytest.raises(FrozenInstanceError):
        entry.size = 10

    error = guard_module._UnverifiableChangedPathsError(
        [
            ("a.bin", "changed file is not valid UTF-8 text"),
            ("z", "new empty directory cannot be represented"),
        ]
    )
    assert error.problems == (
        ("a.bin", "changed file is not valid UTF-8 text"),
        ("z", "new empty directory cannot be represented"),
    )
    assert error.args == (
        "changed path(s) cannot be safely represented for verification "
        "(a.bin: changed file is not valid UTF-8 text; "
        "z: new empty directory cannot be represented)",
    )


def test_candidate_tree_exact_serialization_and_order_are_frozen(
    tmp_path: Path,
) -> None:
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / "same.txt").write_bytes(b"same\n")
    (head / "same.txt").write_bytes(b"same\n")
    (base / "gone.txt").write_bytes(b"gone\n")
    (head / "z.txt").write_bytes(b"last\n")
    (head / "a.txt").write_bytes(b"first\n")

    blocks, deleted = guard_module.blocks_from_dirs(str(base), str(head))
    candidate, candidate_deleted = guard_module.candidate_from_dirs(
        str(base),
        str(head),
    )

    assert blocks == {"a.txt": "first\n", "z.txt": "last\n"}
    assert deleted == ["gone.txt"]
    assert candidate_deleted == deleted
    assert candidate == (
        "<<<FILE: a.txt>>>\n"
        "first\n"
        "\n<<<END FILE>>>\n"
        "<<<FILE: z.txt>>>\n"
        "last\n"
        "\n<<<END FILE>>>"
    )
    assert guard_module.serialize_candidate_blocks(
        {"z.txt": "last\n", "a.txt": "first\n"}
    ) == candidate


def test_candidate_tree_reports_all_unrepresentable_paths_in_sorted_order(
    tmp_path: Path,
) -> None:
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (head / "z-empty").mkdir()
    (head / "a.bin").write_bytes(b"\xff\xfe")
    (head / "m-empty").mkdir()

    with pytest.raises(
        guard_module._UnverifiableChangedPathsError
    ) as raised:
        guard_module.blocks_from_dirs(str(base), str(head))

    assert raised.value.problems == (
        ("a.bin", "changed file is not valid UTF-8 text"),
        ("m-empty", "new empty directory cannot be represented"),
        ("z-empty", "new empty directory cannot be represented"),
    )
    assert str(raised.value) == (
        "changed path(s) cannot be safely represented for verification "
        "(a.bin: changed file is not valid UTF-8 text; "
        "m-empty: new empty directory cannot be represented; "
        "z-empty: new empty directory cannot be represented)"
    )


def test_changed_text_rejects_stale_size_metadata_above_limit() -> None:
    entry = guard_module._TreeEntry(
        "not-opened",
        "regular",
        0o644,
        101,
    )

    with pytest.raises(
        ValueError,
        match=r"changed file is 101 bytes, above the 100-byte limit",
    ):
        guard_module._read_changed_text(entry, 100)


def test_changed_text_rejects_growth_after_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "changed.txt"
    target.write_bytes(b"safe")
    entry = guard_module._tree_entry(str(target))

    monkeypatch.setattr(
        guard_module,
        "_read_fd_bounded",
        lambda _descriptor, maximum: b"x" * maximum,
    )

    with pytest.raises(
        ValueError,
        match=r"changed file grew above the 4-byte limit while being read",
    ):
        guard_module._read_changed_text(entry, 4)


def test_walk_tree_uses_current_copy_ignore_and_always_ignores_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for directory in ("first-cache", "second-cache", ".git"):
        child = tmp_path / directory
        child.mkdir()
        (child / "tracked.txt").write_text(directory, encoding="utf-8")
    (tmp_path / "visible.txt").write_text("visible", encoding="utf-8")

    monkeypatch.setattr(guard_module, "COPY_IGNORE", ("first-cache",))
    first = guard_module._walk_tree_entries(str(tmp_path))
    monkeypatch.setattr(guard_module, "COPY_IGNORE", ("second-cache",))
    second = guard_module._walk_tree_entries(str(tmp_path))
    monkeypatch.setattr(guard_module, "COPY_IGNORE", ())
    neither = guard_module._walk_tree_entries(str(tmp_path))

    assert "first-cache" not in first
    assert "second-cache/tracked.txt" in first
    assert "second-cache" not in second
    assert "first-cache/tracked.txt" in second
    assert "first-cache/tracked.txt" in neither
    assert "second-cache/tracked.txt" in neither
    assert not any(path == ".git" or path.startswith(".git/") for path in neither)


def test_walk_tree_ignores_gitfiles_at_every_depth(tmp_path: Path) -> None:
    (tmp_path / ".git").write_text("gitdir: ../root.git\n", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / ".git").write_text(
        "gitdir: ../../nested.git\n",
        encoding="utf-8",
    )
    (nested / "visible.txt").write_text("visible", encoding="utf-8")

    walked = guard_module._walk_tree_entries(str(tmp_path))

    assert ".git" not in walked
    assert "nested/.git" not in walked
    assert "nested/visible.txt" in walked


def test_gitfile_add_change_delete_is_invisible_without_hiding_git_names(
    tmp_path: Path,
) -> None:
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    for root in (base, head):
        for directory in ("added", "changed", "deleted"):
            (root / directory).mkdir()
        (root / ".gitignore").write_text(".cache/\n", encoding="utf-8")
        workflow = root / ".github" / "workflows"
        workflow.mkdir(parents=True)
        (workflow / "guard.yml").write_text("name: guard\n", encoding="utf-8")

    (base / ".git").write_text("gitdir: ../old.git\n", encoding="utf-8")
    (head / ".git").write_text("gitdir: ../new.git\n", encoding="utf-8")
    (head / "added" / ".git").write_text(
        "gitdir: ../../added.git\n",
        encoding="utf-8",
    )
    (base / "changed" / ".git").write_text(
        "gitdir: ../../changed-old.git\n",
        encoding="utf-8",
    )
    (head / "changed" / ".git").write_text(
        "gitdir: ../../changed-new.git\n",
        encoding="utf-8",
    )
    (base / "deleted" / ".git").write_text(
        "gitdir: ../../deleted.git\n",
        encoding="utf-8",
    )

    blocks, deleted = guard_module.blocks_from_dirs(str(base), str(head))
    walked = guard_module._walk_tree_entries(str(head))

    assert blocks == {}
    assert deleted == []
    assert ".gitignore" in walked
    assert ".github/workflows/guard.yml" in walked
    assert not any(path == ".git" or path.endswith("/.git") for path in walked)


def test_walk_error_resolves_private_entry_type_after_os_walk_starts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_type = guard_module._TreeEntry

    class LateTreeEntry(original_type):
        pass

    unreadable = tmp_path / "unreadable"

    def late_walk(
        _root: str,
        *,
        onerror: Any,
    ) -> list[tuple[str, list[str], list[str]]]:
        monkeypatch.setattr(guard_module, "_TreeEntry", LateTreeEntry)
        onerror(OSError(errno.EACCES, "access denied", str(unreadable)))
        return []

    monkeypatch.setattr(guard_module.os, "walk", late_walk)

    walked = guard_module._walk_tree_entries(str(tmp_path))

    assert type(walked["unreadable"]) is LateTreeEntry


def test_tree_entry_resolves_private_type_after_lstat_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "file.txt"
    target.write_text("payload", encoding="utf-8")
    original_type = guard_module._TreeEntry
    original_lstat = guard_module.os.lstat

    class LateTreeEntry(original_type):
        pass

    def lstat_and_rebind(path: str) -> Any:
        observed = original_lstat(path)
        monkeypatch.setattr(guard_module, "_TreeEntry", LateTreeEntry)
        return observed

    monkeypatch.setattr(guard_module.os, "lstat", lstat_and_rebind)

    entry = guard_module._tree_entry(str(target))

    assert type(entry) is LateTreeEntry


def test_walk_tree_resolves_tree_entry_through_live_guard_facade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "file.txt"
    target.write_text("payload", encoding="utf-8")
    calls: list[str] = []

    def late_tree_entry(path: str) -> Any:
        calls.append(path)
        return guard_module._TreeEntry(path, "regular", 0o600, 123)

    monkeypatch.setattr(guard_module, "_tree_entry", late_tree_entry)

    walked = guard_module._walk_tree_entries(str(tmp_path))

    assert calls == [str(target)]
    assert walked["file.txt"].size == 123


def test_tree_entry_resolves_private_entry_type_at_call_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "file.txt"
    target.write_text("payload", encoding="utf-8")
    original_type = guard_module._TreeEntry

    class LateTreeEntry(original_type):
        pass

    monkeypatch.setattr(guard_module, "_TreeEntry", LateTreeEntry)

    entry = guard_module._tree_entry(str(target))

    assert type(entry) is LateTreeEntry


def test_blocks_from_dirs_resolves_private_error_type_at_call_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_type = guard_module._UnverifiableChangedPathsError

    class LateUnverifiableChangedPathsError(original_type):
        pass

    monkeypatch.setattr(
        guard_module,
        "_UnverifiableChangedPathsError",
        LateUnverifiableChangedPathsError,
    )
    monkeypatch.setattr(
        guard_module,
        "_tree_entry",
        lambda path: guard_module._TreeEntry(
            path,
            "special",
            None,
            None,
            problem="late root rejection",
        ),
    )

    with pytest.raises(LateUnverifiableChangedPathsError):
        guard_module.blocks_from_dirs("base", "head")


def test_blocks_from_dirs_resolves_helpers_through_live_guard_facade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_entry = guard_module._TreeEntry("root", "directory", 0o755, None)
    base_entry = guard_module._TreeEntry("base/a.txt", "regular", 0o644, 3)
    head_entry = guard_module._TreeEntry("head/a.txt", "regular", 0o644, 3)
    walk_results = iter(({"a.txt": base_entry}, {"a.txt": head_entry}))
    timeline: list[str] = []

    def late_tree_entry(root: str) -> Any:
        timeline.append(f"root:{root}")
        return root_entry

    def late_walk(root: str) -> dict[str, Any]:
        timeline.append(f"walk:{root}")
        return next(walk_results)

    def late_compare(base: Any, head: Any) -> tuple[bool, str | None]:
        assert base is base_entry
        assert head is head_entry
        timeline.append("compare")
        return True, None

    def late_read(entry: Any, max_bytes: int) -> str:
        assert entry is head_entry
        timeline.append(f"read:{max_bytes}")
        return "late\n"

    monkeypatch.setattr(guard_module, "_tree_entry", late_tree_entry)
    monkeypatch.setattr(guard_module, "_walk_tree_entries", late_walk)
    monkeypatch.setattr(guard_module, "_entries_changed", late_compare)
    monkeypatch.setattr(guard_module, "_read_changed_text", late_read)

    blocks, deleted = guard_module.blocks_from_dirs(
        "base",
        "head",
        max_bytes=17,
    )

    assert blocks == {"a.txt": "late\n"}
    assert deleted == []
    assert timeline == [
        "root:base",
        "root:head",
        "walk:base",
        "walk:head",
        "compare",
        "read:17",
    ]


def test_blocks_from_dirs_resolves_later_helpers_after_walk_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_entry = guard_module._TreeEntry("root", "directory", 0o755, None)
    base_entry = guard_module._TreeEntry("base/a.txt", "regular", 0o644, 3)
    head_entry = guard_module._TreeEntry("head/a.txt", "regular", 0o644, 3)
    walk_results = iter(({"a.txt": base_entry}, {"a.txt": head_entry}))

    def late_compare(base: Any, head: Any) -> tuple[bool, str | None]:
        assert base is base_entry
        assert head is head_entry
        return False, "late comparison provider"

    def walk_and_rebind(_root: str) -> dict[str, Any]:
        result = next(walk_results)
        monkeypatch.setattr(guard_module, "_entries_changed", late_compare)
        return result

    def stale_compare(_base: Any, _head: Any) -> tuple[bool, str | None]:
        raise AssertionError("comparison provider was snapshotted before walking")

    monkeypatch.setattr(guard_module, "_tree_entry", lambda _root: root_entry)
    monkeypatch.setattr(guard_module, "_walk_tree_entries", walk_and_rebind)
    monkeypatch.setattr(guard_module, "_entries_changed", stale_compare)

    with pytest.raises(
        guard_module._UnverifiableChangedPathsError,
        match="late comparison provider",
    ):
        guard_module.blocks_from_dirs("base", "head")


def test_blocks_from_dirs_resolves_private_error_after_walk_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_entry = guard_module._TreeEntry("root", "directory", 0o755, None)
    empty_directory = guard_module._TreeEntry(
        "head/empty",
        "directory",
        0o755,
        None,
    )
    walk_results = iter(({}, {"empty": empty_directory}))
    original_type = guard_module._UnverifiableChangedPathsError

    class LateUnverifiableChangedPathsError(original_type):
        pass

    def walk_and_rebind(_root: str) -> dict[str, Any]:
        result = next(walk_results)
        monkeypatch.setattr(
            guard_module,
            "_UnverifiableChangedPathsError",
            LateUnverifiableChangedPathsError,
        )
        return result

    monkeypatch.setattr(guard_module, "_tree_entry", lambda _root: root_entry)
    monkeypatch.setattr(guard_module, "_walk_tree_entries", walk_and_rebind)

    with pytest.raises(LateUnverifiableChangedPathsError):
        guard_module.blocks_from_dirs("base", "head")


def test_candidate_from_dirs_resolves_facades_at_call_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timeline: list[Any] = []

    def late_blocks(
        base_dir: str,
        head_dir: str,
        *,
        max_bytes: int,
    ) -> tuple[dict[str, str], list[str]]:
        timeline.append(("blocks", base_dir, head_dir, max_bytes))
        return {"late.py": "VALUE = 1\n"}, ["old.py"]

    def late_serialize(blocks: dict[str, str]) -> str:
        timeline.append(("serialize", blocks))
        return "late-candidate"

    monkeypatch.setattr(guard_module, "blocks_from_dirs", late_blocks)
    monkeypatch.setattr(
        guard_module,
        "serialize_candidate_blocks",
        late_serialize,
    )

    result = guard_module.candidate_from_dirs("base", "head", max_bytes=23)

    assert result == ("late-candidate", ["old.py"])
    assert timeline == [
        ("blocks", "base", "head", 23),
        ("serialize", {"late.py": "VALUE = 1\n"}),
    ]


def test_candidate_from_dirs_resolves_serializer_after_derivation_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def late_serialize(_blocks: dict[str, str]) -> str:
        return "late-serialization"

    def blocks_and_rebind(
        _base_dir: str,
        _head_dir: str,
        *,
        max_bytes: int,
    ) -> tuple[dict[str, str], list[str]]:
        assert max_bytes == 29
        monkeypatch.setattr(
            guard_module,
            "serialize_candidate_blocks",
            late_serialize,
        )
        return {"late.py": "VALUE = 1\n"}, []

    def stale_serialize(_blocks: dict[str, str]) -> str:
        raise AssertionError("serializer was snapshotted before derivation")

    monkeypatch.setattr(guard_module, "blocks_from_dirs", blocks_and_rebind)
    monkeypatch.setattr(
        guard_module,
        "serialize_candidate_blocks",
        stale_serialize,
    )

    assert guard_module.candidate_from_dirs(
        "base",
        "head",
        max_bytes=29,
    ) == ("late-serialization", [])
