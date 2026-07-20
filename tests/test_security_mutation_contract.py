"""Small direct contracts used by the deterministic security mutation gate."""

from evoom_guard.verifiers.repo_verifier import _BoundedOutput


def test_bounded_output_marks_any_truncated_bytes_as_exceeded() -> None:
    capture = _BoundedOutput(limit=4)

    capture.append("stdout", b"12345")

    assert capture.exceeded is True
    assert capture.text("stdout") == "1234"
