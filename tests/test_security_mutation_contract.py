"""Small direct contracts used by the deterministic security mutation gate."""

from evoom_guard.execution import BoundedOutput


def test_bounded_output_marks_any_truncated_bytes_as_exceeded() -> None:
    capture = BoundedOutput(limit=4)

    capture.append("stdout", b"12345")

    assert capture.exceeded is True
    assert capture.text("stdout") == "1234"
