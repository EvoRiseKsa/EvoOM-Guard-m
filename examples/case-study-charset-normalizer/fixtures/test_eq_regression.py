from charset_normalizer.api import from_bytes


def test_direct_cmp_charset_match():
    best_guess = from_bytes(
        "\U0001f600 Hello World! How affairs are going? \U0001f600".encode("utf_8")
    ).best()

    assert best_guess == "utf_8"
    assert best_guess == "utf-8"
    assert best_guess != 8
    assert best_guess != None  # noqa: E711
