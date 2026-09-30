"""``is_url`` and ``display_url`` - the rest of ``webdav.url_safety`` is tested in
``test_redirect_hardening.py`` and ``test_properties.py``."""

import pytest

from webdav.url_safety import display_url, is_url


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://dav.example/a", True),
        ("HTTP://dav.example", True),
        ("ftp://dav.example/a", True),
        ("/a/b", False),
        ("a/b", False),
        ("dav.example:8080/a", False),
        ("", False),
        ("//dav.example/a", False),
    ],
)
def test_is_url(value: str, expected: bool) -> None:
    assert is_url(value) is expected


def test_a_url_is_shown_without_its_secrets() -> None:
    shown = display_url("https://user:pw@dav.example/a?sig=SECRET#frag")
    assert shown == "https://dav.example/a"


def test_a_plain_path_is_shown_as_it_is() -> None:
    assert display_url("/docs/a b.txt") == "/docs/a b.txt"
