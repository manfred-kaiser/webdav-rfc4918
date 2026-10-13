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


@pytest.mark.parametrize(
    "authority", ["h:²", "h:٣٠", "[::1]:٨٠", "h:1_0", "h:+80", "h:8 0"]
)
def test_EXC06_a_port_is_ascii_digits(authority: str) -> None:
    from webdav._webdavs_url import host_and_port

    with pytest.raises(ValueError, match="host"):
        host_and_port(authority)


@pytest.mark.parametrize(
    ("authority", "expected"),
    [("h:80", ("h", 80)), ("[::1]:8080", ("::1", 8080)), ("h", ("h", None))],
)
def test_EXC06_guard_ordinary_authorities(
    authority: str, expected: "tuple[str, int | None]"
) -> None:
    from webdav._webdavs_url import host_and_port

    assert host_and_port(authority) == expected
