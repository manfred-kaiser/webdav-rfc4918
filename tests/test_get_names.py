"""What ``get`` writes from the names a server lists: Windows names and names that are one file."""

# ruff: noqa: SIM117, PLC0415

import errno
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.credentials import AUTH
from tests.scripted_server import Reply, Seen, always, scripted_server
from webdav import FileSystem, _fsspec_guards
from webdav.fsspec import WebdavFileSystem


def _listing(*names: str) -> bytes:
    entries = "".join(
        f"<d:response><d:href>/dir/{n}</d:href><d:propstat><d:prop><d:resourcetype/>"
        "<d:getcontentlength>2</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK"
        "</d:status></d:propstat></d:response>"
        for n in names
    )
    return (
        '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/dir/</d:href>'
        "<d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>"
        f"<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>{entries}</d:multistatus>"
    ).encode()


def _server(*names: str):  # noqa: ANN202
    def respond(seen: Seen) -> Reply:
        if seen.method == "PROPFIND":
            return 207, {"Content-Type": "application/xml"}, _listing(*names)
        if seen.method == "GET":
            return 200, {}, b"hi"
        return 404, {}, b""

    return scripted_server(respond)


@pytest.mark.parametrize("name", ["CON", "nul.txt", "a:b", "trail.", "COM1"])
def test_windows_refuses_what_is_not_a_windows_file_name(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_fsspec_guards, "_on_windows", lambda: True)
    with _server(name) as (url, _):
        with pytest.raises(OSError, match="Windows") as caught:
            WebdavFileSystem(url).get("/dir", str(tmp_path / "dst"), recursive=True)
    assert caught.value.errno == errno.EINVAL
    assert (
        not list((tmp_path / "dst").rglob("*")) if (tmp_path / "dst").exists() else True
    )


def test_windows_accepts_a_plain_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_fsspec_guards, "_on_windows", lambda: True)
    with _server("ok.txt") as (url, _):
        WebdavFileSystem(url).get("/dir", str(tmp_path / "dst"), recursive=True)
    assert (tmp_path / "dst" / "ok.txt").read_bytes() == b"hi"


@pytest.mark.parametrize("name", ["CON", "a:b", "back\\slash"])
def test_other_platforms_keep_these_names(name: str, tmp_path: Path) -> None:
    """On Linux and macOS a colon or a backslash is an ordinary character; ``CON`` a name."""
    if os.name == "nt":
        pytest.skip("Windows")
    with _server(name) as (url, _):
        WebdavFileSystem(url).get("/dir", str(tmp_path / "dst"), recursive=True)
    assert (tmp_path / "dst" / name).read_bytes() == b"hi"


def test_two_names_that_are_one_file_are_not_written_over_each_other(
    tmp_path: Path,
) -> None:
    """A hard link stands in for a case-insensitive file system: ``B`` is the file ``A``."""
    dst = tmp_path / "dst"
    dst.mkdir()
    first = dst / "a.txt"
    tree = _fsspec_guards.GetTree(str(dst), contained=True)
    first.write_bytes(b"first")
    tree.record(str(first))
    (dst / "A.TXT").hardlink_to(first)
    with pytest.raises(OSError, match="same file") as caught:
        tree.check(str(dst / "A.TXT"))
    assert caught.value.errno == errno.EEXIST
    tree.check(str(dst / "other.txt"))


def test_FS03_safe_local_name_on_posix() -> None:
    from webdav.resource import safe_local_name

    assert safe_local_name("dir/sub/file.txt") == "file.txt"
    assert safe_local_name("dir/sub/") == "sub"
    # a backslash, a colon and a leading dash are ordinary POSIX names
    for name in ("a\\b.txt", "a:b", "-rf", "~", ".bashrc"):
        assert safe_local_name(name) == name


@pytest.mark.parametrize(
    "name", ["", "/", ".", "..", "a\x00b", "x\ny", "\x1b[31mred", "a\x7fb"]
)
def test_FS03_safe_local_name_refuses_what_no_platform_can_use(name: str) -> None:
    from webdav.resource import safe_local_name

    with pytest.raises(ValueError, match="not usable"):
        safe_local_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "CON",
        "con.txt",
        "NUL",
        "com1",
        "LPT9.log",
        "a:evil",
        "a\\b",
        "trail.",
        "trail ",
        'a"b',
        "a*b",
        "a?b",
    ],
)
def test_FS03_safe_local_name_on_windows(name: str) -> None:
    from webdav.resource import safe_local_name

    with pytest.raises(ValueError, match="not usable on Windows"):
        safe_local_name(name, windows=True)


def test_FS03_guard_ordinary_names_on_windows() -> None:
    from webdav.resource import safe_local_name

    for name in ("report.txt", "Straße.txt", "console.txt", "日本語.md", "a b.txt"):
        assert safe_local_name(name, windows=True) == name


def test_FS03_the_message_escapes_the_server_name() -> None:
    from webdav.resource import safe_local_name

    with pytest.raises(ValueError) as caught:
        safe_local_name("\x1b[2Jfake\x00", windows=False)
    assert "\x1b" not in str(caught.value)


def test_FS03_resource_basename() -> None:
    from webdav import Resource

    r = Resource("dir/sub/a\\b.txt", href="/dir/sub/a%5Cb.txt", is_dir=False)
    assert r.basename == "a\\b.txt"
    assert Resource("dir/sub", href="/dir/sub/", is_dir=True).basename == "sub"


def test_FS03_windows_rules_are_not_on_by_themselves() -> None:
    from webdav.resource import safe_local_name

    assert (
        safe_local_name("CON") == "CON"
    )  # only windows=True refuses it, whatever os.name is
    assert safe_local_name("trail.") == "trail."


def test_FS03_prepared_windows_name_check(tmp_path: Path) -> None:
    from webdav._fsspec_guards import GetTree

    tree = GetTree(str(tmp_path), contained=True)
    tree.check_windows_names(str(tmp_path / "ok" / "a.txt"))
    with pytest.raises(OSError, match="not usable on Windows"):
        tree.check_windows_names(str(tmp_path / "d" / "CON"))


def test_FS03_prepared_collision_check(tmp_path: Path) -> None:
    from webdav._fsspec_guards import GetTree

    (tmp_path / "a.txt").write_bytes(b"x")
    os.link(
        tmp_path / "a.txt", tmp_path / "A.TXT"
    )  # what the two are where case is folded
    tree = GetTree(str(tmp_path), contained=True)
    tree.record(str(tmp_path / "a.txt"))
    with pytest.raises(OSError, match="same file"):
        tree.check_collision(str(tmp_path / "A.TXT"))
    tree.check_collision(
        str(tmp_path / "a.txt")
    )  # the same name again is not a collision


@pytest.fixture
def ffs(server_url: str) -> Iterator[WebdavFileSystem]:
    filesystem = WebdavFileSystem(server_url, auth=AUTH)
    yield filesystem
    filesystem.filesystem.close()


def test_FS03_get_does_not_enforce_platform_name_rules(
    ffs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    ffs.pipe_file("/d/CON", b"x")
    ffs.pipe_file("/d/Case.TXT", b"4")
    ffs.pipe_file("/d/case.txt", b"5")
    dst = tmp_path_factory.mktemp("get") / "dst"
    ffs.get("/d/", str(dst), recursive=True)
    assert sorted(p.name for p in dst.iterdir()) == ["CON", "Case.TXT", "case.txt"]


def test_FS03_guard_posix_names_download_as_they_are(
    ffs: WebdavFileSystem, tmp_path_factory: pytest.TempPathFactory
) -> None:
    ffs.pipe_file("/d/a\\b.txt", b"1")
    ffs.pipe_file("/d/c:d", b"2")
    ffs.pipe_file("/d/-rf", b"3")
    ffs.pipe_file("/d/Case.TXT", b"4")
    ffs.pipe_file("/d/case.txt", b"5")
    dst = tmp_path_factory.mktemp("get") / "dst"
    ffs.get("/d/", str(dst), recursive=True)
    assert sorted(p.name for p in dst.iterdir()) == sorted(
        ["a\\b.txt", "c:d", "-rf", "Case.TXT", "case.txt"]
    )


_MS = '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">{}</d:multistatus>'


def _multistatus_ls(*hrefs: str) -> bytes:
    rows = "".join(
        f"<d:response><d:href>{h}</d:href><d:propstat><d:prop><d:resourcetype>"
        f"{'<d:collection/>' if h.endswith('/') else ''}</d:resourcetype></d:prop>"
        f"<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        for h in hrefs
    )
    return _MS.format(rows).encode()


def test_a_backslash_in_a_name_is_an_ordinary_character_on_posix() -> None:
    import os

    if os.name == "nt":
        pytest.skip("a backslash separates paths on Windows")
    body = _multistatus_ls("/d/", "/d/a%5Cb.txt", "/d/c\\d.txt")
    with scripted_server(always((207, {}, body))) as (url, _rec):
        assert sorted(FileSystem(retry=False).ls(f"{url}/d")) == [
            "d/a\\b.txt",
            "d/c\\d.txt",
        ]
