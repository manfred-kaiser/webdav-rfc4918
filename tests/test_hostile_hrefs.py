"""A server that lists a name outside the folder it was asked about writes nothing outside the destination."""

from pathlib import Path

import pytest

from tests.scripted_server import Reply, Seen, scripted_server
from webdav.exceptions import MalformedResponseError
from webdav.fs import FileSystem
from webdav.fsspec import WebdavFileSystem

HOSTILE = [
    "/../../etc/passwd",
    "/dir/../secret.txt",
    "/other/x.txt",
    "http://evil.example/x.txt",
    "/dir/..%2F..%2Fx.txt",
    "/dir/%2e%2e/y.txt",
    "/dir/nul%00.txt",
    "/dir/%2e%2e",
    "/dir/..",
    "/dir/%2e%2e%2f%2e%2e%2fz",
    "/dir/a%2Fb.txt",
    "/dir/a%0Ab.txt",
]

#: Listed (a newline is a legal name on Linux), but never written.
NOT_WRITTEN = ["/dir/a%0Ab.txt"]


def _doc(href: str) -> bytes:
    return (
        '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/dir/</d:href>'
        "<d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        f"<d:response><d:href>{href}</d:href><d:propstat><d:prop><d:resourcetype/>"
        "<d:getcontentlength>2</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK"
        "</d:status></d:propstat></d:response></d:multistatus>"
    ).encode()


def _respond(href: str):  # noqa: ANN202
    def respond(seen: Seen) -> Reply:
        if seen.method == "PROPFIND":
            return 207, {"Content-Type": "application/xml"}, _doc(href)
        if seen.method == "GET":
            return 200, {}, b"hi"
        return 404, {}, b""

    return respond


@pytest.mark.parametrize("href", [h for h in HOSTILE if h not in NOT_WRITTEN])
def test_the_listing_of_a_folder_refuses_a_name_outside_it(href: str) -> None:
    with scripted_server(_respond(href)) as (url, _), FileSystem(url) as fs:
        with pytest.raises(MalformedResponseError):
            fs.ls("/dir")


@pytest.mark.parametrize("href", HOSTILE)
def test_get_writes_nothing_outside_the_destination_and_asks_for_nothing_outside(
    href: str, tmp_path: Path
) -> None:
    dst = tmp_path / "work" / "dst"
    with scripted_server(_respond(href)) as (url, recorder):
        try:
            WebdavFileSystem(url).get("/dir", str(dst), recursive=True)
        except (OSError, MalformedResponseError):
            pass
    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert all(dst in p.parents for p in written), written
    assert all(
        seen.path.startswith("/dir")
        for seen in recorder.requests
        if seen.method == "GET"
    )


def test_a_plain_name_is_listed_and_written(tmp_path: Path) -> None:
    with scripted_server(_respond("/dir/ok.txt")) as (url, _):
        names = [r.name for r in FileSystem(url).ls("/dir")]
        WebdavFileSystem(url).get("/dir", str(tmp_path / "dst"), recursive=True)
    assert names == ["dir/ok.txt"]
    assert (tmp_path / "dst" / "ok.txt").read_bytes() == b"hi"


def test_a_name_with_a_control_character_is_not_written(tmp_path: Path) -> None:
    with scripted_server(_respond("/dir/a%0Ab.txt")) as (url, _):
        with pytest.raises(OSError, match="not usable"):
            WebdavFileSystem(url).get("/dir", str(tmp_path / "dst"), recursive=True)
    assert not [p for p in tmp_path.rglob("*") if p.is_file()]
