"""Corners found in review: Content-Range units, MKCOL answered 405, a private test directory."""

import os
from pathlib import Path

import pytest

from tests.instance_dir import ensure_private_dir
from tests.scripted_server import Reply, Seen, scripted_server
from webdav import FileSystem
from webdav.exceptions import HTTPStatusError, ResourceAlreadyExistsError
from webdav.transport.parse_utils import parse_content_range


@pytest.mark.parametrize("unit", ["bytes", "Bytes", "BYTES"])
def test_the_range_unit_is_case_insensitive(unit: str) -> None:
    assert parse_content_range(f"{unit} 0-9/10") == (0, 9, 10)


def test_another_unit_is_not_a_byte_range() -> None:
    assert parse_content_range("items 0-9/10") is None


_MULTISTATUS = (
    b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/d/</d:href>'
    b"<d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>"
    b"<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
)


def _mkcol_405(propfind: Reply):  # noqa: ANN202
    def respond(seen: Seen) -> Reply:
        if seen.method == "MKCOL":
            return 405, {}, b""
        return propfind

    return respond


def test_mkcol_405_is_already_exists_when_the_resource_is_there() -> None:
    reply = (207, {"Content-Type": "application/xml"}, _MULTISTATUS)
    with (
        scripted_server(_mkcol_405(reply)) as (url, _),
        FileSystem(url, retry=False) as fs,
    ):
        with pytest.raises(ResourceAlreadyExistsError):
            fs.mkdir("/d")


@pytest.mark.parametrize("status", [401, 403, 500])
def test_mkcol_405_stays_already_exists_when_the_server_will_not_say(
    status: int,
) -> None:
    """A server that answers MKCOL 405 (it is mapped) and refuses PROPFIND: ``exist_ok`` must still work."""
    with scripted_server(_mkcol_405((status, {}, b""))) as (url, _):
        with (
            FileSystem(url, retry=False) as fs,
            pytest.raises(ResourceAlreadyExistsError),
        ):
            fs.mkdir("/d")


def test_mkcol_405_is_not_already_exists_when_the_resource_is_missing() -> None:
    """A read-only server answers 405 for everything."""
    with scripted_server(_mkcol_405((404, {}, b""))) as (url, _):
        with (
            FileSystem(url, retry=False) as fs,
            pytest.raises(HTTPStatusError) as caught,
        ):
            fs.mkdir("/d")
    assert caught.value.status_code == 405


@pytest.mark.skipif(not hasattr(os, "getgid"), reason="POSIX owner and mode")
def test_a_directory_with_the_callers_group_writable_is_fine(tmp_path: Path) -> None:
    """``mkdir`` leaves 0775 under ``umask 002``, the default of several distributions."""
    target = tmp_path / "instance"
    target.mkdir()
    target.chmod(0o770)
    ensure_private_dir(target)


@pytest.mark.skipif(not hasattr(os, "getgid"), reason="POSIX owner and mode")
def test_a_directory_others_can_write_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "instance"
    target.mkdir()
    target.chmod(0o707)
    with pytest.raises(RuntimeError, match="writable by others"):
        ensure_private_dir(target)
