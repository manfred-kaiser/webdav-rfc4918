"""Compliance check against a real Nextcloud instance - core RFC 4918 surface only.

Runs as its own GitHub Actions workflow (.github/workflows/nextcloud-compliance.yml,
separate from ci.yml/apache-compliance.yml/nginx-compliance.yml - see
docs/nextcloud-compliance-check.md). Nextcloud is one of the most common
real-world WebDAV deployments this library's users point it at, so this
is worth its own cross-check - but deliberately scoped to what RFC 4918
itself defines: no Nextcloud/ownCloud-namespaced properties (``oc:``/
``nc:``), no chunked-upload endpoint, no OCS/share APIs, no public-share
token-as-username auth convention. None of that is tested here; it is a
separate, later decision if ever wanted.

Several of the tests below exercise real-world interop problems other
Python WebDAV clients (webdav4, webdavclient3) have hit against real
Nextcloud servers (found via a search of their issue trackers, not
invented) - each test names the upstream issue it is checking this
library against.

Skipped only when no Nextcloud is reachable: with
``WEBDAV_TEST_NEXTCLOUD_URL`` set, these tests run against that (possibly
remote) instance; otherwise, if Docker is usable (see
``tests/nextcloud_instance.py``), a throwaway instance is started and
stopped automatically.
"""

import io
import os
from collections.abc import Iterator

import pytest

from tests import nextcloud_instance
from webdav import FileSystem, ResourceAlreadyExistsError, WebDAVError
from webdav.dav.locks import EXCLUSIVE

_ENV_URL = os.environ.get("WEBDAV_TEST_NEXTCLOUD_URL")
_MISSING = [] if _ENV_URL else nextcloud_instance.missing_prerequisites()

pytestmark = [
    pytest.mark.skipif(
        bool(_MISSING),
        reason=(
            "no Nextcloud reachable: set WEBDAV_TEST_NEXTCLOUD_URL to point at an "
            "existing instance, or install what's missing for a local "
            "throwaway one: " + ", ".join(_MISSING)
        ),
    ),
    # One shared instance/account per session - pin every test here to one
    # xdist worker, same reason and mechanism as the Apache/nginx suites.
    pytest.mark.xdist_group(name="nextcloud"),
]


class _Nextcloud:
    """Where the instance this test session uses lives - set once, by ``_nextcloud_session`` below."""

    url: "str | None" = None
    auth: "tuple[str, str]" = (nextcloud_instance.TEST_USER, nextcloud_instance.TEST_PASSWORD)


@pytest.fixture(scope="session", autouse=True)
def _nextcloud_session() -> Iterator[None]:
    """Point ``_Nextcloud`` at a usable instance: the one given by env, or a throwaway one started here."""
    if _ENV_URL:
        _Nextcloud.url = _ENV_URL
        _Nextcloud.auth = (
            os.environ.get("WEBDAV_TEST_NEXTCLOUD_USER", nextcloud_instance.TEST_USER),
            os.environ.get(
                "WEBDAV_TEST_NEXTCLOUD_PASSWORD", nextcloud_instance.TEST_PASSWORD
            ),
        )
        yield
        return
    nextcloud_instance.start()
    _Nextcloud.url = (
        f"http://{nextcloud_instance.HOST}:{nextcloud_instance.PORT}"
        f"/remote.php/dav/files/{nextcloud_instance.TEST_USER}"
    )
    try:
        yield
    finally:
        nextcloud_instance.stop()


@pytest.fixture
def nc_client() -> Iterator[FileSystem]:
    assert _Nextcloud.url is not None  # set by _nextcloud_session above
    with FileSystem(_Nextcloud.url, auth=_Nextcloud.auth) as c:
        yield c


# ---------------------------------------------------------------------------
# Baseline: core RFC 4918 surface
# ---------------------------------------------------------------------------


def test_nextcloud_advertises_class_1_but_not_class_2(nc_client: FileSystem) -> None:
    """Nextcloud's SabreDAV-based WebDAV endpoint never registers a LOCK plugin.

    Pinned as a documented, long-standing limitation (confirmed against a
    real instance, not assumed) - a future Nextcloud release that adds
    Class 2 support would turn this red, which is exactly the point of
    having it here rather than silently assuming the gap stays forever.
    """
    compliances = nc_client.dav_compliance()
    assert "1" in compliances
    assert "2" not in compliances


def test_nextcloud_lock_fails_with_a_clean_webdaverror(nc_client: FileSystem) -> None:
    """A caller who doesn't know about the Class 2 gap still gets a sane, catchable error (501), not a crash."""
    nc_client.upload_fileobj(io.BytesIO(b"x"), "lock-attempt.txt")
    with pytest.raises(WebDAVError), nc_client.locked("lock-attempt.txt", scope=EXCLUSIVE):
        pass


def test_nextcloud_mkdir_upload_download_roundtrip(nc_client: FileSystem) -> None:
    nc_client.mkdir("compliance")
    nc_client.upload_fileobj(io.BytesIO(b"nextcloud says hi"), "compliance/a.txt")

    buf = io.BytesIO()
    nc_client.download_fileobj("compliance/a.txt", buf)
    assert buf.getvalue() == b"nextcloud says hi"


def test_nextcloud_move_and_copy_roundtrip(nc_client: FileSystem) -> None:
    nc_client.upload_fileobj(io.BytesIO(b"v1"), "compliance/src.txt")
    nc_client.copy("compliance/src.txt", "compliance/copied.txt")
    nc_client.move("compliance/copied.txt", "compliance/moved.txt")

    buf = io.BytesIO()
    nc_client.download_fileobj("compliance/moved.txt", buf)
    assert buf.getvalue() == b"v1"
    assert not nc_client.exists("compliance/copied.txt")


def test_nextcloud_overwrite_protection(nc_client: FileSystem) -> None:
    """Overwrite=False uses If-None-Match against Nextcloud's real ETag, not just wsgidav's/Apache's."""
    nc_client.upload_fileobj(io.BytesIO(b"v1"), "compliance/protected.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        nc_client.upload_fileobj(
            io.BytesIO(b"v2"), "compliance/protected.txt", overwrite=False
        )


def test_nextcloud_standard_dav_properties(nc_client: FileSystem) -> None:
    """Only ``DAV:`` properties - no ``oc:``/``nc:`` namespace, by design (see module docstring)."""
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/props.txt")
    props = nc_client.get_props(
        "compliance/props.txt",
        props=["etag", "modified", "content_length", "resourcetype"],
    )
    assert props.etag is not None
    assert props.modified is not None
    assert props.content_length == 1
    assert props.collection is False


def test_nextcloud_custom_property_round_trips(nc_client: FileSystem) -> None:
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/customprop.txt")
    nc_client.set_props(
        "compliance/customprop.txt",
        set_props={("https://example.org/ns", "color"): "blue"},
    )
    props = nc_client.get_props(
        "compliance/customprop.txt", props=[("https://example.org/ns", "color")]
    )
    assert props.text("https://example.org/ns", "color") == "blue"


# ---------------------------------------------------------------------------
# Interop regressions found in other Python WebDAV clients' issue trackers
# ---------------------------------------------------------------------------


def test_nextcloud_filename_with_hash_round_trips(nc_client: FileSystem) -> None:
    """webdavclient3#163: an unescaped '#' in a server-returned href must not be read as a URL fragment."""
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/with#hash.txt")
    assert nc_client.exists("compliance/with#hash.txt")
    buf = io.BytesIO()
    nc_client.download_fileobj("compliance/with#hash.txt", buf)
    assert buf.getvalue() == b"x"


def test_nextcloud_non_ascii_filename_move_and_delete(nc_client: FileSystem) -> None:
    """webdavclient3#40: a Cyrillic filename crashed that library's MOVE/DELETE with a latin-1 codec error."""
    name = "compliance/файл-théta.txt"
    nc_client.upload_fileobj(io.BytesIO(b"x"), name)
    nc_client.move(name, "compliance/файл-moved.txt")
    assert nc_client.exists("compliance/файл-moved.txt")
    nc_client.remove("compliance/файл-moved.txt")
    assert not nc_client.exists("compliance/файл-moved.txt")


def test_nextcloud_path_with_special_characters_round_trips(
    nc_client: FileSystem,
) -> None:
    """webdavclient3#108: parentheses (and other characters needing percent-encoding) in a path."""
    nc_client.mkdir("compliance/special (2026) & more+stuff")
    nc_client.upload_fileobj(
        io.BytesIO(b"x"), "compliance/special (2026) & more+stuff/a.txt"
    )
    buf = io.BytesIO()
    nc_client.download_fileobj("compliance/special (2026) & more+stuff/a.txt", buf)
    assert buf.getvalue() == b"x"
