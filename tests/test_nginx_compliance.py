"""Compliance check against a real nginx + dav-ext server - a second, differently limited Class 2.

Runs as its own GitHub Actions workflow (.github/workflows/nginx-compliance.yml,
separate from ci.yml and apache-compliance.yml - see
docs/nginx-compliance-check.md) - nginx's own ``ngx_http_dav_module`` plus
``nginx-dav-ext-module`` is a real, independent WebDAV implementation,
useful here specifically because it only implements *exclusive* locks
(RFC 4918 sec. 7's shared-lock support is simply not there), unlike Apache
(tested in ``test_apache_compliance.py``) and wsgidav (the main suite),
which both support both lock scopes. Skipped only when no nginx is
reachable: with ``WEBDAV_TEST_NGINX_URL`` set, these tests run against
that (possibly remote) instance; otherwise, if a local nginx + dav-ext
install is found (see ``tests/nginx_instance.py``), a throwaway instance
is started and stopped automatically.
"""

import io
import os
from collections.abc import Iterator
from pathlib import Path
from tempfile import gettempdir

import pytest

from tests import nginx_instance
from webdav import (
    FileSystem,
    ResourceAlreadyExistsError,
    ResourceLockedError,
    WebDAVError,
)
from webdav.dav.locks import EXCLUSIVE, SHARED

_ENV_URL = os.environ.get("WEBDAV_TEST_NGINX_URL")
_MISSING = [] if _ENV_URL else nginx_instance.missing_prerequisites()

pytestmark = [
    pytest.mark.skipif(
        bool(_MISSING),
        reason=(
            "no nginx+dav-ext reachable: set WEBDAV_TEST_NGINX_URL to point at an "
            "existing instance, or install what's missing for a local "
            "throwaway one: " + ", ".join(_MISSING)
        ),
    ),
    # One shared instance/dav-root per session (not test-isolated like
    # wsgidav's tmp_path) - pin every test here to one xdist worker, same
    # reason and mechanism as test_apache_compliance.py's own xdist_group.
    pytest.mark.xdist_group(name="nginx"),
]


class _Nginx:
    """Where the instance this test session uses lives - set once, by ``_nginx_session`` below."""

    url: "str | None" = None
    auth: "tuple[str, str]" = (nginx_instance.TEST_USER, nginx_instance.TEST_PASSWORD)


@pytest.fixture(scope="session", autouse=True)
def _nginx_session() -> Iterator[None]:
    """Point ``_Nginx`` at a usable instance: the one given by env, or a throwaway one started here."""
    if _ENV_URL:
        _Nginx.url = _ENV_URL
        _Nginx.auth = (
            os.environ.get("WEBDAV_TEST_NGINX_USER", nginx_instance.TEST_USER),
            os.environ.get(
                "WEBDAV_TEST_NGINX_PASSWORD", nginx_instance.TEST_PASSWORD
            ),
        )
        yield
        return
    instance_dir = Path(gettempdir()) / "webdav-rfc4918-nginx-test"
    conf_file = nginx_instance.write_instance(instance_dir)
    nginx_instance.start(conf_file)
    _Nginx.url = f"http://{nginx_instance.HOST}:{nginx_instance.PORT}"
    try:
        yield
    finally:
        nginx_instance.stop(conf_file)


@pytest.fixture
def nginx_client() -> Iterator[FileSystem]:
    assert _Nginx.url is not None  # set by _nginx_session above
    with FileSystem(_Nginx.url, auth=_Nginx.auth) as c:
        yield c


# ---------------------------------------------------------------------------
# Baseline: a second, independent Class 2 implementation
# ---------------------------------------------------------------------------


def test_nginx_advertises_class_2(nginx_client: FileSystem) -> None:
    compliances = nginx_client.dav_compliance()
    assert "1" in compliances
    assert "2" in compliances, "server does not advertise Class 2 (locking) support"


def test_nginx_mkdir_upload_download_roundtrip(nginx_client: FileSystem) -> None:
    nginx_client.mkdir("compliance")
    nginx_client.upload_fileobj(io.BytesIO(b"nginx says hi"), "compliance/a.txt")

    buf = io.BytesIO()
    nginx_client.download_fileobj("compliance/a.txt", buf)
    assert buf.getvalue() == b"nginx says hi"


def test_nginx_move_and_copy_roundtrip(nginx_client: FileSystem) -> None:
    nginx_client.upload_fileobj(io.BytesIO(b"v1"), "compliance/src.txt")
    nginx_client.copy("compliance/src.txt", "compliance/copied.txt")
    nginx_client.move("compliance/copied.txt", "compliance/moved.txt")

    buf = io.BytesIO()
    nginx_client.download_fileobj("compliance/moved.txt", buf)
    assert buf.getvalue() == b"v1"
    assert not nginx_client.exists("compliance/copied.txt")


def test_nginx_overwrite_protection(nginx_client: FileSystem) -> None:
    nginx_client.upload_fileobj(io.BytesIO(b"v1"), "compliance/protected.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        nginx_client.upload_fileobj(
            io.BytesIO(b"v2"), "compliance/protected.txt", overwrite=False
        )


# ---------------------------------------------------------------------------
# Locking: exclusive works, shared is the one thing this server cannot do
# ---------------------------------------------------------------------------


def test_nginx_exclusive_lock_and_write_with_held_token(
    nginx_client: FileSystem,
) -> None:
    nginx_client.upload_fileobj(io.BytesIO(b"v1"), "compliance/locked.txt")

    with nginx_client.locked("compliance/locked.txt", scope=EXCLUSIVE):
        nginx_client.upload_fileobj(
            io.BytesIO(b"v2"), "compliance/locked.txt", overwrite=True
        )

    buf = io.BytesIO()
    nginx_client.download_fileobj("compliance/locked.txt", buf)
    assert buf.getvalue() == b"v2"


def test_nginx_exclusive_lock_blocks_a_second_client(nginx_client: FileSystem) -> None:
    nginx_client.upload_fileobj(io.BytesIO(b"v1"), "compliance/locked2.txt")

    assert _Nginx.url is not None  # set by _nginx_session above
    other = FileSystem(_Nginx.url, auth=_Nginx.auth)
    try:
        with (
            nginx_client.locked("compliance/locked2.txt", scope=EXCLUSIVE),
            pytest.raises(ResourceLockedError),
        ):
            other.upload_fileobj(
                io.BytesIO(b"v2"), "compliance/locked2.txt", overwrite=True
            )
    finally:
        other.close()


def test_nginx_does_not_support_shared_locks(nginx_client: FileSystem) -> None:
    """nginx-dav-ext only implements exclusive locks (RFC 4918 sec. 7 shared locks: absent).

    Pinned as a documented limitation of this server, not a client-side
    assumption - a future nginx-dav-ext release that adds shared-lock
    support would turn this test red, which is exactly the point of
    having it here rather than silently assuming the gap stays forever.
    """
    nginx_client.upload_fileobj(io.BytesIO(b"v1"), "compliance/shared.txt")
    with (
        pytest.raises(WebDAVError),
        nginx_client.locked("compliance/shared.txt", scope=SHARED),
    ):
        pass
