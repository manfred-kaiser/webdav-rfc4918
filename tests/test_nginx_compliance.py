"""Compliance check against a real nginx + dav-ext server - a second, differently limited Class 2.

Runs as its own GitHub Actions workflow (.github/workflows/nginx-compliance.yml,
separate from ci.yml and apache-compliance.yml - see
docs/nginx-compliance-check.md) - nginx's own ``ngx_http_dav_module`` plus
``nginx-dav-ext-module`` is a real, independent WebDAV implementation,
useful here specifically for the real limitations it has that Apache
(tested in ``test_apache_compliance.py``), wsgidav (the main suite) and
Nextcloud (``test_nextcloud_compliance.py``) do not share, confirmed
against a real instance, not assumed from documentation:

- its ``DAV:`` header lists only class ``2``, never ``1``;
- it never evaluates ``If-None-Match`` on PUT (no overwrite protection);
- a requested *shared* lock is silently granted as *exclusive* instead of
  being refused or honored.

Skipped only when no nginx is reachable: with ``WEBDAV_TEST_NGINX_URL``
set, these tests run against that (possibly remote) instance; otherwise,
if a local nginx + dav-ext install is found (see ``tests/nginx_instance.py``),
a throwaway instance is started and stopped automatically.
"""

import io
import os
from collections.abc import Iterator
from pathlib import Path
from tempfile import gettempdir

import pytest

from tests import nginx_instance
from webdav import FileSystem, ResourceLockedError
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


def test_nginx_advertises_class_2_but_not_class_1(nginx_client: FileSystem) -> None:
    """nginx-dav-ext's ``DAV:`` header lists only ``2``, never ``1`` - confirmed against a real instance.

    RFC 4918 sec. 18 requires class 2 compliance to also be class 1
    compliant, and §10.1 says the header should reflect every class a
    resource supports - this is nginx-dav-ext not fully following that,
    not a startup race (reproduced 7/7 times, including immediately after
    a fresh restart). The server's actual *behavior* is still class 1
    (MKCOL/PUT/DELETE/COPY/MOVE all work - see the round-trip tests below);
    only the advertised header is incomplete.
    """
    compliances = nginx_client.dav_compliance()
    assert "2" in compliances, "server does not advertise Class 2 (locking) support"
    assert "1" not in compliances


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


def test_nginx_does_not_honor_overwrite_protection(nginx_client: FileSystem) -> None:
    """nginx's plain ``ngx_http_dav_module`` never evaluates ``If-None-Match`` on PUT.

    Confirmed against a real instance: ``overwrite=False`` sends
    ``If-None-Match: *``, same as against Apache/wsgidav/Nextcloud, but
    nginx answers ``204`` and overwrites anyway instead of ``412``. Pinned
    as a known, real interop gap - a caller relying on this library's
    race-free overwrite protection does not get it against nginx-dav-ext.
    """
    nginx_client.upload_fileobj(io.BytesIO(b"v1"), "compliance/protected.txt")
    nginx_client.upload_fileobj(
        io.BytesIO(b"v2"), "compliance/protected.txt", overwrite=False
    )
    buf = io.BytesIO()
    nginx_client.download_fileobj("compliance/protected.txt", buf)
    assert buf.getvalue() == b"v2"


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


def test_nginx_silently_grants_a_shared_lock_request_as_exclusive(
    nginx_client: FileSystem,
) -> None:
    """nginx-dav-ext ignores the requested lockscope and always grants an exclusive lock.

    Confirmed against a real instance: a LOCK request with
    ``<D:lockscope><D:shared/></D:lockscope>`` gets a ``200`` with a token,
    not refused - but the granted lock's own ``<D:lockscope>`` in the
    response is ``<D:exclusive/>``, not what was asked for. A real interop
    footgun worth pinning explicitly: a caller requesting ``scope=SHARED``
    against nginx believes it holds a shared lock and does not.
    """
    nginx_client.upload_fileobj(io.BytesIO(b"v1"), "compliance/shared.txt")
    with nginx_client.locked("compliance/shared.txt", scope=SHARED) as active_lock:
        assert active_lock.scope == EXCLUSIVE
