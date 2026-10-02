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
- it never evaluates ``If-None-Match``/``If-Match`` on PUT at all (no
  overwrite protection, no conditional PUT);
- a requested *shared* lock is silently granted as *exclusive* instead of
  being refused or honored;
- COPY/MOVE of a collection needs a trailing slash on both URIs, or it
  answers a plain ``400`` instead of recursing;
- ``PROPPATCH`` is not supported at all - not even a valid value for
  nginx-dav-ext's own ``dav_ext_methods`` directive;
- PROPFIND never returns a ``getetag`` property, for any resource.

Skipped only when no nginx is reachable: with ``WEBDAV_TEST_NGINX_URL``
set, these tests run against that (possibly remote) instance; otherwise,
if a local nginx + dav-ext install is found (see ``tests/nginx_instance.py``),
a throwaway instance is started and stopped automatically.
"""

import io
import os
import threading
import uuid
from collections.abc import Iterator
from pathlib import Path
from tempfile import gettempdir

import pytest

from tests import nginx_instance
from webdav import (
    FileSystem,
    HTTPStatusError,
    ResourceAlreadyExistsError,
    ResourceConflictError,
    ResourceLockedError,
)
from webdav.dav.locks import EXCLUSIVE, SHARED
from webdav.exceptions import UnsupportedMediaTypeError

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


def test_nginx_delete_of_a_locked_resource_without_the_token_fails(
    nginx_client: FileSystem,
) -> None:
    nginx_client.upload_fileobj(io.BytesIO(b"x"), "compliance/delwrong.txt")
    assert _Nginx.url is not None  # set by _nginx_session above
    other = FileSystem(_Nginx.url, auth=_Nginx.auth)
    try:
        with (
            nginx_client.locked("compliance/delwrong.txt", scope=EXCLUSIVE),
            pytest.raises(ResourceLockedError),
        ):
            other.remove("compliance/delwrong.txt")
    finally:
        other.close()
    assert nginx_client.exists("compliance/delwrong.txt")


# ---------------------------------------------------------------------------
# MKCOL negative cases
# ---------------------------------------------------------------------------


def test_nginx_mkcol_on_an_existing_file_is_resourcealreadyexists(
    nginx_client: FileSystem,
) -> None:
    nginx_client.upload_fileobj(io.BytesIO(b"x"), "compliance/plain.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        nginx_client.mkdir("compliance/plain.txt")


def test_nginx_mkcol_with_a_missing_ancestor_is_a_conflict(
    nginx_client: FileSystem,
) -> None:
    with pytest.raises(ResourceConflictError):
        nginx_client.mkdir("compliance/nonexistent-parent/child")


def test_nginx_a_race_to_create_a_collection_has_one_winner(
    nginx_client: FileSystem,
) -> None:
    """RFC 4918 sec. 9.3.1: exactly one concurrent MKCOL wins; nothing else about the losers is assumed here."""
    statuses: list[int] = []
    barrier = threading.Barrier(12)
    path = f"compliance/race-{uuid.uuid4().hex}"

    def create() -> None:
        barrier.wait()
        response = nginx_client.session.mkcol(path, raise_on_error=False)
        statuses.append(response.status_code)

    threads = [threading.Thread(target=create) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert statuses.count(201) == 1
    assert not [status for status in statuses if status < 400 and status != 201]
    assert nginx_client.isdir(path)


# ---------------------------------------------------------------------------
# Nested collections: COPY/MOVE of a whole subtree, and overwriting one
# ---------------------------------------------------------------------------


def test_nginx_copy_of_a_nested_collection_duplicates_the_whole_subtree(
    nginx_client: FileSystem,
) -> None:
    """nginx's dav_module requires a trailing slash on *both* URIs to COPY/MOVE a collection.

    Confirmed against a real instance: the identical request without a
    trailing slash on the source and ``Destination`` gets a plain ``400
    Bad Request`` - not a recursion limit, a stricter URI requirement
    than Apache/wsgidav/Nextcloud enforce. ``resolve_url()`` already
    preserves a caller-given trailing slash end to end (see its
    docstring: "a trailing / says this is a collection"), so this is a
    matter of calling ``copy``/``move`` the way nginx needs, not a
    library gap.
    """
    nginx_client.mkdir("compliance/nestedsrc")
    nginx_client.mkdir("compliance/nestedsrc/sub")
    nginx_client.upload_fileobj(io.BytesIO(b"a"), "compliance/nestedsrc/a.txt")
    nginx_client.upload_fileobj(io.BytesIO(b"b"), "compliance/nestedsrc/sub/b.txt")
    nginx_client.copy("compliance/nestedsrc/", "compliance/nesteddst/")
    buf = io.BytesIO()
    nginx_client.download_fileobj("compliance/nesteddst/sub/b.txt", buf)
    assert buf.getvalue() == b"b"
    assert nginx_client.exists("compliance/nestedsrc/sub/b.txt")


def test_nginx_move_of_a_nested_collection_relocates_the_whole_subtree(
    nginx_client: FileSystem,
) -> None:
    """Same trailing-slash requirement as the COPY case above."""
    nginx_client.mkdir("compliance/movesrc")
    nginx_client.mkdir("compliance/movesrc/sub")
    nginx_client.upload_fileobj(io.BytesIO(b"a"), "compliance/movesrc/sub/a.txt")
    nginx_client.move("compliance/movesrc/", "compliance/movedst/")
    assert not nginx_client.exists("compliance/movesrc")
    buf = io.BytesIO()
    nginx_client.download_fileobj("compliance/movedst/sub/a.txt", buf)
    assert buf.getvalue() == b"a"


def test_nginx_move_overwrites_an_existing_destination_collection_when_told_to(
    nginx_client: FileSystem,
) -> None:
    """§9.9.3: with Overwrite: T, an existing destination collection is replaced, not merged with."""
    nginx_client.mkdir("compliance/ovsrc")
    nginx_client.upload_fileobj(io.BytesIO(b"new"), "compliance/ovsrc/new.txt")
    nginx_client.mkdir("compliance/ovdst")
    nginx_client.upload_fileobj(io.BytesIO(b"stale"), "compliance/ovdst/stale.txt")
    nginx_client.move("compliance/ovsrc/", "compliance/ovdst/", overwrite=True)
    assert nginx_client.exists("compliance/ovdst/new.txt")
    assert not nginx_client.exists("compliance/ovdst/stale.txt")


def test_nginx_copy_onto_an_existing_destination_is_resourcealreadyexists(
    nginx_client: FileSystem,
) -> None:
    nginx_client.upload_fileobj(io.BytesIO(b"src"), "compliance/ow_src.txt")
    nginx_client.upload_fileobj(io.BytesIO(b"dst"), "compliance/ow_dst.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        nginx_client.copy("compliance/ow_src.txt", "compliance/ow_dst.txt", overwrite=False)


def test_nginx_move_onto_an_existing_destination_is_resourcealreadyexists(
    nginx_client: FileSystem,
) -> None:
    nginx_client.upload_fileobj(io.BytesIO(b"src"), "compliance/owm_src.txt")
    nginx_client.upload_fileobj(io.BytesIO(b"dst"), "compliance/owm_dst.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        nginx_client.move("compliance/owm_src.txt", "compliance/owm_dst.txt", overwrite=False)


# ---------------------------------------------------------------------------
# GET on a collection, isdir, walk - against a real nested tree
# ---------------------------------------------------------------------------


def test_nginx_get_on_a_collection_does_not_crash(nginx_client: FileSystem) -> None:
    nginx_client.mkdir("compliance/plaincoll")
    session = nginx_client.session
    response = session.get("compliance/plaincoll/")
    assert response.status_code < 500


def test_nginx_isdir_correctly_identifies_a_real_collection(
    nginx_client: FileSystem,
) -> None:
    nginx_client.mkdir("compliance/adircheck")
    nginx_client.upload_fileobj(io.BytesIO(b"x"), "compliance/afilecheck.txt")
    assert nginx_client.isdir("compliance/adircheck") is True
    assert nginx_client.isdir("compliance/afilecheck.txt") is False


def test_nginx_walk_covers_a_real_nested_tree(nginx_client: FileSystem) -> None:
    nginx_client.mkdir("compliance/walkroot")
    nginx_client.mkdir("compliance/walkroot/sub")
    nginx_client.upload_fileobj(io.BytesIO(b"x"), "compliance/walkroot/top.txt")
    nginx_client.upload_fileobj(io.BytesIO(b"x"), "compliance/walkroot/sub/deep.txt")
    seen_files: set[str] = set()
    for _path, _dirs, files in nginx_client.walk("compliance/walkroot"):
        seen_files.update(f.name for f in files)
    assert "compliance/walkroot/top.txt" in seen_files
    assert "compliance/walkroot/sub/deep.txt" in seen_files


# ---------------------------------------------------------------------------
# Range/resumable reads, against a real server
# ---------------------------------------------------------------------------


def test_nginx_supports_range_reads(nginx_client: FileSystem) -> None:
    nginx_client.upload_fileobj(io.BytesIO(b"0123456789"), "compliance/range.txt")
    with nginx_client.open("compliance/range.txt", "rb") as reader:
        assert reader.read(4) == b"0123"
        reader.seek(7)
        assert reader.read() == b"789"


def test_nginx_download_fileobj_resumes_after_a_seek(nginx_client: FileSystem) -> None:
    nginx_client.upload_fileobj(io.BytesIO(b"abcdefghij"), "compliance/range2.txt")
    with nginx_client.open("compliance/range2.txt", "rb") as reader:
        first_half = reader.read(5)
        reader.seek(0)
        full = reader.read()
    assert first_half == b"abcde"
    assert full == b"abcdefghij"


# ---------------------------------------------------------------------------
# Extended MKCOL, 423 response shape, clean nested delete
# ---------------------------------------------------------------------------


def test_nginx_extended_mkcol_is_refused_with_415(nginx_client: FileSystem) -> None:
    """A server that doesn't support RFC 5689 answers 415, same as Apache."""
    with pytest.raises(UnsupportedMediaTypeError):
        nginx_client.mkdir(
            "compliance/special", set_props={"displayname": "Special Dir"}
        )


def test_nginx_423_response_is_never_crashed_on_even_without_a_structured_error_body(
    nginx_client: FileSystem,
) -> None:
    """nginx's 423 has no body at all, not even HTML - error_codes must degrade to empty, not raise."""
    nginx_client.upload_fileobj(io.BytesIO(b"x"), "compliance/errbody.txt")
    assert _Nginx.url is not None  # set by _nginx_session above
    other = FileSystem(_Nginx.url, auth=_Nginx.auth)
    try:
        with nginx_client.locked("compliance/errbody.txt", scope=EXCLUSIVE):
            other_session = other.session
            response = other_session.put(
                "compliance/errbody.txt", b"y", raise_on_error=False
            )
            assert response.status_code == 423
            with pytest.raises(ResourceLockedError) as exc_info:
                response.raise_for_status()
            assert exc_info.value.error_codes == frozenset()
    finally:
        other.close()


def test_nginx_a_clean_delete_of_a_nested_collection_is_204(
    nginx_client: FileSystem,
) -> None:
    """Same trailing-slash requirement as COPY/MOVE (see the usage note in the docs) - also applies to DELETE."""
    nginx_client.mkdir("compliance/cleandel")
    nginx_client.mkdir("compliance/cleandel/sub")
    nginx_client.remove("compliance/cleandel/")
    assert not nginx_client.exists("compliance/cleandel")


# ---------------------------------------------------------------------------
# PROPPATCH and getetag: two things nginx-dav-ext simply does not have
# ---------------------------------------------------------------------------


def test_nginx_does_not_support_proppatch_at_all(nginx_client: FileSystem) -> None:
    """Confirmed against a real instance, two ways: PROPPATCH is not even
    a legal value for nginx-dav-ext's own ``dav_ext_methods`` directive
    (``nginx -t`` refuses it outright), and the method gets a plain
    ``405`` from nginx's core regardless. Unlike the other nginx
    limitations here, there is no partial support to speak of - PROPPATCH
    is entirely absent.
    """
    nginx_client.upload_fileobj(io.BytesIO(b"x"), "compliance/noproppatch.txt")
    with pytest.raises(HTTPStatusError) as exc_info:
        nginx_client.set_props(
            "compliance/noproppatch.txt", set_props={"displayname": "won't work"}
        )
    assert exc_info.value.status_code == 405


def test_nginx_propfind_never_returns_an_etag(nginx_client: FileSystem) -> None:
    """Confirmed against a real instance: no resource, of any kind, gets a getetag property back."""
    nginx_client.upload_fileobj(io.BytesIO(b"x"), "compliance/noetag.txt")
    props = nginx_client.get_props("compliance/noetag.txt")
    assert props.etag is None
