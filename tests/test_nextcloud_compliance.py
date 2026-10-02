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
import threading
import uuid
from collections.abc import Iterator
from typing import TYPE_CHECKING
from xml.etree.ElementTree import Element

import pytest

from tests import nextcloud_instance
from webdav import (
    FileSystem,
    ResourceAlreadyExistsError,
    ResourceConflictError,
    ResourceLockedError,
)
from webdav.dav.locks import EXCLUSIVE, SHARED

if TYPE_CHECKING:
    from webdav import Session

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


def test_nextcloud_advertises_class_2(nc_client: FileSystem) -> None:
    """Confirmed against a real instance: this pinned Nextcloud release supports locking.

    Older Nextcloud releases (confirmed: 29) did not register a LOCK
    plugin at all and answered with a plain 501 - locking support was
    added to Nextcloud's own WebDAV stack at some point before the
    version pinned here. Pinned both ways on purpose: a future bump that
    lands on a release where this regresses, or where it was never true
    to begin with for a differently-configured instance, should turn this
    red rather than silently assumed away either direction.
    """
    compliances = nc_client.dav_compliance()
    assert "1" in compliances
    assert "2" in compliances


def test_nextcloud_lock_and_write_with_held_token(nc_client: FileSystem) -> None:
    nc_client.upload_fileobj(io.BytesIO(b"v1"), "locked.txt")

    with nc_client.locked("locked.txt", scope=EXCLUSIVE):
        nc_client.upload_fileobj(io.BytesIO(b"v2"), "locked.txt", overwrite=True)

    buf = io.BytesIO()
    nc_client.download_fileobj("locked.txt", buf)
    assert buf.getvalue() == b"v2"


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


# ---------------------------------------------------------------------------
# RFC 4918 locking, against a second real independent implementation
# ---------------------------------------------------------------------------


def test_nextcloud_lock_refresh(nc_client: FileSystem) -> None:
    """§9.10.2: a bodyless LOCK with an If header refreshes the timeout, same token."""
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/refresh.txt")
    with nc_client.locked(
        "compliance/refresh.txt", scope=EXCLUSIVE, lock_timeout=30
    ) as active_lock:
        refreshed = nc_client.refresh_lock(
            "compliance/refresh.txt", active_lock.token, lock_timeout=60
        )
        assert refreshed.token == active_lock.token
        nc_client.upload_fileobj(
            io.BytesIO(b"y"), "compliance/refresh.txt", overwrite=True
        )


def test_nextcloud_root_depth_infinity_lock_covers_children(
    nc_client: FileSystem,
) -> None:
    """§6.1: a Depth:infinity lock on the root must cascade to every path under it."""
    nc_client.upload_fileobj(io.BytesIO(b"v1"), "rootlock.txt")
    with nc_client.locked("", scope=EXCLUSIVE, depth="infinity"):
        nc_client.upload_fileobj(io.BytesIO(b"v2"), "rootlock.txt", overwrite=True)
    buf = io.BytesIO()
    nc_client.download_fileobj("rootlock.txt", buf)
    assert buf.getvalue() == b"v2"


def test_nextcloud_destination_lock_token_is_submitted_for_copy_and_move(
    nc_client: FileSystem,
) -> None:
    """RFC 4918 §10.2: a locked *destination*'s token MUST be submitted too."""
    session: Session = nc_client._session
    nc_client.upload_fileobj(io.BytesIO(b"source"), "compliance/xfer_src.txt")
    nc_client.upload_fileobj(io.BytesIO(b"old dest"), "compliance/xfer_dst.txt")
    with nc_client.locked("compliance/xfer_dst.txt", scope=EXCLUSIVE):
        session.copy(
            "compliance/xfer_src.txt",
            destination="compliance/xfer_dst.txt",
            overwrite=True,
        ).raise_for_status()
    buf = io.BytesIO()
    nc_client.download_fileobj("compliance/xfer_dst.txt", buf)
    assert buf.getvalue() == b"source"


def test_nextcloud_moving_a_member_out_of_a_locked_collection_needs_only_the_parents_token(
    nc_client: FileSystem,
) -> None:
    """§7.4: a lock on a collection protects "MOVE an internal member out of the collection"."""
    session: Session = nc_client._session
    nc_client.mkdir("compliance/lockedsrc")
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/lockedsrc/child.txt")
    with nc_client.locked("compliance/lockedsrc", depth="0"):
        session.move(
            "compliance/lockedsrc/child.txt", destination="compliance/moved-out.txt"
        ).raise_for_status()
    assert nc_client.exists("compliance/moved-out.txt")
    assert not nc_client.exists("compliance/lockedsrc/child.txt")


def test_nextcloud_locking_an_unmapped_url_creates_a_resource_while_held(
    nc_client: FileSystem,
) -> None:
    """§9.10.4: a successful lock request to an unmapped URL creates an empty resource there."""
    with nc_client.locked("compliance/brand-new.txt") as active_lock:
        assert active_lock.token
        assert nc_client.exists("compliance/brand-new.txt")


def test_nextcloud_lockdiscovery_and_supportedlock_are_parsed_from_a_live_response(
    nc_client: FileSystem,
) -> None:
    """§15.8/§15.10: structural parsing, against a real activelock/lockentry shape.

    Named explicitly (unlike the Apache version of this test, which relies
    on allprop) - confirmed against a real instance that Nextcloud's
    SabreDAV does not include ``lockdiscovery``/``supportedlock`` in an
    ``allprop`` response at all, only when asked for by name.
    """
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/disco.txt")
    with nc_client.locked("compliance/disco.txt", scope=EXCLUSIVE) as active_lock:
        props = nc_client.get_props(
            "compliance/disco.txt", props=["lockdiscovery", "supportedlock"]
        )
        assert len(props.active_locks) == 1
        assert props.active_locks[0].token == active_lock.token
        assert len(props.supported_locks) >= 1


def test_nextcloud_allprop_with_include(nc_client: FileSystem) -> None:
    """§9.1/§14.8: <allprop/> combined with <include>."""
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/allprop.txt")
    props = nc_client.get_props(
        "compliance/allprop.txt", all_prop=True, include=["etag"]
    )
    assert props.etag is not None


def test_nextcloud_structured_lock_owner_round_trips(nc_client: FileSystem) -> None:
    """owner's content model is ANY - a structured <D:href> owner."""
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/owner.txt")
    owner_el = Element("{DAV:}href")
    owner_el.text = "mailto:test@example.org"
    with nc_client.locked("compliance/owner.txt", owner=owner_el) as active_lock:
        assert active_lock.owner is not None


def test_nextcloud_timeout_preference_list(nc_client: FileSystem) -> None:
    """§10.7: Timeout can list several values; the server picks one."""
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/timeout.txt")
    with nc_client.locked(
        "compliance/timeout.txt", lock_timeout=[86400, 3600]
    ) as active_lock:
        assert active_lock.timeout is None or active_lock.timeout > 0


def test_nextcloud_a_shared_lock_blocks_a_second_clients_exclusive_lock(
    nc_client: FileSystem,
) -> None:
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/scope1.txt")
    assert _Nextcloud.url is not None  # set by _nextcloud_session above
    other = FileSystem(_Nextcloud.url, auth=_Nextcloud.auth)
    try:
        with nc_client.locked("compliance/scope1.txt", scope=SHARED):
            with pytest.raises(ResourceLockedError):
                with other.locked("compliance/scope1.txt", scope=EXCLUSIVE):
                    pass
    finally:
        other.close()


def test_nextcloud_an_exclusive_lock_blocks_a_second_clients_shared_lock(
    nc_client: FileSystem,
) -> None:
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/scope2.txt")
    assert _Nextcloud.url is not None  # set by _nextcloud_session above
    other = FileSystem(_Nextcloud.url, auth=_Nextcloud.auth)
    try:
        with nc_client.locked("compliance/scope2.txt", scope=EXCLUSIVE):
            with pytest.raises(ResourceLockedError):
                with other.locked("compliance/scope2.txt", scope=SHARED):
                    pass
    finally:
        other.close()


def test_nextcloud_unlock_by_a_different_client_without_the_token_fails(
    nc_client: FileSystem,
) -> None:
    """An invalid UNLOCK token is refused - though Nextcloud's own answer for it is a bare 500.

    Confirmed against a real instance: Apache/wsgidav answer a proper 4xx
    (400/403/409/412) for this; Nextcloud's SabreDAV raises a plain
    ``500 Internal Server Error`` instead - a real, if inelegant,
    Nextcloud-side bug, not something this library can paper over. What
    matters here is confirmed either way: the bogus token is refused, the
    real lock is not released by it.
    """
    session: Session = nc_client._session
    session.put("compliance/wrongclient.txt", b"x").raise_for_status()
    response = session.lock("compliance/wrongclient.txt", scope=EXCLUSIVE)
    token = response.active_lock.token
    assert _Nextcloud.url is not None  # set by _nextcloud_session above
    other = FileSystem(_Nextcloud.url, auth=_Nextcloud.auth)
    try:
        other_session: Session = other._session
        unlock_response = other_session.unlock(
            "compliance/wrongclient.txt",
            "opaquelocktoken:not-the-real-one",
            raise_on_error=False,
        )
        assert unlock_response.status_code in (400, 403, 409, 412, 500)
    finally:
        other.close()
    session.unlock("compliance/wrongclient.txt", token)


def test_nextcloud_delete_of_a_locked_resource_without_the_token_fails(
    nc_client: FileSystem,
) -> None:
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/delwrong.txt")
    assert _Nextcloud.url is not None  # set by _nextcloud_session above
    other = FileSystem(_Nextcloud.url, auth=_Nextcloud.auth)
    try:
        with (
            nc_client.locked("compliance/delwrong.txt", scope=EXCLUSIVE),
            pytest.raises(ResourceLockedError),
        ):
            other.remove("compliance/delwrong.txt")
    finally:
        other.close()
    assert nc_client.exists("compliance/delwrong.txt")


def test_nextcloud_deleting_a_collection_does_not_check_a_locked_members_token(
    nc_client: FileSystem,
) -> None:
    """§9.6.1 expects a 207 here, as Apache gives (see the matching Apache test) - Nextcloud does not.

    Confirmed against a real instance: a DELETE on a collection with an
    exclusively-locked member, sent by a session that does not hold that
    lock's token, succeeds outright (204) - the member is deleted along
    with everything else, no multistatus, no error at all. A real,
    confirmed gap in Nextcloud's lock enforcement during a recursive
    delete, not something this library's own ``If``-header bookkeeping
    can compensate for (the request correctly carries no token for a
    lock this session never took).
    """
    session: Session = nc_client._session
    nc_client.mkdir("compliance/delcoll")
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/delcoll/ok.txt")
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/delcoll/locked.txt")
    assert _Nextcloud.url is not None  # set by _nextcloud_session above
    other = FileSystem(_Nextcloud.url, auth=_Nextcloud.auth)
    try:
        with other.locked("compliance/delcoll/locked.txt", scope=EXCLUSIVE):
            session.delete("compliance/delcoll/").raise_for_status()
        assert not nc_client.exists("compliance/delcoll")
    finally:
        other.close()


# ---------------------------------------------------------------------------
# MKCOL negative cases, nested COPY/MOVE, GET/isdir/walk, range reads
# ---------------------------------------------------------------------------


def test_nextcloud_mkcol_on_an_existing_file_is_resourcealreadyexists(
    nc_client: FileSystem,
) -> None:
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/plain.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        nc_client.mkdir("compliance/plain.txt")


def test_nextcloud_mkcol_with_a_missing_ancestor_is_a_conflict(
    nc_client: FileSystem,
) -> None:
    with pytest.raises(ResourceConflictError):
        nc_client.mkdir("compliance/nonexistent-parent/child")


def test_nextcloud_a_race_to_create_a_collection_has_one_winner(
    nc_client: FileSystem,
) -> None:
    """RFC 4918 sec. 9.3.1: exactly one concurrent MKCOL wins; nothing else about the losers is assumed here."""
    statuses: list[int] = []
    barrier = threading.Barrier(12)
    path = f"compliance/race-{uuid.uuid4().hex}"

    def create() -> None:
        barrier.wait()
        response = nc_client.session.mkcol(path, raise_on_error=False)
        statuses.append(response.status_code)

    threads = [threading.Thread(target=create) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert statuses.count(201) == 1
    assert not [status for status in statuses if status < 400 and status != 201]
    assert nc_client.isdir(path)


def test_nextcloud_copy_of_a_nested_collection_duplicates_the_whole_subtree(
    nc_client: FileSystem,
) -> None:
    nc_client.mkdir("compliance/nestedsrc")
    nc_client.mkdir("compliance/nestedsrc/sub")
    nc_client.upload_fileobj(io.BytesIO(b"a"), "compliance/nestedsrc/a.txt")
    nc_client.upload_fileobj(io.BytesIO(b"b"), "compliance/nestedsrc/sub/b.txt")
    nc_client.copy("compliance/nestedsrc", "compliance/nesteddst")
    buf = io.BytesIO()
    nc_client.download_fileobj("compliance/nesteddst/sub/b.txt", buf)
    assert buf.getvalue() == b"b"
    assert nc_client.exists("compliance/nestedsrc/sub/b.txt")


def test_nextcloud_move_of_a_nested_collection_relocates_the_whole_subtree(
    nc_client: FileSystem,
) -> None:
    nc_client.mkdir("compliance/movesrc")
    nc_client.mkdir("compliance/movesrc/sub")
    nc_client.upload_fileobj(io.BytesIO(b"a"), "compliance/movesrc/sub/a.txt")
    nc_client.move("compliance/movesrc", "compliance/movedst")
    assert not nc_client.exists("compliance/movesrc")
    buf = io.BytesIO()
    nc_client.download_fileobj("compliance/movedst/sub/a.txt", buf)
    assert buf.getvalue() == b"a"


def test_nextcloud_move_overwrites_an_existing_destination_collection_when_told_to(
    nc_client: FileSystem,
) -> None:
    """§9.9.3: with Overwrite: T, an existing destination collection is replaced, not merged with."""
    nc_client.mkdir("compliance/ovsrc")
    nc_client.upload_fileobj(io.BytesIO(b"new"), "compliance/ovsrc/new.txt")
    nc_client.mkdir("compliance/ovdst")
    nc_client.upload_fileobj(io.BytesIO(b"stale"), "compliance/ovdst/stale.txt")
    nc_client.move("compliance/ovsrc", "compliance/ovdst", overwrite=True)
    assert nc_client.exists("compliance/ovdst/new.txt")
    assert not nc_client.exists("compliance/ovdst/stale.txt")


def test_nextcloud_copy_onto_an_existing_destination_is_resourcealreadyexists(
    nc_client: FileSystem,
) -> None:
    nc_client.upload_fileobj(io.BytesIO(b"src"), "compliance/ow_src.txt")
    nc_client.upload_fileobj(io.BytesIO(b"dst"), "compliance/ow_dst.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        nc_client.copy("compliance/ow_src.txt", "compliance/ow_dst.txt", overwrite=False)


def test_nextcloud_move_onto_an_existing_destination_is_resourcealreadyexists(
    nc_client: FileSystem,
) -> None:
    nc_client.upload_fileobj(io.BytesIO(b"src"), "compliance/owm_src.txt")
    nc_client.upload_fileobj(io.BytesIO(b"dst"), "compliance/owm_dst.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        nc_client.move("compliance/owm_src.txt", "compliance/owm_dst.txt", overwrite=False)


def test_nextcloud_get_on_a_collection_does_not_crash(nc_client: FileSystem) -> None:
    nc_client.mkdir("compliance/plaincoll")
    session = nc_client.session
    response = session.get("compliance/plaincoll/")
    assert response.status_code < 500


def test_nextcloud_isdir_correctly_identifies_a_real_collection(
    nc_client: FileSystem,
) -> None:
    nc_client.mkdir("compliance/adircheck")
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/afilecheck.txt")
    assert nc_client.isdir("compliance/adircheck") is True
    assert nc_client.isdir("compliance/afilecheck.txt") is False


def test_nextcloud_walk_covers_a_real_nested_tree(nc_client: FileSystem) -> None:
    nc_client.mkdir("compliance/walkroot")
    nc_client.mkdir("compliance/walkroot/sub")
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/walkroot/top.txt")
    nc_client.upload_fileobj(io.BytesIO(b"x"), "compliance/walkroot/sub/deep.txt")
    seen_files: set[str] = set()
    for _path, _dirs, files in nc_client.walk("compliance/walkroot"):
        seen_files.update(f.name for f in files)
    assert "compliance/walkroot/top.txt" in seen_files
    assert "compliance/walkroot/sub/deep.txt" in seen_files


def test_nextcloud_supports_range_reads(nc_client: FileSystem) -> None:
    nc_client.upload_fileobj(io.BytesIO(b"0123456789"), "compliance/range.txt")
    with nc_client.open("compliance/range.txt", "rb") as reader:
        assert reader.read(4) == b"0123"
        reader.seek(7)
        assert reader.read() == b"789"


def test_nextcloud_download_fileobj_resumes_after_a_seek(nc_client: FileSystem) -> None:
    nc_client.upload_fileobj(io.BytesIO(b"abcdefghij"), "compliance/range2.txt")
    with nc_client.open("compliance/range2.txt", "rb") as reader:
        first_half = reader.read(5)
        reader.seek(0)
        full = reader.read()
    assert first_half == b"abcde"
    assert full == b"abcdefghij"


def test_nextcloud_if_match_with_a_stale_etag_is_refused(nc_client: FileSystem) -> None:
    session: Session = nc_client._session
    session.put("compliance/etagstale.txt", b"v1").raise_for_status()
    response = session.put(
        "compliance/etagstale.txt",
        b"v2",
        if_match='"not-the-real-etag"',
        raise_on_error=False,
    )
    assert response.status_code == 412
    buf = io.BytesIO()
    nc_client.download_fileobj("compliance/etagstale.txt", buf)
    assert buf.getvalue() == b"v1"
