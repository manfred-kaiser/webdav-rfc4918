"""Compliance check against a real Apache + mod_dav server - an ordinary, reproducible pytest suite.

Runs as its own GitHub Actions workflow (.github/workflows/apache-compliance.yml,
separate from ci.yml - see that file and docs/apache-compliance-check.md)
- an independent-implementation cross-check, since server implementations
are known to disagree on locking/property edge cases in particular, and
this project's primary deployment target is Apache specifically. Skipped
only when no
Apache is reachable at all: with ``WEBDAV_TEST_APACHE_URL`` set, these
tests run against that (possibly remote, possibly specially-configured)
instance; otherwise, if a local Apache + ``mod_dav`` install is found
(see ``tests/apache_instance.py``), a throwaway instance is started and
stopped automatically - no manual step needed either way. See
``docs/apache-compliance-check.md`` for the full setup story and the
Apache-specific behavior these tests pin down (so a future Apache upgrade
that changes one is caught here, not discovered in production).
"""

import base64
import collections
import contextlib
import hashlib
import io
import logging
import os
import re
import socket
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import gettempdir
from typing import TYPE_CHECKING, Any, BinaryIO, cast
from urllib.parse import urlsplit
from xml.etree.ElementTree import Element

import pytest
import requests

from tests import apache_instance
from webdav import FileSystem, ResourceAlreadyExistsError, ResourceLockedError
from webdav.dav.locks import EXCLUSIVE, SHARED
from webdav.exceptions import (
    ForbiddenError,
    HTTPStatusError,
    InternalServerError,
    MultiStatusError,
    PreconditionFailedError,
    ResourceConflictError,
    UnsupportedMediaTypeError,
)

if TYPE_CHECKING:
    from webdav import Session

_ENV_URL = os.environ.get("WEBDAV_TEST_APACHE_URL")
_MISSING = [] if _ENV_URL else apache_instance.missing_prerequisites()

pytestmark = [
    pytest.mark.skipif(
        bool(_MISSING),
        reason=(
            "no Apache reachable: set WEBDAV_TEST_APACHE_URL to point at an "
            "existing instance, or install what's missing for a local "
            "throwaway one: " + ", ".join(_MISSING)
        ),
    ),
    # Every test here shares one Apache instance/dav-root (started once by
    # _apache_session, not test-isolated like wsgidav's tmp_path) - under
    # the default -nauto, each xdist *worker* is its own pytest "session",
    # so without this, two workers could each try to bind the same port, or
    # race each other on the shared dav-root exactly like running this file
    # by hand without -n0 does (see docs/apache-compliance-check.md). This
    # pins every test in this module to one worker, deterministically.
    pytest.mark.xdist_group(name="apache"),
]


class _Apache:
    """Where the instance this test session uses lives - set once, by ``_apache_session`` below."""

    url: "str | None" = None
    auth: "tuple[str, str]" = (apache_instance.TEST_USER, apache_instance.TEST_PASSWORD)


@pytest.fixture(scope="session", autouse=True)
def _apache_session() -> Iterator[None]:
    """Point ``_Apache`` at a usable instance: the one given by env, or a throwaway one started here.

    Nothing to do if every test in this module is being skipped (``_MISSING``
    non-empty and no env URL) - collection already short-circuits that case.
    """
    if _ENV_URL:
        _Apache.url = _ENV_URL
        _Apache.auth = (
            os.environ.get("WEBDAV_TEST_APACHE_USER", apache_instance.TEST_USER),
            os.environ.get(
                "WEBDAV_TEST_APACHE_PASSWORD", apache_instance.TEST_PASSWORD
            ),
        )
        yield
        return
    instance_dir = Path(gettempdir()) / "webdav-rfc4918-apache-test"
    conf_file = apache_instance.write_instance(instance_dir)
    apache_instance.start(conf_file)
    _Apache.url = f"http://{apache_instance.HOST}:{apache_instance.PORT}"
    try:
        yield
    finally:
        apache_instance.stop(conf_file)


@pytest.fixture
def apache_client() -> Iterator[FileSystem]:
    assert _Apache.url is not None  # set by _apache_session above
    with FileSystem(_Apache.url, auth=_Apache.auth) as c:
        yield c


def test_apache_options_advertises_class_2(apache_client: FileSystem) -> None:
    compliances = apache_client.dav_compliance()
    assert "1" in compliances
    assert "2" in compliances, "server does not advertise Class 2 (locking) support"


def test_apache_mkdir_upload_download_roundtrip(apache_client: FileSystem) -> None:
    apache_client.mkdir("compliance")
    apache_client.upload_fileobj(io.BytesIO(b"apache says hi"), "compliance/a.txt")

    buf = io.BytesIO()
    apache_client.download_fileobj("compliance/a.txt", buf)
    assert buf.getvalue() == b"apache says hi"


def test_apache_overwrite_protection(apache_client: FileSystem) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"v1"), "compliance/protected.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        apache_client.upload_fileobj(
            io.BytesIO(b"v2"), "compliance/protected.txt", overwrite=False
        )


def test_apache_lock_and_write_with_held_token(apache_client: FileSystem) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"v1"), "compliance/locked.txt")

    with apache_client.locked("compliance/locked.txt", scope=EXCLUSIVE):
        apache_client.upload_fileobj(
            io.BytesIO(b"v2"), "compliance/locked.txt", overwrite=True
        )

    buf = io.BytesIO()
    apache_client.download_fileobj("compliance/locked.txt", buf)
    assert buf.getvalue() == b"v2"


def test_apache_lock_blocks_a_second_client(apache_client: FileSystem) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"v1"), "compliance/locked2.txt")

    assert _Apache.url is not None  # set by _apache_session above
    other = FileSystem(_Apache.url, auth=_Apache.auth)
    try:
        with (
            apache_client.locked("compliance/locked2.txt", scope=EXCLUSIVE),
            pytest.raises(ResourceLockedError),
        ):
            other.upload_fileobj(
                io.BytesIO(b"v2"), "compliance/locked2.txt", overwrite=True
            )
    finally:
        other.close()


def test_apache_set_and_get_custom_property(apache_client: FileSystem) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/p.txt")
    apache_client.set_props(
        "compliance/p.txt",
        set_props={("https://example.org/ns", "color"): "blue"},
    )

    props = apache_client.get_props(
        "compliance/p.txt", props=[("https://example.org/ns", "color")]
    )
    assert props.text("https://example.org/ns", "color") == "blue"


# ---------------------------------------------------------------------------
# RFC 4918 locking, against an independent implementation (the original
# RFC_COMPLIANCE.md findings this session re-verifies and keeps live)
# ---------------------------------------------------------------------------


def test_apache_lock_refresh(apache_client: FileSystem) -> None:
    """§9.10.2: a bodyless LOCK with an If header refreshes the timeout, same token."""
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/refresh.txt")
    with apache_client.locked(
        "compliance/refresh.txt", scope=EXCLUSIVE, lock_timeout=30
    ) as active_lock:
        refreshed = apache_client.refresh_lock(
            "compliance/refresh.txt", active_lock.token, lock_timeout=60
        )
        assert refreshed.token == active_lock.token
        # Still holding it afterwards - a write through it must still work.
        apache_client.upload_fileobj(
            io.BytesIO(b"y"), "compliance/refresh.txt", overwrite=True
        )


def test_apache_root_depth_infinity_lock_covers_children(
    apache_client: FileSystem,
) -> None:
    """§6.1: a Depth:infinity lock on the root must cascade to every path under it (RFC_COMPLIANCE.md finding 2)."""
    apache_client.upload_fileobj(io.BytesIO(b"v1"), "rootlock.txt")
    with apache_client.locked("", scope=EXCLUSIVE, depth="infinity"):
        apache_client.upload_fileobj(io.BytesIO(b"v2"), "rootlock.txt", overwrite=True)
    buf = io.BytesIO()
    apache_client.download_fileobj("rootlock.txt", buf)
    assert buf.getvalue() == b"v2"


def test_apache_concurrent_shared_locks_on_the_same_path(
    apache_client: FileSystem,
) -> None:
    """§6.2: several shared locks from the same principal coexist on one resource."""
    apache_client.upload_fileobj(io.BytesIO(b"v1"), "compliance/shared.txt")
    with apache_client.locked("compliance/shared.txt", scope=SHARED) as lock_a:
        with apache_client.locked("compliance/shared.txt", scope=SHARED):
            pass  # released here - must not evict lock_a's bookkeeping
        apache_client.upload_fileobj(
            io.BytesIO(b"v2"), "compliance/shared.txt", overwrite=True
        )
        assert lock_a.token


def test_apache_destination_lock_token_is_submitted_for_copy_and_move(
    apache_client: FileSystem,
) -> None:
    """RFC 4918 §10.2: a locked *destination*'s token MUST be submitted too (RFC_COMPLIANCE.md finding 5)."""
    session: Session = apache_client._session
    apache_client.upload_fileobj(io.BytesIO(b"source"), "compliance/xfer_src.txt")
    apache_client.upload_fileobj(io.BytesIO(b"old dest"), "compliance/xfer_dst.txt")
    with apache_client.locked("compliance/xfer_dst.txt", scope=EXCLUSIVE):
        session.copy(
            "compliance/xfer_src.txt",
            destination="compliance/xfer_dst.txt",
            overwrite=True,
        ).raise_for_status()
    buf = io.BytesIO()
    apache_client.download_fileobj("compliance/xfer_dst.txt", buf)
    assert buf.getvalue() == b"source"


def test_apache_moving_a_member_out_of_a_locked_collection_needs_only_the_parents_token(
    apache_client: FileSystem,
) -> None:
    """§7.4: a lock on a collection protects "MOVE an internal member out of the collection"."""
    session: Session = apache_client._session
    apache_client.mkdir("compliance/lockedsrc")
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/lockedsrc/child.txt")
    with apache_client.locked("compliance/lockedsrc", depth="0"):
        session.move(
            "compliance/lockedsrc/child.txt", destination="compliance/moved-out.txt"
        ).raise_for_status()
    assert apache_client.exists("compliance/moved-out.txt")
    assert not apache_client.exists("compliance/lockedsrc/child.txt")


def test_apache_locking_an_unmapped_url_creates_a_resource_while_held(
    apache_client: FileSystem,
) -> None:
    """§9.10.4: a successful lock request to an unmapped URL creates an empty resource there.

    RFC 4918 only says it "SHOULD NOT disappear" once the lock is gone (not
    a MUST) - confirmed here, against a real instance, that Apache's
    mod_dav takes the RFC up on that latitude and deletes it again on
    UNLOCK (unlike wsgidav, see tests/test_rfc_compliance.py's version of
    this same check). Pinned so a future Apache upgrade that changes this
    is noticed, not silently assumed away.
    """
    with apache_client.locked("compliance/brand-new.txt") as active_lock:
        assert active_lock.token
        assert apache_client.exists("compliance/brand-new.txt")
    assert not apache_client.exists("compliance/brand-new.txt")


def test_apache_lockdiscovery_and_supportedlock_are_parsed_from_a_live_response(
    apache_client: FileSystem,
) -> None:
    """§15.8/§15.10: structural parsing (RFC_COMPLIANCE.md finding 10), against a real activelock/lockentry shape."""
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/disco.txt")
    with apache_client.locked("compliance/disco.txt", scope=EXCLUSIVE) as active_lock:
        props = apache_client.get_props("compliance/disco.txt")
        assert len(props.active_locks) == 1
        assert props.active_locks[0].token == active_lock.token
        assert len(props.supported_locks) >= 1


def test_apache_allprop_with_include(apache_client: FileSystem) -> None:
    """§9.1/§14.8: <allprop/> combined with <include> (RFC_COMPLIANCE.md finding 11)."""
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/allprop.txt")
    props = apache_client.get_props(
        "compliance/allprop.txt", all_prop=True, include=["etag"]
    )
    assert props.etag is not None


def test_apache_structured_lock_owner_round_trips(apache_client: FileSystem) -> None:
    """owner's content model is ANY (RFC_COMPLIANCE.md finding 13) - a structured <D:href> owner."""
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/owner.txt")
    owner_el = Element("{DAV:}href")
    owner_el.text = "mailto:test@example.org"
    with apache_client.locked("compliance/owner.txt", owner=owner_el) as active_lock:
        assert active_lock.owner is not None


def test_apache_timeout_preference_list(apache_client: FileSystem) -> None:
    """§10.7: Timeout can list several values; the server picks one (RFC_COMPLIANCE.md finding 14)."""
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/timeout.txt")
    with apache_client.locked(
        "compliance/timeout.txt", lock_timeout=[86400, 3600]
    ) as active_lock:
        assert active_lock.timeout is None or active_lock.timeout > 0


# ---------------------------------------------------------------------------
# MKCOL/Extended MKCOL, against a real server that (like wsgidav) does not
# advertise RFC 5689 support
# ---------------------------------------------------------------------------


def test_apache_does_not_advertise_extended_mkcol(apache_client: FileSystem) -> None:
    assert "extended-mkcol" not in apache_client.dav_compliance()


def test_apache_mkcol_on_an_existing_file_is_resourcealreadyexists(
    apache_client: FileSystem,
) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/plain.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        apache_client.mkdir("compliance/plain.txt")


def test_apache_mkcol_with_a_missing_ancestor_is_a_conflict(
    apache_client: FileSystem,
) -> None:
    with pytest.raises(ResourceConflictError):
        apache_client.mkdir("compliance/nonexistent-parent/child")


def test_apache_extended_mkcol_is_refused_with_415(apache_client: FileSystem) -> None:
    """A server that doesn't support RFC 5689 answers 415, same as any other unsupported MKCOL body."""
    with pytest.raises(UnsupportedMediaTypeError):
        apache_client.mkdir(
            "compliance/special", set_props={"displayname": "Special Dir"}
        )


# ---------------------------------------------------------------------------
# Error response shape from a real server
# ---------------------------------------------------------------------------


def test_apache_423_response_is_never_crashed_on_even_without_a_structured_error_body(
    apache_client: FileSystem,
) -> None:
    """Apache's 423 is a plain HTML page, not an RFC 4918 §16 <d:error> body - error_codes must degrade to empty, not raise."""
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/errbody.txt")
    assert _Apache.url is not None  # set by _apache_session above
    other = FileSystem(_Apache.url, auth=_Apache.auth)
    try:
        with apache_client.locked("compliance/errbody.txt", scope=EXCLUSIVE):
            session: Session = other._session
            response = session.put("compliance/errbody.txt", b"y", raise_on_error=False)
            assert response.status_code == 423
            with pytest.raises(ResourceLockedError) as exc_info:
                response.raise_for_status()
            assert exc_info.value.error_codes == frozenset()
    finally:
        other.close()


# ---------------------------------------------------------------------------
# Appendix B: the 207 partial-failure trap, against real nested/locked state
# ---------------------------------------------------------------------------


def test_apache_deleting_a_collection_with_a_locked_member_is_a_multistatuserror(
    apache_client: FileSystem,
) -> None:
    """§9.6.1: DELETE on a collection with a member this client cannot touch answers 207, not 204."""
    session: Session = apache_client._session
    apache_client.mkdir("compliance/delcoll")
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/delcoll/ok.txt")
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/delcoll/locked.txt")
    other = FileSystem(_Apache.url, auth=_Apache.auth)  # type: ignore[arg-type]
    try:
        with other.locked("compliance/delcoll/locked.txt", scope=EXCLUSIVE):
            with pytest.raises(MultiStatusError):
                session.delete("compliance/delcoll/").raise_for_status()
        # the lock is gone now - a retry succeeds and actually removes it.
        apache_client.remove("compliance/delcoll")
        assert not apache_client.exists("compliance/delcoll")
    finally:
        other.close()


def test_apache_a_clean_delete_of_a_nested_collection_is_204_not_207(
    apache_client: FileSystem,
) -> None:
    apache_client.mkdir("compliance/cleandel")
    apache_client.mkdir("compliance/cleandel/sub")
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/cleandel/a.txt")
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/cleandel/sub/b.txt")
    apache_client.remove("compliance/cleandel")
    assert not apache_client.exists("compliance/cleandel")


# ---------------------------------------------------------------------------
# RFC 9110 §13 conditional requests, against a real server
# ---------------------------------------------------------------------------


def test_apache_if_match_with_a_stale_etag_is_refused(
    apache_client: FileSystem,
) -> None:
    session: Session = apache_client._session
    session.put("compliance/etagstale.txt", b"v1").raise_for_status()
    response = session.put(
        "compliance/etagstale.txt",
        b"v2",
        if_match='"not-the-real-etag"',
        raise_on_error=False,
    )
    assert response.status_code == 412
    buf = io.BytesIO()
    apache_client.download_fileobj("compliance/etagstale.txt", buf)
    assert buf.getvalue() == b"v1"  # refused - the old content survives


def test_apache_if_none_match_star_atomic_create_is_really_atomic(
    apache_client: FileSystem,
) -> None:
    """§13.1.2: already covered generically against wsgidav (test_session_api.py) - re-verified here independently."""
    apache_client.upload_fileobj(
        io.BytesIO(b"first"), "compliance/atomic.txt", overwrite=False
    )
    with pytest.raises(ResourceAlreadyExistsError):
        apache_client.upload_fileobj(
            io.BytesIO(b"second"), "compliance/atomic.txt", overwrite=False
        )
    buf = io.BytesIO()
    apache_client.download_fileobj("compliance/atomic.txt", buf)
    assert buf.getvalue() == b"first"


def test_apache_a_race_to_create_a_collection_has_one_winner(
    apache_client: FileSystem,
) -> None:
    """RFC 4918 sec. 9.3.1 gives the losers a 405; Apache answers some of them 403 (seen in CI).

    So the fsspec filesystem takes a 403 or a 500 (WsgiDAV) for "exists" when the collection is
    there afterwards, see ``WebdavFileSystem._mkdir``. What is pinned here is what has to hold
    whatever the losers get: exactly one 201, and no other success.
    """
    statuses: list[int] = []
    barrier = threading.Barrier(12)
    path = f"compliance/race-{uuid.uuid4().hex}"

    def create() -> None:
        barrier.wait()
        response = apache_client.session.mkcol(path, raise_on_error=False)
        statuses.append(response.status_code)

    threads = [threading.Thread(target=create) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert statuses.count(201) == 1
    assert not [status for status in statuses if status < 400 and status != 201]
    assert apache_client.isdir(path)


# ---------------------------------------------------------------------------
# Range/resumable reads, against a real server
# ---------------------------------------------------------------------------


def test_apache_supports_range_reads(apache_client: FileSystem) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"0123456789"), "compliance/range.txt")
    with apache_client.open("compliance/range.txt", "rb") as reader:
        assert reader.read(4) == b"0123"
        reader.seek(7)
        assert reader.read() == b"789"


def test_apache_download_fileobj_resumes_after_a_seek(
    apache_client: FileSystem,
) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"abcdefghij"), "compliance/range2.txt")
    with apache_client.open("compliance/range2.txt", "rb") as reader:
        first_half = reader.read(5)
        reader.seek(0)
        full = reader.read()
    assert first_half == b"abcde"
    assert full == b"abcdefghij"


# ---------------------------------------------------------------------------
# PROPPATCH against a real, protected (server-maintained) property
# ---------------------------------------------------------------------------


def test_apache_proppatch_of_a_protected_property_fails_with_a_real_error_body(
    apache_client: FileSystem,
) -> None:
    """getcontentlength is server-maintained (§15.4) - confirmed here that Apache actually refuses to let a client set it."""
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/protected_prop.txt")
    with pytest.raises(MultiStatusError) as exc_info:
        apache_client.set_props(
            "compliance/protected_prop.txt", set_props={"getcontentlength": "999"}
        )
    assert "getcontentlength" in next(iter(exc_info.value.statuses))
    # content is untouched - the server did not actually accept the bogus value.
    props = apache_client.get_props(
        "compliance/protected_prop.txt", props=["content_length"]
    )
    assert props.content_length == 1


# ---------------------------------------------------------------------------
# Lock scope conflicts: SHARED vs. EXCLUSIVE, both directions
# ---------------------------------------------------------------------------


def test_apache_a_shared_lock_blocks_a_second_clients_exclusive_lock(
    apache_client: FileSystem,
) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/scope1.txt")
    other = FileSystem(_Apache.url, auth=_Apache.auth)  # type: ignore[arg-type]
    try:
        with apache_client.locked("compliance/scope1.txt", scope=SHARED):
            with pytest.raises(ResourceLockedError):
                with other.locked("compliance/scope1.txt", scope=EXCLUSIVE):
                    pass
    finally:
        other.close()


def test_apache_an_exclusive_lock_blocks_a_second_clients_shared_lock(
    apache_client: FileSystem,
) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/scope2.txt")
    other = FileSystem(_Apache.url, auth=_Apache.auth)  # type: ignore[arg-type]
    try:
        with apache_client.locked("compliance/scope2.txt", scope=EXCLUSIVE):
            with pytest.raises(ResourceLockedError):
                with other.locked("compliance/scope2.txt", scope=SHARED):
                    pass
    finally:
        other.close()


# ---------------------------------------------------------------------------
# UNLOCK: wrong client, wrong token
# ---------------------------------------------------------------------------


def test_apache_unlock_by_a_different_client_without_the_token_fails(
    apache_client: FileSystem,
) -> None:
    session: Session = apache_client._session
    session.put("compliance/wrongclient.txt", b"x").raise_for_status()
    response = session.lock("compliance/wrongclient.txt", scope=EXCLUSIVE)
    token = response.active_lock.token
    other = FileSystem(_Apache.url, auth=_Apache.auth)  # type: ignore[arg-type]
    try:
        other_session: Session = other._session
        unlock_response = other_session.unlock(
            "compliance/wrongclient.txt",
            "opaquelocktoken:not-the-real-one",
            raise_on_error=False,
        )
        assert unlock_response.status_code in (400, 403, 409, 412)
    finally:
        other.close()
    session.unlock("compliance/wrongclient.txt", token)


def test_apache_delete_of_a_locked_resource_without_the_token_fails(
    apache_client: FileSystem,
) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/delwrong.txt")
    other = FileSystem(_Apache.url, auth=_Apache.auth)  # type: ignore[arg-type]
    try:
        with apache_client.locked("compliance/delwrong.txt", scope=EXCLUSIVE):
            with pytest.raises(ResourceLockedError):
                other.remove("compliance/delwrong.txt")
    finally:
        other.close()
    assert apache_client.exists("compliance/delwrong.txt")


# ---------------------------------------------------------------------------
# Nested collections: COPY/MOVE of a whole subtree, and overwriting one
# ---------------------------------------------------------------------------


def test_apache_copy_of_a_nested_collection_duplicates_the_whole_subtree(
    apache_client: FileSystem,
) -> None:
    apache_client.mkdir("compliance/nestedsrc")
    apache_client.mkdir("compliance/nestedsrc/sub")
    apache_client.upload_fileobj(io.BytesIO(b"a"), "compliance/nestedsrc/a.txt")
    apache_client.upload_fileobj(io.BytesIO(b"b"), "compliance/nestedsrc/sub/b.txt")
    apache_client.copy("compliance/nestedsrc", "compliance/nesteddst")
    buf = io.BytesIO()
    apache_client.download_fileobj("compliance/nesteddst/sub/b.txt", buf)
    assert buf.getvalue() == b"b"
    # the source is untouched by a COPY.
    assert apache_client.exists("compliance/nestedsrc/sub/b.txt")


def test_apache_move_of_a_nested_collection_relocates_the_whole_subtree(
    apache_client: FileSystem,
) -> None:
    apache_client.mkdir("compliance/movesrc")
    apache_client.mkdir("compliance/movesrc/sub")
    apache_client.upload_fileobj(io.BytesIO(b"a"), "compliance/movesrc/sub/a.txt")
    apache_client.move("compliance/movesrc", "compliance/movedst")
    assert not apache_client.exists("compliance/movesrc")
    buf = io.BytesIO()
    apache_client.download_fileobj("compliance/movedst/sub/a.txt", buf)
    assert buf.getvalue() == b"a"


def test_apache_move_overwrites_an_existing_destination_collection_when_told_to(
    apache_client: FileSystem,
) -> None:
    """§9.9.3: with Overwrite: T, an existing destination collection is replaced, not merged with."""
    apache_client.mkdir("compliance/ovsrc")
    apache_client.upload_fileobj(io.BytesIO(b"new"), "compliance/ovsrc/new.txt")
    apache_client.mkdir("compliance/ovdst")
    apache_client.upload_fileobj(io.BytesIO(b"stale"), "compliance/ovdst/stale.txt")
    apache_client.move("compliance/ovsrc", "compliance/ovdst", overwrite=True)
    assert apache_client.exists("compliance/ovdst/new.txt")
    assert not apache_client.exists(
        "compliance/ovdst/stale.txt"
    )  # replaced, not merged


# ---------------------------------------------------------------------------
# copy()/move() exception-type consistency (this session's fix), against Apache
# ---------------------------------------------------------------------------


def test_apache_copy_onto_an_existing_destination_is_resourcealreadyexists(
    apache_client: FileSystem,
) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"src"), "compliance/ow_src.txt")
    apache_client.upload_fileobj(io.BytesIO(b"dst"), "compliance/ow_dst.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        apache_client.copy(
            "compliance/ow_src.txt", "compliance/ow_dst.txt", overwrite=False
        )


def test_apache_move_onto_an_existing_destination_is_resourcealreadyexists(
    apache_client: FileSystem,
) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"src"), "compliance/owm_src.txt")
    apache_client.upload_fileobj(io.BytesIO(b"dst"), "compliance/owm_dst.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        apache_client.move(
            "compliance/owm_src.txt", "compliance/owm_dst.txt", overwrite=False
        )


# ---------------------------------------------------------------------------
# GET on a collection: server-defined (§9.4) - must not crash either way
# ---------------------------------------------------------------------------


def test_apache_get_on_a_collection_does_not_crash(apache_client: FileSystem) -> None:
    apache_client.mkdir("compliance/plaincoll")
    session: Session = apache_client._session
    response = session.get("compliance/plaincoll/")
    assert response.status_code < 500


def test_apache_isdir_correctly_identifies_a_real_collection(
    apache_client: FileSystem,
) -> None:
    apache_client.mkdir("compliance/adircheck")
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/afilecheck.txt")
    assert apache_client.isdir("compliance/adircheck") is True
    assert apache_client.isdir("compliance/afilecheck.txt") is False


# ---------------------------------------------------------------------------
# walk(), against a real nested tree
# ---------------------------------------------------------------------------


def test_apache_walk_covers_a_real_nested_tree(apache_client: FileSystem) -> None:
    apache_client.mkdir("compliance/walkroot")
    apache_client.mkdir("compliance/walkroot/sub")
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/walkroot/top.txt")
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/walkroot/sub/deep.txt")
    seen_files: set[str] = set()
    for _path, _dirs, files in apache_client.walk("compliance/walkroot"):
        seen_files.update(f.name for f in files)
    assert "compliance/walkroot/top.txt" in seen_files
    assert "compliance/walkroot/sub/deep.txt" in seen_files


# ===========================================================================
# Apache's behavior, measured against a real 2.4 instance and traced in the
# mod_dav / mod_dav_fs / core sources (modules/dav/main/mod_dav.c, util.c,
# modules/dav/fs/repos.c, lock.c, modules/http/http_etag.c). Each test says
# which behavior it pins and where it comes from. The requests that must not
# carry anything this library adds on its own (an ``If`` header for a lock the
# session holds, ...) are sent with ``requests`` directly.
# ===========================================================================

_LOCK_BODY = (
    '<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:">'
    "<D:lockscope><D:{scope}/></D:lockscope><D:locktype><D:write/></D:locktype>"
    "</D:lockinfo>"
)
_HTML_ERROR_PAGE = re.compile(r"<title>\d{3} ", re.IGNORECASE)

#: Ports of the extra instances below - distinct from the shared one (8765) and from nginx's (8766).
_PORTS = {
    "etag": 8781,
    "depth": 8782,
    "mintimeout": 8783,
    "nolockdb": 8784,
    "nodavlock": 8785,
    "keepalive_max": 8786,
    "keepalive_idle": 8787,
    "timeout": 8788,
    "limit": 8789,
    "dbm": 8791,
}

_needs_local_apache = pytest.mark.skipif(
    bool(apache_instance.missing_prerequisites()),
    reason="starts a second, differently configured Apache - needs a local install",
)


def _http(
    method: str, path: str, *, base: "str | None" = None, **kwargs: Any
) -> requests.Response:
    """One request, with nothing but what is passed: no lock tokens, no conditions of its own."""
    root = base or _Apache.url
    assert root is not None  # set by _apache_session above
    return requests.request(
        method, f"{root}/{path}", auth=_Apache.auth, timeout=10, **kwargs
    )


def _lock(
    path: str,
    *,
    scope: str = "exclusive",
    depth: "str | None" = None,
    timeout: "str | None" = None,
    base: "str | None" = None,
) -> requests.Response:
    headers = {}
    if depth is not None:
        headers["Depth"] = depth
    if timeout is not None:
        headers["Timeout"] = timeout
    return _http(
        "LOCK",
        path,
        base=base,
        data=_LOCK_BODY.format(scope=scope),
        headers=headers,
    )


def _token(lock_response: requests.Response) -> str:
    assert lock_response.status_code == 200, lock_response.text
    return lock_response.headers["Lock-Token"].strip("<>")


def _unlock(path: str, token: str, *, base: "str | None" = None) -> requests.Response:
    return _http("UNLOCK", path, base=base, headers={"Lock-Token": f"<{token}>"})


def _granted_timeout(lock_response: requests.Response) -> str:
    match = re.search(r"timeout>([^<]*)<", lock_response.text)
    assert match is not None, lock_response.text
    return match.group(1)


def _etag(path: str, *, base: "str | None" = None) -> str:
    response = _http("PROPFIND", path, base=base, headers={"Depth": "0"})
    match = re.search(r"getetag>([^<]*)<", response.text)
    assert match is not None, response.text
    return match.group(1)


def _hrefs(multistatus: requests.Response) -> "dict[str, str]":
    """``href`` to the status line of a multistatus body, in the order it lists them."""
    return dict(
        re.findall(
            r"<D:href>([^<]*)</D:href>\s*<D:status>HTTP/1\.1 ([^<]*)</D:status>",
            multistatus.text,
        )
    )


@pytest.fixture
def scratch(apache_client: FileSystem) -> Iterator[str]:
    """A collection of its own, so that no test depends on what another left behind."""
    name = f"scratch-{uuid.uuid4().hex[:10]}"
    apache_client.mkdir(name)
    yield name
    with contextlib.suppress(Exception):
        apache_client.remove(name)


@contextmanager
def _variant(tmp_path: Path, name: str, **options: Any) -> Iterator[str]:
    """A second instance, configured differently from the shared one; yields its base URL."""
    port = _PORTS[name]
    conf_file = apache_instance.write_instance(tmp_path / name, port=port, **options)
    apache_instance.start(conf_file, port=port)
    try:
        yield f"http://{apache_instance.HOST}:{port}"
    finally:
        apache_instance.stop(conf_file)


@contextmanager
def _variant_fs(tmp_path: Path, name: str, **options: Any) -> Iterator[FileSystem]:
    """A client of :func:`_variant`'s instance."""
    with (
        _variant(tmp_path, name, **options) as base,
        FileSystem(base, auth=_Apache.auth) as fs,
    ):
        yield fs


# ---------------------------------------------------------------------------
# ETag - the rule is in modules/http/http_etag.c
# ---------------------------------------------------------------------------


def _weak_etag_after_a_write(directory: str, *, base: "str | None" = None) -> str:
    """The ETag of a file just written - a few tries, as a run that stalls for a second cannot see it weak."""
    for attempt in range(5):
        path = f"{directory}/fresh-{attempt}.txt"
        _http("PUT", path, base=base, data=b"v1").raise_for_status()
        etag = _etag(path, base=base)
        if etag.startswith("W/"):
            return etag
    pytest.fail("the ETag of a file written a moment ago was never weak")


def test_apache_etag_is_weak_right_after_a_write(scratch: str) -> None:
    """Weak (``W/``) if the file changed less than one second before the request - the rule is
    ``request_time - mtime < 1s``, in the core, not a setting."""
    assert _weak_etag_after_a_write(scratch).startswith('W/"')


def test_apache_etag_is_strong_once_the_file_is_a_second_old(scratch: str) -> None:
    path = f"{scratch}/aged.txt"
    _http("PUT", path, data=b"v1").raise_for_status()
    time.sleep(1.2)
    etag = _etag(path)
    assert etag.startswith('"')
    assert _etag(path) == etag  # and it stays the same, it is not drawn per request


def test_apache_put_response_carries_no_etag_header(scratch: str) -> None:
    """The new ETag is not in the answer to the PUT - a client has to ask for it."""
    response = _http("PUT", f"{scratch}/noetag.txt", data=b"v1")
    assert response.status_code == 201
    assert "ETag" not in response.headers


def test_apache_a_weak_etag_taken_right_after_a_write_is_refused_client_side(
    apache_client: FileSystem, scratch: str
) -> None:
    """Not a library bug: a weak ETag can never be used for ``If-Match`` (RFC 9110 sec. 13.1.1), and
    Apache's own ETag is weak for the first second - so passing it straight on fails client-side.
    Wait a second (next test), or ask again later."""
    session: Session = apache_client._session
    etag = _weak_etag_after_a_write(scratch)
    with pytest.raises(ValueError, match="weak"):
        session.put(f"{scratch}/fresh-0.txt", b"v2", if_match=etag)


def test_apache_if_match_with_the_strong_etag_of_an_aged_file_replaces_it(
    apache_client: FileSystem, scratch: str
) -> None:
    session: Session = apache_client._session
    path = f"{scratch}/ifmatch.txt"
    session.put(path, b"v1").raise_for_status()
    time.sleep(1.2)
    etag = apache_client.get_props(path, props=["etag"]).etag
    assert etag is not None
    assert not etag.startswith("W/")
    session.put(path, b"v2", if_match=etag).raise_for_status()
    # ... and the ETag the file had is not valid any more
    stale = session.put(path, b"v3", if_match=etag, raise_on_error=False)
    assert stale.status_code == 412
    buf = io.BytesIO()
    apache_client.download_fileobj(path, buf)
    assert buf.getvalue() == b"v2"


def test_apache_refuses_a_weak_if_match_on_its_own(scratch: str) -> None:
    """Apache compares ``If-Match`` strongly as well: even its own current ETag, sent as ``W/...``, is a 412."""
    path = f"{scratch}/weakmatch.txt"
    _http("PUT", path, data=b"v1").raise_for_status()
    time.sleep(1.2)
    etag = _etag(path)
    refused = _http("PUT", path, data=b"v2", headers={"If-Match": f"W/{etag}"})
    assert refused.status_code == 412
    accepted = _http("PUT", path, data=b"v2", headers={"If-Match": etag})
    assert accepted.status_code == 204


@_needs_local_apache
def test_apache_file_etag_directive_does_not_make_a_fresh_etag_strong(
    tmp_path: Path,
) -> None:
    """``FileETag`` picks what the value is made of (inode, size, mtime), not whether it is weak -
    ``docs/apache-compliance-check.md`` used to recommend it for that, which does not work.
    """
    with _variant(tmp_path, "etag", extra_conf="FileETag INode MTime Size") as base:
        assert _http("MKCOL", "d", base=base).status_code == 201
        assert _weak_etag_after_a_write("d", base=base).startswith('W/"')
        path = "d/aged.txt"
        _http("PUT", path, base=base, data=b"v1").raise_for_status()
        time.sleep(1.2)
        assert not _etag(path, base=base).startswith("W/")


# ---------------------------------------------------------------------------
# A lock on an unmapped URL: lock-null, not an empty resource (mod_dav_fs
# lock.c, dav_fs_add_locknull_state / dav_fs_remove_locknull_member)
# ---------------------------------------------------------------------------


def test_apache_lock_on_an_unmapped_url_is_lock_null_and_not_a_resource(
    apache_client: FileSystem, scratch: str
) -> None:
    """RFC 2518 sec. 7.4's lock-null state, which RFC 4918 replaced by "an empty resource": PROPFIND
    finds it (so ``exists()`` is true), GET and HEAD do not, and the parent lists it."""
    path = f"{scratch}/ln.txt"
    with apache_client.locked(path) as active_lock:
        assert active_lock.token
        assert apache_client.exists(path)
        assert _http("GET", path).status_code == 404
        assert _http("HEAD", path).status_code == 404
        listing = _http("PROPFIND", scratch, headers={"Depth": "1"})
        assert f"/{path}" in listing.text
        assert apache_client.get_props(path).active_locks
    assert not apache_client.exists(path)
    assert _http("GET", path).status_code == 404


def test_apache_a_lock_null_resource_looks_like_an_empty_file(
    apache_client: FileSystem, scratch: str
) -> None:
    """Its ``resourcetype`` is empty, so ``isfile()`` is true for it - there is nothing else to tell
    it from a file by (no ``getcontentlength``, no ``getetag``)."""
    path = f"{scratch}/ln-type.txt"
    with apache_client.locked(path):
        assert apache_client.isfile(path)
        assert not apache_client.isdir(path)
        props = apache_client.get_props(path)
        assert props.etag is None
        assert props.content_length is None
    assert not apache_client.isfile(path)


def test_apache_put_with_the_token_makes_a_lock_null_resource_a_real_file(
    apache_client: FileSystem, scratch: str
) -> None:
    """A write through the lock turns lock-null into a file that outlives the UNLOCK."""
    path = f"{scratch}/ln-put.txt"
    with apache_client.locked(path):
        apache_client.upload_fileobj(io.BytesIO(b"hello"), path, overwrite=True)
    buf = io.BytesIO()
    apache_client.download_fileobj(path, buf)
    assert buf.getvalue() == b"hello"


def test_apache_put_without_the_token_cannot_fill_a_lock_null_resource(
    apache_client: FileSystem, scratch: str
) -> None:
    path = f"{scratch}/ln-foreign.txt"
    with apache_client.locked(path):
        assert _http("PUT", path, data=b"x").status_code == 423
    assert not apache_client.exists(path)


# ---------------------------------------------------------------------------
# If-None-Match: * is decided before the body is read - not atomic
# (mod_dav.c dav_method_put: dav_validate_request, then open_stream, write,
# close_stream = rename of a temp file, repos.c dav_fs_close_stream)
# ---------------------------------------------------------------------------


def _put_in_two_parts(path: str, first: bytes, rest: bytes, *, between: Any) -> int:
    """``PUT`` with ``If-None-Match: *`` whose body stops after ``first`` until ``between()`` has run."""
    assert _Apache.url is not None
    parts = urlsplit(_Apache.url)
    credentials = base64.b64encode(":".join(_Apache.auth).encode()).decode()
    head = (
        f"PUT /{path} HTTP/1.1\r\nHost: {parts.netloc}\r\n"
        f"Authorization: Basic {credentials}\r\nIf-None-Match: *\r\n"
        f"Content-Length: {len(first) + len(rest)}\r\nConnection: close\r\n\r\n"
    ).encode()
    address = (parts.hostname or apache_instance.HOST, parts.port or 80)
    with socket.create_connection(address, timeout=10) as sock:
        sock.sendall(head + first)
        between()
        sock.sendall(rest)
        status_line = sock.makefile("rb").readline().decode()
    return int(status_line.split()[1])


def test_apache_if_none_match_star_is_checked_before_the_body_is_read(
    apache_client: FileSystem, scratch: str
) -> None:
    """Why ``overwrite=False`` is not a guarantee of exactly one writer on Apache: the condition is
    evaluated when the request arrives, the file is created when the body is complete. A creator
    that arrives and finishes in between does not stop the one that was already let through - its
    file is replaced, and both are told 201."""
    for attempt in range(3):
        path = f"{scratch}/race-{attempt}.txt"
        second: list[int] = []

        def create_in_between(path: str = path, second: "list[int]" = second) -> None:
            time.sleep(
                0.5
            )  # long enough for the first request's headers to have been checked
            second.append(
                _http(
                    "PUT", path, data=b"second", headers={"If-None-Match": "*"}
                ).status_code
            )

        first = _put_in_two_parts(path, b"fi", b"rst", between=create_in_between)
        if first == 201:  # the first request was checked before the second was done
            assert second == [201]
            buf = io.BytesIO()
            apache_client.download_fileobj(path, buf)
            assert buf.getvalue() == b"first"  # the later creator's file is gone
            return
    pytest.fail(
        "the first request was never let through - the server is too slow for this check"
    )


def test_apache_concurrent_if_none_match_star_creators_only_ever_get_201_or_412(
    apache_client: FileSystem, scratch: str
) -> None:
    """What does hold, whatever the timing: nothing but 201 and 412, at least one winner, and the
    file is one writer's whole body. (More than one 201 is possible - see the test above.)
    """
    path = f"{scratch}/many.txt"
    statuses: list[int] = []
    barrier = threading.Barrier(16)

    def create(index: int) -> None:
        barrier.wait()
        statuses.append(
            _http(
                "PUT",
                path,
                data=f"writer-{index}".encode(),
                headers={"If-None-Match": "*"},
            ).status_code
        )

    threads = [threading.Thread(target=create, args=(i,)) for i in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert set(statuses) <= {201, 412}
    assert 201 in statuses
    buf = io.BytesIO()
    apache_client.download_fileobj(path, buf)
    assert re.fullmatch(rb"writer-\d+", buf.getvalue())


def test_apache_a_sequential_second_creator_is_refused(
    apache_client: FileSystem, scratch: str
) -> None:
    path = f"{scratch}/seq.txt"
    apache_client.upload_fileobj(io.BytesIO(b"first"), path, overwrite=False)
    with pytest.raises(ResourceAlreadyExistsError):
        apache_client.upload_fileobj(io.BytesIO(b"second"), path, overwrite=False)
    buf = io.BytesIO()
    apache_client.download_fileobj(path, buf)
    assert buf.getvalue() == b"first"


def test_apache_a_lock_makes_the_creator_exclusive(scratch: str) -> None:
    """What to use where exactly one writer must win: a lock, which Apache does enforce."""
    path = f"{scratch}/exclusive.txt"
    token = _token(_lock(path))
    try:
        assert (
            _http("PUT", path, data=b"x", headers={"If-None-Match": "*"}).status_code
            == 423
        )
    finally:
        _unlock(path, token)


# ---------------------------------------------------------------------------
# MKCOL (mod_dav.c dav_method_mkcol, repos.c dav_fs_get_resource and
# dav_fs_create_collection)
# ---------------------------------------------------------------------------


def test_apache_mkcol_on_an_existing_file_is_405_but_400_with_the_trailing_slash(
    scratch: str,
) -> None:
    """The slash ``mkdir()`` always adds makes Apache's path resolution see "extraneous path
    components" below a file: a 400 from ``dav_fs_get_resource`` (2.4; trunk answers 404).
    """
    _http("PUT", f"{scratch}/f.txt", data=b"x").raise_for_status()
    assert _http("MKCOL", f"{scratch}/f.txt").status_code == 405
    assert _http("MKCOL", f"{scratch}/f.txt/").status_code == 400


@pytest.mark.parametrize("suffix", ["child", "child/", "child/grandchild/"])
def test_apache_mkcol_below_a_file_is_a_400(scratch: str, suffix: str) -> None:
    _http("PUT", f"{scratch}/f.txt", data=b"x").raise_for_status()
    assert _http("MKCOL", f"{scratch}/f.txt/{suffix}").status_code == 400


def test_apache_mkdir_on_a_file_is_already_exists_but_below_a_file_it_is_not(
    apache_client: FileSystem, scratch: str
) -> None:
    """Both are a 400 on the wire; only the resource that is there makes it "already exists"."""
    apache_client.upload_fileobj(io.BytesIO(b"x"), f"{scratch}/f.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        apache_client.mkdir(f"{scratch}/f.txt")
    with pytest.raises(HTTPStatusError) as exc_info:
        apache_client.mkdir(f"{scratch}/f.txt/child")
    assert exc_info.value.status_code == 400
    assert not isinstance(exc_info.value, ResourceAlreadyExistsError)


def test_apache_mkcol_on_an_existing_collection_is_405(scratch: str) -> None:
    assert _http("MKCOL", f"{scratch}/").status_code == 405


def test_apache_a_mkcol_race_has_one_winner_and_the_rest_are_refused(
    scratch: str,
) -> None:
    """One 201; every other request is refused - mostly 405 ("exists" when they looked), or 403
    (``apr_dir_make`` failed with EEXIST after they had looked: ``dav_fs_create_collection`` maps every
    error but ENOSPC/ENOENT to 403). Which code a loser gets is timing, and not pinned.
    """
    statuses: list[int] = []
    barrier = threading.Barrier(24)
    path = f"{scratch}/race-{uuid.uuid4().hex}"

    def create() -> None:
        barrier.wait()
        statuses.append(_http("MKCOL", path).status_code)

    threads = [threading.Thread(target=create) for _ in range(24)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert statuses.count(201) == 1
    assert all(status >= 400 for status in statuses if status != 201)


@pytest.mark.parametrize(
    "headers",
    [{"Content-Type": "application/xml"}, {}],
    ids=["xml", "no-content-type"],
)
def test_apache_mkcol_with_a_body_is_415_and_creates_nothing(
    scratch: str, headers: "dict[str, str]"
) -> None:
    """``process_mkcol_body``: any body at all, whatever it says (no RFC 5689 support)."""
    path = f"{scratch}/withbody"
    assert _http("MKCOL", path, data=b"<x/>", headers=headers).status_code == 415
    assert _http("PROPFIND", path, headers={"Depth": "0"}).status_code == 404


def test_apache_mkcol_with_an_empty_body_creates_the_collection(scratch: str) -> None:
    assert _http("MKCOL", f"{scratch}/emptybody", data=b"").status_code == 201


# ---------------------------------------------------------------------------
# 423 and what stands behind it (util.c dav_validate_request; the core's
# error page; mod_dav never builds a <D:error> for a lock)
# ---------------------------------------------------------------------------


def test_apache_423_is_the_cores_html_error_page_and_never_a_dav_error(
    scratch: str,
) -> None:
    path = f"{scratch}/locked.txt"
    _http("PUT", path, data=b"x").raise_for_status()
    token = _token(_lock(path))
    try:
        response = _http("PUT", path, data=b"y")
    finally:
        _unlock(path, token)
    assert response.status_code == 423
    assert response.headers["Content-Type"].startswith("text/html")
    assert _HTML_ERROR_PAGE.search(response.text)
    assert "DAV:" not in response.text
    assert "lock-token-submitted" not in response.text


@pytest.mark.parametrize("depth", ["0", "infinity"])
def test_apache_a_new_member_of_a_locked_collection_is_a_207_and_not_created(
    apache_client: FileSystem, scratch: str, depth: str
) -> None:
    """The parent is what is locked: the 423 is reported for the parent, with a 424 for the new
    member, under a 207 - a status a PUT is not expected to answer (``DAV_VALIDATE_PARENT``).
    """
    token = _token(_lock(scratch, depth=depth))
    try:
        response = _http("PUT", f"{scratch}/new.txt", data=b"x")
        assert response.status_code == 207
        assert _hrefs(response) == {
            f"/{scratch}/new.txt": "424 Failed Dependency",
            f"/{scratch}": "423 Locked",
        }
        assert _http("MKCOL", f"{scratch}/newdir").status_code == 207
        assert not apache_client.exists(f"{scratch}/new.txt")
        assert not apache_client.exists(f"{scratch}/newdir")
        # the same request, naming the collection's lock for the collection, is let through
        tagged = {"If": f"<{_Apache.url}/{scratch}/> (<{token}>)"}
        created = _http("PUT", f"{scratch}/new.txt", data=b"x", headers=tagged)
        assert created.status_code == 201
    finally:
        _unlock(scratch, token)


def test_apache_an_existing_member_of_an_infinity_locked_collection_is_a_plain_423(
    scratch: str,
) -> None:
    """Only a *new* member is a 207: an existing one is itself covered by the lock."""
    _http("PUT", f"{scratch}/old.txt", data=b"x").raise_for_status()
    token = _token(_lock(scratch, depth="infinity"))
    try:
        assert _http("PUT", f"{scratch}/old.txt", data=b"y").status_code == 423
    finally:
        _unlock(scratch, token)


def test_apache_the_client_reports_a_new_member_in_a_locked_collection_as_a_multistatuserror(
    apache_client: FileSystem, scratch: str
) -> None:
    """The 207 is not a created resource: the client raises, naming the locked parent - it is not
    a ``ResourceLockedError``, since the member itself is not what is locked."""
    assert _Apache.url is not None
    with (
        FileSystem(_Apache.url, auth=_Apache.auth) as other,
        apache_client.locked(scratch, depth="0"),
    ):
        with pytest.raises(MultiStatusError) as exc_info:
            other.upload_fileobj(io.BytesIO(b"x"), f"{scratch}/new.txt")
        assert any(scratch in href for href in exc_info.value.statuses)
        assert not apache_client.exists(f"{scratch}/new.txt")
        # the holder of the lock can write there
        apache_client.upload_fileobj(io.BytesIO(b"x"), f"{scratch}/new.txt")
    assert apache_client.exists(f"{scratch}/new.txt")


def test_apache_delete_blocked_by_a_locked_member_is_a_424_that_deletes_nothing(
    apache_client: FileSystem, scratch: str
) -> None:
    """``DAV_VALIDATE_USE_424``: the whole DELETE is refused up front, the multistatus names only the
    member that is locked - the other members and the collection itself stay."""
    apache_client.mkdir(f"{scratch}/tree")
    apache_client.upload_fileobj(io.BytesIO(b"x"), f"{scratch}/tree/ok.txt")
    apache_client.upload_fileobj(io.BytesIO(b"x"), f"{scratch}/tree/locked.txt")
    token = _token(_lock(f"{scratch}/tree/locked.txt"))
    try:
        response = _http("DELETE", f"{scratch}/tree/")
    finally:
        _unlock(f"{scratch}/tree/locked.txt", token)
    assert response.status_code == 424
    assert response.headers["Content-Type"].startswith("text/xml")
    assert _hrefs(response) == {f"/{scratch}/tree/locked.txt": "423 Locked"}
    assert apache_client.exists(f"{scratch}/tree/ok.txt")
    assert apache_client.exists(f"{scratch}/tree/locked.txt")


def test_apache_move_out_of_a_locked_collection_is_a_424_naming_the_collection(
    scratch: str,
) -> None:
    _http("PUT", f"{scratch}/child.txt", data=b"x").raise_for_status()
    token = _token(_lock(scratch, depth="0"))
    try:
        response = _http(
            "MOVE",
            f"{scratch}/child.txt",
            headers={"Destination": f"{_Apache.url}/{scratch}-out.txt"},
        )
        assert response.status_code == 424
        assert _hrefs(response) == {f"/{scratch}": "423 Locked"}
    finally:
        _unlock(scratch, token)
    _http("DELETE", f"{scratch}-out.txt")


# ---------------------------------------------------------------------------
# The If header: which list applies to which resource (util.c
# dav_validate_resource_state - a list for a resource that does not hold the
# lock is false, a list tagged with another resource does not apply)
# ---------------------------------------------------------------------------


def test_apache_untagged_if_with_a_lock_token_fails_for_a_copy_onto_a_locked_file(
    scratch: str,
) -> None:
    """An untagged list is evaluated for every resource the method touches, the unlocked source
    included - where the token is false, so the whole request is a 412. Tagged with the
    destination it applies to the destination alone (what ``Session.copy`` sends)."""
    _http("PUT", f"{scratch}/src.txt", data=b"source").raise_for_status()
    _http("PUT", f"{scratch}/dst.txt", data=b"old").raise_for_status()
    token = _token(_lock(f"{scratch}/dst.txt"))
    destination = {"Destination": f"{_Apache.url}/{scratch}/dst.txt"}
    try:
        none = _http("COPY", f"{scratch}/src.txt", headers=destination)
        untagged = _http(
            "COPY", f"{scratch}/src.txt", headers={**destination, "If": f"(<{token}>)"}
        )
        tagged = _http(
            "COPY",
            f"{scratch}/src.txt",
            headers={
                **destination,
                "If": f"<{_Apache.url}/{scratch}/dst.txt> (<{token}>)",
            },
        )
    finally:
        _unlock(f"{scratch}/dst.txt", token)
    assert (none.status_code, untagged.status_code, tagged.status_code) == (
        423,
        412,
        204,
    )
    assert _http("GET", f"{scratch}/dst.txt").content == b"source"


def test_apache_untagged_if_with_the_collections_token_fails_for_a_move_of_a_member(
    scratch: str,
) -> None:
    _http("PUT", f"{scratch}/m.txt", data=b"x").raise_for_status()
    token = _token(_lock(scratch, depth="0"))
    destination = {"Destination": f"{_Apache.url}/{scratch}-m.txt"}
    try:
        untagged = _http(
            "MOVE", f"{scratch}/m.txt", headers={**destination, "If": f"(<{token}>)"}
        )
        tagged = _http(
            "MOVE",
            f"{scratch}/m.txt",
            headers={**destination, "If": f"<{_Apache.url}/{scratch}/> (<{token}>)"},
        )
    finally:
        _unlock(scratch, token)
    assert (untagged.status_code, tagged.status_code) == (412, 201)
    _http("DELETE", f"{scratch}-m.txt")


def test_apache_untagged_if_with_a_token_fails_for_a_new_member_but_a_tagged_one_does_not(
    scratch: str,
) -> None:
    token = _token(_lock(scratch, depth="0"))
    try:
        untagged = _http(
            "PUT", f"{scratch}/n.txt", data=b"x", headers={"If": f"(<{token}>)"}
        )
        tagged = _http(
            "PUT",
            f"{scratch}/n.txt",
            data=b"x",
            headers={"If": f"<{_Apache.url}/{scratch}/> (<{token}>)"},
        )
    finally:
        _unlock(scratch, token)
    assert (untagged.status_code, tagged.status_code) == (412, 201)


def test_apache_the_session_tags_the_tokens_it_sends(
    apache_client: FileSystem, scratch: str
) -> None:
    """The reason the untagged form is not used: every write of the session under a held lock
    works - member into a locked collection, copy onto a locked file, move out of a collection.
    """
    session: Session = apache_client._session
    apache_client.upload_fileobj(io.BytesIO(b"x"), f"{scratch}/a.txt")
    apache_client.upload_fileobj(io.BytesIO(b"y"), f"{scratch}/b.txt")
    with apache_client.locked(scratch, depth="0"):
        apache_client.upload_fileobj(io.BytesIO(b"z"), f"{scratch}/c.txt")
        session.move(
            f"{scratch}/a.txt", destination=f"{scratch}-a.txt"
        ).raise_for_status()
    session.delete(f"{scratch}-a.txt").raise_for_status()
    with apache_client.locked(f"{scratch}/b.txt"):
        session.copy(
            f"{scratch}/c.txt", destination=f"{scratch}/b.txt", overwrite=True
        ).raise_for_status()


# ---------------------------------------------------------------------------
# PROPPATCH (props.c: a live property is read-only; mod_dav.c
# dav_failed_proppatch writes the status line itself)
# ---------------------------------------------------------------------------


def test_apache_a_failed_proppatch_is_a_207_with_a_409_and_a_status_line_of_its_own(
    scratch: str,
) -> None:
    _http("PUT", f"{scratch}/pp.txt", data=b"x").raise_for_status()
    body = (
        '<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>'
        "<D:getcontentlength>999</D:getcontentlength></D:prop></D:set></D:propertyupdate>"
    )
    response = _http("PROPPATCH", f"{scratch}/pp.txt", data=body)
    assert response.status_code == 207
    # the reason phrase is the literal "(status)" in mod_dav.c, not "Conflict"
    assert "<D:status>HTTP/1.1 409 (status)</D:status>" in response.text
    assert "Property is read-only." in response.text


def test_apache_the_client_names_the_read_only_property(
    apache_client: FileSystem, scratch: str
) -> None:
    path = f"{scratch}/pp-client.txt"
    apache_client.upload_fileobj(io.BytesIO(b"x"), path)
    with pytest.raises(MultiStatusError) as exc_info:
        apache_client.set_props(path, set_props={"getcontentlength": "999"})
    assert exc_info.value.statuses == {f"/{path} (getcontentlength)": "Conflict"}


def test_apache_a_proppatch_is_all_or_nothing(
    apache_client: FileSystem, scratch: str
) -> None:
    """One read-only property in the update fails the other, writable one too (it is rolled back)."""
    path = f"{scratch}/pp-atomic.txt"
    apache_client.upload_fileobj(io.BytesIO(b"x"), path)
    namespace = "https://example.org/ns"
    with pytest.raises(MultiStatusError) as exc_info:
        apache_client.set_props(
            path,
            set_props={"getcontentlength": "999", (namespace, "color"): "blue"},
        )
    assert len(exc_info.value.statuses) == 2
    assert (
        apache_client.get_props(path, props=[(namespace, "color")]).text(
            namespace, "color"
        )
        is None
    )


# ---------------------------------------------------------------------------
# PROPFIND depth (mod_dav.c dav_method_propfind: DavDepthInfinity is off)
# ---------------------------------------------------------------------------


def test_apache_depth_infinity_and_no_depth_at_all_are_forbidden_on_a_collection(
    scratch: str,
) -> None:
    assert (
        _http("PROPFIND", f"{scratch}/", headers={"Depth": "infinity"}).status_code
        == 403
    )
    assert (
        _http("PROPFIND", f"{scratch}/").status_code == 403
    )  # no header means infinity
    assert _http("PROPFIND", f"{scratch}/", headers={"Depth": "0"}).status_code == 207
    assert _http("PROPFIND", f"{scratch}/", headers={"Depth": "1"}).status_code == 207


def test_apache_a_file_needs_no_depth(scratch: str) -> None:
    """The ban is on a *collection* with infinity: a file has no members."""
    _http("PUT", f"{scratch}/f.txt", data=b"x").raise_for_status()
    assert _http("PROPFIND", f"{scratch}/f.txt").status_code == 207


@_needs_local_apache
def test_apache_depth_infinity_is_answered_with_davdepthinfinity_on(
    tmp_path: Path,
) -> None:
    with _variant(tmp_path, "depth", extra_conf="DavDepthInfinity On") as base:
        assert _http("MKCOL", "d/", base=base).status_code == 201
        assert (
            _http(
                "PROPFIND", "d/", base=base, headers={"Depth": "infinity"}
            ).status_code
            == 207
        )
        assert _http("PROPFIND", "d/", base=base).status_code == 207


# ---------------------------------------------------------------------------
# Lock timeouts (util.c dav_get_timeout; mod_dav.c dav_method_lock, DavMinTimeout)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "granted"),
    [
        ("Second-30", "Second-30"),
        ("Second-5", "Second-5"),
        ("Second-4100000000", "Second-4100000000"),
        ("Infinite", "Infinite"),
        # the first one it understands - in the order sent, not the shortest
        ("Second-30, Second-3600", "Second-30"),
        ("Second-3600, Second-30", "Second-3600"),
        ("Infinite, Second-4100000000", "Infinite"),
        # nothing it understands is infinite, and so is no header at all
        ("garbage", "Infinite"),
        ("Second-", "Second-0"),
        (None, "Infinite"),
    ],
)
def test_apache_lock_timeout_header(
    scratch: str, header: "str | None", granted: str
) -> None:
    path = f"{scratch}/timeout.txt"
    response = _lock(path, timeout=header)
    token = _token(response)
    try:
        assert _granted_timeout(response) == granted
    finally:
        _unlock(path, token)


def test_apache_a_lock_without_a_timeout_never_runs_out(scratch: str) -> None:
    """The default of the *client* is 600 seconds (``DEFAULT_LOCK_TIMEOUT``) - Apache's own is no limit."""
    path = f"{scratch}/forever.txt"
    token = _token(_lock(path))
    try:
        discovery = _http("PROPFIND", path, headers={"Depth": "0"})
        assert "<D:timeout>Infinite</D:timeout>" in discovery.text
    finally:
        _unlock(path, token)


def test_apache_the_client_asks_for_600_seconds_by_default_and_for_none_with_none(
    apache_client: FileSystem, scratch: str
) -> None:
    with apache_client.locked(f"{scratch}/t600.txt") as default:
        assert default.timeout == 600
    with apache_client.locked(f"{scratch}/tnone.txt", lock_timeout=None) as forever:
        assert forever.timeout is None
    with apache_client.locked(
        f"{scratch}/tlist.txt", lock_timeout=[90, 3600]
    ) as preferred:
        assert preferred.timeout == 90


def test_apache_a_refresh_answers_the_new_timeout_and_no_lock_token(
    scratch: str,
) -> None:
    """A LOCK without a body and with the token in ``If`` (RFC 4918 sec. 9.10.2) - nothing new is created."""
    path = f"{scratch}/refresh.txt"
    token = _token(_lock(path, timeout="Second-30"))
    try:
        refreshed = _http(
            "LOCK", path, headers={"If": f"(<{token}>)", "Timeout": "Second-90"}
        )
        assert refreshed.status_code == 200
        assert _granted_timeout(refreshed) == "Second-90"
        assert "Lock-Token" not in refreshed.headers
        assert token in refreshed.text
    finally:
        _unlock(path, token)


@_needs_local_apache
def test_apache_davmintimeout_raises_a_short_timeout_but_not_infinite(
    tmp_path: Path,
) -> None:
    with _variant(tmp_path, "mintimeout", extra_conf="DavMinTimeout 120") as base:
        short = _lock("a.txt", timeout="Second-5", base=base)
        forever = _lock("b.txt", timeout="Infinite", base=base)
        try:
            assert _granted_timeout(short) == "Second-120"
            assert _granted_timeout(forever) == "Infinite"
        finally:
            _unlock("a.txt", _token(short), base=base)
            _unlock("b.txt", _token(forever), base=base)


# ---------------------------------------------------------------------------
# UNLOCK (mod_dav.c dav_method_unlock; util.c dav_validate_request, the dummy
# If header made of the Lock-Token): every way to get it wrong is a 400
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case",
    [
        "no-header",
        "no-brackets",
        "empty",
        "not-a-token",
        "unknown-token",
        "token-of-another-resource",
        "already-released",
    ],
)
def test_apache_unlock_with_anything_but_the_right_token_is_a_400(
    scratch: str, case: str
) -> None:
    path = f"{scratch}/u.txt"
    other = f"{scratch}/u-other.txt"
    _http("PUT", path, data=b"x").raise_for_status()
    _http("PUT", other, data=b"x").raise_for_status()
    token = _token(_lock(path))
    other_token = _token(_lock(other))
    released = _token(_lock(f"{scratch}/u-released.txt"))
    _unlock(f"{scratch}/u-released.txt", released)
    headers: dict[str, str] = {
        "no-header": {},
        "no-brackets": {"Lock-Token": token},
        "empty": {"Lock-Token": "<>"},
        "not-a-token": {"Lock-Token": "<garbage>"},
        "unknown-token": {
            "Lock-Token": "<opaquelocktoken:00000000-0000-0000-0000-000000000000>"
        },
        "token-of-another-resource": {"Lock-Token": f"<{other_token}>"},
        "already-released": {"Lock-Token": f"<{released}>"},
    }[case]
    target = f"{scratch}/u-released.txt" if case == "already-released" else path
    try:
        assert _http("UNLOCK", target, headers=headers).status_code == 400
        # and the lock is still there
        assert _http("PUT", path, data=b"y").status_code == 423
    finally:
        _unlock(path, token)
        _unlock(other, other_token)


def test_apache_unlock_with_the_right_token_is_a_204_once(scratch: str) -> None:
    path = f"{scratch}/u-once.txt"
    _http("PUT", path, data=b"x").raise_for_status()
    token = _token(_lock(path))
    assert _unlock(path, token).status_code == 204
    assert _unlock(path, token).status_code == 400
    assert _http("PUT", path, data=b"y").status_code == 204


# ---------------------------------------------------------------------------
# Shared locks (util.c dav_validate_resource_state, state 3)
# ---------------------------------------------------------------------------


def test_apache_any_one_shared_token_is_enough_to_write(scratch: str) -> None:
    path = f"{scratch}/shared.txt"
    _http("PUT", path, data=b"x").raise_for_status()
    first = _token(_lock(path, scope="shared"))
    second = _token(_lock(path, scope="shared"))
    try:
        assert first != second
        assert _http("PUT", path, data=b"y").status_code == 423
        for token in (first, second):
            written = _http("PUT", path, data=b"y", headers={"If": f"(<{token}>)"})
            assert written.status_code == 204
        discovery = _http("PROPFIND", path, headers={"Depth": "0"})
        assert first in discovery.text
        assert second in discovery.text
    finally:
        _unlock(path, first)
        _unlock(path, second)


def test_apache_a_lock_without_a_depth_header_is_infinite(scratch: str) -> None:
    path = f"{scratch}/depth.txt"
    token = _token(_lock(path))
    try:
        assert (
            "<D:depth>infinity</D:depth>"
            in _http("PROPFIND", path, headers={"Depth": "0"}).text
        )
    finally:
        _unlock(path, token)


# ---------------------------------------------------------------------------
# What OPTIONS says about locking, and what is needed for it (mod_dav.c
# dav_method_options: "1,2" whenever the provider has lock hooks; mod_dav_fs
# owns DavLockDB, mod_dav_lock is a different, generic provider)
# ---------------------------------------------------------------------------


@_needs_local_apache
def test_apache_without_a_lockdb_it_advertises_class_2_and_cannot_lock(
    tmp_path: Path,
) -> None:
    with (
        _variant(tmp_path, "nolockdb", lock_db=False) as base,
        FileSystem(base, auth=_Apache.auth) as fs,
    ):
        assert "2" in fs.dav_compliance()
        with pytest.raises(InternalServerError), fs.locked("x.txt"):
            pass  # pragma: no cover - the LOCK is refused
        refused = _lock("x.txt", base=base)
        assert refused.status_code == 500


@_needs_local_apache
def test_apache_locking_needs_the_lockdb_of_mod_dav_fs_but_not_mod_dav_lock(
    tmp_path: Path,
) -> None:
    with (
        _variant(
            tmp_path, "nodavlock", without_modules=frozenset({"mod_dav_lock.so"})
        ) as base,
        FileSystem(base, auth=_Apache.auth) as fs,
    ):
        assert "2" in fs.dav_compliance()
        with fs.locked("x.txt") as active_lock:
            assert active_lock.token


# ---------------------------------------------------------------------------
# COPY / MOVE and plain reads
# ---------------------------------------------------------------------------


def test_apache_copy_of_a_collection_needs_no_trailing_slash(
    apache_client: FileSystem, scratch: str
) -> None:
    """Unlike nginx (see docs/nginx-compliance-check.md): with or without the slash, the subtree is copied."""
    apache_client.mkdir(f"{scratch}/tree")
    apache_client.mkdir(f"{scratch}/tree/sub")
    apache_client.upload_fileobj(io.BytesIO(b"1"), f"{scratch}/tree/sub/f.txt")
    response = _http(
        "COPY",
        f"{scratch}/tree",
        headers={"Destination": f"{_Apache.url}/{scratch}/copy"},
    )
    assert response.status_code == 201
    assert apache_client.exists(f"{scratch}/copy/sub/f.txt")


def test_apache_overwrite_f_on_an_existing_destination_is_412_for_copy_and_move(
    apache_client: FileSystem, scratch: str
) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"A"), f"{scratch}/a.txt")
    apache_client.upload_fileobj(io.BytesIO(b"B"), f"{scratch}/b.txt")
    for method in ("COPY", "MOVE"):
        response = _http(
            method,
            f"{scratch}/a.txt",
            headers={"Destination": f"{_Apache.url}/{scratch}/b.txt", "Overwrite": "F"},
        )
        assert response.status_code == 412
    assert _http("GET", f"{scratch}/a.txt").content == b"A"
    assert _http("GET", f"{scratch}/b.txt").content == b"B"


def test_apache_copy_answers_201_for_a_new_destination_and_204_for_an_existing_one(
    scratch: str,
) -> None:
    _http("PUT", f"{scratch}/a.txt", data=b"A").raise_for_status()
    destination = {"Destination": f"{_Apache.url}/{scratch}/b.txt"}
    assert _http("COPY", f"{scratch}/a.txt", headers=destination).status_code == 201
    assert _http("COPY", f"{scratch}/a.txt", headers=destination).status_code == 204


def test_apache_copy_into_a_missing_parent_is_a_conflict(scratch: str) -> None:
    _http("PUT", f"{scratch}/a.txt", data=b"A").raise_for_status()
    response = _http(
        "COPY",
        f"{scratch}/a.txt",
        headers={"Destination": f"{_Apache.url}/{scratch}/nope/b.txt"},
    )
    assert response.status_code == 409


@pytest.mark.skipif(
    bool(_ENV_URL), reason="a remote instance may serve its directories"
)
def test_apache_get_on_a_collection_is_the_cores_404(scratch: str) -> None:
    """mod_dav leaves GET to the core (``handle_get`` is off for the filesystem provider), whose
    default handler refuses a directory ("Attempt to serve directory") - with no ``mod_dir`` or
    ``mod_autoindex`` loaded, as here, that is a 404."""
    assert _http("GET", f"{scratch}/").status_code == 404


def test_apache_ranges_are_answered_by_the_core(scratch: str) -> None:
    path = f"{scratch}/range.txt"
    _http("PUT", path, data=b"0123456789").raise_for_status()
    tail = _http("GET", path, headers={"Range": "bytes=7-"})
    assert tail.status_code == 206
    assert tail.headers["Content-Range"] == "bytes 7-9/10"
    assert tail.content == b"789"
    assert _http("GET", path, headers={"Range": "bytes=0-3"}).content == b"0123"
    assert _http("HEAD", path).headers["Accept-Ranges"] == "bytes"
    assert _http("GET", path, headers={"Range": "bytes=100-"}).status_code == 416


# ===========================================================================
# Over time: locks that run out, connections that the server closes, a server
# that gives up on a slow upload (mod_dav_fs lock.c, the core's Timeout and
# KeepAlive handling)
# ===========================================================================


def _in_parallel(count: int, work: Any) -> list[Any]:
    """Run ``work(index)`` in ``count`` threads that all start at once; their results, in no order."""
    barrier = threading.Barrier(count)
    results: list[Any] = []

    def run(index: int) -> None:
        barrier.wait()
        results.append(work(index))

    threads = [threading.Thread(target=run, args=(i,)) for i in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


def test_apache_an_expired_lock_is_gone_and_its_token_is_refused(scratch: str) -> None:
    """A lock is not a record that is swept on a timer: it is dropped when the next request looks at
    it. From then on the resource is free for everybody - and the old token is worth nothing:
    writing with it is a 412, so is refreshing it, and ``UNLOCK`` of it is a 400 (not 409).
    """
    path = f"{scratch}/expiring.txt"
    _http("PUT", path, data=b"v1").raise_for_status()
    token = _token(_lock(path, timeout="Second-1"))
    assert _http("PUT", path, data=b"v2").status_code == 423  # while it lasts
    time.sleep(2.2)
    assert token not in _http("PROPFIND", path, headers={"Depth": "0"}).text
    stale = {"If": f"(<{token}>)"}
    assert _http("PUT", path, data=b"v3", headers=stale).status_code == 412
    assert (
        _http("LOCK", path, headers={**stale, "Timeout": "Second-60"}).status_code
        == 412
    )
    assert _unlock(path, token).status_code == 400
    # free for everybody: a write without a token, a lock of somebody else
    assert _http("PUT", path, data=b"v4").status_code == 204
    other = _lock(path)
    assert other.status_code == 200
    _unlock(path, _token(other))


def test_apache_the_client_meets_an_expired_lock_with_a_412_and_a_log_line(
    apache_client: FileSystem, scratch: str, caplog: pytest.LogCaptureFixture
) -> None:
    """A write under an expired lock, and a refresh of it, are ``PreconditionFailedError`` - the lock
    is not silently taken for held. Leaving the block tries to release it: Apache answers 400 for
    the token it no longer knows, which is logged as a lock that is already gone, not as a failure.
    """
    path = f"{scratch}/client-expiry.txt"
    apache_client.upload_fileobj(io.BytesIO(b"v1"), path)
    with (
        caplog.at_level(logging.WARNING, logger="webdav"),
        apache_client.locked(path, lock_timeout=1) as active_lock,
    ):
        time.sleep(2.2)
        with pytest.raises(PreconditionFailedError):
            apache_client.upload_fileobj(io.BytesIO(b"v2"), path, overwrite=True)
        with pytest.raises(PreconditionFailedError):
            apache_client.refresh_lock(path, active_lock.token, lock_timeout=30)
    assert [r for r in caplog.records if "already gone" in r.getMessage()]
    assert not [r for r in caplog.records if "could not release" in r.getMessage()]
    apache_client.upload_fileobj(io.BytesIO(b"v3"), path, overwrite=True)  # free again


def test_apache_an_expired_lock_null_resource_stays_visible_until_it_is_locked_again(
    apache_client: FileSystem, scratch: str
) -> None:
    """A client that locks an unmapped URL and never comes back leaves a lock-null entry behind that
    outlives its lock: ``PROPFIND`` on the path keeps answering (so ``exists()`` stays true), ``GET``
    does not - and ``DELETE`` cannot remove what is not a resource (404). What clears it is another
    ``LOCK`` + ``UNLOCK`` of the path, or a ``PUT`` / ``MKCOL`` that makes it a real one.
    """
    ghosts = [
        f"{scratch}/ghost-{name}" for name in ("unlock", "put", "mkcol", "delete")
    ]
    for ghost in ghosts:
        _lock(ghost, timeout="Second-1").raise_for_status()
    time.sleep(2.2)
    for (
        ghost
    ) in (
        ghosts
    ):  # asked directly, before anything lists the collection (see the next test)
        assert apache_client.exists(ghost)
        assert _http("GET", ghost).status_code == 404
    assert _http("DELETE", ghosts[3]).status_code == 404
    assert apache_client.exists(ghosts[3])
    fresh = _lock(ghosts[0])
    assert _unlock(ghosts[0], _token(fresh)).status_code == 204
    assert not apache_client.exists(ghosts[0])
    assert _http("PUT", ghosts[1], data=b"x").status_code == 201
    assert _http("GET", ghosts[1]).content == b"x"
    assert _http("MKCOL", f"{ghosts[2]}/").status_code == 201
    assert apache_client.isdir(ghosts[2])


def _collection_with_expired_lock_null_entries(
    apache_client: FileSystem, scratch: str, count: int
) -> str:
    """A collection that holds ``count`` lock-null entries whose locks have run out (1 s) - nobody has asked since."""
    collection = f"{scratch}/poisoned-{count}"
    apache_client.mkdir(collection)
    for index in range(count):
        _lock(f"{collection}/ghost{index}.txt", timeout="Second-1").raise_for_status()
    time.sleep(2.2)
    return collection


def test_apache_a_listing_that_meets_an_expired_lock_null_entry_is_aborted_once_per_entry(
    apache_client: FileSystem, scratch: str
) -> None:
    """An Apache bug (``dav_fs_get_locks``: it drops the expired lock while ``PROPFIND`` has the lock
    database open read-only, which ``DAV_DEBUG`` - compiled in, not a setting - turns into a 500 with
    "INTERNAL DESIGN ERROR ... opened readonly" in the error log, after the answer has started): the
    connection is closed with no response. The entry is dropped all the same, so the *next* listing
    works - one failed listing per expired entry."""
    collection = _collection_with_expired_lock_null_entries(apache_client, scratch, 2)
    for _ in range(2):
        with pytest.raises(requests.exceptions.ConnectionError):
            _http("PROPFIND", f"{collection}/", headers={"Depth": "1"})
    listing = _http("PROPFIND", f"{collection}/", headers={"Depth": "1"})
    assert listing.status_code == 207
    assert "ghost" not in listing.text
    # asking about the collection itself was never a problem
    assert (
        _http("PROPFIND", f"{collection}/", headers={"Depth": "0"}).status_code == 207
    )


def test_apache_ls_gets_through_an_expired_lock_null_entry_by_retrying(
    apache_client: FileSystem, scratch: str
) -> None:
    """``PROPFIND`` is retried (``retry=True``, three attempts), so the aborted listing is absorbed:
    a little slower (the retry waits), no error. Up to two entries are absorbed this way.
    """
    collection = _collection_with_expired_lock_null_entries(apache_client, scratch, 1)
    started = time.monotonic()
    assert apache_client.ls(collection) == []
    assert time.monotonic() - started >= 0.5  # it did have to try again


def test_apache_ls_fails_once_past_the_retries_and_then_works_for_a_collection_with_many(
    apache_client: FileSystem, scratch: str
) -> None:
    """With more expired entries than there are attempts the first ``ls`` is a ``ConnectionError`` -
    which cleared some of them, so asking again is all it takes (the cost of leaving a lock on a name
    nothing was ever written to)."""
    collection = _collection_with_expired_lock_null_entries(apache_client, scratch, 4)
    with pytest.raises(requests.exceptions.ConnectionError):
        apache_client.ls(collection)
    for _ in range(4):
        with contextlib.suppress(requests.exceptions.ConnectionError):
            assert apache_client.ls(collection) == []
            return
    pytest.fail("the listing never recovered")


def test_apache_a_connection_the_server_closes_after_a_few_requests_is_not_an_error(
    tmp_path: Path,
) -> None:
    """``MaxKeepAliveRequests 3``: every third answer says ``Connection: close`` - for sixty requests
    in a row, writes included (which are never retried), the client opens a new connection each time.
    """
    extra_conf = "KeepAlive On\nMaxKeepAliveRequests 3"
    with _variant_fs(tmp_path, "keepalive_max", extra_conf=extra_conf) as fs:
        for index in range(20):
            fs.upload_fileobj(io.BytesIO(b"x"), f"f{index}.txt")
            assert fs.exists(f"f{index}.txt")
            fs.remove(f"f{index}.txt")


def test_apache_a_connection_that_idled_past_the_keepalive_timeout_is_not_an_error(
    tmp_path: Path,
) -> None:
    """``KeepAliveTimeout 1``: the server has closed the pooled connection by the time the next
    request goes out, a write included - the client must see that before it sends, not after.
    """
    extra_conf = "KeepAlive On\nKeepAliveTimeout 1"
    with _variant_fs(tmp_path, "keepalive_idle", extra_conf=extra_conf) as fs:
        fs.upload_fileobj(io.BytesIO(b"x"), "first.txt")
        for index in range(2):
            time.sleep(1.4)
            fs.upload_fileobj(io.BytesIO(b"y"), f"idle{index}.txt")
        assert fs.exists("idle1.txt")


class _SlowReader(io.RawIOBase):
    """A file object that makes the upload wait ``pause`` seconds before each of its ``parts``."""

    def __init__(self, parts: "list[bytes]", pause: float) -> None:
        super().__init__()
        self._parts = list(parts)
        self._pause = pause

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        if not self._parts:
            return 0
        time.sleep(self._pause)
        part = self._parts.pop(0)
        buffer[: len(part)] = part
        return len(part)


def _slow(parts: "list[bytes]", pause: float) -> BinaryIO:
    """A file object for ``upload_fileobj`` that makes the upload wait ``pause`` seconds before each part."""
    return cast("BinaryIO", _SlowReader(parts, pause))


def test_apache_gives_up_on_a_stalled_upload_with_408_and_creates_nothing(
    tmp_path: Path,
) -> None:
    """``Timeout 1``: a body that stops for longer than that is a 408 (not retried, a PUT) - no partial
    file, not even a temporary one the next listing could show - while a slow but moving one is fine.
    """
    with _variant_fs(tmp_path, "timeout", extra_conf="Timeout 1") as fs:
        with pytest.raises(HTTPStatusError) as exc_info:
            fs.upload_fileobj(_slow([b"a" * 1024, b"b" * 1024], 1.6), "slow.txt")
        assert exc_info.value.status_code == 408
        assert not fs.exists("slow.txt")
        fs.upload_fileobj(_slow([b"a" * 1024, b"b" * 1024], 0.3), "steady.txt")
        props = fs.get_props("steady.txt", props=["content_length"])
        assert props.content_length == 2048
        assert [name for name in fs.ls("") if "tmp" in name] == []


def test_apache_limitrequestbody_refuses_with_413_before_anything_is_stored(
    tmp_path: Path,
) -> None:
    """With ``LimitRequestBody 1048576``: below the limit it is stored; above it - announced by its
    length, huge, or streamed without a length - a 413, and the file that was there stays as it was.
    """
    extra_conf = "LimitRequestBody 1048576"
    with _variant_fs(tmp_path, "limit", extra_conf=extra_conf) as fs:
        fs.upload_fileobj(io.BytesIO(b"small"), "kept.bin")
        too_large = [
            io.BytesIO(bytes(2 << 20)),
            io.BytesIO(bytes(40 << 20)),
            _slow([bytes(2 << 20)], 0),
        ]
        for source in too_large:  # announced, huge, and without a length
            with pytest.raises(HTTPStatusError) as exc_info:
                fs.upload_fileobj(source, "kept.bin", overwrite=True)
            assert exc_info.value.status_code == 413
        with pytest.raises(HTTPStatusError):
            fs.upload_fileobj(io.BytesIO(bytes(2 << 20)), "new.bin")
        assert not fs.exists("new.bin")
        buf = io.BytesIO()
        fs.download_fileobj("kept.bin", buf)
        assert buf.getvalue() == b"small"
        fs.upload_fileobj(io.BytesIO(bytes(512 << 10)), "fits.bin")
        assert (
            fs.get_props("fits.bin", props=["content_length"]).content_length
            == 512 << 10
        )


# ===========================================================================
# Size: what goes through the client and Apache without being held in memory,
# and names that have to survive being a URL
# ===========================================================================


def _random_file(path: Path, mebibytes: int) -> str:
    """Write ``mebibytes`` MiB of random bytes to ``path``; its SHA-256."""
    digest = hashlib.sha256()
    with path.open("wb") as handle:
        for _ in range(mebibytes):
            block = os.urandom(1 << 20)
            digest.update(block)
            handle.write(block)
    return digest.hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def test_apache_a_large_file_round_trips_byte_for_byte(
    apache_client: FileSystem, scratch: str, tmp_path: Path
) -> None:
    source = tmp_path / "large.bin"
    expected = _random_file(source, 48)
    apache_client.upload_file(source, f"{scratch}/large.bin")
    assert (
        apache_client.get_props(
            f"{scratch}/large.bin", props=["content_length"]
        ).content_length
        == 48 << 20
    )
    target = tmp_path / "large.out"
    apache_client.download_file(f"{scratch}/large.bin", target)
    assert _sha256(target) == expected
    # a range far into it is answered from the right place, without sending what comes before
    tail = _http(
        "GET",
        f"{scratch}/large.bin",
        headers={"Range": f"bytes={40 << 20}-{(40 << 20) + 9}"},
    )
    assert tail.status_code == 206
    with source.open("rb") as handle:
        handle.seek(40 << 20)
        assert tail.content == handle.read(10)


def test_apache_an_upload_of_unknown_length_is_streamed_chunked_and_complete(
    apache_client: FileSystem, scratch: str
) -> None:
    """No length to announce: ``Transfer-Encoding: chunked`` - which ``mod_dav`` reads to the end."""
    parts = [bytes([65 + index]) * (1 << 20) for index in range(8)]
    apache_client.upload_fileobj(_slow(parts, 0), f"{scratch}/chunked.bin")
    buf = io.BytesIO()
    apache_client.download_fileobj(f"{scratch}/chunked.bin", buf)
    assert buf.getvalue() == b"".join(parts)


def test_apache_an_empty_file_is_stored_and_read_back_empty(
    apache_client: FileSystem, scratch: str
) -> None:
    apache_client.upload_fileobj(io.BytesIO(b""), f"{scratch}/empty.txt")
    assert (
        apache_client.get_props(
            f"{scratch}/empty.txt", props=["content_length"]
        ).content_length
        == 0
    )
    buf = io.BytesIO()
    apache_client.download_fileobj(f"{scratch}/empty.txt", buf)
    assert buf.getvalue() == b""


def test_apache_a_collection_of_many_members_is_listed_in_full_and_removed_at_once(
    apache_client: FileSystem, scratch: str
) -> None:
    count = 1200
    apache_client.mkdir(f"{scratch}/many")

    def create(offset: int) -> None:
        with requests.Session() as session:
            session.auth = _Apache.auth
            for index in range(offset, count, 8):
                session.put(
                    f"{_Apache.url}/{scratch}/many/f{index:05d}.txt",
                    data=b"x",
                    timeout=10,
                )

    threads = [threading.Thread(target=create, args=(offset,)) for offset in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    names = [name.rsplit("/", 1)[-1] for name in apache_client.ls(f"{scratch}/many")]
    assert sorted(names) == [f"f{index:05d}.txt" for index in range(count)]
    apache_client.remove(f"{scratch}/many")
    assert not apache_client.exists(f"{scratch}/many")


_ODD_NAMES = [
    "a b", "a#b", "a?b", "a%b", "a%20b", "a%2Fb", "a+b", "a&b", "a;b", "a=b", "a'b", 'a"b',
    "a<b>", "a|b", "a[b]", "ä ö ü ß", "日本語", "emoji-😀", "é-combining", " lead", "trail ",
    "a..b", ".hidden", "-dash", "x" * 255, "é" * 127,
]  # fmt: skip


@pytest.mark.parametrize(
    "name", _ODD_NAMES, ids=[f"{i}-{n[:12]}" for i, n in enumerate(_ODD_NAMES)]
)
def test_apache_a_name_survives_the_round_trip(
    apache_client: FileSystem, scratch: str, name: str
) -> None:
    """Every character that means something in a URL, and some that are not ASCII, is stored under
    exactly that name - ``%20`` stays the six characters it is, it is not read as a space.
    """
    path = f"{scratch}/{name}"
    apache_client.upload_fileobj(io.BytesIO(name.encode()), path)
    buf = io.BytesIO()
    apache_client.download_fileobj(path, buf)
    assert buf.getvalue() == name.encode()
    assert name in [member.rsplit("/", 1)[-1] for member in apache_client.ls(scratch)]
    apache_client.remove(path)
    assert not apache_client.exists(path)


def test_apache_names_that_differ_only_in_case_are_two_resources(
    apache_client: FileSystem, scratch: str
) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"upper"), f"{scratch}/CASE")
    apache_client.upload_fileobj(io.BytesIO(b"lower"), f"{scratch}/case")
    assert sorted(m.rsplit("/", 1)[-1] for m in apache_client.ls(scratch)) == [
        "CASE",
        "case",
    ]


@pytest.mark.parametrize(
    "name", ["x" * 256, "é" * 128], ids=["256-bytes", "128-two-byte-chars"]
)
def test_apache_a_name_longer_than_255_bytes_is_a_403(
    apache_client: FileSystem, scratch: str, name: str
) -> None:
    """The file system's limit, not the URL's: ``apr_file_open`` fails and ``mod_dav`` answers 403."""
    with pytest.raises(ForbiddenError):
        apache_client.upload_fileobj(io.BytesIO(b"x"), f"{scratch}/{name}")


@pytest.mark.parametrize("path", [".DAV", ".DAV/inside"])
def test_apache_the_lock_database_directory_cannot_be_written(
    apache_client: FileSystem, scratch: str, path: str
) -> None:
    """``dav_fs_is_state_path``: ``.DAV`` holds Apache's own state (locks, properties) - a client does not
    get to name it, at any level of the tree."""
    with pytest.raises(ForbiddenError):
        apache_client.upload_fileobj(io.BytesIO(b"x"), f"{scratch}/{path}")


# ===========================================================================
# Parallel: what many clients at once do to each other (prefork processes, a
# shared lock database, temporary files that are renamed into place)
# ===========================================================================


def _dbm_is_sdbm(instance_dir: Path) -> bool:
    """Whether the instance in ``instance_dir`` keeps its lock and property databases in sdbm files.

    The DBM type is not a setting of ``mod_dav_fs``: it is the default of the APR-util the server
    was built with. sdbm (a build from the release tarball: ``davlock.pag`` / ``davlock.dir``) holds up
    when several processes write at once; Debian's and Ubuntu's APR-util defaults to Berkeley DB, which
    does not - concurrent writes can be lost, and the database damaged (see "The DBM type decides" in
    docs/apache-compliance-check.md). The tests that write from many clients at once ask for the strict
    result only where it is guaranteed, and for what holds on both everywhere else.
    """
    return next(instance_dir.rglob("*.pag"), None) is not None


@contextmanager
def _isolated_instance(tmp_path: Path) -> Iterator[tuple[str, Path]]:
    """An instance of its own - its base URL and directory - for a test that writes to the lock or
    property database from many clients at once. With Berkeley DB that can damage the database for
    good: the shared instance, and every test after, must not have to live with it."""
    with _variant(tmp_path, "dbm") as base:
        yield base, tmp_path / "dbm"


def test_apache_parallel_uploads_through_one_filesystem_arrive_intact(
    apache_client: FileSystem, scratch: str
) -> None:
    bodies = {index: os.urandom(1 << 20) for index in range(32)}

    def upload(index: int) -> None:
        apache_client.upload_fileobj(
            io.BytesIO(bodies[index]), f"{scratch}/up{index}.bin"
        )

    _in_parallel(32, upload)
    for index, body in bodies.items():
        buf = io.BytesIO()
        apache_client.download_fileobj(f"{scratch}/up{index}.bin", buf)
        assert buf.getvalue() == body


@_needs_local_apache
def test_apache_of_many_simultaneous_locks_on_one_resource_one_is_granted_on_sdbm(
    tmp_path: Path,
) -> None:
    """The lock database is shared by all the server's processes. With sdbm exactly one request gets
    the lock and the rest a 423. With Berkeley DB (Debian, Ubuntu) two can be granted the same lock -
    seen once in 25 rounds of sixteen on Ubuntu's 2.4.58 - so only "at least one, nothing but 200
    and 423" holds there."""
    with _isolated_instance(tmp_path) as (base, instance_dir):
        _http("PUT", "contended.txt", base=base, data=b"x").raise_for_status()
        results = _in_parallel(16, lambda _i: _lock("contended.txt", base=base))
        statuses = collections.Counter(r.status_code for r in results)
        assert set(statuses) <= {200, 423}
        assert statuses[200] >= 1
        sdbm = _dbm_is_sdbm(instance_dir)
        if sdbm:
            assert statuses == {200: 1, 423: 15}
        for response in results:
            if response.status_code == 200:
                _unlock("contended.txt", _token(response), base=base)
        if sdbm:
            assert (
                _http("PUT", "contended.txt", base=base, data=b"y").status_code == 204
            )


@_needs_local_apache
def test_apache_many_simultaneous_locks_on_different_resources_are_all_granted(
    tmp_path: Path,
) -> None:
    """Every request is told 200 with a token of its own. Whether the lock database then holds all of
    them depends on its DBM type: with sdbm none is lost; with Berkeley DB (Debian, Ubuntu) up to a
    fifth were not enforced a second later (1 to 8 of 40 in half of the rounds on Ubuntu's 2.4.58).
    """
    with _isolated_instance(tmp_path) as (base, instance_dir):
        for index in range(40):
            _http("PUT", f"l{index}.txt", base=base, data=b"x").raise_for_status()
        results = _in_parallel(40, lambda i: _lock(f"l{i}.txt", base=base))
        assert {r.status_code for r in results} == {200}
        assert len({_token(r) for r in results}) == 40
        if _dbm_is_sdbm(instance_dir):
            discovery = _http("PROPFIND", "", base=base, headers={"Depth": "1"}).text
            assert all(_token(r) in discovery for r in results)  # none was lost
        for index, response in enumerate(results):
            _unlock(f"l{index}.txt", _token(response), base=base)


@_needs_local_apache
def test_apache_through_the_client_a_contended_lock_is_held_by_one_and_leaks_none(
    tmp_path: Path,
) -> None:
    """The client side holds everywhere: each outcome is "held" or "refused" (and with sdbm at least
    one is held), the session keeps no token afterwards. That no lock is left on the server holds with
    sdbm - with Berkeley DB a lost update can undo an ``UNLOCK``, and it can damage the database.
    """
    with (
        _isolated_instance(tmp_path) as (base, instance_dir),
        FileSystem(base, auth=_Apache.auth) as fs,
    ):
        fs.upload_fileobj(io.BytesIO(b"x"), "cycle.txt")
        outcomes: collections.Counter[str] = collections.Counter()

        def cycle(_index: int) -> None:
            for _ in range(3):
                try:
                    with fs.locked("cycle.txt", lock_timeout=30):
                        fs.upload_fileobj(io.BytesIO(b"w"), "cycle.txt", overwrite=True)
                    outcomes["held"] += 1
                except ResourceLockedError:
                    outcomes["refused"] += 1

        _in_parallel(12, cycle)
        assert set(outcomes) <= {"held", "refused"}
        assert fs.session.locks.token_for(f"{base}/cycle.txt") is None
        if _dbm_is_sdbm(instance_dir):
            assert outcomes["held"] >= 1
            assert _http("PUT", "cycle.txt", base=base, data=b"free").status_code == 204


def test_apache_simultaneous_overwrites_leave_exactly_one_whole_file(
    scratch: str,
) -> None:
    """The temporary file is renamed over the target: whichever writer is last wins, whole - the result
    is never a mixture of two bodies."""
    path = f"{scratch}/overwritten.bin"
    bodies = {index: bytes([65 + index]) * (2 << 20) for index in range(16)}
    results = _in_parallel(16, lambda i: _http("PUT", path, data=bodies[i]).status_code)
    assert set(results) <= {201, 204}
    assert _http("GET", path).content in bodies.values()


def test_apache_a_reader_never_sees_a_half_written_file(scratch: str) -> None:
    path = f"{scratch}/replaced.bin"
    first, second = b"A" * (4 << 20), b"B" * (4 << 20)
    _http("PUT", path, data=first).raise_for_status()
    stop = threading.Event()
    seen: list[bytes] = []

    def read() -> None:
        while not stop.is_set():
            seen.append(_http("GET", path).content)

    readers = [threading.Thread(target=read) for _ in range(4)]
    for reader in readers:
        reader.start()
    try:
        for index in range(12):
            _http(
                "PUT", path, data=second if index % 2 == 0 else first
            ).raise_for_status()
    finally:
        stop.set()
        for reader in readers:
            reader.join()
    assert seen
    assert all(content in (first, second) for content in seen)


@_needs_local_apache
def test_apache_simultaneous_property_updates_on_one_resource_are_kept_on_sdbm(
    tmp_path: Path,
) -> None:
    """Sixteen clients each set their own property on the same file: all are told 207. With sdbm all
    sixteen properties are there afterwards; with Berkeley DB (Debian, Ubuntu) one or more were lost
    in most rounds (one of sixteen in six of ten on Ubuntu's 2.4.58)."""
    namespace = "https://example.org/ns"

    def update(index: int, base: str) -> int:
        body = (
            f'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="{namespace}">'
            f"<D:set><D:prop><Z:p{index}>v{index}</Z:p{index}></D:prop></D:set></D:propertyupdate>"
        )
        return _http("PROPPATCH", "props.txt", base=base, data=body).status_code

    with (
        _isolated_instance(tmp_path) as (base, instance_dir),
        FileSystem(base, auth=_Apache.auth) as fs,
    ):
        fs.upload_fileobj(io.BytesIO(b"x"), "props.txt")
        assert set(_in_parallel(16, lambda i: update(i, base))) == {207}
        props = fs.get_props(
            "props.txt", props=[(namespace, f"p{i}") for i in range(16)]
        )
        kept = [props.text(namespace, f"p{i}") for i in range(16)]
        assert all(
            value in (None, f"v{i}") for i, value in enumerate(kept)
        )  # never a wrong value
        if _dbm_is_sdbm(instance_dir):
            assert kept == [f"v{i}" for i in range(16)]


def test_apache_copy_move_and_delete_of_one_source_at_once_have_one_winner_where_one_is_possible(
    scratch: str,
) -> None:
    """A source can be copied any number of times, but only moved or deleted once. The losers are told
    an error: 404 (it was gone when they looked), 500 (it went between looking and renaming:
    ``dav_fs_move_resource`` answers "Could not rename resource" for the ENOENT) or 403 (a failed
    removal) - which one is timing, and not pinned: only that exactly one wins.
    """
    _http("PUT", f"{scratch}/src.txt", data=b"src").raise_for_status()
    copies = _in_parallel(
        12,
        lambda i: _http(
            "COPY",
            f"{scratch}/src.txt",
            headers={"Destination": f"{_Apache.url}/{scratch}/copy{i}.txt"},
        ).status_code,
    )
    assert set(copies) == {201}  # a source can be copied any number of times
    assert all(
        _http("GET", f"{scratch}/copy{i}.txt").content == b"src" for i in range(12)
    )
    moves = _in_parallel(
        12,
        lambda i: _http(
            "MOVE",
            f"{scratch}/src.txt",
            headers={"Destination": f"{_Apache.url}/{scratch}/moved{i}.txt"},
        ).status_code,
    )
    assert moves.count(201) == 1  # ... but only once moved
    assert all(status >= 400 for status in moves if status != 201)
    assert (
        sum(
            _http("HEAD", f"{scratch}/moved{i}.txt").status_code == 200
            for i in range(12)
        )
        == 1
    )
    deletes = _in_parallel(
        12, lambda _i: _http("DELETE", f"{scratch}/copy0.txt").status_code
    )
    assert deletes.count(204) == 1
    assert all(status >= 400 for status in deletes if status != 204)
