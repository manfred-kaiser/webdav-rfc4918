"""Compliance check against a real Apache + mod_dav server - an ordinary, reproducible pytest suite.

Not part of the automated CI suite (wsgidav already covers that broad
ground, see ``tests/test_session_e2e.py``) - this is an independent-
implementation cross-check, since server implementations are known to
disagree on locking/property edge cases in particular, and this project's
primary deployment target is Apache specifically. Skipped only when no
Apache is reachable at all: with ``WEBDAV_TEST_APACHE_URL`` set, these
tests run against that (possibly remote, possibly specially-configured)
instance; otherwise, if a local Apache + ``mod_dav`` install is found
(see ``tests/apache_instance.py``), a throwaway instance is started and
stopped automatically - no manual step needed either way. See
``docs/apache-compliance-check.md`` for the full setup story and the
Apache-specific behavior these tests pin down (so a future Apache upgrade
that changes one is caught here, not discovered in production).
"""

import io
import os
from collections.abc import Iterator
from pathlib import Path
from tempfile import gettempdir
from typing import TYPE_CHECKING
from xml.etree.ElementTree import Element

import pytest

from tests import apache_instance
from webdav import FileSystem, ResourceAlreadyExistsError, ResourceLockedError
from webdav.dav.locks import EXCLUSIVE, SHARED
from webdav.exceptions import (
    MultiStatusError,
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


def test_apache_default_getetag_is_weak_so_if_match_with_it_is_refused_client_side(
    apache_client: FileSystem,
) -> None:
    """A real, confirmed operational limitation for Apache, not a library bug.

    With the stock ``mod_dav_fs`` config (no ``FileETag`` override; see
    ``docs/apache-compliance-check.md``), ``getetag`` is a *weak* validator
    (``W/"..."``). RFC 9110 sec. 13.1.1 requires If-Match to use strong
    comparison, so ``strong_etag()`` correctly refuses it - which means
    passing Apache's own current ``getetag`` straight into ``if_match=``
    always fails client-side against a default install. Configure Apache
    with a strong ``FileETag`` (e.g. ``FileETag INode MTime Size``) to get
    a working If-Match-based conditional PUT.
    """
    session: Session = apache_client._session
    session.put("compliance/etagmatch.txt", b"v1").raise_for_status()
    props = apache_client.get_props("compliance/etagmatch.txt", props=["etag"])
    assert props.etag is not None
    assert props.etag.startswith("W/")
    with pytest.raises(ValueError, match="weak"):
        session.put("compliance/etagmatch.txt", b"v2", if_match=props.etag)


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
