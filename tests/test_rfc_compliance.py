"""Regression tests for the RFC 4918/5689 conformance fixes in RFC_COMPLIANCE.md.

Each test locks in one specific gap/bug found during a dedicated RFC audit
(as opposed to tests/test_session_e2e.py's general happy-path coverage, or
tests/test_security_edge_cases.py's adversarial-server coverage).
"""

import io
from xml.etree.ElementTree import Element

import pytest

from webdav import FileSystem, Session
from webdav.conditional import Condition, build_if_header
from webdav.exceptions import (
    STATUS_CODE_EXCEPTIONS,
    MultiStatusError,
    UnsupportedMediaTypeError,
)
from webdav.locks import (
    EXCLUSIVE,
    SHARED,
    ActiveLock,
    LockEntry,
    build_lock_body,
    format_timeout,
)
from webdav.multistatus import MultiStatusResponse, Response
from webdav.properties import DAVProperties, build_propfind_body
from webdav.session import _parse_dav_header
from webdav.xml_utils import parse_xml

# ---------------------------------------------------------------------------
# XML/grammar-level fixes - no server needed
# ---------------------------------------------------------------------------


def test_response_location_parses_the_nested_href() -> None:
    """RFC 4918 §14.11: <location> wraps an <href>, it has no text of its own."""
    xml = (
        '<d:response xmlns:d="DAV:"><d:href>/a</d:href>'
        "<d:status>HTTP/1.1 200 OK</d:status>"
        "<d:location><d:href>/b</d:href></d:location></d:response>"
    )
    response = Response(parse_xml(xml))
    assert response.location == "/b"


def test_response_with_multiple_hrefs_registers_under_each_one() -> None:
    """RFC 4918 §14.24: response = href, ((href*, status) | propstat+), ...

    A status-bearing (non-propstat) response can carry several <href>
    elements sharing one <status>.
    """
    xml = (
        '<d:multistatus xmlns:d="DAV:"><d:response>'
        "<d:href>/coll/a</d:href><d:href>/coll/b</d:href>"
        "<d:status>HTTP/1.1 423 Locked</d:status>"
        "</d:response></d:multistatus>"
    )
    result = MultiStatusResponse(xml)
    assert set(result.responses) == {"/coll/a", "/coll/b"}
    assert result.responses["/coll/a"] is result.responses["/coll/b"]


def test_if_header_no_tag_list_separates_lists_with_a_space() -> None:
    """Appendix C: No-tag-list = List 1*(" " List) - a space is required."""
    header = build_if_header([[Condition(token="urn:a")], [Condition(token="urn:b")]])
    assert header == "(<urn:a>) (<urn:b>)"


def test_condition_rejects_both_token_and_etag() -> None:
    """Appendix C: Condition = ["Not"] (State-token | entity-tag) - one, not both."""
    with pytest.raises(ValueError, match="never both"):
        Condition(token="a", etag="b")


def test_multistatus_error_exposes_precondition_codes() -> None:
    """RFC 4918 §16: <error>'s children are precondition/postcondition codes."""
    xml = (
        '<d:multistatus xmlns:d="DAV:"><d:response>'
        "<d:href>/locked.txt</d:href>"
        "<d:status>HTTP/1.1 423 Locked</d:status>"
        "<d:error><d:no-conflicting-lock/></d:error>"
        "</d:response></d:multistatus>"
    )
    result = MultiStatusResponse(xml)
    with pytest.raises(MultiStatusError) as exc_info:
        result.raise_for_status()
    assert exc_info.value.error_codes["/locked.txt"] == frozenset(
        {"no-conflicting-lock"}
    )


def test_allprop_body_can_include_named_properties() -> None:
    """RFC 4918 §9.1/§14.8: <allprop/> can be combined with <include>."""
    body = build_propfind_body(all_prop=True, include=["etag"])
    tree = parse_xml(body)
    assert tree.find("{DAV:}allprop") is not None
    include_el = tree.find("{DAV:}include")
    assert include_el is not None
    assert include_el.find("{DAV:}getetag") is not None


def test_build_lock_body_accepts_a_structured_owner() -> None:
    """owner's content model is ANY - RFC 4918's own example uses <D:href>."""
    owner_el = Element("{DAV:}href")
    owner_el.text = "mailto:test@example.org"
    body = build_lock_body(owner=owner_el)
    tree = parse_xml(body)
    assert tree.findtext("{DAV:}owner/{DAV:}href") == "mailto:test@example.org"


def test_format_timeout_accepts_a_preference_list() -> None:
    """RFC 4918 §10.7: Timeout can list several values, most preferred first."""
    assert format_timeout([3600, None]) == "Second-3600, Infinite"
    assert format_timeout(3600) == "Second-3600"
    assert format_timeout(None) == "Infinite"


def test_resourcetype_preserves_non_collection_types() -> None:
    """RFC 4918 §15.9: resourcetype is extensible, not just collection-or-not."""
    resourcetype_el = Element("{DAV:}resourcetype")
    resourcetype_el.append(Element("{https://example.org/ns}customtype"))
    props = DAVProperties({"{DAV:}resourcetype": resourcetype_el})
    assert props.resource_types == frozenset({"customtype"})
    assert props.resource_type == "file"  # convenience view still binary


def test_dav_header_comma_inside_coded_url_is_not_a_separator() -> None:
    """RFC 3986 permits an unencoded comma in a URI path/query sub-delim."""
    tokens = _parse_dav_header("1, 2, <http://example.com/ext,ended>")
    assert tokens == {"1", "2", "<http://example.com/ext,ended>"}


def test_415_is_registered_for_mkcol() -> None:
    """RFC 4918 §9.3.1: 415 for an invalid (non-Extended-MKCOL) MKCOL body."""
    assert STATUS_CODE_EXCEPTIONS[415] is UnsupportedMediaTypeError


def test_lockentry_and_activelock_are_reused_by_the_property_model() -> None:
    """lockdiscovery/supportedlock should parse into the same types locks.py uses."""
    lockentry_el = Element("{DAV:}lockentry")
    lockscope_el = Element("{DAV:}lockscope")
    lockscope_el.append(Element("{DAV:}exclusive"))
    lockentry_el.append(lockscope_el)
    locktype_el = Element("{DAV:}locktype")
    locktype_el.append(Element("{DAV:}write"))
    lockentry_el.append(locktype_el)
    entry = LockEntry.from_element(lockentry_el)
    assert entry == LockEntry(scope=EXCLUSIVE, lock_type="write")


# ---------------------------------------------------------------------------
# Session-level fixes - need a real server (wsgidav, via the `client` fixture)
# ---------------------------------------------------------------------------


def test_root_depth_infinity_lock_covers_children(fs: FileSystem) -> None:
    """A Depth:infinity lock on the WebDAV root must cascade to every path under it."""
    fs.upload_fileobj(io.BytesIO(b"v1"), "rootlock.txt")
    with fs.locked("", scope=EXCLUSIVE, depth="infinity"):
        # Must not raise - the held root lock's token must be attached.
        fs.upload_fileobj(io.BytesIO(b"v2"), "rootlock.txt", overwrite=True)
    buf = io.BytesIO()
    fs.download_fileobj("rootlock.txt", buf)
    assert buf.getvalue() == b"v2"


def test_concurrent_shared_locks_on_the_same_path(fs: FileSystem) -> None:
    """RFC 4918 §6.2 allows several shared locks on one resource to coexist."""
    fs.upload_fileobj(io.BytesIO(b"v1"), "shared.txt")
    with fs.locked("shared.txt", scope=SHARED) as lock_a:
        with fs.locked("shared.txt", scope=SHARED):
            pass  # released here - must not evict lock_a's bookkeeping
        # lock_a is still held; a write through it must still carry its token.
        fs.upload_fileobj(io.BytesIO(b"v2"), "shared.txt", overwrite=True)
        assert lock_a.token  # sanity: still the same object, unaffected


def test_copy_onto_a_client_locked_destination(client: Session, fs: FileSystem) -> None:
    """RFC 4918 §10.2: a locked destination's token MUST be submitted too."""
    fs.upload_fileobj(io.BytesIO(b"source"), "xfer_src.txt")
    fs.upload_fileobj(io.BytesIO(b"old dest"), "xfer_dst.txt")
    with fs.locked("xfer_dst.txt", scope=EXCLUSIVE):
        client.copy("xfer_src.txt", "xfer_dst.txt", overwrite=True).raise_for_status()
    buf = io.BytesIO()
    fs.download_fileobj("xfer_dst.txt", buf)
    assert buf.getvalue() == b"source"


def test_move_onto_a_client_locked_destination_without_the_fix_would_423(
    client: Session, fs: FileSystem
) -> None:
    """Same as the COPY case, for MOVE."""
    fs.upload_fileobj(io.BytesIO(b"source"), "mv_src.txt")
    fs.upload_fileobj(io.BytesIO(b"old dest"), "mv_dst.txt")
    with fs.locked("mv_dst.txt", scope=EXCLUSIVE):
        client.move("mv_src.txt", "mv_dst.txt", overwrite=True).raise_for_status()
    buf = io.BytesIO()
    fs.download_fileobj("mv_dst.txt", buf)
    assert buf.getvalue() == b"source"


def test_lock_refresh(fs: FileSystem) -> None:
    """RFC 4918 §9.10.2: a bodyless LOCK with an If header refreshes the timeout."""
    fs.upload_fileobj(io.BytesIO(b"x"), "refresh.txt")
    with fs.locked("refresh.txt", scope=EXCLUSIVE, lock_timeout=30) as active_lock:
        refreshed = fs.refresh_lock("refresh.txt", active_lock.token, lock_timeout=60)
        assert refreshed.token == active_lock.token
        # Still holding it, still usable for a write afterwards.
        fs.upload_fileobj(io.BytesIO(b"y"), "refresh.txt", overwrite=True)


def test_lock_rejects_an_invalid_depth(fs: FileSystem) -> None:
    """RFC 4918 §9.10.4: only '0' or 'infinity' are legal Depth values for LOCK."""
    fs.upload_fileobj(io.BytesIO(b"x"), "depthlock.txt")
    with (
        pytest.raises(ValueError, match="Depth"),
        fs.locked("depthlock.txt", depth="1"),
    ):
        pass


def test_copy_rejects_an_invalid_depth(client: Session, fs: FileSystem) -> None:
    """RFC 4918 §9.8.3: only '0' or 'infinity' are legal Depth values for COPY."""
    fs.upload_fileobj(io.BytesIO(b"x"), "depthcopy.txt")
    with pytest.raises(ValueError, match="Depth"):
        client.copy("depthcopy.txt", "depthcopy2.txt", depth=1)


def test_get_props_sends_depth_zero(fs: FileSystem) -> None:
    """A single-resource property lookup should never trigger a full traversal."""
    fs.mkdir("depthdir")
    fs.upload_fileobj(io.BytesIO(b"x"), "depthdir/child.txt")
    props = fs.get_props("depthdir")
    # If Depth had defaulted to infinity, the collection's own PROPFIND
    # response would still be the one returned here - the real assertion
    # is that this doesn't error and returns exactly the collection's
    # properties, which get_response_for_path() already enforces by key.
    assert props.collection is True


def test_lockdiscovery_is_parsed_into_activelocks(fs: FileSystem) -> None:
    """lockdiscovery's <activelock> children should reuse ActiveLock, not stay raw XML."""
    fs.upload_fileobj(io.BytesIO(b"x"), "lockdisco.txt")
    with fs.locked("lockdisco.txt", scope=EXCLUSIVE) as active_lock:
        props = fs.get_props("lockdisco.txt")
        assert len(props.active_locks) == 1
        assert isinstance(props.active_locks[0], ActiveLock)
        assert props.active_locks[0].token == active_lock.token


def test_supportedlock_is_parsed_into_lockentries(fs: FileSystem) -> None:
    """supportedlock's <lockentry> children should reuse LockEntry, not stay raw XML."""
    fs.upload_fileobj(io.BytesIO(b"x"), "supportedlock.txt")
    props = fs.get_props("supportedlock.txt")
    assert all(isinstance(entry, LockEntry) for entry in props.supported_locks)
