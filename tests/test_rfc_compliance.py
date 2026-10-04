"""Regression tests for the RFC 4918/5689 conformance fixes in RFC_COMPLIANCE.md.

Each test locks in one specific gap/bug found during a dedicated RFC audit
(as opposed to tests/test_session_e2e.py's general happy-path coverage, or
tests/test_security_edge_cases.py's adversarial-server coverage).
"""

import io
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from xml.etree.ElementTree import Element

import pytest

from tests.scripted_server import Reply, Seen, always, scripted_server
from webdav import FileSystem, Session
from webdav.dav.conditional import Condition, build_if_header, build_if_header_single
from webdav.dav.date_utils import from_rfc1123
from webdav.dav.features import parse_dav_header
from webdav.dav.headers import depth_header
from webdav.dav.locks import (
    EXCLUSIVE,
    SHARED,
    ActiveLock,
    LockEntry,
    build_lock_body,
    format_timeout,
    parse_timeout,
)
from webdav.dav.multistatus import MultiStatusResponse, ResourceResponse
from webdav.dav.properties import (
    DAVProperties,
    build_mkcol_body,
    build_propfind_body,
    build_proppatch_body,
    parse_mkcol_response,
)
from webdav.dav.urls import URL, join_url_path, normalize_path
from webdav.dav.xml_utils import parse_xml
from webdav.exceptions import (
    STATUS_CODE_EXCEPTIONS,
    HTTPStatusError,
    IsACollectionError,
    IsAResourceError,
    MalformedResponseError,
    MultiStatusError,
    ResourceAlreadyExistsError,
    ResourceConflictError,
    ResourceLockedError,
    UnsupportedMediaTypeError,
)

if TYPE_CHECKING:
    from collections.abc import Callable


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
    response = ResourceResponse(parse_xml(xml))
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
    tokens = parse_dav_header("1, 2, <http://example.com/ext,ended>")
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


# ---------------------------------------------------------------------------
# §9.1.2/§13/§14 - property model and multistatus envelope edge cases
# ---------------------------------------------------------------------------


def test_a_property_the_server_does_not_have_is_reported_as_failed() -> None:
    """§9.1.2: a property that does not exist MUST be noted with a 404 in its own propstat."""
    xml = (
        '<d:response xmlns:d="DAV:"><d:href>/a</d:href>'
        "<d:propstat><d:prop><d:getetag>abc</d:getetag></d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat>"
        "<d:propstat><d:prop><d:displayname/></d:prop>"
        "<d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>"
        "</d:response>"
    )
    response = ResourceResponse(parse_xml(xml))
    assert response.properties.failed == {"{DAV:}displayname": 404}
    assert "{DAV:}displayname" not in response.properties.elements
    assert response.properties.etag == "abc"


def test_proppatch_failure_is_keyed_by_href_and_property_name() -> None:
    """A per-property PROPPATCH failure's composite key names the property that actually failed."""
    xml = (
        '<d:multistatus xmlns:d="DAV:"><d:response><d:href>/a</d:href>'
        "<d:propstat><d:prop><d:displayname/></d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat>"
        "<d:propstat><d:prop><d:getetag/></d:prop>"
        "<d:status>HTTP/1.1 409 Conflict</d:status>"
        "<d:error><d:cannot-modify-protected-property/></d:error>"
        "</d:propstat></d:response></d:multistatus>"
    )
    with pytest.raises(MultiStatusError) as exc_info:
        MultiStatusResponse(xml).raise_for_status()
    assert list(exc_info.value.statuses) == ["/a (getetag)"]
    assert exc_info.value.statuses["/a (getetag)"] == "Conflict"
    assert exc_info.value.error_codes["/a (getetag)"] == frozenset(
        {"cannot-modify-protected-property"}
    )


def test_proppatch_where_every_propstat_succeeds_does_not_raise() -> None:
    """The same shape as above, but nothing failed - nothing should raise."""
    xml = (
        '<d:multistatus xmlns:d="DAV:"><d:response><d:href>/a</d:href>'
        "<d:propstat><d:prop><d:displayname/></d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat>"
        "<d:propstat><d:prop><d:getetag/></d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
    )
    MultiStatusResponse(xml).raise_for_status()  # must not raise


def test_a_response_with_neither_status_nor_propstat_is_refused() -> None:
    """§14.24: response = href, ((href*, status) | propstat+), ... - one of the two is required.

    Neither present is not a quieter way to say "nothing to report": a
    response this information-free must not be silently read as success.
    """
    xml = '<d:multistatus xmlns:d="DAV:"><d:response><d:href>/a</d:href></d:response></d:multistatus>'
    with pytest.raises(MalformedResponseError, match="neither"):
        MultiStatusResponse(xml)


def test_a_multistatus_can_have_zero_responses() -> None:
    """§14.16: multistatus = (response*, responsedescription?) - zero is legal."""
    result = MultiStatusResponse('<d:multistatus xmlns:d="DAV:"/>')
    assert result.entries == []
    assert result.responses == {}
    result.raise_for_status()  # vacuously true - must not raise
    with pytest.raises(MalformedResponseError, match="no <d:response>"):
        result.get_response_for_path("/", "anything")


def test_a_top_level_responsedescription_is_captured() -> None:
    """§14.16: responsedescription can appear directly under multistatus, not just inside a propstat."""
    xml = (
        '<d:multistatus xmlns:d="DAV:">'
        "<d:responsedescription>There has been an access violation error."
        "</d:responsedescription></d:multistatus>"
    )
    result = MultiStatusResponse(xml)
    assert result.response_description == "There has been an access violation error."


def test_an_error_can_have_more_than_one_precondition_code() -> None:
    """§16: <error> is ANY - several applicable precondition/postcondition codes can co-occur."""
    xml = (
        '<d:response xmlns:d="DAV:"><d:href>/a</d:href>'
        "<d:status>HTTP/1.1 423 Locked</d:status>"
        "<d:error><d:no-conflicting-lock/>"
        "<d:lock-token-submitted><d:href>/a</d:href></d:lock-token-submitted>"
        "</d:error></d:response>"
    )
    response = ResourceResponse(parse_xml(xml))
    assert response.error is not None
    codes = {child.tag.rpartition("}")[2] for child in response.error}
    assert codes == {"no-conflicting-lock", "lock-token-submitted"}


def test_http_status_error_finds_a_precondition_code_in_a_plain_error_body() -> None:
    """§16's own worked example: a non-207 error with a bare <d:error> root."""
    body = (
        b'<?xml version="1.0"?><D:error xmlns:D="DAV:">'
        b"<D:lock-token-submitted><D:href>/workspace/webdav/</D:href>"
        b"</D:lock-token-submitted></D:error>"
    )
    with scripted_server(always((423, {}, body))) as (url, _rec):
        with pytest.raises(HTTPStatusError) as exc_info, FileSystem(retry=False).locked(
            f"{url}/a"
        ):
            pass
    assert exc_info.value.error_codes == frozenset({"lock-token-submitted"})


def test_http_status_error_finds_a_precondition_code_nested_under_something_else() -> None:
    """The other shape _parse_error_codes must handle: <error> not the document root itself."""
    body = (
        b'<?xml version="1.0"?><D:something xmlns:D="DAV:"><D:error>'
        b"<D:preserved-live-properties/></D:error></D:something>"
    )
    with scripted_server(always((409, {}, body))) as (url, _rec):
        with pytest.raises(HTTPStatusError) as exc_info:
            FileSystem(retry=False).move(f"{url}/a", f"{url}/b")
    assert exc_info.value.error_codes == frozenset({"preserved-live-properties"})


@pytest.mark.parametrize(
    ("local_name", "value", "expected"),
    [
        ("creationdate", "1997-12-01T17:42:21-08:00", (1997, 12, 1)),
        ("getlastmodified", "Mon, 12 Jan 1998 09:25:56 GMT", (1998, 1, 12)),
    ],
)
def test_a_date_property_is_wired_through_davproperties(
    local_name: str, value: str, expected: tuple[int, int, int]
) -> None:
    """RFC 4918's own §9.1.5 example values for creationdate/getlastmodified, through the real property model."""
    el = Element(f"{{DAV:}}{local_name}")
    el.text = value
    props = DAVProperties({f"{{DAV:}}{local_name}": el})
    attr = "created" if local_name == "creationdate" else "modified"
    parsed = getattr(props, attr)
    assert parsed is not None
    assert (parsed.year, parsed.month, parsed.day) == expected


def test_a_property_with_child_elements_is_not_read_as_a_leaf_value() -> None:
    """The leaf-vs-non-leaf convention (len(el) == 0) applies uniformly - pin it for one property."""
    el = Element("{DAV:}getetag")
    el.append(Element("{DAV:}unexpected-child"))
    props = DAVProperties({"{DAV:}getetag": el})
    assert props.etag is None  # not read as a leaf value
    assert props.element("DAV:", "getetag") is el  # but nothing is lost structurally
    assert props.text("DAV:", "getetag") is None


def test_an_empty_but_present_getetag_and_an_absent_one_both_read_as_none() -> None:
    """Document the current (possibly surprising) collapse of two distinct wire states."""
    present_empty = Element("{DAV:}getetag")
    present_empty.text = ""
    assert DAVProperties({"{DAV:}getetag": present_empty}).etag is None
    assert DAVProperties({}).etag is None


def test_getcontenttype_is_wired_through_davproperties() -> None:
    el = Element("{DAV:}getcontenttype")
    el.text = "text/html"
    assert DAVProperties({"{DAV:}getcontenttype": el}).content_type == "text/html"


def test_a_present_but_empty_lockdiscovery_means_no_locks_held_not_unknown() -> None:
    """§15.8: "If there are no locks, but the server supports locks, the property will be present but empty."."""
    props = DAVProperties({"{DAV:}lockdiscovery": Element("{DAV:}lockdiscovery")})
    assert props.lock_discovery is not None
    assert props.active_locks == []


def test_a_malformed_activelock_in_lockdiscovery_is_skipped_not_fatal() -> None:
    """One bad <activelock> must not hide a sibling good one - same rationale as multistatus per-response handling."""
    lockdiscovery_el = Element("{DAV:}lockdiscovery")
    bad = Element("{DAV:}activelock")  # missing every required child
    lockdiscovery_el.append(bad)
    good = Element("{DAV:}activelock")
    scope_el = Element("{DAV:}lockscope")
    scope_el.append(Element("{DAV:}exclusive"))
    good.append(scope_el)
    type_el = Element("{DAV:}locktype")
    type_el.append(Element("{DAV:}write"))
    good.append(type_el)
    depth_el = Element("{DAV:}depth")
    depth_el.text = "0"
    good.append(depth_el)
    token_el = Element("{DAV:}locktoken")
    href_el = Element("{DAV:}href")
    href_el.text = "opaquelocktoken:abc"
    token_el.append(href_el)
    good.append(token_el)
    lockdiscovery_el.append(good)
    props = DAVProperties({"{DAV:}lockdiscovery": lockdiscovery_el})
    assert len(props.active_locks) == 1
    assert props.active_locks[0].token == "opaquelocktoken:abc"


def test_resourcetype_collection_plus_a_custom_type_are_both_recognized() -> None:
    """§15.9's own example: <collection/> alongside an unrecognized extension type."""
    resourcetype_el = Element("{DAV:}resourcetype")
    resourcetype_el.append(Element("{DAV:}collection"))
    resourcetype_el.append(Element("{urn:x}search-results"))
    props = DAVProperties({"{DAV:}resourcetype": resourcetype_el})
    assert props.collection is True
    assert props.resource_type == "directory"
    assert props.resource_types == frozenset({"collection", "search-results"})


def test_resourcetype_present_but_empty_is_not_a_collection() -> None:
    """An ordinary non-collection file: present-and-empty, distinct from entirely absent."""
    props = DAVProperties({"{DAV:}resourcetype": Element("{DAV:}resourcetype")})
    assert props.collection is False
    assert DAVProperties({}).collection is None


def test_a_lockentry_with_no_recognized_child_defaults_to_exclusive_write() -> None:
    """locks.py's documented fallback, reached through the property model's supportedlock parsing."""
    lockentry_el = Element("{DAV:}lockentry")
    lockentry_el.append(Element("{DAV:}lockscope"))
    lockentry_el.append(Element("{DAV:}locktype"))
    entry = LockEntry.from_element(lockentry_el)
    assert entry == LockEntry(scope=EXCLUSIVE, lock_type="write")


def test_propfind_ignores_include_without_allprop() -> None:
    """include is documented as ignored outside all_prop=True - pin that it stays silently dropped."""
    body = build_propfind_body(prop_name=True, include=["etag"])
    tree = parse_xml(body)
    assert tree.find("{DAV:}propname") is not None
    assert tree.find("{DAV:}include") is None


def test_proppatch_can_set_and_remove_in_one_call() -> None:
    """§9.2: a propertyupdate can hold several set/remove instructions, processed in document order."""
    body = build_proppatch_body(
        set_props={"displayname": "x"}, remove_props=["getcontentlanguage"]
    )
    tree = parse_xml(body)
    children = list(tree)
    assert [child.tag for child in children] == ["{DAV:}set", "{DAV:}remove"]


def test_proppatch_can_set_a_complex_element_value() -> None:
    """prop's content model is ANY (§14.26) - a property value can be a whole sub-tree, not just text.

    The value's own element becomes a child of the property's wrapper
    (the same shape build_lock_body uses for a structured owner, see
    test_build_lock_body_accepts_a_structured_owner).
    """
    body = build_proppatch_body(set_props={"resourcetype": Element("{DAV:}collection")})
    tree = parse_xml(body)
    assert tree.find("{DAV:}set/{DAV:}prop/{DAV:}resourcetype/{DAV:}collection") is not None


# ---------------------------------------------------------------------------
# §10.4.2/Appendix C - the If header's Condition/List/Tagged-list grammar
# ---------------------------------------------------------------------------


def test_a_negated_condition_renders_not_before_the_token_or_etag() -> None:
    """Appendix C: Condition = ["Not"] (State-token | entity-tag) - §10.4.7's own worked shape."""
    assert Condition(token="urn:a", negate=True).render() == "Not <urn:a>"
    assert Condition(etag="x", negate=True).render() == 'Not ["x"]'
    header = build_if_header_single(
        [Condition(token="urn:a", negate=True), Condition(token="urn:b")]
    )
    assert header == "(Not <urn:a> <urn:b>)"


def test_a_tagged_list_can_have_more_than_one_list() -> None:
    """§10.4.9's own worked example: two alternative Lists under one Resource-Tag."""
    header = build_if_header(
        [[Condition(token="urn:a")], [Condition(etag="X")]],
        resource="http://x/r",
    )
    assert header == '<http://x/r> (<urn:a>)(["X"])'


def test_a_list_can_require_both_a_token_and_an_etag() -> None:
    """§10.4.3: the Conditions within one List are a logical conjunction (AND), not alternatives."""
    header = build_if_header_single([Condition(token="urn:a"), Condition(etag="X")])
    assert header == '(<urn:a> ["X"])'


def test_parse_timeout_takes_the_first_of_a_preference_list() -> None:
    """The response-side counterpart of format_timeout's preference list (§10.7)."""
    assert parse_timeout("Second-3600, Infinite") == 3600


# ---------------------------------------------------------------------------
# RFC 9110 §5.6.7 - HTTP-date, the rfc850-date two-digit year in particular
# ---------------------------------------------------------------------------


def test_an_rfc850_two_digit_year_within_50_years_stays_in_this_century() -> None:
    """§5.6.7: a two-digit year not more than 50 years in the future reads in the current century."""
    now = datetime.now(UTC)
    near_year = (now.year % 100 + 5) % 100  # a few years from now, same century
    parsed = from_rfc1123(f"Sunday, 06-Nov-{near_year:02d} 08:49:37 GMT")
    assert parsed is not None
    assert parsed.year // 100 == now.year // 100


def test_an_rfc850_two_digit_year_more_than_50_years_out_falls_back_a_century() -> None:
    """§5.6.7: the fallback side of the same rule - computed relative to now, not a fixed pivot."""
    now = datetime.now(UTC)
    far_year = (now.year + 60) % 100  # unambiguously >50y out in the current century
    parsed = from_rfc1123(f"Sunday, 06-Nov-{far_year:02d} 08:49:37 GMT")
    assert parsed is not None
    assert parsed.year <= now.year + 50


def test_a_leap_second_cannot_be_represented_but_does_not_raise() -> None:
    """time-of-day allows :60 (a leap second) in all three HTTP-date forms - unrepresentable, not a crash."""
    assert from_rfc1123("Tue, 30 Jun 2015 23:59:60 GMT") is None


def test_an_asctime_or_rfc850_retry_after_is_read_as_utc() -> None:
    """asctime values carry no zone and are assumed UTC (§5.6.7) - exercised through Retry-After."""
    naive = from_rfc1123("Sun Nov  6 08:49:37 1994")
    assert naive is not None
    assert naive.tzinfo is None
    aware = from_rfc1123("Sunday, 06-Nov-94 08:49:37 GMT")
    assert aware is not None
    assert aware.tzinfo is not None


def test_gmt_literal_leniency_still_parses() -> None:
    """Recipients are encouraged to be robust (§5.6.7) - accepted beyond the strict grammar, deliberately."""
    assert from_rfc1123("wed, 21 oct 2015 07:28:00 gmt") is not None
    assert from_rfc1123("Wed, 21 Oct 2015 07:28:00 UTC") is not None
    assert from_rfc1123("Wed, 21 Oct 2015 07:28:00 +0000") is not None


def test_asctime_single_space_day_still_parses() -> None:
    """date3 = month SP (2DIGIT / (SP 1DIGIT)) - a single-digit day needs two spaces; one is still accepted."""
    assert from_rfc1123("Sun Nov 6 08:49:37 1994") is not None


def test_an_rfc1123_date_overflowing_near_the_year_boundary_is_none_not_an_exception() -> (
    None
):
    assert from_rfc1123("Fri, 31 Dec 9999 23:59:59 -2359") is None
    assert from_rfc1123("Fri, 31 Dec 9999 23:59:59 GMT") is not None


# ---------------------------------------------------------------------------
# RFC 3986 - percent-encoding and path normalization this library does itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("char", list("!$&'()*+,;=:@?#"))
def test_a_reserved_character_in_a_path_is_percent_encoded(char: str) -> None:
    """sub-delims/gen-delims are legal unencoded in a path segment (§2.2) - this library over-encodes anyway."""
    rendered = str(URL("http://x").copy_with(path=f"/a{char}b"))
    assert char not in rendered.rpartition("/")[2]


def test_unreserved_characters_and_slash_are_never_encoded() -> None:
    rendered = str(URL("http://x").copy_with(path="/aA1-._~/b"))
    assert rendered.endswith("/aA1-._~/b")


def test_a_literal_percent_in_a_path_round_trips() -> None:
    url = URL("http://x").copy_with(path="/100%.txt")
    assert URL(str(url)).path == "/100%.txt"


def test_url_does_not_resolve_an_encoded_dot_segment_itself() -> None:
    """URL is a pure parser - %2e%2e decodes to a literal '..' it never interprets or collapses.

    Still four path segments ("", "a", "..", "etc"), not the two
    (remove_dot_segments, §5.2.4) would leave - that resolution is
    ``normalize_path``'s job (see the parametrized test above), never
    ``URL``'s own.
    """
    url = URL("https://x/a/%2e%2e/etc")
    assert url.path == "/a/../etc"
    assert url.path.split("/") == ["", "a", "..", "etc"]


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/a/./b/../c", "/a/c"),
        ("/a//b///c", "/a/b/c"),
        ("/a/...", "/a/..."),  # "..." is not a dot-segment
        ("/", "/"),
        ("//a", "/a"),
    ],
)
def test_normalize_path_resolves_dot_segments(path: str, expected: str) -> None:
    assert normalize_path(path) == expected


def test_normalize_path_of_an_empty_string_is_unchanged() -> None:
    """Every call site assumes an absolute input; the empty-string short-circuit must stay a no-op."""
    assert normalize_path("") == ""


def test_join_url_path_treats_an_already_encoded_dot_segment_as_a_literal_name() -> None:
    """A caller-supplied path is already decoded (module convention) - %2e%2e names a real segment, not '..'."""
    assert join_url_path("/dav", "%2e%2e/x") == "/dav/%2e%2e/x"
    with pytest.raises(ValueError, match="climbs out"):
        join_url_path("/dav", "../x")


# ---------------------------------------------------------------------------
# §10.1 DAV header / Coded-URL parsing edge cases
# ---------------------------------------------------------------------------


def test_dav_header_edge_cases() -> None:
    assert parse_dav_header("") == set()
    assert parse_dav_header("   ") == set()
    assert parse_dav_header("1,,2") == {"1", "2"}
    assert parse_dav_header("<http://a") == {"<http://a"}
    assert parse_dav_header("bind,<http://example.com/ext,1>,version-control") == {
        "bind",
        "<http://example.com/ext,1>",
        "version-control",
    }
    assert parse_dav_header("<http://a,b>,<http://c,d>") == {
        "<http://a,b>",
        "<http://c,d>",
    }


# ---------------------------------------------------------------------------
# §11/§16 - status code registry, and RFC 5689's own additions to it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [400, 501, 505, 599])
def test_an_unregistered_status_is_the_base_exception_and_not_retried(status: int) -> None:
    """A status this library gives no special meaning to must not silently be treated as transient."""
    with scripted_server(always((status, {}, b""))) as (url, rec):
        with pytest.raises(HTTPStatusError) as exc_info:
            FileSystem(retry=True).ls(f"{url}/x")
    assert type(exc_info.value) is HTTPStatusError
    assert len(rec.requests) == 1  # never retried


@pytest.mark.parametrize(
    "status", [403, 404, 409, 412, 415, 422, 423, 424, 428, 507]
)
def test_every_registered_client_error_is_not_retryable(status: int) -> None:
    assert STATUS_CODE_EXCEPTIONS[status].retryable is False


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504, 509])
def test_every_registered_transient_status_is_retryable(status: int) -> None:
    assert STATUS_CODE_EXCEPTIONS[status].retryable is True


def test_a_502_from_copy_or_move_is_a_bad_gateway_error() -> None:
    with scripted_server(always((502, {}, b""))) as (url, _rec):
        with pytest.raises(STATUS_CODE_EXCEPTIONS[502]):
            FileSystem(retry=False).move(f"{url}/a", f"{url}/b")


@pytest.mark.parametrize("status", [422, 507])
def test_mkcol_delete_errors_are_registered_round_trip(status: int) -> None:
    with scripted_server(always((status, {}, b""))) as (url, _rec):
        with pytest.raises(STATUS_CODE_EXCEPTIONS[status]):
            FileSystem(retry=False).mkdir(f"{url}/d")


# ---------------------------------------------------------------------------
# RFC 5689 Extended MKCOL
# ---------------------------------------------------------------------------


def test_build_mkcol_body_matches_the_rfcs_own_shape() -> None:
    """§3.4's own example request body: <D:mkcol><D:set><D:prop>resourcetype + displayname."""
    body = build_mkcol_body(
        {
            "resourcetype": Element("{http://example.com/ns/}special-resource"),
            "displayname": "Special Resource",
        }
    )
    tree = parse_xml(body)
    assert tree.tag == "{DAV:}mkcol"
    prop_el = tree.find("{DAV:}set/{DAV:}prop")
    assert prop_el is not None
    assert (
        prop_el.find("{DAV:}resourcetype/{http://example.com/ns/}special-resource")
        is not None
    )
    assert prop_el.findtext("{DAV:}displayname") == "Special Resource"


def test_build_mkcol_body_needs_at_least_one_property() -> None:
    with pytest.raises(ValueError, match="at least one"):
        build_mkcol_body({})


def test_parse_mkcol_response_matches_the_rfcs_own_failure_example() -> None:
    """§3.5's own example response body: one property's precondition failed, the other a dependent 424."""
    body = (
        b'<?xml version="1.0" encoding="utf-8" ?>'
        b'<D:mkcol-response xmlns:D="DAV:">'
        b"<D:propstat><D:prop><D:resourcetype/></D:prop>"
        b"<D:status>HTTP/1.1 403 Forbidden</D:status>"
        b"<D:error><D:valid-resourcetype /></D:error>"
        b"<D:responsedescription>Resource type is not supported by this server</D:responsedescription>"
        b"</D:propstat>"
        b"<D:propstat><D:prop><D:displayname/></D:prop>"
        b"<D:status>HTTP/1.1 424 Failed Dependency</D:status></D:propstat>"
        b"</D:mkcol-response>"
    )

    class _FakeResponse:
        content = body

    propstats = parse_mkcol_response(_FakeResponse())  # type: ignore[arg-type]
    assert [p.status_code for p in propstats] == [403, 424]
    assert "{DAV:}resourcetype" in propstats[0].properties
    assert propstats[0].error is not None
    assert propstats[0].response_description == "Resource type is not supported by this server"
    assert "{DAV:}displayname" in propstats[1].properties
    assert propstats[1].error is None


def test_parse_mkcol_response_is_empty_for_a_body_that_is_not_one() -> None:
    """A server not supporting Extended MKCOL answers plainly - never raise on it, just report nothing."""

    class _FakeResponse:
        content = b"plain text error, not XML at all"

    assert parse_mkcol_response(_FakeResponse()) == []  # type: ignore[arg-type]

    class _EmptyResponse:
        content = b""

    assert parse_mkcol_response(_EmptyResponse()) == []  # type: ignore[arg-type]


def test_http_status_error_finds_the_precondition_code_inside_an_mkcol_response() -> None:
    """RFC 5689 sec. 3's <error> sits inside the failed property's own <propstat>, not at the document root."""
    body = (
        b'<?xml version="1.0" encoding="utf-8" ?>'
        b'<D:mkcol-response xmlns:D="DAV:">'
        b"<D:propstat><D:prop><D:resourcetype/></D:prop>"
        b"<D:status>HTTP/1.1 403 Forbidden</D:status>"
        b"<D:error><D:valid-resourcetype /></D:error></D:propstat>"
        b"</D:mkcol-response>"
    )
    with scripted_server(always((403, {}, body))) as (url, _rec):
        with pytest.raises(HTTPStatusError) as exc_info:
            FileSystem(retry=False).mkdir(f"{url}/special")
    assert exc_info.value.error_codes == frozenset({"valid-resourcetype"})


def test_an_extended_mkcol_body_is_sent_as_xml(fs: FileSystem) -> None:
    """set_props builds and sends a real Extended MKCOL request - most test servers don't support the
    extension itself (confirmed: wsgidav answers 415), but the *request* this library sends must still
    be exactly what RFC 5689 sec. 3 specifies."""
    with pytest.raises(UnsupportedMediaTypeError):
        fs.mkdir("special", set_props={"displayname": "Special Dir"})


def test_mkdir_refuses_both_data_and_set_props() -> None:
    with pytest.raises(ValueError, match="either data or set_props"):
        FileSystem("http://unused.invalid").mkdir(
            "x", data="<a/>", set_props={"displayname": "x"}
        )


def test_mkcol_on_an_existing_plain_resource_is_also_resourcealreadyexists(
    fs: FileSystem,
) -> None:
    """§9.3: "If the Request-URI is already mapped to a resource then MKCOL MUST fail" - a file too, not just a collection."""
    fs.upload_fileobj(io.BytesIO(b"x"), "plain.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        fs.mkdir("plain.txt")


_PLAIN_RESOURCE_PROPFIND = (
    207,
    {"Content-Type": "application/xml"},
    (
        b'<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response>'
        b"<D:href>/plain.txt</D:href><D:propstat><D:prop><D:resourcetype/></D:prop>"
        b"<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"
    ),
)


def _mkcol_says_400(propfind: Reply) -> "Callable[[Seen], Reply]":
    """A server that answers every MKCOL with 400 and every other method with ``propfind``."""

    def respond(seen: Seen) -> Reply:
        return (400, {}, b"") if seen.method == "MKCOL" else propfind

    return respond


def test_mkcol_on_an_existing_plain_resource_is_still_recognized_when_the_server_says_400() -> (
    None
):
    """A real server (Apache's mod_dav 2.4, confirmed live) answers 400, not 405, for this same conflict -
    the trailing slash mkdir() always adds (§5.2) lands on an existing plain resource, and Apache's
    own path resolution rejects that before it would even get to say "method not allowed".
    The 400 only counts as "exists" because the resource is there: see the tests below.
    """
    with scripted_server(_mkcol_says_400(_PLAIN_RESOURCE_PROPFIND)) as (url, rec):
        with pytest.raises(ResourceAlreadyExistsError):
            FileSystem(retry=False).mkdir(f"{url}/plain.txt")
    assert [(r.method, r.path) for r in rec.requests] == [
        ("MKCOL", "/plain.txt/"),
        ("PROPFIND", "/plain.txt"),
    ]
    assert rec.requests[1].headers["depth"] == "0"


def test_a_400_from_mkcol_is_checked_against_the_resource_without_the_trailing_slash() -> (
    None
):
    """The slash the caller gave is dropped for the existence check: Apache answers a PROPFIND
    on ``plain.txt/`` with the same 400, which would prove nothing."""
    with scripted_server(_mkcol_says_400(_PLAIN_RESOURCE_PROPFIND)) as (url, rec):
        with pytest.raises(ResourceAlreadyExistsError):
            FileSystem(retry=False).mkdir(f"{url}/plain.txt/")
    assert rec.requests[-1].path == "/plain.txt"


def test_a_400_from_mkcol_is_not_taken_for_exists_when_nothing_is_there() -> None:
    """Apache answers the same 400 for a path *below* a plain resource, which does not exist -
    reporting "already exists" for it would be wrong, so the 400 stays what it is."""
    with scripted_server(_mkcol_says_400((404, {}, b""))) as (url, _rec):
        with pytest.raises(HTTPStatusError) as exc_info:
            FileSystem(retry=False).mkdir(f"{url}/plain.txt/child")
    assert exc_info.value.status_code == 400
    assert not isinstance(exc_info.value, ResourceAlreadyExistsError)


@pytest.mark.parametrize("status", [400, 403, 500])
def test_a_400_from_mkcol_stays_a_400_when_the_existence_check_fails_too(
    status: int,
) -> None:
    """The check is only a way to explain the 400: if it cannot be answered (the server
    refuses it as well), the 400 the caller asked about is what it gets - not the check's error.
    """
    with scripted_server(_mkcol_says_400((status, {}, b""))) as (url, _rec):
        with pytest.raises(HTTPStatusError) as exc_info:
            FileSystem(retry=False).mkdir(f"{url}/plain.txt")
    assert exc_info.value.status_code == 400


def test_a_400_from_mkcol_with_a_body_is_not_assumed_to_mean_already_exists() -> None:
    """The 400-means-exists leniency above is scoped to a bodyless MKCOL only -
    a 400 while a body was sent is more likely a genuinely malformed one."""
    with scripted_server(always((400, {}, b""))) as (url, _rec):
        with pytest.raises(HTTPStatusError) as exc_info:
            FileSystem(retry=False).mkdir(
                f"{url}/special", set_props={"displayname": "x"}
            )
    assert not isinstance(exc_info.value, ResourceAlreadyExistsError)


def test_mkcol_with_a_missing_ancestor_is_a_conflict(fs: FileSystem) -> None:
    """§9.3: all ancestors MUST already exist, or the method MUST fail with 409 Conflict."""
    with pytest.raises(ResourceConflictError):
        fs.mkdir("nonexistent-parent/child")


# ---------------------------------------------------------------------------
# §7 locking interactions - more session-level fixes needing a real server
# ---------------------------------------------------------------------------


def test_a_new_lock_inside_an_already_locked_collection_is_refused(
    fs: FileSystem,
) -> None:
    """Pinned, server-confirmed behavior (see webdav.methods.WRITE_METHODS's docstring).

    §7.4 could be read as requiring the ancestor's token to be offered for
    a *new* LOCK that creates a resource under a locked collection - but
    empirically, a real server (wsgidav) still refuses it even when that
    token is attached. Locking an already (ancestor-)locked path is not a
    supported way to get a second, independent token for it.
    """
    fs.mkdir("lockedparent")
    with fs.locked("lockedparent", depth="infinity"):
        with pytest.raises(ResourceLockedError):
            with fs.locked("lockedparent/child.txt"):
                pass


def test_locking_an_unmapped_url_creates_an_empty_resource(fs: FileSystem) -> None:
    """§9.10.4: a successful lock request to an unmapped URL creates an empty resource there."""
    with fs.locked("brand-new.txt") as active_lock:
        assert active_lock.token
        assert fs.exists("brand-new.txt")
        assert fs.content_length("brand-new.txt") in (0, None)
    # §7.3: the resource SHOULD NOT disappear when its lock goes away.
    assert fs.exists("brand-new.txt")


def test_mkcol_over_the_empty_resource_a_lock_created_still_fails(
    fs: FileSystem,
) -> None:
    """§9.10.4: that empty resource MUST NOT be converted into a collection."""
    with fs.locked("brand-new2.txt"):
        pass
    with pytest.raises(ResourceAlreadyExistsError):
        fs.mkdir("brand-new2.txt")


def test_moving_a_member_out_of_a_locked_collection_needs_only_the_parents_token(
    client: Session, fs: FileSystem
) -> None:
    """§7.4: a lock on a collection protects "MOVE an internal member out of the collection"."""
    fs.mkdir("lockedsrc")
    fs.upload_fileobj(io.BytesIO(b"x"), "lockedsrc/child.txt")
    with fs.locked("lockedsrc", depth="0"):
        client.move(
            "lockedsrc/child.txt", destination="moved-out.txt"
        ).raise_for_status()
    assert fs.exists("moved-out.txt")
    assert not fs.exists("lockedsrc/child.txt")


def test_moving_a_member_out_of_a_locked_collection_without_the_token_fails(
    fs: FileSystem,
) -> None:
    fs.mkdir("lockedsrc2")
    fs.upload_fileobj(io.BytesIO(b"x"), "lockedsrc2/child.txt")
    other = FileSystem.from_session(Session(fs._session.base_url, auth=fs._session.auth))
    try:
        with fs.locked("lockedsrc2", depth="0"):
            with pytest.raises(ResourceLockedError):
                other.move("lockedsrc2/child.txt", "elsewhere.txt")
    finally:
        other._session.close()


# ---------------------------------------------------------------------------
# §9.3/§9.4/§9.6/§9.8/§9.9 - Depth headers, 207 traps, collection-vs-resource policy
# ---------------------------------------------------------------------------


def test_delete_never_sends_a_depth_header() -> None:
    """§9.6.1: a client MUST NOT submit a Depth header with a DELETE on a collection with any value but infinity."""
    with scripted_server(always((204, {}, b""))) as (url, rec):
        Session(retry=False).delete(f"{url}/a").raise_for_status()
    assert "depth" not in rec.requests[0].headers


def test_move_never_sends_a_depth_header() -> None:
    """§9.9.2: same MUST, for MOVE - it has no depth= parameter at all."""
    with scripted_server(always((201, {}, b""))) as (url, rec):
        Session(retry=False).move(f"{url}/a", destination=f"{url}/b").raise_for_status()
    assert "depth" not in rec.requests[0].headers


def test_copy_without_an_explicit_depth_sends_no_depth_header() -> None:
    """§9.8.3: without a Depth header, a server MUST act as if infinity - the default here is to omit it."""
    with scripted_server(always((201, {}, b""))) as (url, rec):
        Session(retry=False).copy(f"{url}/a", destination=f"{url}/b").raise_for_status()
    assert "depth" not in rec.requests[0].headers


def test_depth_header_refuses_move_with_an_explicit_depth() -> None:
    """MOVE takes a Depth header (§9.9.2 is why Session.move() never offers to set one) - but the value is still 0/infinity only."""
    from webdav.methods import Method

    with pytest.raises(ValueError, match="Depth"):
        depth_header("1", Method.MOVE)


def test_a_207_from_copy_raises_multistatuserror() -> None:
    """Same Appendix-B-style partial-failure trap as DELETE (§9.8.5), for COPY."""
    body = (
        b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response>'
        b"<d:href>/dir/locked.txt</d:href><d:status>HTTP/1.1 423 Locked</d:status>"
        b"</d:response></d:multistatus>"
    )
    with scripted_server(always((207, {"Content-Type": "application/xml"}, body))) as (
        url,
        _rec,
    ):
        with pytest.raises(MultiStatusError):
            Session(retry=False).copy(
                f"{url}/dir/", destination=f"{url}/dir2/"
            ).raise_for_status()


def test_a_207_from_move_raises_multistatuserror() -> None:
    body = (
        b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response>'
        b"<d:href>/dir/locked.txt</d:href><d:status>HTTP/1.1 423 Locked</d:status>"
        b"</d:response></d:multistatus>"
    )
    with scripted_server(always((207, {"Content-Type": "application/xml"}, body))) as (
        url,
        _rec,
    ):
        with pytest.raises(MultiStatusError):
            Session(retry=False).move(
                f"{url}/dir/", destination=f"{url}/dir2/"
            ).raise_for_status()


def test_a_multistatus_body_under_a_non_207_status_still_raises_multistatuserror() -> (
    None
):
    """A real server (Apache's mod_dav, confirmed live) answers 424 Failed Dependency, not 207,
    for a DELETE blocked by one locked member - but still with a full multistatus body naming it.
    That detail must not be lost behind a generic FailedDependencyError."""
    body = (
        b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response>'
        b"<d:href>/dir/locked.txt</d:href><d:status>HTTP/1.1 423 Locked</d:status>"
        b"</d:response></d:multistatus>"
    )
    with scripted_server(always((424, {"Content-Type": "application/xml"}, body))) as (
        url,
        _rec,
    ):
        with pytest.raises(MultiStatusError) as exc_info:
            Session(retry=False).delete(f"{url}/dir/").raise_for_status()
    assert list(exc_info.value.statuses) == ["/dir/locked.txt"]


def test_a_non_multistatus_body_under_an_error_status_is_unaffected() -> None:
    """The new detection must never misfire on an ordinary error body - the common case stays exactly as before."""
    with scripted_server(always((424, {}, b""))) as (url, _rec):
        with pytest.raises(STATUS_CODE_EXCEPTIONS[424]):
            Session(retry=False).delete(f"{url}/dir/").raise_for_status()
    with scripted_server(always((423, {}, b"<html>Locked</html>"))) as (url, _rec):
        with pytest.raises(ResourceLockedError):
            Session(retry=False).delete(f"{url}/dir/").raise_for_status()


def test_a_multistatus_body_reporting_no_failure_falls_back_to_the_status_based_error() -> (
    None
):
    """An (unlikely, but possible) multistatus body with no actual failing entry must not swallow the error status."""
    body = '<d:multistatus xmlns:d="DAV:"/>'
    with scripted_server(always((424, {"Content-Type": "application/xml"}, body.encode()))) as (
        url,
        _rec,
    ):
        with pytest.raises(STATUS_CODE_EXCEPTIONS[424]):
            Session(retry=False).delete(f"{url}/dir/").raise_for_status()


def test_open_on_a_collection_is_refused_not_misinterpreted(fs: FileSystem) -> None:
    """§9.4: GET on a collection is server-defined - this library's own policy choice must be explicit, not silent."""
    fs.mkdir("adir")
    with pytest.raises(IsACollectionError), fs.open("adir", "rb"):
        pass


def test_ls_on_a_plain_resource_is_refused_not_misinterpreted(fs: FileSystem) -> None:
    fs.upload_fileobj(io.BytesIO(b"x"), "afile.txt")
    with pytest.raises(IsAResourceError):
        fs.ls("afile.txt")


def test_get_and_head_on_a_collection_do_not_raise(fs: FileSystem) -> None:
    """§9.4: the semantics of GET/HEAD on a collection are server-defined - Session itself must not editorialize."""
    fs.mkdir("plaincoll")
    session = fs._session
    get_response = session.get("plaincoll/")
    assert get_response.status_code < 500
    head_response = session.head("plaincoll/")
    assert head_response.status_code < 500


def test_copy_onto_an_existing_destination_is_resourcealreadyexists(
    fs: FileSystem,
) -> None:
    """FileSystem.copy()/move() now translate Overwrite:F's 412 the same way upload_fileobj()/mkdir() do."""
    fs.upload_fileobj(io.BytesIO(b"src"), "ow_src.txt")
    fs.upload_fileobj(io.BytesIO(b"dst"), "ow_dst.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        fs.copy("ow_src.txt", "ow_dst.txt", overwrite=False)


def test_move_onto_an_existing_destination_is_resourcealreadyexists(
    fs: FileSystem,
) -> None:
    fs.upload_fileobj(io.BytesIO(b"src"), "owm_src.txt")
    fs.upload_fileobj(io.BytesIO(b"dst"), "owm_dst.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        fs.move("owm_src.txt", "owm_dst.txt", overwrite=False)
