"""The pure pieces of ``webdav.dav`` that build request bodies, headers and server features."""

import dataclasses

import pytest
import requests

from webdav.dav.body import prepare_body
from webdav.dav.features import FeatureDetection
from webdav.dav.headers import depth_header, strong_etag
from webdav.dav.locks import LockRegistry
from webdav.methods import Method

# ---------------------------------------------------------------------------
# prepare_body
# ---------------------------------------------------------------------------


def test_an_xml_body_gets_a_content_type_and_becomes_utf8() -> None:
    data, headers = prepare_body(Method.PROPFIND, "<a>ü</a>", None)
    assert data == "<a>ü</a>".encode()
    assert headers == {"Content-Type": "application/xml; charset=utf-8"}


def test_a_content_type_the_caller_set_is_kept_whatever_its_case() -> None:
    data, headers = prepare_body(Method.LOCK, "<a/>", {"content-type": "text/xml"})
    assert data == b"<a/>"
    assert headers == {"content-type": "text/xml"}


def test_text_is_utf8_even_when_another_charset_is_declared() -> None:
    data, headers = prepare_body(
        Method.PROPPATCH, "<a>ü</a>", {"Content-Type": "text/xml; charset=latin-1"}
    )
    assert data == "<a>ü</a>".encode()  # another encoding has to be passed as bytes
    assert headers == {"Content-Type": "text/xml; charset=latin-1"}


def test_a_text_body_of_any_other_method_is_utf8_and_its_headers_are_untouched() -> (
    None
):
    given = {"X-Test": "1"}
    data, headers = prepare_body(Method.PUT, "ü", given)
    assert data == "ü".encode()
    assert headers is given


def test_no_body_is_no_change() -> None:
    assert prepare_body(Method.PROPFIND, None, None) == (None, None)
    assert prepare_body(Method.GET, b"raw", None) == (b"raw", None)


def test_the_headers_passed_in_are_never_changed_in_place() -> None:
    given = {"Accept": "*/*"}
    _, headers = prepare_body(Method.MKCOL, "<a/>", given)
    assert given == {"Accept": "*/*"}
    assert headers is not given
    assert headers == {
        "Accept": "*/*",
        "Content-Type": "application/xml; charset=utf-8",
    }


# ---------------------------------------------------------------------------
# depth_header / strong_etag
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "depth"),
    [
        (Method.PROPFIND, 0),
        (Method.PROPFIND, "1"),
        (Method.PROPFIND, "infinity"),
        (Method.COPY, "0"),
        (Method.LOCK, "infinity"),
    ],
)
def test_depth_header_accepts_what_the_method_allows(
    method: Method, depth: "int | str"
) -> None:
    assert depth_header(depth, method) == str(depth)


@pytest.mark.parametrize(
    ("method", "depth"),
    [
        (Method.PROPFIND, 2),
        (Method.PROPFIND, "Infinity"),
        (Method.COPY, 1),
        (Method.LOCK, "1"),
        (Method.LOCK, ""),
    ],
)
def test_depth_header_refuses_the_rest(method: Method, depth: "int | str") -> None:
    with pytest.raises(ValueError, match=f"{method} Depth must be one of"):
        depth_header(depth, method)


def test_a_method_without_a_depth_header_says_so() -> None:
    with pytest.raises(ValueError, match="takes no Depth header"):
        depth_header("0", Method.GET)
    with pytest.raises(ValueError, match="takes no Depth header"):
        depth_header("0", "FROBNICATE")


@pytest.mark.parametrize(
    ("given", "sent"), [('"abc"', '"abc"'), ("abc", '"abc"'), ("*", "*")]
)
def test_strong_etag(given: str, sent: str) -> None:
    assert strong_etag(given) == sent


def test_a_weak_etag_is_refused() -> None:
    with pytest.raises(ValueError, match="weak"):
        strong_etag('W/"abc"')


def test_an_obs_text_byte_in_an_etag_is_refused() -> None:
    """RFC 9110 §8.8.3's etagc grammar permits obs-text (%x80-FF) - this is a deliberately stricter choice.

    (entity_tag's own ``_ETAGC`` excludes it alongside ``]``, for the
    If-header-bracket-safety reason in conditional.py's module docstring.)
    Pinned here so a future change to that choice is a conscious one.
    """
    with pytest.raises(ValueError):
        strong_etag('"a\x80b"')


# ---------------------------------------------------------------------------
# FeatureDetection
# ---------------------------------------------------------------------------


def _options(**headers: str) -> requests.Response:
    response = requests.Response()
    response.headers.update({k.replace("_", "-"): v for k, v in headers.items()})
    return response


def test_features_are_read_from_the_answer_to_options() -> None:
    features = FeatureDetection.from_response(
        _options(DAV="1, 2, <http://example.com/ext,ended>", Accept_Ranges="bytes")
    )
    assert features.supports_ranges is True
    assert features.dav_compliances == {"1", "2", "<http://example.com/ext,ended>"}


def test_nothing_known_is_the_empty_state() -> None:
    assert FeatureDetection() == FeatureDetection.from_response(_options())
    assert FeatureDetection().supports_ranges is False
    assert FeatureDetection().dav_compliances == frozenset()


def test_what_one_caller_gets_cannot_be_changed_for_the_next() -> None:
    features = FeatureDetection.from_response(_options(DAV="1, 2"))
    with pytest.raises(dataclasses.FrozenInstanceError):
        features.supports_ranges = True  # type: ignore[misc]
    with pytest.raises(AttributeError):
        features.dav_compliances.add("3")  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# LockRegistry.headers_for / if_header_for_transfer
# ---------------------------------------------------------------------------

URL = "http://dav.example/docs/a.txt"
TOKEN = "opaquelocktoken:1"  # noqa: S105


def _held() -> LockRegistry:
    registry = LockRegistry()
    registry.add(URL, TOKEN, "0")
    return registry


def test_a_write_to_a_locked_resource_carries_the_lock() -> None:
    headers = _held().headers_for(Method.PUT, URL, {"X-A": "1"})
    assert headers == {"X-A": "1", "If": f"(<{TOKEN}>)"}


@pytest.mark.parametrize(
    "method", [Method.GET, Method.HEAD, Method.PROPFIND, Method.LOCK]
)
def test_a_read_never_carries_a_lock(method: Method) -> None:
    assert _held().headers_for(method, URL, {}) == {}


def test_an_if_header_the_caller_wrote_is_left_alone() -> None:
    given = {"if": "(<other>)"}
    assert _held().headers_for(Method.PUT, URL, given) == {"if": "(<other>)"}


def test_nothing_held_adds_nothing_and_the_input_is_not_handed_back() -> None:
    given = {"X-A": "1"}
    result = LockRegistry().headers_for(Method.PUT, URL, given)
    assert result == given
    assert result is not given


def test_a_delete_presents_the_locks_below_it_too() -> None:
    registry = _held()
    assert registry.headers_for(Method.DELETE, "http://dav.example/docs/", {}).get("If")
    assert "If" not in registry.headers_for(Method.PUT, "http://dav.example/docs/", {})


def test_a_move_presents_locks_below_its_source_a_copy_does_not() -> None:
    registry = _held()
    source, target = "http://dav.example/docs/", "http://dav.example/other/"
    assert registry.if_header_for_transfer(source, target, moves=True)
    assert registry.if_header_for_transfer(source, target, moves=False) is None
