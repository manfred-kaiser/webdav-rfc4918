"""The final form of a request body: XML gets its type, text becomes UTF-8 bytes."""

from typing import TYPE_CHECKING, Any

from requests.structures import CaseInsensitiveDict

from webdav.methods import XML_BODY_METHODS

if TYPE_CHECKING:
    from collections.abc import Mapping


def prepare_body(
    method: str, data: Any, headers: "Mapping[str, str] | None"
) -> "tuple[Any, Mapping[str, str] | None]":
    """Return ``(data, headers)`` as they are to be sent.

    An XML body (RFC 4918: PROPFIND, PROPPATCH, MKCOL, LOCK) gets a
    ``Content-Type`` unless the caller set one, and text is always encoded
    as UTF-8 whatever ``requests`` version is installed: older ones leave a
    ``str`` to ``http.client``, which encodes Latin-1 (and fails outside it)
    and declares a ``Content-Length`` that no longer matches the bytes. A
    body in another encoding has to be passed as ``bytes``.

    Nothing is changed in place: ``headers`` comes back as a new ``dict``
    whenever it was touched, and as the object passed in otherwise.
    """
    if method in XML_BODY_METHODS and data is not None:
        headers = _with_xml_content_type(headers)
    if isinstance(data, str):
        data = data.encode("utf-8")
    return data, headers


def _with_xml_content_type(headers: "Mapping[str, str] | None") -> dict[str, str]:
    merged = CaseInsensitiveDict(headers or {})
    if "Content-Type" not in merged:
        merged["Content-Type"] = "application/xml; charset=utf-8"
    return dict(merged)
