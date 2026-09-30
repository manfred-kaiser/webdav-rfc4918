"""What a server tells about itself in answer to ``OPTIONS`` (RFC 4918 sec. 18)."""

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Self

    import requests


@dataclass(frozen=True, slots=True)
class FeatureDetection:
    """Server features detected via an ``OPTIONS`` request.

    Mostly used for detecting ``Accept-Ranges`` support, since some
    servers (e.g. ownCloud/Nextcloud) don't advertise it on GET responses.

    Immutable, because one instance is cached per server and handed to every
    caller: a caller that could change it would change it for all of them.
    ``FeatureDetection()`` is the "nothing known" state.
    """

    supports_ranges: bool = False
    dav_compliances: frozenset[str] = frozenset()

    @classmethod
    def from_response(cls, response: "requests.Response") -> "Self":
        """Read the features out of the answer to an ``OPTIONS`` request."""
        return cls(
            supports_ranges=response.headers.get("accept-ranges") == "bytes",
            dav_compliances=parse_dav_header(response.headers.get("dav", "")),
        )


def parse_dav_header(value: str) -> frozenset[str]:
    """Split a ``DAV`` compliance-class header into its tokens (RFC 4918 §18).

    ``compliance-class = ("1" | "2" | "3" | extend)``, and ``extend`` can
    be a bare token (``"bind"``) or a ``Coded-URL`` (``<absolute-URI>``) -
    a comma inside the URI (legal per RFC 3986, unencoded, as a path/query
    sub-delim) is part of it, not a token separator, so this tracks
    bracket depth instead of blindly splitting on every comma.
    """
    tokens = []
    depth = 0
    current: list[str] = []
    for char in value:
        if char == "<":
            depth += 1
            current.append(char)
        elif char == ">":
            depth = max(0, depth - 1)
            current.append(char)
        elif char == "," and depth == 0:
            tokens.append("".join(current))
            current = []
        else:
            current.append(char)
    tokens.append("".join(current))
    return frozenset(t.strip() for t in tokens if t.strip())
