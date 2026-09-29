"""URL parsing and path-joining helpers used throughout the client.

Built on :mod:`urllib.parse` only - no dependency on the HTTP transport
library for URL handling, so this module stays reusable independent of
what does the actual HTTP requests.
"""

import re
import unicodedata
from posixpath import normpath
from urllib.parse import quote, unquote, urlsplit, urlunsplit

_LEADING_SLASHES = re.compile("^/{2,}")


class URL:
    """A parsed URL with an always percent-decoded ``path``.

    Percent-encoding is re-applied only when the URL is turned back into a
    string (via :func:`str`). This mirrors how a WebDAV server's ``href``
    in a multistatus XML response must be interpreted - the path segment
    is percent-encoded on the wire but the encoded parts (e.g. ``%2e%2e``)
    must be decoded before it is safe to reason about ``..`` segments,
    trailing slashes, or subpath containment.
    """

    __slots__ = ("fragment", "netloc", "path", "query", "scheme")

    scheme: str
    netloc: str
    path: str
    query: str
    fragment: str

    def __init__(self, url: "str | URL" = "") -> None:
        """Parse ``url``, percent-decoding its path component."""
        if isinstance(url, URL):
            self.scheme = url.scheme
            self.netloc = url.netloc
            self.path = url.path
            self.query = url.query
            self.fragment = url.fragment
            return

        split = urlsplit(url)
        self.scheme = split.scheme
        self.netloc = split.netloc
        # NFC-normalized so a server's href and a caller-supplied path that
        # happen to use different (but canonically equivalent) Unicode
        # normalization forms of the same characters - e.g. a precomposed
        # "é" (NFC) vs. "e" + a combining acute accent (NFD), which is what
        # macOS filesystem APIs commonly hand back - still compare equal.
        self.path = unicodedata.normalize("NFC", unquote(split.path))
        self.query = split.query
        self.fragment = split.fragment

    @property
    def is_absolute_url(self) -> bool:
        """True if the URL has both a scheme and a network location."""
        return bool(self.scheme and self.netloc)

    def copy_with(
        self,
        path: str | None = None,
        query: str | None = None,
    ) -> "URL":
        """Return a new URL with ``path``/``query`` replaced."""
        new = URL.__new__(URL)
        new.scheme = self.scheme
        new.netloc = self.netloc
        new.path = self.path if path is None else path
        new.query = self.query if query is None else query
        new.fragment = self.fragment
        return new

    def __str__(self) -> str:
        """Render the URL, percent-encoding the (decoded) path."""
        encoded_path = quote(self.path, safe="/!$&'()*+,;=:@%")
        return urlunsplit(
            (self.scheme, self.netloc, encoded_path, self.query, self.fragment),
        )

    def __repr__(self) -> str:
        """Debug representation."""
        return f"URL({str(self)!r})"

    def __eq__(self, other: object) -> bool:
        """Compare by rendered string form."""
        if isinstance(other, URL | str):
            return str(self) == str(other)
        return NotImplemented

    def __hash__(self) -> int:
        """Hash by rendered string form, consistent with ``__eq__``."""
        return hash(str(self))


def strip_trailing_slash(path: str) -> str:
    """Strips trailing slash from the path, except when it's a root."""
    return path.rstrip("/") if path and path != "/" else path


def normalize_path(path: str) -> str:
    """Normalize an absolute path.

    Collapses repeated slashes, resolves ``.``/``..`` segments (so the
    result always agrees with what a compliant server's own request-target
    normalization, RFC 3986 sec. 6.2.2.3, would resolve the same path to -
    a client-side dict key built from the unresolved form would otherwise
    silently disagree with the server's), NFC-normalizes Unicode (see
    :class:`URL`), and strips a trailing slash (except for the root ``/``
    itself). Always assumes an absolute (``/``-prefixed) input, matching
    every call site in this codebase.
    """
    if not path:
        return path
    # posixpath.normpath special-cases a *leading* run of exactly two
    # slashes (POSIX historically reserves "//" for implementation-defined
    # behavior) and deliberately refuses to collapse it to one - collapse
    # it ourselves first so this always returns a normal single-slash-
    # prefixed path regardless of how many slashes ended up at the front
    # of the input (e.g. joining a root base_path with a path segment).
    collapsed = _LEADING_SLASHES.sub("/", unicodedata.normalize("NFC", path))
    return strip_trailing_slash(normpath(collapsed))


def join_url_path(base_path: str, path: str) -> str:
    """Join ``base_path`` (the WebDAV root) with a resource path.

    Returns an absolute, normalized path - see :func:`normalize_path`.

    Raises:
        ValueError: ``path`` contains enough ``..`` segments that the
            resolved path would climb outside of ``base_path``. This is
            never a legitimate WebDAV request; treat it the same as any
            other caller-input error (e.g. wrap it into a
            :class:`~webdav.exceptions.ClientError` at the call site, the
            way :meth:`~webdav.client.Client.join_url` does) rather than
            letting it reach a server.

    """
    base = normalize_path(f"/{base_path.strip('/')}")
    joined = normalize_path(f"{base}/{path.strip('/')}")
    if base not in ("/", joined) and not joined.startswith(f"{base}/"):
        msg = f"{path!r} resolves outside of the WebDAV root {base_path!r}"
        raise ValueError(msg)
    return joined


def join_url(base_url: URL, path: str, add_trailing_slash: bool = False) -> URL:
    """Joins base url with a path."""
    base_path = base_url.path
    new_path = join_url_path(base_path, path)
    if add_trailing_slash:
        new_path += "/"
    return base_url.copy_with(path=new_path)


def relative_url_to(base_url: URL, rel: str) -> str:
    """Finds relative url to a base url path.

    Raises ValueError if ``rel`` does not resolve to a path under
    ``base_url`` - a server response should never point outside of what
    was requested. Also rejects embedded NUL bytes and backslashes, which
    ``posixpath.normpath`` does not treat as separators but which a
    downstream consumer joining this onto a real filesystem path (e.g. on
    Windows) might.
    """
    if "\x00" in rel or "\\" in rel:
        msg = f"{rel!r} contains an unexpected NUL byte or backslash"
        raise ValueError(msg)

    base = normpath(f"/{base_url.path.strip('/')}").strip("/")
    rel = normpath(f"/{rel.strip('/')}").strip("/")

    if base == rel or not rel:
        return "/"

    if not base and rel:
        return rel

    if not rel.startswith(f"{base}/"):
        msg = f"{rel!r} is not a subpath of {base!r}"
        raise ValueError(msg)

    index = len(base) + 1
    return rel[index:]
