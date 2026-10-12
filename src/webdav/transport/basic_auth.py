"""Basic authentication (RFC 7617) that sends non-ASCII credentials the way curl and browsers do.

``requests`` encodes the user name and password as ISO-8859-1. A server that stores them
as UTF-8 (Apache with an ``htpasswd`` file made on a UTF-8 system, Nextcloud) then does not
know ``päss``, and ``名前`` is a ``UnicodeEncodeError``. RFC 7617 leaves the default
encoding undefined, names UTF-8 as the only encoding a server can ask for (``charset``),
and notes that some old sites expect ISO-8859-1: :class:`BasicAuth` takes either.
"""

import base64

import requests.auth

from webdav._base_exceptions import ClientError


def _octets(value: "str | bytes", encoding: str, what: str) -> bytes:
    if isinstance(value, bytes):
        return value
    try:
        return value.encode(encoding)
    except UnicodeEncodeError as exc:
        msg = f"the {what} cannot be encoded as {encoding}; give it as bytes, or use encoding='utf-8'"
        raise ClientError(msg) from exc


class BasicAuth(requests.auth.HTTPBasicAuth):
    """HTTP Basic authentication whose user name and password are encoded as ``encoding``.

    UTF-8 is the default, as in curl, HTTPie and the browsers. Pass
    ``encoding="latin-1"`` for a server that expects ISO-8859-1, or ``bytes`` for
    credentials that are encoded already. ``(user, password)`` as ``auth=`` is
    this class with the defaults.

    Raises:
        ClientError: The user name contains a colon (RFC 7617 sec. 2: it cannot be
            told from the end of the name), or a name or password cannot be
            encoded as ``encoding``.

    """

    def __init__(
        self, username: "str | bytes", password: "str | bytes", encoding: str = "utf-8"
    ) -> None:
        """Check the credentials and remember the encoding."""
        user = _octets(username, encoding, "user name")
        if b":" in user:
            msg = "a user name with a colon cannot be sent in Basic authentication (RFC 7617 sec. 2)"
            raise ClientError(msg)
        _octets(password, encoding, "password")
        super().__init__(username, password)
        self.encoding = encoding

    def header(self) -> str:
        """The ``Authorization`` header value."""
        raw = (
            _octets(self.username, self.encoding, "user name")
            + b":"
            + _octets(self.password, self.encoding, "password")
        )
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        """Set the ``Authorization`` header of ``r``."""
        r.headers["Authorization"] = self.header()
        return r

    def __repr__(self) -> str:
        """Without the password."""
        return f"BasicAuth({self.username!r}, '***', encoding={self.encoding!r})"


def as_basic(auth: object) -> object:
    """``auth`` as a :class:`BasicAuth` if it is a ``(user, password)`` or a plain ``HTTPBasicAuth``.

    Anything else (a token, a callable, a ``BasicAuth`` already) comes back as it is.
    """
    if (
        isinstance(auth, tuple)
        and len(auth) == 2
        and all(isinstance(part, str | bytes) for part in auth)
    ):
        return BasicAuth(auth[0], auth[1])
    # The exact class: a subclass (HTTPProxyAuth, one of the caller's own) stays as it is.
    # pylint: disable-next=unidiomatic-typecheck
    if type(auth) is requests.auth.HTTPBasicAuth:
        return BasicAuth(auth.username, auth.password)
    return auth


__all__ = ["BasicAuth", "as_basic"]
