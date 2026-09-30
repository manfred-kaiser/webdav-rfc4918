"""HTTP/WebDAV method name constants, and the groups of methods the library treats alike."""

from enum import StrEnum


class Method(StrEnum):
    """HTTP/WebDAV method name constants, to avoid typos in call sites."""

    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    PROPFIND = "PROPFIND"
    PROPPATCH = "PROPPATCH"
    MKCOL = "MKCOL"
    COPY = "COPY"
    MOVE = "MOVE"
    LOCK = "LOCK"
    UNLOCK = "UNLOCK"


#: Methods that change something: only these carry the ``If`` header of a held
#: lock. A read has no use for a lock token, and sending one anyway would
#: only put a capability on the wire for nothing.
WRITE_METHODS = frozenset(
    {
        Method.PUT,
        Method.DELETE,
        Method.PROPPATCH,
        Method.MKCOL,
        Method.COPY,
        Method.MOVE,
        Method.POST,
        Method.PATCH,
    }
)

#: Methods whose request body is an XML document (RFC 4918).
XML_BODY_METHODS = frozenset(
    {Method.PROPFIND, Method.PROPPATCH, Method.MKCOL, Method.LOCK}
)

#: Methods a transient failure (429, 5xx, a dropped connection) is retried
#: for: the *safe* ones (RFC 9110 sec. 9.2.1) - ``PROPFIND`` is a read. Never a
#: write: when the connection drops after the server acted, the retry finds
#: the work already done and reports the opposite of what happened (MKCOL
#: "exists", DELETE "not found", COPY "precondition failed"), and a lost
#: LOCK reply would leave an orphaned lock. Whoever knows a particular
#: write is safe to repeat can repeat it.
RETRYABLE_METHODS = frozenset(
    {Method.GET, Method.HEAD, Method.OPTIONS, Method.PROPFIND}
)
