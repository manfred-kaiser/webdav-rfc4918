"""Module-level API: ``webdav.get(url)``, ``webdav.propfind(url)``, ...

Same idea as :mod:`requests.api`: each function opens a
:class:`~webdav.session.Session`, does one thing and closes it again.
For more than one call against the same server use a
:class:`~webdav.session.Session` instead - it keeps the connection open,
and its methods have the same names, arguments and return values as these
functions (a test compares the signatures).

Every function takes a full ``http(s)`` URL first, and returns a
:class:`webdav.response.Response`; like ``requests``, none of them raise for
an error status unless asked to (``raise_for_status()``, or
``raise_on_error=True``). Besides the keyword arguments
:meth:`requests.Session.request` takes (``auth=``, ``headers=``, ``timeout=``,
``verify=``, ``cert=``, ``stream=``, ...), each also takes the session
options ``redirect_policy=``, ``trusted_redirect_origins=``,
``max_response_size=``, ``retry=``, ``chunk_size=`` and ``raise_on_error=``.

For filesystem-shaped one-off calls (``webdav.ls(url)``, ``webdav.mkdir(url)``,
...) see :mod:`webdav.fs`.
"""

import inspect
from typing import (
    TYPE_CHECKING,
    Any,
    Concatenate,
    ParamSpec,
)

from webdav.response import Response
from webdav.session import Session

if TYPE_CHECKING:
    from collections.abc import Callable

_P = ParamSpec("_P")


#: Options that configure the session itself. ``auth``/``headers``/
#: ``timeout``/``verify``/``cert`` are deliberately *not* here for the
#: verbs: ``requests`` takes them per call, and a per-call header - unlike
#: a session one - is what a redirect to a trusted origin keeps.
_SESSION_OPTIONS = (
    "redirect_policy",
    "trusted_redirect_origins",
    "max_response_size",
    "retry",
    "chunk_size",
    "raise_on_error",
    "tls",
    "max_response_time",
)


def _new_session(session_options: "dict[str, Any]") -> Session:
    """A session from the (already split off) session options.

    ``max_response_time`` is an attribute of the session, not a constructor
    argument, so it is set after construction.
    """
    max_response_time = session_options.pop("max_response_time", None)
    session = Session(**session_options)
    if max_response_time is not None:
        session.max_response_time = max_response_time
    return session


def _verb(
    method: "Callable[Concatenate[Session, _P], Response]",
) -> "Callable[_P, Response]":
    name = method.__name__

    def caller(*args: _P.args, **kwargs: _P.kwargs) -> Response:
        session_options = {k: kwargs.pop(k) for k in _SESSION_OPTIONS if k in kwargs}
        with _new_session(session_options) as session:
            response: Response = getattr(session, name)(*args, **kwargs)
            return response

    signature = inspect.signature(method)
    caller.__signature__ = signature.replace(  # type: ignore[attr-defined]
        parameters=list(signature.parameters.values())[1:]
    )
    caller.__name__ = name
    caller.__qualname__ = name
    what = "a request" if name == "request" else f"a ``{name.upper()}`` request"
    caller.__doc__ = (
        f"Send {what}; see :meth:`webdav.session.Session.{name}`.\n\n"
        "Returns a :class:`webdav.response.Response`."
    )
    return caller


request = _verb(Session.request)
get = _verb(Session.get)
head = _verb(Session.head)
options = _verb(Session.options)
put = _verb(Session.put)
delete = _verb(Session.delete)
propfind = _verb(Session.propfind)
proppatch = _verb(Session.proppatch)
mkcol = _verb(Session.mkcol)
lock = _verb(Session.lock)
unlock = _verb(Session.unlock)
# No verb-shaped module-level one-off for `copy`/`move`: `webdav.copy`/
# `webdav.move` are defined by webdav.fs instead (raising, filesystem-shaped -
# what a one-off, no-session-management call should mean). Session.copy/
# .move (the verbs, raw Response) are still there as Session methods.
