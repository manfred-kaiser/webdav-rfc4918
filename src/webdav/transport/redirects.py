"""Redirect policy: which redirects a session may follow.

HTTP permits a server to answer *any* method with a redirect (RFC 9110
sec. 15.4); nothing requires a client to *follow* one, and blindly doing
so is unsafe for a general-purpose client - a malicious or compromised
server could otherwise redirect a write to a different resource, or
(307/308) to a completely different host while fully replaying the
request body, with no error raised to the caller.

Everything here is about deciding *whether* a redirect target may be
followed (the URL checks behind it are in :mod:`webdav.url_safety`);
:class:`webdav.session.Session` does the following itself.
"""

from enum import Enum
from typing import TYPE_CHECKING

from webdav.url_safety import effective_origin

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

#: How many redirects a single request will follow automatically before
#: giving up - guards against a redirect loop between trusted origins.
MAX_REDIRECTS = 5

#: How much of a redirect's own body is kept for ``response.history``.
MAX_REDIRECT_BODY = 1024 * 1024


class RedirectPolicy(Enum):
    """How a :class:`~webdav.session.Session` decides whether to follow a 3xx redirect.

    Four explicit, named tiers, deliberately mirroring the browser
    ``fetch()`` ``redirect``/``credentials`` options for a familiar mental
    model - there is no implicit "trust everything" default; :data:`ALL`
    exists, but has to be chosen on purpose:

    - :data:`NEVER`: never follow any redirect - ``fetch``'s
      ``redirect: "error"``. The strictest tier, for a caller that wants
      zero surprises about where a request ends up.
    - :data:`SAME_ORIGIN` (the default): follow a same-origin redirect
      automatically, refuse (``RedirectNotFollowedError``) anything else
      - safe by construction, since a same-origin redirect can't move a
      request or its body outside the server the caller already chose
      to trust. An origin is scheme + host + port (RFC 6454), so an
      ``http`` -> ``https`` upgrade on the same host is a *different*
      origin and is refused too: the request that produced it already
      sent its credentials in clear text, and following the redirect
      would only hide that from the caller. Use an ``https`` URL.
    - :data:`WHITELIST`: additionally follow a redirect to an origin
      ``trusted_redirect_origins`` names - e.g. a signed-upload gateway
      on a separate origin. Requires ``trusted_redirect_origins`` to
      actually be set; using ``WHITELIST`` without it (or setting
      ``trusted_redirect_origins`` under a different policy) is rejected
      at construction as a likely mistake rather than silently doing
      nothing.
    - :data:`ALL`: follow a redirect to any origin at all - except an
      ``https`` -> ``http`` downgrade, which is never followed. The
      unrestricted tier - only ever appropriate when the caller has
      independently decided every redirect this server could possibly
      issue is fine to follow.

    Regardless of tier, credentials, cookies and lock tokens are never
    forwarded to a *different* origin a redirect lands on - nor is any
    header the session sets by default, since a custom API-key header
    can't be told apart from an unrelated one.
    """

    NEVER = "never"
    SAME_ORIGIN = "same-origin"
    WHITELIST = "whitelist"
    ALL = "all"


def validate_policy(
    policy: RedirectPolicy,
    trusted_redirect_origins: "Iterable[str] | Callable[[str], bool] | None",
) -> None:
    """Reject an inconsistent ``policy`` / ``trusted_redirect_origins`` pair.

    Raises:
        ValueError: ``WHITELIST`` without trusted origins, or trusted
            origins under any other policy - almost certainly a mistake,
            and silently doing nothing would be the unsafe way to fail.

    """
    if policy == RedirectPolicy.WHITELIST and trusted_redirect_origins is None:
        msg = (
            "redirect_policy=RedirectPolicy.WHITELIST requires "
            "trusted_redirect_origins to be set"
        )
        raise ValueError(msg)
    if policy != RedirectPolicy.WHITELIST and trusted_redirect_origins is not None:
        msg = (
            "trusted_redirect_origins has no effect without "
            "redirect_policy=RedirectPolicy.WHITELIST"
        )
        raise ValueError(msg)


def build_trust_check(
    trusted_redirect_origins: "Iterable[str] | Callable[[str], bool] | None",
) -> "Callable[[str], bool]":
    """Build the predicate deciding whether a cross-origin target is trusted.

    Accepts either shape ``trusted_redirect_origins`` documents: a
    caller-supplied predicate is used as-is; an iterable of origin strings
    is turned into one exact-origin-membership check.
    """
    if trusted_redirect_origins is None:
        return lambda _url: False
    if callable(trusted_redirect_origins):
        return trusted_redirect_origins
    trusted = frozenset(o for o in map(effective_origin, trusted_redirect_origins) if o)
    return lambda url: effective_origin(url) in trusted


def has_replayable_body(kwargs: "dict[str, object]") -> bool:
    """Whether a request's payload is safe to send a second time.

    ``None``/``str``/``bytes`` (and a ``json=`` value) are - a lack of a
    body is trivially replayable, and a string/bytes body is read fresh
    from memory every time. Anything else (a generator, an
    already-partially-read file object, :class:`~webdav.transport.streaming.SizedIterator`,
    ``files=``, ...) may already have been exhausted by a first attempt -
    resending it would silently send a truncated/empty body instead of
    raising, which is worse than not following at all.
    """
    data = kwargs.get("data")
    return kwargs.get("files") is None and (
        data is None or isinstance(data, str | bytes)
    )
