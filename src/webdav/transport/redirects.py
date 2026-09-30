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

import logging
from dataclasses import dataclass
from enum import Enum
from http import HTTPStatus
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from webdav.methods import Method
from webdav.response import Response
from webdav.url_safety import effective_origin, redact_url

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

    import requests

_LOGGER = logging.getLogger("webdav")

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


def check_redirect_policy(policy: RedirectPolicy, *, trusted: bool) -> RedirectPolicy:
    """Return ``policy`` if a session with (or without) trusted origins can use it.

    Raises:
        TypeError: ``policy`` is not a :class:`RedirectPolicy` - a string
            such as ``"all"`` would match none of the tiers and be treated as
            the strictest one without a word.
        ValueError: ``WHITELIST`` without trusted origins.

    """
    if not isinstance(policy, RedirectPolicy):
        msg = f"redirect_policy must be a RedirectPolicy, got {policy!r}"
        raise TypeError(msg)
    if policy == RedirectPolicy.WHITELIST and not trusted:
        msg = (
            "redirect_policy=RedirectPolicy.WHITELIST requires "
            "trusted_redirect_origins to be set"
        )
        raise ValueError(msg)
    return policy


def validate_policy(
    policy: RedirectPolicy,
    trusted_redirect_origins: "Iterable[str] | Callable[[str], bool] | None",
) -> None:
    """Reject an inconsistent ``policy`` / ``trusted_redirect_origins`` pair.

    Raises:
        TypeError: ``policy`` is not a :class:`RedirectPolicy`.
        ValueError: ``WHITELIST`` without trusted origins, or trusted
            origins under any other policy - almost certainly a mistake,
            and silently doing nothing would be the unsafe way to fail.

    """
    check_redirect_policy(policy, trusted=trusted_redirect_origins is not None)
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
    already-partially-read file object, :class:`~webdav.fs.streams.SizedIterator`,
    ``files=``, ...) may already have been exhausted by a first attempt -
    resending it would silently send a truncated/empty body instead of
    raising, which is worse than not following at all.
    """
    data = kwargs.get("data")
    return kwargs.get("files") is None and (
        data is None or isinstance(data, str | bytes)
    )


@dataclass(frozen=True, slots=True)
class Follow:
    """A redirect that may be followed."""

    #: The absolute URL it leads to.
    target: str
    #: Whether it stays on the origin the request started at. If not, nothing
    #: that belongs to this session may go along (see :func:`cross_origin_headers`).
    same_origin: bool


@dataclass(frozen=True, slots=True)
class Refuse:
    """A redirect that may not be followed, and why."""

    reason: str


#: What the decision about one redirect is. Two distinct types rather than a
#: flag or a string that means "no": a caller has to look at which one it got.
Decision = Follow | Refuse


def may_follow(
    source: str,
    target: str,
    policy: RedirectPolicy,
    *,
    is_trusted: "Callable[[str], bool]",
) -> Decision:
    """Whether ``policy`` lets a request for ``source`` be redirected to ``target``.

    Args:
        source: The URL the request started at.
        target: Where the redirect leads.
        policy: What the session allows.
        is_trusted: Whether a target on another origin is one the session
            trusts (see :func:`build_trust_check`); asked under ``WHITELIST`` only.

    """
    source_origin = effective_origin(source)
    target_origin = effective_origin(target)
    if source_origin is None or target_origin is None:
        return Refuse("the target is not one unambiguous http(s) URL")
    if source_origin == target_origin:
        return Follow(target, same_origin=True)
    # Never step down from https to http on the strength of a policy
    # alone - not even a whitelisted target, not even ALL: trusting a
    # target with credentials is a different question from accepting
    # that the same bytes cross the network in clear text, and there is
    # no legitimate reason to want the latter. No browser allows it either.
    if source_origin[0] == "https" and target_origin[0] == "http":
        return Refuse("the redirect would downgrade https to http")
    if policy == RedirectPolicy.ALL or (
        policy == RedirectPolicy.WHITELIST and is_trusted(target)
    ):
        return Follow(target, same_origin=False)
    return Refuse(
        "the target is on another origin and redirect_policy does not allow that"
    )


def hop_target(
    response: "requests.Response",
    method: str,
    *,
    get_location: "Callable[[requests.Response], str | None]",
) -> "str | Refuse":
    """The absolute URL ``response`` redirects to - or why that is unusable.

    Args:
        response: A 3xx response.
        method: The method of the request it answers.
        get_location: Reads the ``Location`` header (decoded) off a response.

    """
    # RFC 9110 sec. 15.4.4: 303 means "retrieve the result with GET".
    # Re-sending a write (or a PROPFIND) to it would be wrong, and
    # silently turning it into a GET would report a write as done.
    if response.status_code == HTTPStatus.SEE_OTHER and method not in (
        Method.GET,
        Method.HEAD,
    ):
        return Refuse("a 303 is only followed for GET/HEAD (RFC 9110 sec. 15.4.4)")
    try:
        location = get_location(response)
        target = urljoin(response.url, location) if location else ""
    except (UnicodeError, ValueError):
        return Refuse("the Location header is malformed")
    return target or Refuse("the redirect has no Location")


def plan_hop(
    response: "requests.Response",
    method: str,
    policy: RedirectPolicy,
    *,
    body_replayable: bool,
    seen: "set[str]",
    origin_url: "str | None" = None,
    is_trusted: "Callable[[str], bool]",
    get_location: "Callable[[requests.Response], str | None]",
) -> Decision:
    """Decide whether ``response``'s redirect may be followed.

    Args:
        response: A 3xx response.
        method: The method of the request it answers.
        policy: What the session allows.
        body_replayable: The request body can be sent a second time
            (see :func:`has_replayable_body`).
        seen: URLs this request has already been at; one of them again is a loop.
        origin_url: Where the request *started* (every hop is judged against
            that, not against the page that redirected); ``response.url`` if not given.
        is_trusted: See :func:`may_follow`.
        get_location: See :func:`hop_target`.

    """
    target = hop_target(response, method, get_location=get_location)
    if isinstance(target, Refuse):
        return target
    if target in seen:
        return Refuse("the redirect leads back to a URL already visited (a loop)")
    if not body_replayable:
        return Refuse("the request body cannot be sent a second time")
    return may_follow(origin_url or response.url, target, policy, is_trusted=is_trusted)


def refuse(response: "requests.Response", reason: str) -> None:
    """Record (and log) why a redirect was not followed."""
    if isinstance(response, Response):
        response.redirect_refusal = reason
    _LOGGER.warning(
        "not following the %s redirect from %s to %s: %s",
        response.status_code,
        redact_url(response.url),
        redact_url(response.headers.get("Location", "")),
        reason,
    )


#: Headers that are credentials or capabilities of *this* server and so
#: must never be forwarded to another origin a redirect lands on: login
#: credentials, session cookies, a lock token (``If``/``Lock-Token``, a
#: bearer capability for one resource), and ``Destination`` (which names
#: a resource on the *original* server).
NEVER_FORWARD = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "if",
        "lock-token",
        "destination",
    }
)

#: The only per-call headers a cross-origin redirect keeps: the ones that
#: describe the representation being sent or the conditions of the request.
#: Everything else - a custom ``X-Api-Key``, a bearer token in a header the
#: library cannot recognise as one - is dropped, because a whitelisted
#: origin is trusted with the *body*, not with whatever else the caller
#: attached. Extend with ``Session.redirect_forward_headers``.
FORWARD_HEADERS = frozenset(
    {
        "content-type",
        "content-encoding",
        "content-language",
        "content-md5",
        "accept",
        "accept-language",
        "range",
        "if-match",
        "if-none-match",
        "if-modified-since",
        "if-unmodified-since",
    }
)


def cross_origin_headers(
    headers: "Mapping[str, str] | None", extra_allowed: "Iterable[str]" = ()
) -> dict[str, str]:
    """The per-call ``headers`` a request to *another* origin may carry.

    Only those in :data:`FORWARD_HEADERS` and ``extra_allowed`` (names in any
    case) - and never one in :data:`NEVER_FORWARD`, which wins over
    ``extra_allowed``: naming ``authorization`` there does not send it.
    """
    allowed = (FORWARD_HEADERS | {n.lower() for n in extra_allowed}) - NEVER_FORWARD
    return {
        name: value
        for name, value in (headers or {}).items()
        if name.lower() in allowed
    }
