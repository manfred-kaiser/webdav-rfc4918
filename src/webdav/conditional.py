"""``If`` header construction (RFC 4918 §10.4).

Used to make a write conditional on holding a lock token and/or an
``ETag`` still matching - the mechanism a server uses to distinguish a
locked resource's own lock holder from anyone else, and the WebDAV-level
alternative to bare HTTP conditional headers (``If-Match``) for a locked
resource.

Only the subset of the full ``If`` grammar a client actually needs to
*produce* is implemented: building conditions (state-tokens/entity-tags,
optionally negated), grouped into one or more alternative ``List``s, and
optionally scoped to a specific resource (``Tagged-list``, needed when a
request such as COPY/MOVE touches more than one resource and each needs
its own token). Parsing an ``If`` header sent by someone else is out of
scope for a client library.
"""

import re
from dataclasses import dataclass

#: What may sit between ``<`` and ``>``: the URI characters, nothing that closes the bracket.
_SAFE_TOKEN = re.compile(r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{1,1024}")

#: RFC 9110 ``etagc``: printable ASCII except the double quote (and, for
#: safety inside an If header, the closing bracket).
_ETAGC = re.compile(r"[\x21\x23-\x5C\x5E-\x7E]*")


def entity_tag(value: str) -> str:
    """``value`` as a quoted entity-tag (``"abc"`` / ``W/"abc"``); bare values get quoted."""
    weak = "W/" if value.startswith("W/") else ""
    core = value.removeprefix("W/")
    inner = core[1:-1] if len(core) >= 2 and core[0] == core[-1] == '"' else core
    if not _ETAGC.fullmatch(inner):
        msg = f"not a valid entity-tag: {value[:60]!r}"
        raise ValueError(msg)
    return f'{weak}"{inner}"'


@dataclass(frozen=True)
class Condition:
    """One ``Condition`` production: an (optionally negated) state-token OR entity-tag.

    Per the grammar (Appendix C), ``Condition = ["Not"] (State-token |
    ["[" entity-tag "]"])`` is one or the other, never both - a single
    ``Not`` can only scope to one of them. To require *both* a token and
    an etag to match (each optionally negated independently), put two
    ``Condition``s in the same :data:`ConditionList` instead - a ``List``
    already ANDs every ``Condition`` it holds.
    """

    token: str | None = None
    etag: str | None = None
    negate: bool = False

    def __post_init__(self) -> None:
        """Validate that exactly one of ``token``/``etag`` was given."""
        if not self.token and not self.etag:
            msg = "a Condition needs a token or an etag"
            raise ValueError(msg)
        if self.token and self.etag:
            msg = (
                "a Condition is one State-token or one entity-tag, never both "
                "(RFC 4918 Appendix C) - use two Conditions in the same "
                "ConditionList to AND a token and an etag"
            )
            raise ValueError(msg)

    def render(self) -> str:
        """Render as e.g. ``<lock-token>``, ``["etag"]``, or ``Not <lock-token>``.

        An ``etag`` may be given the way a server reports it - with its
        quotes, and ``W/`` if weak (``"abc"``, ``W/"abc"``) - or bare
        (``abc``); either way it is written as the entity-tag of RFC 4918
        Appendix C (``opaque-tag = DQUOTE *etagc DQUOTE``), never quoted twice.

        Raises:
            ValueError: A token or ETag holds a character that would end the
                bracket it is written in.

        """
        if self.token:
            if not _SAFE_TOKEN.fullmatch(self.token):
                msg = f"not a valid Coded-URL for an If header: {self.token[:60]!r}"
                raise ValueError(msg)
            body = f"<{self.token}>"
        else:
            body = f"[{entity_tag(self.etag or '')}]"
        return f"Not {body}" if self.negate else body


ConditionList = list[Condition]


def _render_list(conditions: ConditionList) -> str:
    return "(" + " ".join(c.render() for c in conditions) + ")"


def build_if_header(lists: list[ConditionList], *, resource: str | None = None) -> str:
    """Build an ``If`` header value.

    Args:
        lists: One or more alternative ``List``s, each a list of
            :class:`Condition` - the server accepts the request if *any*
            one of them matches. Wrap a single list in an outer list for
            the common one-``List`` case, e.g. ``[[Condition(...)]]``.
        resource: If given, produces a ``Tagged-list`` scoped to this
            resource URL. Omitted (the common case), produces a
            ``No-tag-list``, which applies to every resource the request
            touches.

    """
    if resource is not None:
        # Tagged-list = Resource-Tag 1*List - the ABNF has no explicit
        # separator token between repeated Lists here, and RFC 4918's own
        # §10.4 examples concatenate them directly.
        rendered = "".join(_render_list(cond_list) for cond_list in lists)
        return f"<{resource}> {rendered}"
    # No-tag-list = List 1*(" " List) - a space is required between each
    # alternative List (unlike the Tagged-list case above).
    return " ".join(_render_list(cond_list) for cond_list in lists)


def build_if_header_single(
    conditions: ConditionList, *, resource: str | None = None
) -> str:
    """Shorthand for :func:`build_if_header` with exactly one ``List``."""
    return build_if_header([conditions], resource=resource)


def merge_if_headers(*headers: str) -> str:
    """Concatenate multiple ``If`` header values (e.g. several tagged-lists)."""
    return " ".join(h for h in headers if h)


def token_condition(token: str) -> str:
    """Shorthand: an ``If`` header asserting a single lock token, untagged."""
    return build_if_header_single([Condition(token=token)])
