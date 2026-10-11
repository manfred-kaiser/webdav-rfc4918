"""Small parsers for values a server controls, that must never raise."""

#: A non-negative integer never needs more digits than this here (a byte
#: count, a number of seconds); anything longer is refused rather than
#: handed to ``int()``, which raises above 4300 digits.
MAX_UINT_DIGITS = 18


def parse_uint(value: "str | None") -> "int | None":
    """Parse ``value`` as a small non-negative decimal integer, or return ``None``.

    Only ASCII digits count: ``str.isdigit()`` alone also accepts
    superscripts, full-width digits and the like, which ``int()`` then
    rejects (or, worse, accepts as something else).
    """
    if not value:
        return None
    text = value.strip()
    if not (text.isascii() and text.isdigit()) or len(text) > MAX_UINT_DIGITS:
        return None
    return int(text)


def parse_content_range(value: "str | None") -> "tuple[int, int, int | None] | None":
    """Parse ``bytes first-last/total`` into ``(first, last, total)``, or ``None`` if it is not one.

    ``total`` is ``None`` for ``*`` (not known). Valid is what RFC 9110
    sec. 14.4 says: ``first <= last``, and ``last < total`` where the total
    is given. Nothing is accepted that merely starts like it (a unit other
    than ``bytes``, a missing part, signs, spaces inside a number).
    """
    unit, _, rest = (value or "").strip().partition(" ")
    span, slash, total_text = rest.partition("/")
    first_text, dash, last_text = span.partition("-")
    if unit != "bytes" or not slash or not dash:
        return None
    first, last = parse_uint(first_text), parse_uint(last_text)
    total = None if total_text == "*" else parse_uint(total_text)
    if first is None or last is None or first > last:
        return None
    if total_text != "*" and (total is None or last >= total):
        return None
    if any(part != part.strip() for part in (first_text, last_text, total_text)):
        return None
    return first, last, total
