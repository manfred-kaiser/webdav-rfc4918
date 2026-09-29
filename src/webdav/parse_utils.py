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
