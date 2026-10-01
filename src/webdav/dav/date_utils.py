"""Date parsing for WebDAV live properties.

``getlastmodified`` is RFC 1123 (HTTP-date), ``creationdate`` is ISO 8601 - both
per RFC 4918 - but servers vary in practice, so both parsers are tried where
relevant. Dates come from the server, so they are parsed strictly: a value is
either a complete date and time that can be used (compared, converted, printed),
or ``None`` - never a lenient guess (``"2024"`` becoming a day of the current
month) and never a datetime that raises later (an offset of ``+99:99``).
"""

import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

# Real HTTP-date/ISO-8601 values are well under this. A longer string is
# either malformed or a crafted input meant to cost excessive CPU time.
MAX_DATE_STRING_LENGTH = 128

_ISO = re.compile(
    r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?)?(?:Z|[+-]\d{2}(?::?\d{2})?)?",
    re.ASCII,
)
_MONTH = re.compile(
    r"\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\b", re.IGNORECASE
)
_TIME = re.compile(r"\b\d{1,2}:\d{2}:\d{2}\b", re.ASCII)

#: The obsolete rfc850-date's own two-digit year (``DD-Mon-YY``, dashes - unlike
#: IMF-fixdate/asctime, which both always carry a four-digit year and so never
#: match this).
_RFC850_TWO_DIGIT_YEAR = re.compile(r"\b\d{2}-[A-Za-z]{3}-(\d{2})\b")


def _usable(value: datetime) -> "datetime | None":
    """``value`` if it can be converted and printed, else ``None`` (a bad offset, an overflow)."""
    try:
        value.utcoffset()
        value.astimezone(UTC)
        value.isoformat()
    except (ValueError, OverflowError):
        return None
    return value


def fromisoformat(datetime_string: str) -> "datetime | None":
    """Convert an ISO 8601 date(-time) string to a datetime, or ``None`` if it is not a usable one."""
    text = datetime_string.strip()
    if len(text) > MAX_DATE_STRING_LENGTH or not _ISO.fullmatch(text):
        return None
    try:
        return _usable(datetime.fromisoformat(text))
    except ValueError:
        return None


def _rfc850_corrected_year(text: str, value: datetime) -> "datetime | None":
    """Reinterpret ``value``'s year per RFC 9110 sec. 5.6.7, if ``text`` is an rfc850-date.

    stdlib's own two-digit-year handling uses a fixed pivot (``<70`` -> 2000s,
    else 1900s), not the RFC's "no more than 50 years in the future, relative
    to now" rule - the two agree only by coincidence, and drift further apart
    as "now" advances. IMF-fixdate and asctime both always carry a four-digit
    year, so this never touches them.
    """
    match = _RFC850_TWO_DIGIT_YEAR.search(text)
    if match is None:
        return value
    now = datetime.now(UTC)
    corrected = (now.year // 100) * 100 + int(match.group(1))
    if corrected > now.year + 50:
        corrected -= 100
    if corrected == value.year:
        return value
    try:
        return value.replace(year=corrected)
    except ValueError:
        return None


def from_rfc1123(datetime_string: str) -> "datetime | None":
    """Convert an HTTP-date (RFC 1123, and the obsolete RFC 850/asctime forms) to a datetime.

    Falls back to ISO 8601. ``None`` if the string is neither, or not a usable date.
    """
    text = datetime_string.strip()
    if len(text) > MAX_DATE_STRING_LENGTH:
        return None
    if _MONTH.search(text) and _TIME.search(text):
        try:
            value = _usable(parsedate_to_datetime(text))
        except (TypeError, ValueError, IndexError, OverflowError):
            value = None
        if value is not None:
            value = _rfc850_corrected_year(text, value)
        if value is not None:
            value = _usable(value)
        if value is not None:
            return value
    return fromisoformat(text)
