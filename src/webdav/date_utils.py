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
            return value
    return fromisoformat(text)
