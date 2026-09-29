"""Date parsing utilities for WebDAV live properties.

``getlastmodified`` is RFC 1123 (HTTP-date), ``creationdate`` is
ISO 8601 - both per RFC 4918 - but servers vary in practice, so both
parsers are tried where relevant.
"""

from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING

from dateutil.parser import parse

if TYPE_CHECKING:
    from datetime import datetime

# Real HTTP-date/ISO-8601 values are well under this. A longer string is
# either malformed or a crafted input meant to cost excessive CPU time in
# the underlying parser before it eventually gives up on it.
MAX_DATE_STRING_LENGTH = 128


def fromisoformat(datetime_string: str) -> "datetime | None":
    """Convert ISO 8601 datetime string to datetime object.

    Returns None instead of raising if the string is unparseable or
    implausibly long - a single malformed date from a server should not
    be fatal to whatever is listing/parsing multiple resources at once.
    """
    if len(datetime_string) > MAX_DATE_STRING_LENGTH:
        return None
    try:
        return parse(datetime_string)
    except Exception:  # noqa: BLE001  # pylint: disable=broad-exception-caught
        return None


def from_rfc1123(datetime_string: str) -> "datetime | None":
    """Convert RFC 1123 datetime string to datetime object.

    Returns None instead of raising if the string is unparseable or
    implausibly long - a single malformed date from a server should not
    be fatal to whatever is listing/parsing multiple resources at once.
    """
    if len(datetime_string) > MAX_DATE_STRING_LENGTH:
        return None
    try:
        return parsedate_to_datetime(datetime_string)
    except Exception:  # noqa: BLE001  # pylint: disable=broad-exception-caught
        # fallback in case the above is unable to parse the datetime string
        return fromisoformat(datetime_string)
