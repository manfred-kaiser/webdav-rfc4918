"""The limits a session puts on what a request and its answer may cost - and the checks for them.

Every limit is checked where it is set, so a value that cannot work
(``0``, a negative number, a string, ``True``) fails at the assignment with a
``ValueError`` that names it, not later in the middle of a response.
``None`` means "no limit" where a limit may be lifted, and has to be asked for.
"""

import math

#: Default chunk size, in bytes, for streaming reads and writes.
DEFAULT_CHUNK_SIZE = 2**22


def _is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _is_positive_seconds(value: object) -> bool:
    return _is_number(value) and math.isfinite(value) and value > 0  # type: ignore[operator,arg-type]


def check_flag(name: str, value: object) -> bool:
    """Return ``value`` if it is exactly ``True`` or ``False``.

    ``0``, ``""`` or ``"no"`` would be read as a flag by ``requests`` (and
    ``"false"`` as true); for an option that decides whether a redirect is
    followed or an error raised, a value that is not one is a mistake.

    Raises:
        TypeError: It is not a ``bool``.

    """
    if not isinstance(value, bool):
        msg = f"{name} must be True or False, got {value!r}"
        raise TypeError(msg)
    return value


def check_chunk_size(value: int) -> int:
    """Return ``value`` if it is a usable chunk size.

    Raises:
        ValueError: It is not a positive integer.

    """
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        msg = f"chunk_size must be a positive integer, got {value!r}"
        raise ValueError(msg)
    return value


def check_max_size(value: "int | None") -> "int | None":
    """Return ``value`` if it is a usable size limit.

    Raises:
        ValueError: It is neither ``None`` (no limit) nor a positive integer.

    """
    if value is not None and (
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
    ):
        msg = f"max_response_size must be a positive integer or None, got {value!r}"
        raise ValueError(msg)
    return value


def check_max_time(seconds: "float | None") -> "float | None":
    """Return ``seconds`` if it is a usable time limit.

    Raises:
        ValueError: It is neither ``None`` (no limit) nor a positive, finite
            number of seconds.

    """
    if seconds is not None and not _is_positive_seconds(seconds):
        msg = f"max_response_time must be a positive number of seconds or None, got {seconds!r}"
        raise ValueError(msg)
    return seconds


def check_timeout(
    value: "float | tuple[float | None, float | None] | None",
) -> "float | tuple[float | None, float | None] | None":
    """Return ``value`` if ``requests`` can use it as a ``timeout``.

    Raises:
        ValueError: It is not ``None`` (``requests``' own "wait forever"), a
            positive, finite number of seconds, or a ``(connect, read)`` pair
            of those.

    """
    parts = value if isinstance(value, tuple) else (value,)
    valid = (len(parts) == 2 or not isinstance(value, tuple)) and all(
        part is None or _is_positive_seconds(part) for part in parts
    )
    if not valid:
        msg = (
            "timeout must be None, a positive number of seconds or a "
            f"(connect, read) pair of those, got {value!r}"
        )
        raise ValueError(msg)
    return value


def check_max_redirects(value: int) -> int:
    """Return ``value`` if it is a usable limit on redirects in a row.

    Raises:
        ValueError: It is not an integer of at least 0.

    """
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        msg = f"max_redirects must be an integer of at least 0, got {value!r}"
        raise ValueError(msg)
    return value


def check_pool_size(name: str, value: int) -> int:
    """Return ``value`` if it is a usable connection-pool size.

    Raises:
        ValueError: It is not a positive integer.

    """
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        msg = f"{name} must be a positive integer, got {value!r}"
        raise ValueError(msg)
    return value


__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "check_chunk_size",
    "check_flag",
    "check_max_redirects",
    "check_max_size",
    "check_max_time",
    "check_pool_size",
    "check_timeout",
]
