"""What a listing returns: one type, for one thing."""

import re
from typing import TYPE_CHECKING, Any, Self

if TYPE_CHECKING:
    from datetime import datetime

#: Names Windows takes for a device, with or without an extension.
_WINDOWS_DEVICES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"{device}{n}" for device in ("COM", "LPT") for n in "123456789"}
)
#: NUL, the other C0 control characters and DEL.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
#: What Windows does not allow in a file name (``:`` opens an alternate data stream).
_WINDOWS_FORBIDDEN = re.compile(r'[\x00-\x1f<>:"/\\|?*]')


def safe_local_name(name: str, *, windows: bool = False) -> str:
    """The last segment of ``name`` - a name from a server - checked for use as a *local* file name.

    A server chooses the names it lists, and a :class:`Resource` is a whole path, not a
    basename: ``os.path.join(directory, resource)`` is not a safe way to a file. This takes
    the last segment (``dir/a.txt`` gives ``a.txt``) and returns it if a file of that name
    can be created in a directory of your own, else raises :exc:`ValueError` with a message
    that shows the name escaped, never raw.

    Always refused: an empty name, ``.``, ``..``, NUL and other control characters. A
    backslash, a colon or a leading ``-`` is an ordinary character of a name on Linux and
    macOS, and not refused. The Windows rules - device names (``CON``, ``NUL``, ``COM1``,
    ...), a name that ends in a dot or a space, a backslash and ``: " < > | ? *`` - apply
    only with ``windows=True``. The fsspec ``get`` turns them on by itself on Windows, and
    refuses two names that end up as one file on a case-insensitive file system; they could
    not be tested on real Windows yet (issue #5, Windows/macOS CI). For your own code that
    creates files from server names, this helper is the check.

    Raises:
        ValueError: ``name`` is not usable as a file name.

    """
    segment = str(name).rstrip("/").rpartition("/")[2]
    if segment in ("", ".", "..") or _CONTROL.search(segment):
        msg = f"{str(name)!r} is not usable as a local file name"
        raise ValueError(msg)
    if windows and (
        _WINDOWS_FORBIDDEN.search(segment)
        or segment[-1] in ". "
        or segment.split(".", 1)[0].rstrip(" ").upper() in _WINDOWS_DEVICES
    ):
        msg = f"{str(name)!r} is not usable on Windows as a local file name"
        raise ValueError(msg)
    return segment


class Resource(str):  # noqa: SLOT000 - a str subclass cannot have a non-empty __slots__
    """A resource on the server: its name - and what the server told about it.

    The one type :meth:`webdav.FileSystem.ls` and :meth:`webdav.FileSystem.info` return,
    always the same fields, whatever the call. It *is* its name (a ``str``), so
    ``fs.ls(path)`` is a list of names as far as any code expecting names is
    concerned - and ``resource.size``, ``resource.is_dir``, ... are there when you
    want more. Two resources are equal when their names are (as any two strings).

    ``name`` is the path relative to the ``base_url`` (relative to the server
    root without one); it can be handed, unchanged, to any other method.
    """

    href: str
    """The ``href`` as the server wrote it.

    It is the server's word, and a server may write another host in it (a reverse proxy
    does, innocently; a hostile one on purpose): never hand it to a
    :class:`~webdav.session.Session` that has no ``base_url`` - the session would send its
    credentials there. :attr:`name` is the safe way to name the resource again.
    """
    is_dir: bool
    """Whether it is a collection."""
    size: "int | None"
    """``getcontentlength``, or ``None`` if the server did not say."""
    created: "datetime | None"
    """``creationdate``, or ``None``."""
    modified: "datetime | None"
    """``getlastmodified``, or ``None``."""
    etag: "str | None"
    """``getetag`` as the server reported it, or ``None``."""
    content_type: "str | None"
    """``getcontenttype``, or ``None``."""
    content_language: "str | None"
    """``getcontentlanguage``, or ``None``."""
    display_name: "str | None"
    """``displayname``, or ``None``."""
    status: "int | None"
    """The status the server gave for this resource in a listing when it was not a success
    (``403`` for a member the account may not read), else ``None``.

    The other fields are empty then, and :attr:`is_dir` is ``False`` whatever the resource is.
    """

    def __new__(
        cls,
        name: str,
        *,
        href: str,
        is_dir: bool,
        size: "int | None" = None,
        created: "datetime | None" = None,
        modified: "datetime | None" = None,
        etag: "str | None" = None,
        content_type: "str | None" = None,
        content_language: "str | None" = None,
        display_name: "str | None" = None,
        status: "int | None" = None,
    ) -> Self:
        """Create a resource named ``name``."""
        self = super().__new__(cls, name)
        self.href = href
        self.is_dir = is_dir
        self.size = size
        self.created = created
        self.modified = modified
        self.etag = etag
        self.content_type = content_type
        self.content_language = content_language
        self.display_name = display_name
        self.status = status
        return self

    @property
    def name(self) -> str:
        """The name, as a plain ``str``."""
        return str(self)

    @property
    def basename(self) -> str:
        """The last segment of the name (``dir/a.txt`` gives ``a.txt``) - what the server calls it.

        It is the server's word, not a vetted file name: :func:`safe_local_name` checks it for
        use as a local one.
        """
        return str(self).rstrip("/").rpartition("/")[2]

    def as_dict(self) -> dict[str, Any]:
        """All fields as a plain dict (``name`` first)."""
        return {
            "name": self.name,
            "href": self.href,
            "is_dir": self.is_dir,
            "size": self.size,
            "created": self.created,
            "modified": self.modified,
            "etag": self.etag,
            "content_type": self.content_type,
            "content_language": self.content_language,
            "display_name": self.display_name,
            "status": self.status,
        }

    def __getnewargs_ex__(self) -> "tuple[tuple[str], dict[str, Any]]":
        """Pickle support (a ``str`` subclass with keyword-only fields)."""
        fields = self.as_dict()
        return (fields.pop("name"),), fields

    def __repr__(self) -> str:
        """Debug representation."""
        kind = "dir" if self.is_dir else "file"
        return f"Resource({self.name!r}, {kind}, size={self.size!r})"
