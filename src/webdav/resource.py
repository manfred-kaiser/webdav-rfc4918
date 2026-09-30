"""What a listing returns: one type, for one thing."""

from typing import TYPE_CHECKING, Any, Self

if TYPE_CHECKING:
    from datetime import datetime


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
    """The ``href`` as the server wrote it."""
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
        return self

    @property
    def name(self) -> str:
        """The name, as a plain ``str``."""
        return str(self)

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
        }

    def __getnewargs_ex__(self) -> "tuple[tuple[str], dict[str, Any]]":
        """Pickle support (a ``str`` subclass with keyword-only fields)."""
        fields = self.as_dict()
        return (fields.pop("name"),), fields

    def __repr__(self) -> str:
        """Debug representation."""
        kind = "dir" if self.is_dir else "file"
        return f"Resource({self.name!r}, {kind}, size={self.size!r})"
