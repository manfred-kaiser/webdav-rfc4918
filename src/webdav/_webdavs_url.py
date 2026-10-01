"""The server a ``webdavs://host[:port]/path`` URL of the fsspec filesystem names.

fsspec lets a URL carry what a filesystem is made with (``sftp://user@host:22/path``): a
backend takes it out in ``_get_kwargs_from_urls`` and leaves the path in ``_strip_protocol``.
"""

from urllib.parse import urlsplit

from webdav.url_safety import redact_url

#: What a URL of the filesystem starts with. Only what follows it can name a server.
SCHEME = "webdavs://"

_DEFAULT_PORTS = {"http": 80, "https": 443}


def authority_of(path: str) -> "tuple[str, str]":
    """``(authority, path)`` of a ``webdavs://host[:port]/path`` URL; ``("", path)`` of anything else.

    Only what follows ``webdavs://`` is an authority: ``//a/b`` and ``a/b`` are paths.
    """
    if not path.startswith(SCHEME):
        return "", path
    authority, slash, rest = path[len(SCHEME) :].partition("/")
    return authority, slash + rest


def host_and_port(authority: str) -> "tuple[str, int | None]":
    """The host (without the brackets of an IPv6 address) and the port of ``host[:port]``.

    Raises:
        ValueError: There are credentials in it, or the port is not a number.

    """
    if "@" in authority:
        msg = (
            "a webdavs:// URL does not carry credentials (they would end up in logs "
            "and reprs): pass auth="
        )
        raise ValueError(msg)
    if authority.startswith("["):
        host, _, tail = authority[1:].partition("]")
        port = tail.removeprefix(":")
    else:
        host, _, port = authority.partition(":")
    if port and not port.isdigit():
        msg = f"{authority!r} is not a host[:port]"
        raise ValueError(msg)
    return host, int(port) if port else None


def server_url(
    base_url: "str | None", host: "str | None", port: "int | None"
) -> "str | None":
    """The ``base_url`` for what a URL named: the ``host`` and ``port`` of ``webdavs://host:port/path``.

    ``webdavs`` is WebDAV over TLS: without a ``base_url`` the server is ``https://host:port``
    (a plain-http one is reached through its ``base_url``). With one, it stays - the URL may
    only name the same server, never redirect to another.

    Raises:
        ValueError: ``base_url`` is another server than the one the URL names.

    """
    if host is None:
        return base_url
    if base_url is None:
        name = f"[{host}]" if ":" in host else host
        return f"https://{name}" + (f":{port}" if port else "")
    given = urlsplit(base_url)
    if (given.hostname or "").lower() != host.lower() or (
        port is not None and port != (given.port or _DEFAULT_PORTS.get(given.scheme))
    ):
        msg = (
            f"the URL names {host}{f':{port}' if port else ''}, "
            f"but base_url is {redact_url(base_url)}: a filesystem is bound to one server"
        )
        raise ValueError(msg)
    return base_url
