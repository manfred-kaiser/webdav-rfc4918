"""The server a ``webdav(s)://host[:port]/path`` URL of the fsspec filesystem names.

fsspec lets a URL carry what a filesystem is made with (``sftp://user@host:22/path``): a
backend takes it out in ``_get_kwargs_from_urls`` and leaves the path in ``_strip_protocol``.
"""

from urllib.parse import urlsplit

from webdav.url_safety import redact_url

#: The two schemes the fsspec filesystem accepts, and the transport each implies
#: when a URL names a host without a ``base_url`` - same convention as the CLI's
#: own ``_SCHEME_MAPPING`` (``webdav``/``dav`` are plain HTTP, ``webdavs``/``davs``
#: are TLS, like ``ftp``/``ftps``).
_TRANSPORTS = {"webdav": "http", "webdavs": "https"}

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _scheme_and_rest(path: str) -> "tuple[str, str] | None":
    """The matching scheme and what follows ``scheme://`` in ``path``, or ``None``."""
    for scheme in _TRANSPORTS:
        prefix = f"{scheme}://"
        if path.startswith(prefix):
            return scheme, path[len(prefix) :]
    return None


def authority_of(path: str) -> "tuple[str, str]":
    """``(authority, path)`` of a ``webdav(s)://host[:port]/path`` URL; ``("", path)`` otherwise.

    Only what follows ``webdav://``/``webdavs://`` is an authority: ``//a/b`` and ``a/b`` are paths.
    """
    found = _scheme_and_rest(path)
    if found is None:
        return "", path
    _, rest = found
    authority, slash, tail = rest.partition("/")
    return authority, slash + tail


def transport_of(path: str) -> "str | None":
    """The transport (``"http"``/``"https"``) a ``webdav(s)://...`` URL implies, or ``None``.

    ``None`` means ``path`` does not start with either scheme - not that there is no host.
    """
    found = _scheme_and_rest(path)
    return _TRANSPORTS[found[0]] if found else None


_SCHEMES_BY_TRANSPORT = {transport: scheme for scheme, transport in _TRANSPORTS.items()}


def scheme_for(transport: str) -> str:
    """``"webdav"``/``"webdavs"`` for ``"http"``/``"https"`` - the reverse of :func:`transport_of`."""
    return _SCHEMES_BY_TRANSPORT[transport]


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
    base_url: "str | None",
    host: "str | None",
    port: "int | None",
    transport: str = "https",
) -> "str | None":
    """The ``base_url`` for what a URL named: the ``host`` and ``port`` of ``webdav(s)://host:port/path``.

    Without a ``base_url`` the server is ``{transport}://host:port`` - ``https`` for a
    ``webdavs://`` URL, ``http`` for a ``webdav://`` one (see ``_get_kwargs_from_urls``,
    which works out ``transport`` from the URL actually given). With a ``base_url``, it
    stays - the URL may only name the same server, never redirect to another.

    Raises:
        ValueError: ``base_url`` is another server than the one the URL names.

    """
    if host is None:
        return base_url
    if base_url is None:
        name = f"[{host}]" if ":" in host else host
        return f"{transport}://{name}" + (f":{port}" if port else "")
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
