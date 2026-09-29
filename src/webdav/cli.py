"""A small ``aws s3``-style CLI for WebDAV servers.

Every command takes one or more WebDAV URLs
(``webdav://host/path``/``webdavs://host/path``, or plain ``http(s)://``) -
the scheme's host/port is the server, everything after it is the
resource path. Authentication is ``user:pass@host`` in the URL,
``--user``/``--password``, or the ``WEBDAV_USER``/``WEBDAV_PASSWORD``
environment variables, in that order of precedence. mTLS (client
certificates) is available via ``--cert``/``--key``/``--ca-cert`` - see
``--help`` on any subcommand.
"""

import argparse
import os
import sys
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

import requests.exceptions

from webdav.client import Client
from webdav.tls import TLSOptions

if TYPE_CHECKING:
    from collections.abc import Sequence

_SCHEME_MAPPING = {
    "webdav": "http",
    "dav": "http",
    "webdavs": "https",
    "davs": "https",
    "http": "http",
    "https": "https",
}


class CLIError(Exception):
    """Raised for CLI-level errors (bad arguments, ...), caught in :func:`main`."""


def _split_url(
    url: str, *, user: str | None, password: str | None
) -> tuple[str, str, tuple[str, str] | None]:
    """Split a WebDAV URL into ``(base_url, path, auth)``."""
    parts = urlsplit(url)
    scheme = _SCHEME_MAPPING.get(parts.scheme)
    if scheme is None:
        msg = f"unsupported URL scheme {parts.scheme!r} (expected webdav(s)/dav(s)/http(s))"
        raise CLIError(msg)

    resolved_user = user or parts.username or os.environ.get("WEBDAV_USER")
    resolved_password = (
        password or parts.password or os.environ.get("WEBDAV_PASSWORD") or ""
    )
    auth = (resolved_user, resolved_password) if resolved_user is not None else None

    host = parts.hostname or ""
    netloc = f"{host}:{parts.port}" if parts.port else host
    base_url = urlunsplit((scheme, netloc, "", "", ""))
    return base_url, parts.path or "/", auth


def _tls_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    """Build the ``cert``/``verify``/``tls`` kwargs for :class:`~webdav.client.Client`."""
    cert: str | tuple[str, str] | None = (
        (args.cert, args.key) if args.cert and args.key else args.cert
    )

    verify: bool | str = args.ca_cert or True

    key_password = args.key_password or os.environ.get("WEBDAV_KEY_PASSWORD")
    tls = TLSOptions(key_password=key_password) if key_password else None

    return {"cert": cert, "verify": verify, "tls": tls}


def _client_for(url: str, args: argparse.Namespace) -> tuple[Client, str]:
    base_url, path, auth = _split_url(url, user=args.user, password=args.password)
    return Client(base_url, auth=auth, **_tls_kwargs(args)), path


def _cmd_ls(args: argparse.Namespace) -> None:
    client, path = _client_for(args.url, args)
    with client:
        entries = client.ls(path, detail=True)
    for entry in entries:
        name = entry.get("name", "")
        size = entry.get("content_length")
        kind = "d" if entry.get("type") == "directory" else "f"
        size_str = "-" if size is None else str(size)
        print(f"{kind}  {size_str:>12}  {name}")


def _cmd_info(args: argparse.Namespace) -> None:
    client, path = _client_for(args.url, args)
    with client:
        info = client.info(path)
    for key, value in info.items():
        print(f"{key}: {value}")


def _cmd_cat(args: argparse.Namespace) -> None:
    client, path = _client_for(args.url, args)
    with client:
        client.download_fileobj(path, sys.stdout.buffer)


def _cmd_get(args: argparse.Namespace) -> None:
    client, path = _client_for(args.url, args)
    with client:
        client.download_file(path, args.local_path)


def _cmd_put(args: argparse.Namespace) -> None:
    client, path = _client_for(args.url, args)
    with client:
        client.upload_file(args.local_path, path, overwrite=args.overwrite)


def _cmd_mkdir(args: argparse.Namespace) -> None:
    client, path = _client_for(args.url, args)
    with client:
        client.mkdir(path)


def _cmd_rm(args: argparse.Namespace) -> None:
    client, path = _client_for(args.url, args)
    with client:
        client.remove(path)


def _same_server_paths(
    src: str, dst: str, args: argparse.Namespace
) -> tuple[Client, str, str]:
    src_base, src_path, src_auth = _split_url(
        src, user=args.user, password=args.password
    )
    dst_base, dst_path, dst_auth = _split_url(
        dst, user=args.user, password=args.password
    )
    if (src_base, src_auth) != (dst_base, dst_auth):
        msg = "source and destination must be on the same server (move/copy is server-side)"
        raise CLIError(msg)
    return Client(src_base, auth=src_auth, **_tls_kwargs(args)), src_path, dst_path


def _cmd_mv(args: argparse.Namespace) -> None:
    client, src_path, dst_path = _same_server_paths(args.src, args.dst, args)
    with client:
        client.move(src_path, dst_path, overwrite=args.overwrite)


def _cmd_cp(args: argparse.Namespace) -> None:
    client, src_path, dst_path = _same_server_paths(args.src, args.dst, args)
    with client:
        client.copy(src_path, dst_path, overwrite=args.overwrite)


def _add_auth_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--user", default=None, help="username (default: $WEBDAV_USER, or from the URL)"
    )
    parser.add_argument(
        "--password",
        default=None,
        help="password (default: $WEBDAV_PASSWORD, or from the URL) - "
        "prefer the environment variable, --password is visible to other "
        "local users via the process list",
    )
    parser.add_argument(
        "--cert",
        default=None,
        metavar="PATH",
        help="client certificate for mTLS (PEM, combined cert+key unless --key is also given)",
    )
    parser.add_argument(
        "--key",
        default=None,
        metavar="PATH",
        help="private key for --cert, if not bundled in the same file",
    )
    parser.add_argument(
        "--key-password",
        default=None,
        metavar="PASSWORD",
        help="password for an encrypted --key/--cert (default: $WEBDAV_KEY_PASSWORD - "
        "prefer that over this flag, for the same reason as --password)",
    )
    parser.add_argument(
        "--ca-cert",
        default=None,
        metavar="PATH",
        help="CA bundle to verify the server certificate against "
        "(default: the system trust store) - server verification "
        "itself can never be disabled",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(prog="dav", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    ls_parser = subparsers.add_parser("ls", help="list a collection's members")
    ls_parser.add_argument("url")
    _add_auth_args(ls_parser)
    ls_parser.set_defaults(func=_cmd_ls)

    info_parser = subparsers.add_parser("info", help="show a resource's properties")
    info_parser.add_argument("url")
    _add_auth_args(info_parser)
    info_parser.set_defaults(func=_cmd_info)

    cat_parser = subparsers.add_parser(
        "cat", help="print a resource's content to stdout"
    )
    cat_parser.add_argument("url")
    _add_auth_args(cat_parser)
    cat_parser.set_defaults(func=_cmd_cat)

    get_parser = subparsers.add_parser(
        "get", help="download a resource to a local file"
    )
    get_parser.add_argument("url")
    get_parser.add_argument("local_path")
    _add_auth_args(get_parser)
    get_parser.set_defaults(func=_cmd_get)

    put_parser = subparsers.add_parser("put", help="upload a local file to a resource")
    put_parser.add_argument("local_path")
    put_parser.add_argument("url")
    put_parser.add_argument("--overwrite", action="store_true")
    _add_auth_args(put_parser)
    put_parser.set_defaults(func=_cmd_put)

    mkdir_parser = subparsers.add_parser("mkdir", help="create a collection")
    mkdir_parser.add_argument("url")
    _add_auth_args(mkdir_parser)
    mkdir_parser.set_defaults(func=_cmd_mkdir)

    rm_parser = subparsers.add_parser(
        "rm", help="remove a resource (or collection, recursively)"
    )
    rm_parser.add_argument("url")
    _add_auth_args(rm_parser)
    rm_parser.set_defaults(func=_cmd_rm)

    mv_parser = subparsers.add_parser("mv", help="move a resource (server-side)")
    mv_parser.add_argument("src")
    mv_parser.add_argument("dst")
    mv_parser.add_argument("--overwrite", action="store_true")
    _add_auth_args(mv_parser)
    mv_parser.set_defaults(func=_cmd_mv)

    cp_parser = subparsers.add_parser("cp", help="copy a resource (server-side)")
    cp_parser.add_argument("src")
    cp_parser.add_argument("dst")
    cp_parser.add_argument("--overwrite", action="store_true")
    _add_auth_args(cp_parser)
    cp_parser.set_defaults(func=_cmd_cp)

    return parser


def main(argv: "Sequence[str] | None" = None) -> int:
    """CLI entry point (``dav``)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (CLIError, OSError, requests.exceptions.RequestException) as exc:
        print(f"dav {args.command}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
