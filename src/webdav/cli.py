"""A small ``aws s3``-style CLI for WebDAV servers.

Every command takes one or more WebDAV URLs
(``webdav://host/path``/``webdavs://host/path``, or plain ``http(s)://``) -
the scheme's host/port is the server, everything after it is the
resource path. Authentication is ``user:pass@host`` in the URL,
``--user``/``--password``, or the ``WEBDAV_USER``/``WEBDAV_PASSWORD``
environment variables, in that order of precedence. mTLS (client
certificates) is available via ``--cert``/``--key``/``--ca-cert`` - see
``--help`` on any subcommand. Every :class:`~webdav.client.Client`
constructor option (redirect policy, response-size cap, retry, TLS
details, ...) has a corresponding flag - see the "connection options"
group in ``--help``.
"""

import argparse
import os
import ssl
import sys
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

import requests.exceptions

from webdav.client import Client, RedirectPolicy
from webdav.tls import DEFAULT_MINIMUM_TLS_VERSION, TLSOptions

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

_TLS_VERSIONS = {
    "1.2": ssl.TLSVersion.TLSv1_2,
    "1.3": ssl.TLSVersion.TLSv1_3,
}

_REDIRECT_POLICIES = {policy.value: policy for policy in RedirectPolicy}

#: Distinguishes "--max-response-size/--chunk-size wasn't given at all"
#: (use Client()'s own default) from "given as 'none'" (None is itself a
#: meaningful value for --max-response-size: disable the cap).
_UNSET = object()


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


def _positive_int_or_none(value: str) -> "int | None":
    """Argparse type: a positive byte count, or 'none'/'0' to disable a cap."""
    if value.lower() in ("none", "unlimited", "0"):
        return None
    parsed = int(value)
    if parsed <= 0:
        msg = f"must be a positive integer or 'none', got {value!r}"
        raise argparse.ArgumentTypeError(msg)
    return parsed


def _redirect_policy(value: str) -> RedirectPolicy:
    """Argparse type: one of RedirectPolicy's values, by its CLI spelling."""
    try:
        return _REDIRECT_POLICIES[value]
    except KeyError:
        msg = f"invalid choice: {value!r} (choose from {', '.join(_REDIRECT_POLICIES)})"
        raise argparse.ArgumentTypeError(msg) from None


def _tls_version(value: str) -> ssl.TLSVersion:
    """Argparse type: a TLS version by its familiar "1.2"/"1.3" spelling."""
    try:
        return _TLS_VERSIONS[value]
    except KeyError:
        msg = f"invalid choice: {value!r} (choose from {', '.join(_TLS_VERSIONS)})"
        raise argparse.ArgumentTypeError(msg) from None


def _client_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    """Build every :class:`~webdav.client.Client` constructor kwarg from ``args``."""
    cert: str | tuple[str, str] | None = (
        (args.cert, args.key) if args.cert and args.key else args.cert
    )
    verify: bool | str = args.ca_cert or True

    key_password = args.key_password or os.environ.get("WEBDAV_KEY_PASSWORD")
    tls = None
    if key_password or args.tls_min_version or args.tls_max_version or args.ciphers or args.crl_cert:
        tls = TLSOptions(
            key_password=key_password,
            crl_files=args.crl_cert or None,
            ciphers=args.ciphers,
            minimum_version=args.tls_min_version or DEFAULT_MINIMUM_TLS_VERSION,
            maximum_version=args.tls_max_version,
        )

    kwargs: dict[str, Any] = {
        "cert": cert,
        "verify": verify,
        "tls": tls,
        "retry": not args.no_retry,
        "redirect_policy": args.redirect_policy,
    }
    # Only override Client()'s own defaults when the flag was actually
    # given - args.max_response_size/.chunk_size default to the _UNSET
    # sentinel, not None, specifically so "not given" and "given as
    # 'none'" (a real, meaningful value for --max-response-size, meaning
    # "disable the cap") stay distinguishable.
    if args.max_response_size is not _UNSET:
        kwargs["max_response_size"] = args.max_response_size
    if args.chunk_size is not _UNSET:
        kwargs["chunk_size"] = args.chunk_size
    if args.trusted_redirect_origin:
        kwargs["trusted_redirect_origins"] = args.trusted_redirect_origin
    return kwargs


def _client_for(url: str, args: argparse.Namespace) -> tuple[Client, str]:
    base_url, path, auth = _split_url(url, user=args.user, password=args.password)
    return Client(base_url, auth=auth, **_client_kwargs(args)), path


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
    return Client(src_base, auth=src_auth, **_client_kwargs(args)), src_path, dst_path


def _cmd_mv(args: argparse.Namespace) -> None:
    client, src_path, dst_path = _same_server_paths(args.src, args.dst, args)
    with client:
        client.move(src_path, dst_path, overwrite=args.overwrite)


def _cmd_cp(args: argparse.Namespace) -> None:
    client, src_path, dst_path = _same_server_paths(args.src, args.dst, args)
    with client:
        client.copy(src_path, dst_path, overwrite=args.overwrite)


def _add_client_args(parser: argparse.ArgumentParser) -> None:
    """Add every flag that configures the underlying :class:`~webdav.client.Client`."""
    auth = parser.add_argument_group("authentication")
    auth.add_argument(
        "--user", default=None, help="username (default: $WEBDAV_USER, or from the URL)"
    )
    auth.add_argument(
        "--password",
        default=None,
        help="password (default: $WEBDAV_PASSWORD, or from the URL) - "
        "prefer the environment variable, --password is visible to other "
        "local users via the process list",
    )

    tls = parser.add_argument_group("TLS / mTLS")
    tls.add_argument(
        "--cert",
        default=None,
        metavar="PATH",
        help="client certificate for mTLS (PEM, combined cert+key unless --key is also given)",
    )
    tls.add_argument(
        "--key",
        default=None,
        metavar="PATH",
        help="private key for --cert, if not bundled in the same file",
    )
    tls.add_argument(
        "--key-password",
        default=None,
        metavar="PASSWORD",
        help="password for an encrypted --key/--cert (default: $WEBDAV_KEY_PASSWORD - "
        "prefer that over this flag, for the same reason as --password)",
    )
    tls.add_argument(
        "--ca-cert",
        default=None,
        metavar="PATH",
        help="CA bundle to verify the server certificate against "
        "(default: the system trust store) - server verification "
        "itself can never be disabled",
    )
    tls.add_argument(
        "--crl-cert",
        action="append",
        default=None,
        metavar="PATH",
        help="CRL file to check the server certificate against "
        "(repeatable for several CRLs)",
    )
    tls.add_argument(
        "--ciphers",
        default=None,
        metavar="LIST",
        help="OpenSSL cipher list string restricting which ciphers are offered",
    )
    tls.add_argument(
        "--tls-min-version",
        type=_tls_version,
        default=None,
        choices=list(_TLS_VERSIONS.values()),
        metavar="{1.2,1.3}",
        help="minimum TLS version to accept (default: 1.2)",
    )
    tls.add_argument(
        "--tls-max-version",
        type=_tls_version,
        default=None,
        choices=list(_TLS_VERSIONS.values()),
        metavar="{1.2,1.3}",
        help="maximum TLS version to accept (default: no cap)",
    )

    redirects = parser.add_argument_group("redirect handling")
    redirects.add_argument(
        "--redirect-policy",
        type=_redirect_policy,
        default=RedirectPolicy.SAME_ORIGIN,
        choices=list(RedirectPolicy),
        metavar="{" + ",".join(_REDIRECT_POLICIES) + "}",
        help="which redirects to follow: 'never', 'same-origin' (default), "
        "'whitelist' (also follow --trusted-redirect-origin), or 'all' "
        "(follow any redirect - only for a server you fully trust)",
    )
    redirects.add_argument(
        "--trusted-redirect-origin",
        action="append",
        default=None,
        metavar="ORIGIN",
        help="an origin (e.g. https://storage.example.com) to also follow "
        "a redirect to, in addition to the server's own - repeatable; "
        "requires --redirect-policy whitelist",
    )

    conn = parser.add_argument_group("connection")
    conn.add_argument(
        "--max-response-size",
        type=_positive_int_or_none,
        default=_UNSET,
        metavar="BYTES",
        help="reject a PROPFIND/PROPPATCH/LOCK response larger than this "
        "many bytes ('none' to disable; default: 64 MiB)",
    )
    conn.add_argument(
        "--chunk-size",
        type=_positive_int_or_none,
        default=_UNSET,
        metavar="BYTES",
        help="chunk size for streaming uploads/downloads (default: 4 MiB)",
    )
    conn.add_argument(
        "--no-retry",
        action="store_true",
        help="don't automatically retry a transient failure (423 Locked, "
        "5xx, connection errors) - retries by default",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(prog="dav", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    ls_parser = subparsers.add_parser("ls", help="list a collection's members")
    ls_parser.add_argument("url")
    _add_client_args(ls_parser)
    ls_parser.set_defaults(func=_cmd_ls)

    info_parser = subparsers.add_parser("info", help="show a resource's properties")
    info_parser.add_argument("url")
    _add_client_args(info_parser)
    info_parser.set_defaults(func=_cmd_info)

    cat_parser = subparsers.add_parser(
        "cat", help="print a resource's content to stdout"
    )
    cat_parser.add_argument("url")
    _add_client_args(cat_parser)
    cat_parser.set_defaults(func=_cmd_cat)

    get_parser = subparsers.add_parser(
        "get", help="download a resource to a local file"
    )
    get_parser.add_argument("url")
    get_parser.add_argument("local_path")
    _add_client_args(get_parser)
    get_parser.set_defaults(func=_cmd_get)

    put_parser = subparsers.add_parser("put", help="upload a local file to a resource")
    put_parser.add_argument("local_path")
    put_parser.add_argument("url")
    put_parser.add_argument("--overwrite", action="store_true")
    _add_client_args(put_parser)
    put_parser.set_defaults(func=_cmd_put)

    mkdir_parser = subparsers.add_parser("mkdir", help="create a collection")
    mkdir_parser.add_argument("url")
    _add_client_args(mkdir_parser)
    mkdir_parser.set_defaults(func=_cmd_mkdir)

    rm_parser = subparsers.add_parser(
        "rm", help="remove a resource (or collection, recursively)"
    )
    rm_parser.add_argument("url")
    _add_client_args(rm_parser)
    rm_parser.set_defaults(func=_cmd_rm)

    mv_parser = subparsers.add_parser("mv", help="move a resource (server-side)")
    mv_parser.add_argument("src")
    mv_parser.add_argument("dst")
    mv_parser.add_argument("--overwrite", action="store_true")
    _add_client_args(mv_parser)
    mv_parser.set_defaults(func=_cmd_mv)

    cp_parser = subparsers.add_parser("cp", help="copy a resource (server-side)")
    cp_parser.add_argument("src")
    cp_parser.add_argument("dst")
    cp_parser.add_argument("--overwrite", action="store_true")
    _add_client_args(cp_parser)
    cp_parser.set_defaults(func=_cmd_cp)

    return parser


def main(argv: "Sequence[str] | None" = None) -> int:
    """CLI entry point (``dav``)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (CLIError, OSError, ValueError, requests.exceptions.RequestException) as exc:
        print(f"dav {args.command}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
