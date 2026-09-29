"""A small ``aws s3``-style CLI for WebDAV servers.

Every command takes one or more WebDAV URLs
(``webdav://host/path``/``webdavs://host/path``, or plain ``http(s)://``) -
the scheme's host/port is the server, everything after it is the
resource path. Authentication is ``--user``/``--password``, else
``user:pass@host`` in the URL, else the ``WEBDAV_USER``/``WEBDAV_PASSWORD``
environment variables, in that order of precedence (an explicit flag beats
what a pasted URL happens to contain). mTLS (client certificates) is
available via ``--cert``/``--key``/``--ca-cert`` - see ``--help`` on any
subcommand. The commonly needed :class:`~webdav.session.Session`
constructor options (redirect policy, response-size cap, retry, timeout,
chunk size, TLS details) have a corresponding flag - see the "connection"
group in ``--help``.
"""

import argparse
import os
import ssl
import sys
from contextlib import suppress
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote, urlsplit, urlunsplit

import requests.exceptions

from webdav.redirects import RedirectPolicy
from webdav.session import Session
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
#: (use Session()'s own default) from "given as 'none'" (None is itself a
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

    if parts.query or parts.fragment:
        # Neither is part of a resource's address here; dropping them silently
        # would act on a different resource than the one the URL names.
        msg = "a URL with a query or fragment is not supported (a signed URL is not a WebDAV path)"
        raise CLIError(msg)

    resolved_user = user or parts.username or os.environ.get("WEBDAV_USER")
    resolved_password = (
        password or parts.password or os.environ.get("WEBDAV_PASSWORD") or ""
    )
    auth = (resolved_user, resolved_password) if resolved_user is not None else None

    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"  # an IPv6 literal keeps its brackets in a URL
    netloc = f"{host}:{parts.port}" if parts.port else host
    base_url = urlunsplit((scheme, netloc, "", "", ""))
    # The path on the command line is the URL's: percent-decode it once, so
    # ``a%20b.txt`` names "a b.txt" (Session paths are plain names).
    return base_url, unquote(parts.path) or "/", auth


def _positive_int(value: str) -> int:
    """Argparse type: a positive integer (``0`` and negatives are refused, not reinterpreted)."""
    try:
        parsed = int(value)
    except ValueError:
        parsed = 0
    if parsed <= 0:
        msg = f"must be a positive integer, got {value!r}"
        raise argparse.ArgumentTypeError(msg)
    return parsed


def _size_cap(value: str) -> "int | None":
    """Argparse type: a positive byte count, or 'none'/'unlimited' to disable the cap.

    ``0`` is deliberately *not* "unlimited": a typo that silently removes a
    safety limit is the wrong way to fail.
    """
    if value.lower() in ("none", "unlimited"):
        return None
    return _positive_int(value)


def _positive_seconds(value: str) -> float:
    """Argparse type: a positive number of seconds."""
    try:
        parsed = float(value)
    except ValueError:
        parsed = 0.0
    if not parsed > 0:
        msg = f"must be a positive number of seconds, got {value!r}"
        raise argparse.ArgumentTypeError(msg)
    return parsed


def _printable(text: object) -> str:
    """``text`` with control characters made visible.

    Names and values come from the server: an ESC sequence or a newline in
    one would otherwise repaint the terminal or forge an extra line of
    output.
    """
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(text))


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
    """Build every :class:`~webdav.session.Session` constructor kwarg from ``args``."""
    cert: str | tuple[str, str] | None = (
        (args.cert, args.key) if args.cert and args.key else args.cert
    )
    verify: bool | str = args.ca_cert or True

    key_password = args.key_password or os.environ.get("WEBDAV_KEY_PASSWORD")
    tls = None
    if (
        key_password
        or args.tls_min_version
        or args.tls_max_version
        or args.ciphers
        or args.crl_cert
    ):
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
    # Only override Session()'s own defaults when the flag was actually
    # given - args.max_response_size/.chunk_size default to the _UNSET
    # sentinel, not None, specifically so "not given" and "given as
    # 'none'" (a real, meaningful value for --max-response-size, meaning
    # "disable the cap") stay distinguishable.
    if args.max_response_size is not _UNSET:
        kwargs["max_response_size"] = args.max_response_size
    if args.chunk_size is not _UNSET:
        kwargs["chunk_size"] = args.chunk_size
    if args.timeout is not _UNSET:
        kwargs["timeout"] = args.timeout
    if args.trusted_redirect_origin:
        kwargs["trusted_redirect_origins"] = args.trusted_redirect_origin
    return kwargs


def _client_for(url: str, args: argparse.Namespace) -> tuple[Session, str]:
    base_url, path, auth = _split_url(url, user=args.user, password=args.password)
    return Session(base_url, auth=auth, **_client_kwargs(args)), path


def _cmd_ls(args: argparse.Namespace) -> None:
    client, path = _client_for(args.url, args)
    with client:
        entries = client.ls(path)
    for entry in entries:
        kind = "d" if entry.is_dir else "f"
        size_str = "-" if entry.size is None else str(entry.size)
        print(f"{kind}  {size_str:>12}  {_printable(entry.name)}")


def _cmd_info(args: argparse.Namespace) -> None:
    client, path = _client_for(args.url, args)
    with client:
        info = client.info(path)
    for key, value in info.as_dict().items():
        print(f"{_printable(key)}: {_printable(value)}")


def _cmd_cat(args: argparse.Namespace) -> None:
    client, path = _client_for(args.url, args)
    with client:
        client.download_fileobj(path, sys.stdout.buffer)


def _cmd_get(args: argparse.Namespace) -> None:
    client, path = _client_for(args.url, args)
    with client:
        if args.local_path == "-":  # standard output, like ``cat``
            client.download_fileobj(path, sys.stdout.buffer)
        else:
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
        # DELETE on a collection removes everything below it; like ``rm``,
        # that takes -r, not an accident.
        if not args.recursive and client.isdir(path) and client.ls(path):
            msg = f"{path} is a non-empty collection (use -r to remove it and everything in it)"
            raise CLIError(msg)
        client.remove(path)


def _same_server_paths(
    src: str, dst: str, args: argparse.Namespace
) -> tuple[Session, str, str]:
    src_base, src_path, src_auth = _split_url(
        src, user=args.user, password=args.password
    )
    dst_base, dst_path, dst_auth = _split_url(
        dst, user=args.user, password=args.password
    )
    if (src_base, src_auth) != (dst_base, dst_auth):
        msg = "source and destination must be on the same server (move/copy is server-side)"
        raise CLIError(msg)
    return Session(src_base, auth=src_auth, **_client_kwargs(args)), src_path, dst_path


def _cmd_mv(args: argparse.Namespace) -> None:
    client, src_path, dst_path = _same_server_paths(args.src, args.dst, args)
    with client:
        client.move(src_path, dst_path, overwrite=args.overwrite).raise_for_status()


def _cmd_cp(args: argparse.Namespace) -> None:
    client, src_path, dst_path = _same_server_paths(args.src, args.dst, args)
    with client:
        client.copy(src_path, dst_path, overwrite=args.overwrite).raise_for_status()


def _add_client_args(parser: argparse.ArgumentParser) -> None:
    """Add every flag that configures the underlying :class:`~webdav.session.Session`."""
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
        type=_size_cap,
        default=_UNSET,
        metavar="BYTES",
        help="reject a response body larger than this many bytes "
        "('none' to disable; default: 64 MiB)",
    )
    conn.add_argument(
        "--chunk-size",
        type=_positive_int,
        default=_UNSET,
        metavar="BYTES",
        help="chunk size for streaming uploads/downloads (default: 4 MiB)",
    )
    conn.add_argument(
        "--timeout",
        type=_positive_seconds,
        default=_UNSET,
        metavar="SECONDS",
        help="give up when the server does not answer for this long "
        "(connect and read; default: 10 to connect, 60 to read)",
    )
    conn.add_argument(
        "--no-retry",
        action="store_true",
        help="don't automatically retry a transient failure (429, 5xx, "
        "connection errors) of a read - retries by default",
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
        "rm", help="remove a resource (a non-empty collection needs -r)"
    )
    rm_parser.add_argument("url")
    rm_parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="remove a collection and everything in it",
    )
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
    except BrokenPipeError:
        # ``dav ls | head``: the reader went away. Not an error - and point stdout
        # at /dev/null so the interpreter's own flush at exit does not complain.
        with suppress(
            OSError, ValueError
        ):  # no real stdout (captured): nothing to redirect
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    except (CLIError, OSError, ValueError, requests.exceptions.RequestException) as exc:
        print(f"dav {args.command}: {_printable(exc)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
