"""TLS/mTLS hardening helpers.

``requests`` supports client certificates via the plain ``cert=`` kwarg,
but that path only accepts an *unencrypted* private key file - there is
no way to supply a password for an encrypted key, which is how most
real-world mTLS client certificates are actually distributed. This module
fills that gap with a small ``HTTPAdapter`` configured from an explicit
:class:`ssl.SSLContext`, built with security-first defaults: server
certificate verification is always required (there is no parameter to
turn it off), TLS 1.2 is the floor, and TLS compression is disabled
(mitigates CRIME-style compression side-channel attacks).
"""

import os
import ssl
from dataclasses import dataclass, field
from functools import partial
from typing import TYPE_CHECKING, Any, cast

import requests

from webdav.deadline import DeadlineAdapter
from webdav.exceptions import TLSConfigError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from os import PathLike

    from urllib3.poolmanager import PoolManager

    StrPath = str | PathLike[str]

DEFAULT_MINIMUM_TLS_VERSION = ssl.TLSVersion.TLSv1_2


@dataclass(frozen=True)
class TLSOptions:
    """Advanced TLS knobs that need the hardened :class:`SSLContextAdapter`.

    Only needed for what plain ``requests`` ``cert=``/``verify=`` cannot
    express: an encrypted private key, CRL checking, or explicit cipher
    restriction. Leave unset (the ``Session`` default) to use ``requests``'
    own attributes directly.
    """

    #: Never shown by ``repr``: a options object ends up in tracebacks and logs.
    key_password: str | None = field(default=None, repr=False)
    ca_files: "Iterable[StrPath] | StrPath | None" = None
    crl_files: "Iterable[StrPath] | StrPath | None" = None
    ciphers: str | None = None
    minimum_version: ssl.TLSVersion = DEFAULT_MINIMUM_TLS_VERSION
    maximum_version: "ssl.TLSVersion | None" = None


def _load(op: str, path: object, fn: "Callable[[], None]") -> None:
    """Run one of the ``ssl.SSLContext`` ``load_*()`` calls.

    Translates its two undifferentiated failure modes - a missing file
    (``OSError``, ``.filename`` frequently unset) and a malformed/wrong
    PEM file (a bare ``ssl.SSLError: [SSL] PEM lib``, identical regardless
    of which configured path was the culprit) - into a
    :class:`~webdav.exceptions.TLSConfigError` that names which path and
    operation actually failed.
    """
    try:
        fn()
    except (OSError, ssl.SSLError) as exc:
        msg = f"{op} failed ({path}): {exc}"
        raise TLSConfigError(msg) from exc


def build_ssl_context(
    *,
    certfile: "StrPath | None" = None,
    keyfile: "StrPath | None" = None,
    options: TLSOptions | None = None,
) -> ssl.SSLContext:
    """Build a hardened :class:`ssl.SSLContext`, optionally for mTLS.

    Server certificate verification and hostname checking are always on -
    on purpose, there is no parameter to disable them. An mTLS setup with
    client-certificate auth but no server verification is a trivial MITM
    target, and this library refuses to make that easy to reach by
    accident. Use ``options.ca_files`` (a private CA) rather than
    disabling verification when the server certificate isn't in the
    system trust store.

    Args:
        certfile: Client certificate (PEM) for mTLS. ``None`` for a
            regular TLS connection without a client certificate.
        keyfile: Private key for ``certfile``, if not bundled in the same
            file.
        options: The advanced knobs - see :class:`TLSOptions`.

    Raises:
        TLSConfigError: A certificate, key or CA/CRL file could not be
            loaded.

    """
    options = options or TLSOptions()
    if options.minimum_version < ssl.TLSVersion.TLSv1_2:
        msg = (
            f"minimum_version {options.minimum_version.name} is below the TLS 1.2 floor"
        )
        raise TLSConfigError(msg)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = options.minimum_version
    if options.maximum_version is not None:
        context.maximum_version = options.maximum_version
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.options |= ssl.OP_NO_COMPRESSION
    # Strict RFC 5280 checking of the certificate chain (the default of
    # ``ssl.create_default_context``, but not of a bare ``SSLContext``).
    context.verify_flags |= ssl.VERIFY_X509_STRICT

    ca_file_list = _as_list(options.ca_files, "ca_files")
    if ca_file_list:
        for ca_file in ca_file_list:
            _load(
                "loading ca_files",
                ca_file,
                partial(context.load_verify_locations, cafile=str(ca_file)),
            )
    else:
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)

    crl_file_list = _as_list(options.crl_files, "crl_files")
    if crl_file_list:
        for crl_file in crl_file_list:
            _load(
                "loading crl_files",
                crl_file,
                partial(context.load_verify_locations, cafile=str(crl_file)),
            )
        context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF

    if certfile is not None:
        _load(
            "loading certfile/keyfile",
            f"{certfile}, {keyfile}",
            partial(
                context.load_cert_chain,
                certfile=str(certfile),
                keyfile=str(keyfile) if keyfile is not None else None,
                # Without a password an encrypted key must fail, not make
                # OpenSSL prompt on the terminal (and block a script).
                password=(
                    options.key_password
                    if options.key_password is not None
                    else _no_password
                ),
            ),
        )

    if options.ciphers:
        _load(
            "setting ciphers",
            options.ciphers,
            partial(context.set_ciphers, options.ciphers),
        )

    return context


def _no_password() -> bytes:
    return b""


def _as_list(value: "Iterable[StrPath] | StrPath | None", name: str) -> "list[StrPath]":
    """``value`` as a list; ``None`` is "not configured", but an *empty* value is an error.

    An empty ``ca_files`` quietly falling back to the system trust store, or
    an empty ``crl_files`` quietly turning revocation checking off, would
    turn a configuration slip into a weaker setup with no message at all.
    """
    if value is None:
        return []
    files = [value] if isinstance(value, str | os.PathLike) else list(value)
    if not files or any(not os.fspath(f) for f in files):
        msg = f"{name} is empty - leave it out (None) to use the default, or name at least one file"
        raise TLSConfigError(msg)
    return files


class SSLContextAdapter(DeadlineAdapter):
    """A :class:`~webdav.deadline.DeadlineAdapter` pinned to an ``SSLContext``.

    Needed for mTLS with a password-protected client-certificate key, a
    custom CRL, or explicit cipher restriction - none of which
    ``requests``' own ``cert=``/``verify=`` kwargs can express. See
    :func:`build_ssl_context`.
    """

    def __init__(self, ssl_context: ssl.SSLContext, **kwargs: Any) -> None:
        """Store the context; applied to both pool managers below."""
        self._ssl_context = ssl_context
        super().__init__(**kwargs)

    def __getstate__(self) -> "dict[str, Any]":
        """Refuse: an ``SSLContext`` (client key, CA set) is not something to serialise."""
        msg = "an SSLContextAdapter holds an SSLContext and cannot be pickled or deep-copied"
        raise TypeError(msg)

    def cert_verify(self, conn: Any, url: str, verify: Any, cert: Any) -> None:
        """Leave certificate verification to the context alone.

        ``requests`` would add its own CA bundle (certifi) to the connection
        on top of the context - so a private CA given as ``ca_files`` would
        also trust every public CA - and would honour a per-call
        ``verify=False``/``cert=``. This context is the whole configuration:
        the server is always verified, against exactly the CAs it holds, and
        the client certificate is the one it was built with.
        """
        conn.cert_reqs = "CERT_REQUIRED"
        conn.ca_certs = None
        conn.ca_cert_dir = None
        conn.cert_file = None
        conn.key_file = None

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        """Inject the SSL context into the connection pool manager."""
        kwargs["ssl_context"] = self._ssl_context
        super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args: Any, **kwargs: Any) -> "PoolManager":
        """Inject the SSL context for proxied (CONNECT-tunneled) connections too."""
        kwargs["ssl_context"] = self._ssl_context
        return cast("PoolManager", super().proxy_manager_for(*args, **kwargs))


def mount_mtls_adapter(
    session: requests.Session,
    *,
    certfile: "StrPath | None" = None,
    keyfile: "StrPath | None" = None,
    options: TLSOptions | None = None,
) -> None:
    """Build an mTLS :class:`SSLContextAdapter` and mount it for ``https://``.

    Convenience wrapper around :func:`build_ssl_context` +
    :class:`SSLContextAdapter` for the common case.
    """
    adapter = SSLContextAdapter(
        build_ssl_context(certfile=certfile, keyfile=keyfile, options=options)
    )
    session.mount("https://", adapter)
