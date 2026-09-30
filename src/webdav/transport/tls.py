"""TLS/mTLS hardening helpers.

``requests`` supports client certificates via the plain ``cert=`` kwarg,
but that path only accepts an *unencrypted* private key file - there is
no way to supply a password for an encrypted key, which is how most
real-world mTLS client certificates are actually distributed. This module
fills that gap with a small ``HTTPAdapter`` configured from an explicit
:class:`ssl.SSLContext`, built with security-first defaults: server
certificate verification, the TLS 1.2 floor and strict certificate-chain
checking are all on by default, and TLS compression is always disabled
(mitigates CRIME-style compression side-channel attacks, and no client
has a legitimate reason to want it back).

The three defaults above can each be turned off explicitly - this library
is not the one deciding a developer isn't allowed to, e.g., talk to a
legacy server that only speaks TLS 1.1. Turning one off logs and raises a
:class:`~webdav.exceptions.TLSHardeningDisabledWarning`, loud and
independent of ``urllib3``'s own warning hierarchy (see its docstring for
why) - a security-conscious deployment should be able to spot every one of
these in its logs, and it should never be possible to accidentally not
notice one.
"""

import logging
import os
import ssl
import warnings
from dataclasses import dataclass, field, replace
from functools import partial
from typing import TYPE_CHECKING, Any, cast

import requests

from webdav.exceptions import TLSConfigError, TLSHardeningDisabledWarning
from webdav.transport.deadline import DeadlineAdapter

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from os import PathLike

    from urllib3.poolmanager import PoolManager

    StrPath = str | PathLike[str]

#: What ``cert=`` accepts: one combined PEM, or a ``(certfile, keyfile)`` pair.
CertTypes = str | tuple[str, str] | None

DEFAULT_MINIMUM_TLS_VERSION = ssl.TLSVersion.TLSv1_2

_LOGGER = logging.getLogger("webdav")


def warn_hardening_disabled(reason: str) -> None:
    """Raise :class:`TLSHardeningDisabledWarning` and log it - see the module docstring."""
    _LOGGER.warning("TLS hardening disabled: %s", reason)
    warnings.warn(
        f"TLS hardening disabled: {reason}", TLSHardeningDisabledWarning, stacklevel=3
    )


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
    #: RFC 5280 chain checking, strict rather than the more lenient default
    #: OpenSSL itself uses. ``False`` accepts a chain some legacy/internal
    #: CAs produce that strict checking rejects - see the module docstring.
    strict_chain_checking: bool = True


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


def _warn_about_disabled_hardening(options: TLSOptions, *, verify: bool) -> None:
    """Warn once for each hardening measure ``options``/``verify`` turns off - see :func:`build_ssl_context`."""
    if options.minimum_version < ssl.TLSVersion.TLSv1_2:
        warn_hardening_disabled(
            f"minimum_version {options.minimum_version.name} is below the TLS 1.2 floor"
        )
    if not options.strict_chain_checking:
        warn_hardening_disabled("strict RFC 5280 certificate chain checking is off")
    if not verify:
        warn_hardening_disabled(
            "TLS server certificate verification is off (verify=False)"
        )


def _load_ca_and_crl(context: ssl.SSLContext, options: TLSOptions) -> None:
    """Load ``options.ca_files``/``crl_files`` into ``context`` - see :func:`build_ssl_context`."""
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


def build_ssl_context(
    *,
    certfile: "StrPath | None" = None,
    keyfile: "StrPath | None" = None,
    options: TLSOptions | None = None,
    verify: bool = True,
) -> ssl.SSLContext:
    """Build a hardened :class:`ssl.SSLContext`, optionally for mTLS.

    Server certificate verification, hostname checking, the TLS 1.2 floor
    and strict chain checking are all on by default. Each can be turned off
    explicitly (``verify=False``; ``options.minimum_version``/
    ``options.strict_chain_checking``) for a developer who has decided they
    need to - this library only owns the default, not the final word - but
    doing so raises and logs a
    :class:`~webdav.exceptions.TLSHardeningDisabledWarning` every time,
    loud and impossible to mistake for routine output. Prefer
    ``options.ca_files`` (a private CA) over ``verify=False`` when the
    server certificate simply isn't in the system trust store - that
    keeps verification on.

    Args:
        certfile: Client certificate (PEM) for mTLS. ``None`` for a
            regular TLS connection without a client certificate.
        keyfile: Private key for ``certfile``, if not bundled in the same
            file.
        options: The advanced knobs - see :class:`TLSOptions`.
        verify: Server certificate verification. ``False`` disables it
            entirely (and hostname checking with it) - the connection is
            then not protected against a machine-in-the-middle.

    Raises:
        TLSConfigError: A certificate, key or CA/CRL file could not be
            loaded.

    """
    options = options or TLSOptions()
    _warn_about_disabled_hardening(options, verify=verify)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = options.minimum_version
    if options.maximum_version is not None:
        context.maximum_version = options.maximum_version
    if verify:
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
    else:
        # check_hostname must be turned off before verify_mode - the ssl
        # module refuses CERT_NONE while check_hostname is still True.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.options |= ssl.OP_NO_COMPRESSION
    # Strict RFC 5280 checking of the certificate chain (the default of
    # ``ssl.create_default_context``, but not of a bare ``SSLContext``).
    if options.strict_chain_checking:
        context.verify_flags |= ssl.VERIFY_X509_STRICT

    if verify:
        _load_ca_and_crl(context, options)

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
    """A :class:`~webdav.transport.deadline.DeadlineAdapter` pinned to an ``SSLContext``.

    Needed for mTLS with a password-protected client-certificate key, a
    custom CRL, or explicit cipher restriction - none of which
    ``requests``' own ``cert=``/``verify=`` kwargs can express. See
    :func:`build_ssl_context`.
    """

    def __init__(
        self, ssl_context: ssl.SSLContext, *, verify: bool = True, **kwargs: Any
    ) -> None:
        """Store the context; applied to both pool managers below."""
        self._ssl_context = ssl_context
        self._verify = verify
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
        verification is exactly what :func:`build_ssl_context` built it
        with, against exactly the CAs it holds (if any), and the client
        certificate is the one it was built with.
        """
        conn.cert_reqs = "CERT_REQUIRED" if self._verify else "CERT_NONE"
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
    verify: bool = True,
) -> None:
    """Build an mTLS :class:`SSLContextAdapter` and mount it for ``https://``.

    Convenience wrapper around :func:`build_ssl_context` +
    :class:`SSLContextAdapter` for the common case.
    """
    adapter = SSLContextAdapter(
        build_ssl_context(
            certfile=certfile, keyfile=keyfile, options=options, verify=verify
        ),
        verify=verify,
    )
    session.mount("https://", adapter)


def verification_on(verify: object) -> bool:
    """Whether ``verify`` means "check the server's certificate" (to ``requests``, anything falsy does not)."""
    return verify is True or (
        isinstance(verify, str | os.PathLike) and bool(os.fspath(verify))
    )


def configure_tls(
    transport: "requests.Session",
    *,
    cert: "CertTypes",
    verify: "bool | str",
    tls: "TLSOptions | None",
) -> None:
    """Wire up ``cert``/``verify`` on ``transport`` - plain ``requests`` attrs, or a hardened adapter.

    The hardened :mod:`webdav.transport.tls` adapter is only needed for what plain
    ``requests`` cannot express (``tls=...``); everything else uses
    ``requests``' own, well-known ``cert=``/``verify=`` attributes.
    """
    verify_certificates = verification_on(verify)
    if tls is None:
        if not verify_certificates:
            warn_hardening_disabled(
                f"TLS server certificate verification is off (verify={verify!r}) "
                "for every request this session sends"
            )
        transport.cert = cert
        transport.verify = verify
        return

    certfile: str | None
    keyfile: str | None
    if cert is None:
        certfile, keyfile = None, None
    elif isinstance(cert, str):
        certfile, keyfile = cert, None
    else:
        certfile, keyfile = cert[0], cert[1]

    if verify_certificates and tls.ca_files is None and isinstance(verify, str):
        tls = replace(tls, ca_files=verify)
    mount_mtls_adapter(
        transport,
        certfile=certfile,
        keyfile=keyfile,
        options=tls,
        verify=verify_certificates,
    )
