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

Where the trust comes from differs by path, and is not "the system trust store"
in every case: plain ``verify=True`` is what ``requests`` does (``certifi``'s
bundle, or the distribution's own when it patches ``certifi``) - unless
``SSL_CERT_FILE``/``SSL_CERT_DIR`` name a CA, which then is the one used. A
session with ``tls=`` loads the OpenSSL default locations (the operating
system's store, plus whatever those two name) unless ``ca_files`` or a
``verify=`` path says otherwise. ``REQUESTS_CA_BUNDLE`` and
``CURL_CA_BUNDLE`` are ignored on every path. Naming the CA (``verify="ca.pem"``
or ``TLSOptions.ca_files``) is the one way to a trust anchor that no
environment variable can widen.
"""

import logging
import os
import ssl
from dataclasses import dataclass, field, replace
from functools import partial
from typing import TYPE_CHECKING, Any, cast

import requests
import requests.adapters

from webdav.exceptions import (
    TLSConfigError,
    TLSHardeningDisabledWarning,
    warn_at_caller,
)
from webdav.response import Response
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
    warn_at_caller(f"TLS hardening disabled: {reason}", TLSHardeningDisabledWarning)


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
    warn: bool = True,
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
        warn: ``False`` for a second context of a configuration that has
            already been warned about (the one a redirect to another origin is
            sent through), which would only repeat every warning.

    Raises:
        TLSConfigError: A certificate, key or CA/CRL file could not be
            loaded.

    """
    options = options or TLSOptions()
    if warn:
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

    @property
    def verifies(self) -> bool:
        """Whether this adapter checks the server's certificate (the context's say, not a per-call ``verify=``)."""
        return self._verify

    def reconfigure(self, ssl_context: ssl.SSLContext, *, verify: bool) -> None:
        """Swap in a new context and start over with fresh connection pools - in place.

        The adapter stays mounted where it is (``requests`` re-orders its
        mounts on every ``mount()``, which a thread that is sending right now
        iterates over). Connections that are in use finish on the old pools,
        which are closed as they come back.
        """
        old_pool, old_proxies = self.poolmanager, self.proxy_manager
        self._ssl_context = ssl_context
        self._verify = verify
        self.proxy_manager = {}
        self.init_poolmanager(
            self._pool_connections,  # type: ignore[attr-defined]
            self._pool_maxsize,  # type: ignore[attr-defined]
            block=self._pool_block,  # type: ignore[attr-defined]
        )
        old_pool.clear()
        for manager in old_proxies.values():
            manager.clear()

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
        certificate is the one it was built with. (``Session`` refuses a
        per-call ``verify=`` that would have said otherwise.)
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
    response_class: type[Response] = Response,
    pool_connections: int = requests.adapters.DEFAULT_POOLSIZE,
    pool_maxsize: int = requests.adapters.DEFAULT_POOLSIZE,
) -> None:
    """Build an mTLS :class:`SSLContextAdapter` and mount it for ``https://``.

    Convenience wrapper around :func:`build_ssl_context` +
    :class:`SSLContextAdapter` for the common case. One that is already
    mounted is reconfigured in place instead of replaced.
    """
    context = build_ssl_context(
        certfile=certfile, keyfile=keyfile, options=options, verify=verify
    )
    mounted = session.get_adapter("https://")
    if isinstance(mounted, SSLContextAdapter):
        mounted.reconfigure(context, verify=verify)
        return
    session.mount(
        "https://",
        SSLContextAdapter(
            context,
            verify=verify,
            response_class=response_class,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
        ),
    )


def build_foreign_adapter(
    tls: "TLSOptions | None",
    *,
    verify: bool,
    response_class: type[Response] = Response,
    adapter: "DeadlineAdapter | None" = None,
) -> DeadlineAdapter:
    """The adapter a redirect to *another* origin is sent through.

    Without ``tls`` a plain one. With it, the policy for how to talk TLS
    (versions, ciphers, strict chain checking, whether to verify) goes along;
    what is the origin server's own does not: no client certificate or key
    password, no CA files or CRLs (a private CA does not vouch for a storage
    host). ``adapter`` is an existing one to reconfigure
    in place.
    """
    if tls is None:
        return adapter or DeadlineAdapter(response_class=response_class)
    context = build_ssl_context(
        options=replace(tls, ca_files=None, crl_files=None, key_password=None),
        verify=verify,
        warn=False,
    )
    if isinstance(adapter, SSLContextAdapter):
        adapter.reconfigure(context, verify=verify)
        return adapter
    return SSLContextAdapter(context, verify=verify, response_class=response_class)


def check_verify_type(verify: object) -> "bool | str":
    """``verify`` as ``True``, ``False`` or the path of a CA bundle (a ``str``) - or a ``TypeError``.

    ``requests`` reads anything falsy as "do not check", so ``verify=""`` from
    an unset environment variable, a ``None`` from a config file or a stray
    ``0`` would turn certificate checking off without a word. Only a ``bool``,
    a non-empty ``str`` or a path-like is a statement about verification.

    Raises:
        TypeError: ``verify`` is anything else.

    """
    if isinstance(verify, bool):
        return verify
    if isinstance(verify, str | os.PathLike):
        path = os.fspath(verify)
        if isinstance(path, str) and path:
            return path
    msg = (
        f"verify must be True, False or the path of a CA bundle, got {verify!r}. "
        "Pass verify=False to turn certificate verification off explicitly, or "
        "verify='/path/to/ca.pem' to trust that CA (an empty or unset value, such "
        "as an empty environment variable, is refused: it would turn verification "
        "off without being asked)"
    )
    raise TypeError(msg)


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
    response_class: type[Response] = Response,
    pool_connections: int = requests.adapters.DEFAULT_POOLSIZE,
    pool_maxsize: int = requests.adapters.DEFAULT_POOLSIZE,
) -> None:
    """Wire up ``cert``/``verify`` on ``transport`` - plain ``requests`` attrs, or a hardened adapter.

    The hardened :mod:`webdav.transport.tls` adapter is only needed for what plain
    ``requests`` cannot express (``tls=...``); everything else uses
    ``requests``' own, well-known ``cert=``/``verify=`` attributes - and,
    with them, whatever pool size the plain ``DeadlineAdapter`` mounts
    already set up before this function ever runs (see
    ``Session._init_derived``). ``pool_connections``/``pool_maxsize`` here
    only matter for the ``tls=...`` branch below, which replaces that
    adapter with a new one of its own.

    With ``tls=`` the attributes are set too (the adapter is what counts, but
    ``session.verify`` must say what is in force). Called again, it rebuilds
    the adapter's context in place - the new context is built before anything
    is touched, so a failure leaves the old configuration as it was.

    Raises:
        TypeError: ``verify`` is not ``True``, ``False`` or a path.
        TLSConfigError: Something in ``tls`` could not be loaded.

    """
    verify = check_verify_type(verify)
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
        response_class=response_class,
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
    )
    transport.cert = cert
    transport.verify = verify
