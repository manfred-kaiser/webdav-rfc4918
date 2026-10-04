"""Stand up / tear down a throwaway Apache + mod_dav instance.

Shared by the ``apache_url`` pytest fixture (see ``test_apache_compliance.py``,
which uses it automatically whenever a usable Apache is found - no manual
step needed) and ``tools/apache_compliance_check.py`` (manual/debugging use:
inspect a running instance, keep it up after a failure, point at a specific
directory). One implementation, so the two can never drift apart.
"""

import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

#: (.so filename, Apache's own LoadModule directive name for it).
REQUIRED_MODULES = (
    ("mod_mpm_prefork.so", "mpm_prefork_module"),
    ("mod_authn_core.so", "authn_core_module"),
    ("mod_authz_core.so", "authz_core_module"),
    ("mod_authn_file.so", "authn_file_module"),
    ("mod_authz_user.so", "authz_user_module"),
    ("mod_auth_basic.so", "auth_basic_module"),
    ("mod_mime.so", "mime_module"),
    ("mod_log_config.so", "log_config_module"),
    ("mod_dav.so", "dav_module"),
    ("mod_dav_fs.so", "dav_fs_module"),
    ("mod_dav_lock.so", "dav_lock_module"),
)
TEST_USER = "testuser"
TEST_PASSWORD = "testpass123"  # noqa: S105
HOST = "127.0.0.1"
PORT = 8765


@dataclass(frozen=True)
class _Profile:
    """Where one distro's ``apache2``/``httpd`` package puts its binary and modules."""

    name: str
    httpd: str
    module_dir: Path
    #: Modules (by .so filename, from REQUIRED_MODULES) this distro's httpd
    #: already has compiled statically into the core binary - confirmed live
    #: on GitHub Actions' ubuntu-latest for two, for different reasons:
    #: Debian/Ubuntu's mod_log_config (every other required module there is
    #: a normal loadable .so; this one alone was missing from the modules
    #: directory) and openSUSE's MPM (the "apache2-prefork" package name
    #: itself says as much - that httpd binary is one specific, built-in
    #: MPM, not a generic one that loads mpm_prefork separately the way
    #: Debian's does; "AH00534: No MPM loaded" without it). A built-in
    #: module is not expected to exist as a .so, and must not get a
    #: LoadModule directive either - Apache refuses to load one already
    #: built in.
    built_in: "frozenset[str]" = frozenset()
    #: Modules this packaging needs loaded on top of REQUIRED_MODULES - the
    #: distro packages have them built in, a build from the release tarball
    #: has ``mod_unixd`` as a loadable module.
    extra_modules: "tuple[tuple[str, str], ...]" = ()
    #: ``htpasswd`` of this packaging if it is not on ``PATH``.
    htpasswd: "str | None" = None

    def missing(self) -> list[str]:
        """What is missing for this specific profile - empty if it is fully usable."""
        missing = []
        if not Path(self.httpd).exists():
            missing.append(self.httpd)
        missing += [
            str(self.module_dir / filename)
            for filename, _directive in (*REQUIRED_MODULES, *self.extra_modules)
            if filename not in self.built_in
            and not (self.module_dir / filename).exists()
        ]
        return missing

    def htpasswd_binary(self) -> "str | None":
        """This packaging's ``htpasswd``, else the one on ``PATH`` - ``None`` if there is none."""
        if self.htpasswd is not None and Path(self.htpasswd).exists():
            return self.htpasswd
        return shutil.which("htpasswd")


#: Tried in order; the first fully present one wins. Same ``httpd`` binary
#: underneath everywhere (both accept the same ``-f``/``-k`` flags) - only
#: the install paths (and which modules are built in vs. loadable) differ
#: per packaging.
_PROFILES = (
    _Profile(
        "openSUSE/RPM",
        "/usr/sbin/httpd",
        Path("/usr/lib64/apache2-prefork"),
        built_in=frozenset({"mod_mpm_prefork.so"}),
    ),
    _Profile(
        "Debian/Ubuntu",
        "/usr/sbin/apache2",
        Path("/usr/lib/apache2/modules"),
        built_in=frozenset({"mod_log_config.so"}),
    ),
)


#: Names a directory that holds an Apache built from the release tarball
#: (``bin/httpd``, ``bin/htpasswd``, ``modules/``) - e.g. a ``--prefix`` of
#: ``./configure``. Tried before the distro layouts, so that the suite can run
#: against exactly that build.
PREFIX_ENV = "WEBDAV_TEST_APACHE_PREFIX"


def _all_profiles() -> "tuple[_Profile, ...]":
    """``_PROFILES``, preceded by the build ``WEBDAV_TEST_APACHE_PREFIX`` names (if any)."""
    prefix = os.environ.get(PREFIX_ENV)
    if not prefix:
        return _PROFILES
    root = Path(prefix)
    return (
        _Profile(
            f"build in {root}",
            str(root / "bin" / "httpd"),
            root / "modules",
            built_in=frozenset({"mod_mpm_prefork.so"}),
            extra_modules=(("mod_unixd.so", "unixd_module"),),
            htpasswd=str(root / "bin" / "htpasswd"),
        ),
        *_PROFILES,
    )


def _resolve_profile() -> "_Profile | None":
    """The first fully-usable profile, or ``None`` if every one is missing something."""
    for profile in _all_profiles():
        if not profile.missing():
            return profile
    return None


HTTPD_CONF_TEMPLATE = """\
ServerRoot "{instance_dir}"
ServerName localhost
Listen {host}:{port}

PidFile "logs/httpd.pid"
ErrorLog "logs/error.log"
LogLevel warn

{load_modules}

# Without this, mod_mime falls back to its compiled-in default TypesConfig,
# which differs by distro and - on Debian/Ubuntu - is a relative path
# ("conf/mime.types") that doesn't exist under our custom ServerRoot
# (AH01597). /etc/mime.types is the standard system-wide file present on
# both distros this project supports.
TypesConfig /etc/mime.types

{lock_db}

# Must be an ABSOLUTE path in both directives, and they must match exactly -
# a relative "dav-root" in <Directory> silently failed to match this
# DocumentRoot on Apache/2.4.67, leaving the whole block (Dav On *and* the
# auth Require) inactive with no error logged.
DocumentRoot "{instance_dir}/dav-root"

<Directory "{instance_dir}/dav-root">
    Dav On
    Options None
    AllowOverride None
    AuthType Basic
    AuthName "webdav-rfc4918 test"
    AuthUserFile "{instance_dir}/htpasswd"
    Require valid-user
</Directory>

{extra_conf}
"""


LOCK_DB_DIRECTIVE = 'DavLockDB "locks/davlock"'


def missing_prerequisites() -> list[str]:
    """What is missing to stand up a local instance - empty if any one known profile is fully usable.

    Each item is prefixed with which profile it belongs to, since more than
    one may be partially present (e.g. a stray ``httpd`` binary with no
    matching modules) without either being usable on its own.
    """
    profile = _resolve_profile()
    if profile is not None:
        if profile.htpasswd_binary() is None:
            return ["htpasswd (package: apache2-utils, or your distro's equivalent)"]
        return []
    return [
        f"[{profile.name}] {item}"
        for profile in _all_profiles()
        for item in profile.missing()
    ]


def write_instance(
    instance_dir: Path,
    *,
    clean: bool = True,
    port: int = PORT,
    lock_db: bool = True,
    without_modules: "frozenset[str]" = frozenset(),
    extra_conf: str = "",
) -> Path:
    """Create/refresh the instance's config, auth file and directories; return the config path.

    ``port``, ``lock_db``, ``without_modules`` (``.so`` filenames from
    ``REQUIRED_MODULES`` to leave out) and ``extra_conf`` (more server-level
    directives, appended as they are) exist for the tests that need a second
    instance next to the shared one, configured differently: e.g. without a
    ``DavLockDB`` Apache still advertises locking but cannot grant a lock.

    Raises:
        RuntimeError: no known profile (see :func:`missing_prerequisites`) is fully usable.

    """
    profile = _resolve_profile()
    htpasswd_bin = profile.htpasswd_binary() if profile is not None else None
    if profile is None or htpasswd_bin is None:
        msg = "missing: " + ", ".join(missing_prerequisites())
        raise RuntimeError(msg)
    dav_root = instance_dir / "dav-root"
    if clean:
        shutil.rmtree(dav_root, ignore_errors=True)
    for sub in ("logs", "dav-root", "locks"):
        (instance_dir / sub).mkdir(parents=True, exist_ok=True)
    htpasswd_file = instance_dir / "htpasswd"
    if not htpasswd_file.exists():
        subprocess.run(
            [htpasswd_bin, "-bc", str(htpasswd_file), TEST_USER, TEST_PASSWORD],
            check=True,
        )
    load_modules = "\n".join(
        f"LoadModule {directive:<22} {profile.module_dir / filename}"
        for filename, directive in (*REQUIRED_MODULES, *profile.extra_modules)
        if filename not in profile.built_in and filename not in without_modules
    )
    conf_file = instance_dir / "httpd.conf"
    conf_file.write_text(
        HTTPD_CONF_TEMPLATE.format(
            instance_dir=instance_dir,
            load_modules=load_modules,
            lock_db=LOCK_DB_DIRECTIVE if lock_db else "# no DavLockDB on purpose",
            extra_conf=extra_conf,
            host=HOST,
            port=port,
        )
    )
    return conf_file


def wait_until_up(url: str, timeout: float = 5.0) -> None:
    """Poll ``url`` until it answers at all - even a 401 (auth required) means the server is up.

    Raises:
        RuntimeError: Nothing answered within ``timeout`` seconds.

    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=0.5):  # noqa: S310
                pass
        except urllib.error.HTTPError:
            return  # a real HTTP response (401 included) - the server is up
        except OSError:
            time.sleep(0.1)
        else:
            return
    msg = f"Apache did not come up at {url} within {timeout}s"
    raise RuntimeError(msg)


def start(conf_file: Path, *, port: int = PORT) -> None:
    """Start Apache with ``conf_file``, and wait until it answers requests.

    Raises:
        RuntimeError: No known profile is usable (see :func:`missing_prerequisites`),
            or ``apache2``/``httpd -k start`` itself failed - the message
            includes its stdout/stderr (e.g. the ``AH0....`` diagnostic) plus
            the tail of its own ErrorLog, since ``-k start`` forks into the
            background and may report nothing on stdout/stderr even on a
            fatal startup error, logging it there instead. That output is
            otherwise easy to lose entirely: inherited stdio from a plain,
            uncaptured ``subprocess.run`` doesn't reliably reach the
            pytest-xdist worker's own captured output or the CI log.

    """
    profile = _resolve_profile()
    if profile is None:
        msg = "missing: " + ", ".join(missing_prerequisites())
        raise RuntimeError(msg)
    result = subprocess.run(
        [profile.httpd, "-f", str(conf_file), "-k", "start"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        error_log = conf_file.parent / "logs" / "error.log"
        error_log_tail = (
            error_log.read_text(errors="replace") if error_log.exists() else "(no error.log)"
        )
        msg = (
            f"{profile.httpd} -f {conf_file} -k start "
            f"failed (exit {result.returncode}):\n"
            f"stdout: {result.stdout!r}\n"
            f"stderr: {result.stderr!r}\n"
            f"{error_log}:\n{error_log_tail}"
        )
        raise RuntimeError(msg)
    wait_until_up(f"http://{HOST}:{port}/")


def stop(conf_file: Path) -> None:
    """Stop the Apache instance ``conf_file`` describes."""
    subprocess.run([httpd_binary(), "-f", str(conf_file), "-k", "stop"], check=False)


def httpd_binary() -> str:
    """The resolved profile's ``httpd``/``apache2`` binary - falls back to the first profile's.

    For display purposes (e.g. "stop it with: ...") after :func:`start` has
    already confirmed a profile is usable; not itself a usability check.
    """
    profile = _resolve_profile()
    return profile.httpd if profile is not None else _all_profiles()[0].httpd
