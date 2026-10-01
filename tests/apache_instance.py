"""Stand up / tear down a throwaway Apache + mod_dav instance.

Shared by the ``apache_url`` pytest fixture (see ``test_apache_compliance.py``,
which uses it automatically whenever a usable Apache is found - no manual
step needed) and ``tools/apache_compliance_check.py`` (manual/debugging use:
inspect a running instance, keep it up after a failure, point at a specific
directory). One implementation, so the two can never drift apart.
"""

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

    def missing(self) -> list[str]:
        """What is missing for this specific profile - empty if it is fully usable."""
        missing = []
        if not Path(self.httpd).exists():
            missing.append(self.httpd)
        missing += [
            str(self.module_dir / filename)
            for filename, _directive in REQUIRED_MODULES
            if filename not in self.built_in
            and not (self.module_dir / filename).exists()
        ]
        return missing


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


def _resolve_profile() -> "_Profile | None":
    """The first fully-usable profile, or ``None`` if every one is missing something."""
    for profile in _PROFILES:
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

DavLockDB "locks/davlock"

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
"""


def missing_prerequisites() -> list[str]:
    """What is missing to stand up a local instance - empty if any one known profile is fully usable.

    Each item is prefixed with which profile it belongs to, since more than
    one may be partially present (e.g. a stray ``httpd`` binary with no
    matching modules) without either being usable on its own.
    """
    if _resolve_profile() is not None:
        return []
    if shutil.which("htpasswd") is None:
        return ["htpasswd (package: apache2-utils, or your distro's equivalent)"]
    return [
        f"[{profile.name}] {item}"
        for profile in _PROFILES
        for item in profile.missing()
    ]


def write_instance(instance_dir: Path, *, clean: bool = True) -> Path:
    """Create/refresh the instance's config, auth file and directories; return the config path.

    Raises:
        RuntimeError: no known profile (see :func:`missing_prerequisites`) is fully usable.

    """
    profile = _resolve_profile()
    if profile is None or shutil.which("htpasswd") is None:
        msg = "missing: " + ", ".join(missing_prerequisites())
        raise RuntimeError(msg)
    dav_root = instance_dir / "dav-root"
    if clean:
        shutil.rmtree(dav_root, ignore_errors=True)
    for sub in ("logs", "dav-root", "locks"):
        (instance_dir / sub).mkdir(parents=True, exist_ok=True)
    htpasswd_file = instance_dir / "htpasswd"
    if not htpasswd_file.exists():
        htpasswd_bin = shutil.which("htpasswd")
        assert htpasswd_bin is not None  # checked above
        subprocess.run(
            [htpasswd_bin, "-bc", str(htpasswd_file), TEST_USER, TEST_PASSWORD],
            check=True,
        )
    load_modules = "\n".join(
        f"LoadModule {directive:<22} {profile.module_dir / filename}"
        for filename, directive in REQUIRED_MODULES
        if filename not in profile.built_in
    )
    conf_file = instance_dir / "httpd.conf"
    conf_file.write_text(
        HTTPD_CONF_TEMPLATE.format(
            instance_dir=instance_dir,
            load_modules=load_modules,
            host=HOST,
            port=PORT,
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


def start(conf_file: Path) -> None:
    """Start Apache with ``conf_file``, and wait until it answers requests.

    Raises:
        RuntimeError: No known profile is usable (see :func:`missing_prerequisites`) -
            checked again here since a caller may hold a stale ``conf_file``
            from a profile that stopped being usable since it was written.

    """
    profile = _resolve_profile()
    if profile is None:
        msg = "missing: " + ", ".join(missing_prerequisites())
        raise RuntimeError(msg)
    subprocess.run([profile.httpd, "-f", str(conf_file), "-k", "start"], check=True)
    wait_until_up(f"http://{HOST}:{PORT}/")


def stop(conf_file: Path) -> None:
    """Stop the Apache instance ``conf_file`` describes."""
    subprocess.run([httpd_binary(), "-f", str(conf_file), "-k", "stop"], check=False)


def httpd_binary() -> str:
    """The resolved profile's ``httpd``/``apache2`` binary - falls back to the first profile's.

    For display purposes (e.g. "stop it with: ...") after :func:`start` has
    already confirmed a profile is usable; not itself a usability check.
    """
    profile = _resolve_profile()
    return profile.httpd if profile is not None else _PROFILES[0].httpd
