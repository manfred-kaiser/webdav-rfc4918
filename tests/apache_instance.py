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
from pathlib import Path

HTTPD = "/usr/sbin/httpd"
#: openSUSE's module directory - see docs/apache-compliance-check.md if
#: this does not match your distro.
MODULE_DIR = Path("/usr/lib64/apache2-prefork")
REQUIRED_MODULES = (
    "mod_authn_core.so",
    "mod_authz_core.so",
    "mod_authn_file.so",
    "mod_authz_user.so",
    "mod_auth_basic.so",
    "mod_mime.so",
    "mod_log_config.so",
    "mod_dav.so",
    "mod_dav_fs.so",
    "mod_dav_lock.so",
)
TEST_USER = "testuser"
TEST_PASSWORD = "testpass123"  # noqa: S105
HOST = "127.0.0.1"
PORT = 8765

HTTPD_CONF_TEMPLATE = """\
ServerRoot "{instance_dir}"
ServerName localhost
Listen {host}:{port}

PidFile "logs/httpd.pid"
ErrorLog "logs/error.log"
LogLevel warn

LoadModule authn_core_module   {modules}/mod_authn_core.so
LoadModule authz_core_module   {modules}/mod_authz_core.so
LoadModule authn_file_module   {modules}/mod_authn_file.so
LoadModule authz_user_module   {modules}/mod_authz_user.so
LoadModule auth_basic_module   {modules}/mod_auth_basic.so
LoadModule mime_module         {modules}/mod_mime.so
LoadModule log_config_module   {modules}/mod_log_config.so
LoadModule dav_module          {modules}/mod_dav.so
LoadModule dav_fs_module       {modules}/mod_dav_fs.so
LoadModule dav_lock_module     {modules}/mod_dav_lock.so

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
    """What is missing to stand up a local instance - empty if nothing is."""
    missing = []
    if not Path(HTTPD).exists():
        missing.append(f"{HTTPD} (package: apache2)")
    if shutil.which("htpasswd") is None:
        missing.append("htpasswd (package: apache2-utils)")
    missing += [
        f"{MODULE_DIR / name}"
        for name in REQUIRED_MODULES
        if not (MODULE_DIR / name).exists()
    ]
    return missing


def write_instance(instance_dir: Path, *, clean: bool = True) -> Path:
    """Create/refresh the instance's config, auth file and directories; return the config path.

    Raises:
        RuntimeError: a prerequisite (see :func:`missing_prerequisites`) is missing.

    """
    missing = missing_prerequisites()
    if missing:
        msg = "missing: " + ", ".join(missing)
        raise RuntimeError(msg)
    dav_root = instance_dir / "dav-root"
    if clean:
        shutil.rmtree(dav_root, ignore_errors=True)
    for sub in ("logs", "dav-root", "locks"):
        (instance_dir / sub).mkdir(parents=True, exist_ok=True)
    htpasswd_file = instance_dir / "htpasswd"
    if not htpasswd_file.exists():
        htpasswd_bin = shutil.which("htpasswd")
        assert (
            htpasswd_bin is not None
        )  # missing_prerequisites() would have raised above
        subprocess.run(
            [htpasswd_bin, "-bc", str(htpasswd_file), TEST_USER, TEST_PASSWORD],
            check=True,
        )
    conf_file = instance_dir / "httpd.conf"
    conf_file.write_text(
        HTTPD_CONF_TEMPLATE.format(
            instance_dir=instance_dir, modules=MODULE_DIR, host=HOST, port=PORT
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
    """Start Apache with ``conf_file``, and wait until it answers requests."""
    subprocess.run([HTTPD, "-f", str(conf_file), "-k", "start"], check=True)
    wait_until_up(f"http://{HOST}:{PORT}/")


def stop(conf_file: Path) -> None:
    """Stop the Apache instance ``conf_file`` describes."""
    subprocess.run([HTTPD, "-f", str(conf_file), "-k", "stop"], check=False)
