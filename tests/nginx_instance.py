"""Stand up / tear down a throwaway nginx + dav-ext instance.

Same role as ``apache_instance.py`` (shared by the ``nginx_url``-style
pytest fixture in ``test_nginx_compliance.py`` and, for manual/debugging
use, ``tools/nginx_compliance_check.py``), for a second, differently
limited real Class 2 (locking) implementation: nginx's own
``ngx_http_dav_module`` (GET/PUT/DELETE/MKCOL/COPY/MOVE) plus
``nginx-dav-ext-module`` (PROPFIND/PROPPATCH/OPTIONS/LOCK/UNLOCK) only
supports *exclusive* locks, unlike Apache's full Class 2 - see
``test_nginx_compliance.py`` for what that means for this suite.
"""

import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

#: Confirmed working on GitHub Actions' ubuntu-latest - apt's own
#: "nginx" + "libnginx-mod-http-dav-ext" packages, no extra repo needed.
#: Not yet confirmed on any RPM-based distro (no equivalent package found
#: via zypper at the time this was written) - add a profile below if one
#: turns up, same as apache_instance.py's own multi-profile story.
TEST_USER = "testuser"
TEST_PASSWORD = "testpass123"  # noqa: S105
HOST = "127.0.0.1"
PORT = 8766


@dataclass(frozen=True)
class _Profile:
    """Where one distro's nginx package puts its binary and the dav-ext module."""

    name: str
    nginx: str
    dav_ext_module: Path
    modules_enabled_dir: Path

    def missing(self) -> list[str]:
        """What is missing for this specific profile - empty if it is fully usable."""
        missing = []
        if not Path(self.nginx).exists():
            missing.append(self.nginx)
        if not self.dav_ext_module.exists():
            missing.append(str(self.dav_ext_module))
        return missing


#: Tried in order; the first fully present one wins.
_PROFILES = (
    _Profile(
        "Debian/Ubuntu",
        "/usr/sbin/nginx",
        Path("/usr/lib/nginx/modules/ngx_http_dav_ext_module.so"),
        Path("/etc/nginx/modules-enabled"),
    ),
)


def _resolve_profile() -> "_Profile | None":
    """The first fully-usable profile, or ``None`` if every one is missing something."""
    for profile in _PROFILES:
        if not profile.missing():
            return profile
    return None


NGINX_CONF_TEMPLATE = """\
pid "{instance_dir}/nginx.pid";
error_log "{instance_dir}/error.log" warn;

load_module "{dav_ext_module}";

events {{
    worker_connections 64;
}}

http {{
    access_log off;
    client_body_temp_path "{instance_dir}/client_body" 1 2;

    dav_ext_lock_zone zone=davlock:1m;

    server {{
        listen {host}:{port};

        location / {{
            root "{dav_root}";
            dav_methods PUT DELETE MKCOL COPY MOVE;
            dav_ext_methods PROPFIND OPTIONS LOCK UNLOCK;
            dav_ext_lock zone=davlock;
            create_full_put_path on;
            dav_access user:rw group:rw all:r;
            autoindex on;

            auth_basic "webdav-rfc4918 test";
            auth_basic_user_file "{instance_dir}/htpasswd";
        }}
    }}
}}
"""


def missing_prerequisites() -> list[str]:
    """What is missing to stand up a local instance - empty if any one known profile is fully usable."""
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
        RuntimeError: No known profile (see :func:`missing_prerequisites`) is fully usable.

    """
    profile = _resolve_profile()
    if profile is None or shutil.which("htpasswd") is None:
        msg = "missing: " + ", ".join(missing_prerequisites())
        raise RuntimeError(msg)
    dav_root = instance_dir / "dav-root"
    if clean:
        shutil.rmtree(dav_root, ignore_errors=True)
    for sub in ("dav-root", "client_body"):
        (instance_dir / sub).mkdir(parents=True, exist_ok=True)
    htpasswd_file = instance_dir / "htpasswd"
    if not htpasswd_file.exists():
        htpasswd_bin = shutil.which("htpasswd")
        assert htpasswd_bin is not None  # checked above
        subprocess.run(
            [htpasswd_bin, "-bc", str(htpasswd_file), TEST_USER, TEST_PASSWORD],
            check=True,
        )
    conf_file = instance_dir / "nginx.conf"
    conf_file.write_text(
        NGINX_CONF_TEMPLATE.format(
            instance_dir=instance_dir,
            dav_ext_module=profile.dav_ext_module,
            dav_root=dav_root,
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
    msg = f"nginx did not come up at {url} within {timeout}s"
    raise RuntimeError(msg)


def start(conf_file: Path) -> None:
    """Start nginx with ``conf_file``, and wait until it answers requests.

    Raises:
        RuntimeError: No known profile is usable (see
            :func:`missing_prerequisites`), or ``nginx`` itself failed to
            start - the message includes its stderr plus the tail of its
            own error log, for the same reason ``apache_instance.py``'s
            ``start()`` does: a daemonizing server can report nothing
            useful on stdout/stderr even on a fatal config error.

    """
    profile = _resolve_profile()
    if profile is None:
        msg = "missing: " + ", ".join(missing_prerequisites())
        raise RuntimeError(msg)
    result = subprocess.run(
        [profile.nginx, "-c", str(conf_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        error_log = conf_file.parent / "error.log"
        error_log_tail = (
            error_log.read_text(errors="replace") if error_log.exists() else "(no error.log)"
        )
        msg = (
            f"{profile.nginx} -c {conf_file} failed (exit {result.returncode}):\n"
            f"stdout: {result.stdout!r}\n"
            f"stderr: {result.stderr!r}\n"
            f"{error_log}:\n{error_log_tail}"
        )
        raise RuntimeError(msg)
    wait_until_up(f"http://{HOST}:{PORT}/")


def stop(conf_file: Path) -> None:
    """Stop the nginx instance ``conf_file`` describes."""
    subprocess.run([nginx_binary(), "-c", str(conf_file), "-s", "stop"], check=False)


def nginx_binary() -> str:
    """The resolved profile's ``nginx`` binary - falls back to the first profile's.

    For display purposes, after :func:`start` already confirmed a profile
    is usable; not itself a usability check.
    """
    profile = _resolve_profile()
    return profile.nginx if profile is not None else _PROFILES[0].nginx
