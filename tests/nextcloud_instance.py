"""Stand up / tear down a throwaway Nextcloud instance (Docker).

Same role as ``apache_instance.py``/``nginx_instance.py`` (shared by the
``nextcloud_url``-style pytest fixture in ``test_nextcloud_compliance.py``
and, for manual/debugging use, ``tools/nextcloud_compliance_check.py``),
but Docker-backed rather than apt-backed: Nextcloud has no system package
on either distro this project otherwise targets, and the official image
is the realistic way most deployments actually run it.
"""

import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request

#: Exact, deliberately pinned image tag - bumping it is a conscious act,
#: the same policy this project already applies to ruff/mypy. Check
#: https://hub.docker.com/_/nextcloud/tags for the current stable line
#: before bumping.
IMAGE = "nextcloud:35.0.1-apache"
CONTAINER_NAME = "webdav-rfc4918-nextcloud-test"
TEST_USER = "admin"
TEST_PASSWORD = "testpass123"  # noqa: S105
HOST = "127.0.0.1"
PORT = 8767


def _docker_binary() -> "str | None":
    """The resolved ``docker`` binary, or ``None`` if it isn't on ``PATH``."""
    return shutil.which("docker")


def missing_prerequisites() -> list[str]:
    """What is missing to stand up a local instance - empty if Docker is usable."""
    docker = _docker_binary()
    if docker is None:
        return ["docker"]
    result = subprocess.run([docker, "info"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return ["a running docker daemon (docker info failed - started? permissions?)"]
    return []


def _docker_logs(docker: str) -> str:
    result = subprocess.run(
        [docker, "logs", CONTAINER_NAME], capture_output=True, text=True, check=False
    )
    return result.stdout + result.stderr


def start(*, timeout: float = 180.0) -> None:
    """Start a throwaway Nextcloud container and wait until it finishes installing.

    Raises:
        RuntimeError: Docker is not usable (see :func:`missing_prerequisites`),
            ``docker run`` itself failed, or Nextcloud did not report
            ``installed: true`` on ``/status.php`` within ``timeout`` -
            either way, the message includes ``docker logs`` for the
            instance, for the same reason ``apache_instance.py``'s
            ``start()`` includes its ErrorLog tail.

    """
    missing = missing_prerequisites()
    if missing:
        msg = "missing: " + ", ".join(missing)
        raise RuntimeError(msg)
    docker = _docker_binary()
    assert docker is not None  # checked above
    subprocess.run([docker, "rm", "-f", CONTAINER_NAME], capture_output=True, check=False)
    result = subprocess.run(
        [
            docker,
            "run",
            "-d",
            "--name",
            CONTAINER_NAME,
            "-p",
            f"{PORT}:80",
            "-e",
            "SQLITE_DATABASE=nc.db",
            "-e",
            f"NEXTCLOUD_ADMIN_USER={TEST_USER}",
            "-e",
            f"NEXTCLOUD_ADMIN_PASSWORD={TEST_PASSWORD}",
            "-e",
            f"NEXTCLOUD_TRUSTED_DOMAINS={HOST}",
            IMAGE,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        msg = (
            f"docker run failed (exit {result.returncode}):\n"
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )
        raise RuntimeError(msg)

    status_url = f"http://{HOST}:{PORT}/status.php"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(status_url, timeout=2) as resp:  # noqa: S310
                status = json.loads(resp.read())
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            time.sleep(1)
            continue
        if status.get("installed"):
            return
        time.sleep(1)
    logs = _docker_logs(docker)
    stop()
    msg = (
        f"Nextcloud did not report installed:true at {status_url} "
        f"within {timeout}s - docker logs:\n{logs}"
    )
    raise RuntimeError(msg)


def stop() -> None:
    """Remove the throwaway Nextcloud container."""
    docker = _docker_binary()
    if docker is None:
        return
    subprocess.run([docker, "rm", "-f", CONTAINER_NAME], capture_output=True, check=False)
