#!/usr/bin/env python3
"""Stand up a throwaway nginx + dav-ext instance and run tests/test_nginx_compliance.py against it.

Everything docs/contributing-nginx.md describes by hand, in one
reproducible command - see that file for what each step does and why.

Note: ``tests/test_nginx_compliance.py`` already starts and stops its own
throwaway instance automatically when run as plain ``pytest`` (no env vars
needed) - this script is for when you want more control: a specific
instance directory, leaving it running afterwards to poke at by hand, or
passing extra arguments through to pytest.

Usage:
    python tools/nginx_compliance_check.py
    python tools/nginx_compliance_check.py --keep-running   # inspect/retry by hand afterwards
    python tools/nginx_compliance_check.py --instance-dir /tmp/my-nginx-test
    python tools/nginx_compliance_check.py -- -k lock -v     # extra args go straight to pytest

Requires ``nginx`` + the ``nginx-dav-ext-module`` (``libnginx-mod-http-dav-ext``
on Debian/Ubuntu) and ``htpasswd`` (``apache2-utils``) - the script checks
for all three and says exactly what is missing, but never installs
anything itself.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tests import nginx_instance  # pylint: disable=wrong-import-position,import-error


def main() -> int:
    """Parse arguments, run the full stand-up/test/tear-down cycle, and return pytest's exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--instance-dir",
        type=Path,
        default=Path("/tmp/nginx-webdav-test"),  # noqa: S108
        help="Where to put the throwaway nginx instance (default: %(default)s)",
    )
    parser.add_argument(
        "--keep-running",
        action="store_true",
        help="Leave nginx running afterwards instead of stopping it",
    )
    parser.add_argument(
        "--no-clean",
        action="store_true",
        help="Do not wipe dav-root before running - reuses whatever state is already there",
    )
    parser.add_argument(
        "pytest_args",
        nargs="*",
        help="Extra arguments passed through to pytest (e.g. -k lock, -v)",
    )
    args = parser.parse_args()

    missing = nginx_instance.missing_prerequisites()
    if missing:
        print("Missing prerequisites:", file=sys.stderr)
        for item in missing:
            print(f"  - {item}", file=sys.stderr)
        print(
            "\nOn Debian/Ubuntu: sudo apt-get install nginx libnginx-mod-http-dav-ext apache2-utils\n"
            "On another distro not in tests/nginx_instance.py's _PROFILES, "
            "add one there - see docs/contributing-nginx.md.",
            file=sys.stderr,
        )
        return 1

    conf_file = nginx_instance.write_instance(args.instance_dir, clean=not args.no_clean)
    nginx_instance.start(conf_file)
    try:
        env = {
            "WEBDAV_TEST_NGINX_URL": f"http://{nginx_instance.HOST}:{nginx_instance.PORT}",
            "WEBDAV_TEST_NGINX_USER": nginx_instance.TEST_USER,
            "WEBDAV_TEST_NGINX_PASSWORD": nginx_instance.TEST_PASSWORD,
        }
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/test_nginx_compliance.py",
                "-n0",  # one shared, persistent dav-root - not test-isolated like wsgidav
                "-v",
                *args.pytest_args,
            ],
            env={**os.environ, **env},
            check=False,
        )
        return result.returncode
    finally:
        if args.keep_running:
            print(
                f"\nnginx left running at http://{nginx_instance.HOST}:{nginx_instance.PORT} "
                f"(user {nginx_instance.TEST_USER!r}, password {nginx_instance.TEST_PASSWORD!r}).\n"
                f"Stop it with: {nginx_instance.nginx_binary()} -c {conf_file} -s stop"
            )
        else:
            nginx_instance.stop(conf_file)


if __name__ == "__main__":
    sys.exit(main())
