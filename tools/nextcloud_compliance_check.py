#!/usr/bin/env python3
"""Stand up a throwaway Nextcloud container and run tests/test_nextcloud_compliance.py against it.

Everything docs/contributing-nextcloud.md describes by hand, in one
reproducible command.

Note: ``tests/test_nextcloud_compliance.py`` already starts and stops its
own throwaway container automatically when run as plain ``pytest`` (no
env vars needed) - this script is for when you want more control: leaving
it running afterwards to poke at by hand, or passing extra arguments
through to pytest.

Usage:
    python tools/nextcloud_compliance_check.py
    python tools/nextcloud_compliance_check.py --keep-running   # inspect/retry by hand afterwards
    python tools/nextcloud_compliance_check.py -- -k lock -v     # extra args go straight to pytest

Requires a usable Docker daemon - the script checks for one and says
exactly what is missing, but never installs anything itself.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tests import (
    nextcloud_instance,  # pylint: disable=wrong-import-position,import-error
)


def main() -> int:
    """Parse arguments, run the full stand-up/test/tear-down cycle, and return pytest's exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep-running",
        action="store_true",
        help="Leave the Nextcloud container running afterwards instead of removing it",
    )
    parser.add_argument(
        "pytest_args",
        nargs="*",
        help="Extra arguments passed through to pytest (e.g. -k lock, -v)",
    )
    args = parser.parse_args()

    missing = nextcloud_instance.missing_prerequisites()
    if missing:
        print("Missing prerequisites:", file=sys.stderr)
        for item in missing:
            print(f"  - {item}", file=sys.stderr)
        return 1

    nextcloud_instance.start()
    try:
        url = (
            f"http://{nextcloud_instance.HOST}:{nextcloud_instance.PORT}"
            f"/remote.php/dav/files/{nextcloud_instance.TEST_USER}"
        )
        env = {
            "WEBDAV_TEST_NEXTCLOUD_URL": url,
            "WEBDAV_TEST_NEXTCLOUD_USER": nextcloud_instance.TEST_USER,
            "WEBDAV_TEST_NEXTCLOUD_PASSWORD": nextcloud_instance.TEST_PASSWORD,
        }
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/test_nextcloud_compliance.py",
                "-n0",  # one shared, persistent account - not test-isolated like wsgidav
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
                f"\nNextcloud left running at "
                f"http://{nextcloud_instance.HOST}:{nextcloud_instance.PORT} "
                f"(user {nextcloud_instance.TEST_USER!r}, "
                f"password {nextcloud_instance.TEST_PASSWORD!r}).\n"
                f"Stop it with: docker rm -f {nextcloud_instance.CONTAINER_NAME}"
            )
        else:
            nextcloud_instance.stop()


if __name__ == "__main__":
    sys.exit(main())
