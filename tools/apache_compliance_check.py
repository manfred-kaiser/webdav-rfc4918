#!/usr/bin/env python3
"""Stand up a throwaway Apache + mod_dav instance and run tests/test_apache_compliance.py against it.

Everything docs/apache-compliance-check.md describes by hand, in one
reproducible command - see that file for what each step does and why, and
for troubleshooting if a step here fails on a distro other than openSUSE
(the module paths in particular are openSUSE's, see
``tests/apache_instance.py``).

Note: ``tests/test_apache_compliance.py`` already starts and stops its own
throwaway instance automatically when run as plain ``pytest`` (no env vars
needed) - this script is for when you want more control: a specific
instance directory, leaving it running afterwards to poke at by hand, or
passing extra arguments through to pytest.

Usage:
    python tools/apache_compliance_check.py
    python tools/apache_compliance_check.py --keep-running   # inspect/retry by hand afterwards
    python tools/apache_compliance_check.py --instance-dir /tmp/my-apache-test
    python tools/apache_compliance_check.py -- -k lock -v     # extra args go straight to pytest

Requires ``apache2``/``apache2-utils`` (``httpd``, ``htpasswd``) - the
script checks for both and says exactly what is missing, but never installs
anything itself.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tests import apache_instance  # pylint: disable=wrong-import-position,import-error


def main() -> int:
    """Parse arguments, run the full stand-up/test/tear-down cycle, and return pytest's exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--instance-dir",
        type=Path,
        default=Path("/tmp/apache-webdav-test"),  # noqa: S108
        help="Where to put the throwaway Apache instance (default: %(default)s)",
    )
    parser.add_argument(
        "--keep-running",
        action="store_true",
        help="Leave Apache running afterwards instead of stopping it",
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

    missing = apache_instance.missing_prerequisites()
    if missing:
        print("Missing prerequisites:", file=sys.stderr)
        for item in missing:
            print(f"  - {item}", file=sys.stderr)
        print(
            "\nOn openSUSE: sudo zypper install apache2 apache2-utils\n"
            "On Debian/Ubuntu: sudo apt-get install apache2 apache2-utils\n"
            "On another distro not in tests/apache_instance.py's _PROFILES, "
            "add one there - see docs/apache-compliance-check.md.",
            file=sys.stderr,
        )
        return 1

    conf_file = apache_instance.write_instance(
        args.instance_dir, clean=not args.no_clean
    )
    apache_instance.start(conf_file)
    try:
        env = {
            "WEBDAV_TEST_APACHE_URL": f"http://{apache_instance.HOST}:{apache_instance.PORT}",
            "WEBDAV_TEST_APACHE_USER": apache_instance.TEST_USER,
            "WEBDAV_TEST_APACHE_PASSWORD": apache_instance.TEST_PASSWORD,
        }
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/test_apache_compliance.py",
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
                f"\nApache left running at http://{apache_instance.HOST}:{apache_instance.PORT} "
                f"(user {apache_instance.TEST_USER!r}, password {apache_instance.TEST_PASSWORD!r}).\n"
                f"Stop it with: {apache_instance.httpd_binary()} -f {conf_file} -k stop"
            )
        else:
            apache_instance.stop(conf_file)


if __name__ == "__main__":
    sys.exit(main())
