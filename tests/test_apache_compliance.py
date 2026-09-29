"""Manual compliance check against a real Apache + mod_dav server.

Not part of the automated suite (wsgidav already covers that, see
``tests/test_client_e2e.py``) - this is a one-off, independent-
implementation cross-check, since server implementations are known to
disagree on locking/property edge cases in particular. Skipped unless
``WEBDAV_TEST_APACHE_URL`` is set; see ``docs/apache-compliance-check.md``
for how to stand up a throwaway instance.
"""

import io
import os
from collections.abc import Iterator

import pytest

from webdav import Client, ResourceAlreadyExistsError, ResourceLockedError
from webdav.locks import EXCLUSIVE

APACHE_URL = os.environ.get("WEBDAV_TEST_APACHE_URL")
APACHE_AUTH = (
    os.environ.get("WEBDAV_TEST_APACHE_USER", "testuser"),
    os.environ.get("WEBDAV_TEST_APACHE_PASSWORD", "testpass123"),
)

pytestmark = pytest.mark.skipif(
    not APACHE_URL,
    reason="set WEBDAV_TEST_APACHE_URL to run the Apache compliance check",
)


@pytest.fixture
def apache_client() -> Iterator[Client]:
    assert APACHE_URL is not None  # guaranteed by pytestmark's skipif above
    with Client(APACHE_URL, auth=APACHE_AUTH) as c:
        yield c


def test_apache_options_advertises_class_2(apache_client: Client) -> None:
    compliances = apache_client.options()
    assert "1" in compliances
    assert "2" in compliances, "server does not advertise Class 2 (locking) support"


def test_apache_mkdir_upload_download_roundtrip(apache_client: Client) -> None:
    apache_client.mkdir("compliance")
    apache_client.upload_fileobj(io.BytesIO(b"apache says hi"), "compliance/a.txt")

    buf = io.BytesIO()
    apache_client.download_fileobj("compliance/a.txt", buf)
    assert buf.getvalue() == b"apache says hi"


def test_apache_overwrite_protection(apache_client: Client) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"v1"), "compliance/protected.txt")
    with pytest.raises(ResourceAlreadyExistsError):
        apache_client.upload_fileobj(
            io.BytesIO(b"v2"), "compliance/protected.txt", overwrite=False
        )


def test_apache_lock_and_write_with_held_token(apache_client: Client) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"v1"), "compliance/locked.txt")

    with apache_client.lock("compliance/locked.txt", scope=EXCLUSIVE):
        apache_client.upload_fileobj(
            io.BytesIO(b"v2"), "compliance/locked.txt", overwrite=True
        )

    buf = io.BytesIO()
    apache_client.download_fileobj("compliance/locked.txt", buf)
    assert buf.getvalue() == b"v2"


def test_apache_lock_blocks_a_second_client(apache_client: Client) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"v1"), "compliance/locked2.txt")

    assert APACHE_URL is not None  # guaranteed by pytestmark's skipif above
    other = Client(APACHE_URL, auth=APACHE_AUTH)
    try:
        with (
            apache_client.lock("compliance/locked2.txt", scope=EXCLUSIVE),
            pytest.raises(ResourceLockedError),
        ):
            other.upload_fileobj(
                io.BytesIO(b"v2"), "compliance/locked2.txt", overwrite=True
            )
    finally:
        other.close()


def test_apache_set_and_get_custom_property(apache_client: Client) -> None:
    apache_client.upload_fileobj(io.BytesIO(b"x"), "compliance/p.txt")
    apache_client.set_props(
        "compliance/p.txt",
        set_props={("https://example.org/ns", "color"): "blue"},
    )

    props = apache_client.get_props(
        "compliance/p.txt", names=[("https://example.org/ns", "color")]
    )
    assert props.get("https://example.org/ns", "color") == "blue"
