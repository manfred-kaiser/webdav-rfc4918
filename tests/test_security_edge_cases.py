"""Invasive security/stability regression tests against an adversarial server.

wsgidav and Apache (the servers used elsewhere in this test suite) are both
RFC-compliant and never exercise these code paths - a redirect-following or
malformed-XML bug simply never triggers against them. These tests use the
deliberately misbehaving server in ``tests/rogue_server.py`` instead, plus a
couple of raw ``http.server`` instances for cross-host scenarios the shared
fixture doesn't cover.

Every test here enforces a fix from the paranoid security audit (see
SECURITY_AUDIT.md) - they all pass against the current code. Several
started out as ``xfail`` (proving the bug); once fixed, the marker was
removed so the test now guards against a regression instead.
"""

import http.server
import io
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

import pytest

from tests.rogue_server import RogueBehavior, rogue_server
from webdav import (
    FileSystem,
    RedirectNotFollowedError,
    RedirectPolicy,
    Session,
    WebDAVError,
)
from webdav.locks import build_lock_body
from webdav.xml_utils import parse_xml

# ---------------------------------------------------------------------------
# Redirect-following on write operations
# ---------------------------------------------------------------------------


def test_put_does_not_follow_redirect_to_a_different_resource() -> None:
    behavior = RogueBehavior(redirect_from="/victim.txt", redirect_target=None)
    with rogue_server(behavior) as url:
        behavior.redirect_target = f"{url}/attacker-stash.txt"
        with FileSystem(url) as fs, pytest.raises(RedirectNotFollowedError):
            fs.upload_fileobj(io.BytesIO(b"secret"), "victim.txt")

    attacker_hits = [r for r in behavior.requests if r[1] == "/attacker-stash.txt"]
    assert (
        not attacker_hits
    ), "request body was forwarded to a location the caller never asked for"


@contextmanager
def _raw_http_server(
    handler_factory: "type[http.server.BaseHTTPRequestHandler]",
) -> Iterator[str]:
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_factory)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join()


def test_string_bodied_write_does_not_leak_across_hosts_on_redirect() -> None:
    attacker_hits: list[bytes] = []

    class Attacker(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a: object) -> None:
            pass

        def do_PROPPATCH(self) -> None:
            length = int(self.headers.get("Content-Length", 0) or 0)
            attacker_hits.append(self.rfile.read(length) if length else b"")
            self.send_response(207)
            self.send_header("Content-Length", "0")
            self.end_headers()

    with _raw_http_server(Attacker) as attacker_url:

        class Victim(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a: object) -> None:
                pass

            def do_PROPPATCH(self) -> None:
                length = int(self.headers.get("Content-Length", 0) or 0)
                self.rfile.read(length) if length else b""
                self.send_response(307)
                self.send_header("Location", f"{attacker_url}/exfil")
                self.send_header("Content-Length", "0")
                self.end_headers()

        with _raw_http_server(Victim) as victim_url:
            fs = FileSystem(victim_url, auth=("realuser", "realpass123"))
            with pytest.raises(RedirectNotFollowedError):
                fs.set_props("victim.txt", set_props={"displayname": "CONFIDENTIAL"})

    assert (
        not attacker_hits
    ), f"request body was forwarded cross-host to the attacker: {attacker_hits!r}"


# ---------------------------------------------------------------------------
# XML parsing: exception-hierarchy contract, and positive controls for the
# XXE/entity-amplification safety claims in webdav/xml_utils.py.
# ---------------------------------------------------------------------------


def test_malformed_multistatus_body_raises_a_webdaverror() -> None:
    behavior = RogueBehavior(malformed_multistatus_body=b"<this is not > < valid xml")
    with (
        rogue_server(behavior) as url,
        FileSystem(url) as fs,
        pytest.raises(WebDAVError),
    ):
        fs.get_props("anything")


def test_xxe_file_entity_is_not_resolved() -> None:
    """Positive control: an external file:// entity must not be resolved."""
    payload = (
        '<?xml version="1.0"?>'
        "<!DOCTYPE d:multistatus [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"
        '<d:multistatus xmlns:d="DAV:"><d:response>'
        "<d:href>/&xxe;</d:href></d:response></d:multistatus>"
    )
    with pytest.raises(Exception):  # noqa: B017, PT011 - expat's own rejection
        parse_xml(payload)


def test_xxe_http_entity_causes_no_outbound_request() -> None:
    """Positive control: an external http:// entity must not trigger an SSRF request."""
    hits: list[str] = []

    class Canary(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a: object) -> None:
            pass

        def do_GET(self) -> None:
            hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    with _raw_http_server(Canary) as canary_url:
        payload = (
            '<?xml version="1.0"?>'
            f"<!DOCTYPE d:multistatus [<!ENTITY xxe SYSTEM '{canary_url}/hit'>]>"
            '<d:multistatus xmlns:d="DAV:"><d:response>'
            "<d:href>/&xxe;</d:href></d:response></d:multistatus>"
        )
        with pytest.raises(Exception):  # noqa: B017, PT011
            parse_xml(payload)
        time.sleep(0.3)

    assert not hits, "external entity triggered an outbound SSRF-style request"


def test_billion_laughs_is_rejected_quickly() -> None:
    """Positive control: expat's amplification limit must reject entity bombs fast."""
    payload = (
        '<?xml version="1.0"?>'
        "<!DOCTYPE lolz ["
        '<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
        '<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">'
        '<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">'
        '<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">'
        '<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">'
        '<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">'
        '<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">'
        "]>"
        '<d:multistatus xmlns:d="DAV:"><d:response><d:href>&lol9;</d:href>'
        "</d:response></d:multistatus>"
    )
    start = time.monotonic()
    with pytest.raises(Exception):  # noqa: B017, PT011
        parse_xml(payload)
    assert time.monotonic() - start < 5.0, "entity bomb was not rejected quickly"


# ---------------------------------------------------------------------------
# client-side header/CRLF injection resilience via a malicious lock token
# ---------------------------------------------------------------------------


def test_owner_with_crlf_stays_inside_the_xml_body() -> None:
    """A CRLF in a lock owner must never escape into raw HTTP header territory.

    It legitimately ends up as literal text inside the <owner> XML element -
    that's fine, XML text content permits it - the point of this test is
    only that build_lock_body() never lets it influence anything outside
    the XML body it returns.
    """
    body = build_lock_body(owner="attacker\r\nX-Injected: evil")
    tree = parse_xml(body)
    owner_text = tree.findtext(".//{DAV:}owner")
    # XML 1.0 sec. 2.11 mandates \r\n -> \n line-ending normalization on
    # parse, so the round-tripped text legitimately differs from the input
    # by that one substitution - the point being tested is that it stays a
    # single XML text node, not raw bytes that could affect anything else.
    assert owner_text == "attacker\r\nX-Injected: evil"


# ---------------------------------------------------------------------------
# get_props()/info() correctness for zero/falsy values
# ---------------------------------------------------------------------------


def test_an_empty_file_has_size_zero_not_none(fs: FileSystem) -> None:
    fs.upload_fileobj(io.BytesIO(b""), "empty.txt")
    assert fs.get_props("empty.txt", names=["content_length"]).content_length == 0
    assert fs.info("empty.txt").size == 0
    assert fs.content_length("empty.txt") == 0


# ---------------------------------------------------------------------------
# Symlink protection on local downloads (positive control)
# ---------------------------------------------------------------------------


def test_download_file_refuses_to_follow_a_local_symlink(
    fs: FileSystem, tmp_path: Path
) -> None:
    fs.upload_fileobj(io.BytesIO(b"remote content"), "dl.txt")

    real_target = tmp_path / "real_target.txt"
    real_target.write_text("do not touch")
    link = tmp_path / "link.txt"
    link.symlink_to(real_target)

    with pytest.raises(OSError):  # noqa: PT011
        fs.download_file("dl.txt", link)

    assert real_target.read_text() == "do not touch"


# ---------------------------------------------------------------------------
# A malicious LOCK response's <lockroot> must never redirect this client's
# own lock bookkeeping to a path the caller never asked to lock.
# ---------------------------------------------------------------------------


def test_spoofed_lockroot_does_not_redirect_lock_bookkeeping() -> None:
    """A server's <lockroot> for a granted lock must never be trusted blindly.

    Found during a later invasive re-audit of the RFC-compliance fixes
    themselves: an earlier version of Session._lock_bookkeeping_path() used
    the server-reported <lockroot> to key self._locks, on the RFC-literal
    reasoning that lockroot is authoritative. A malicious/compromised
    server can set <lockroot> to an entirely unrelated href (even on a
    different host - only the path component was ever read) with nothing
    to cross-check it against. That let the server silently redirect this
    client's own bookkeeping: the resource the caller actually locked
    would carry no `If` token on a later write (so a real conflict
    wouldn't be reported as one), while an unrelated resource the caller
    never locked would start silently carrying one. Fixed by always
    keying bookkeeping off the requested path, never the server-supplied
    lockroot.
    """
    spoofed_root_body = (
        b'<?xml version="1.0"?>'
        b'<d:prop xmlns:d="DAV:"><d:lockdiscovery><d:activelock>'
        b"<d:lockscope><d:exclusive/></d:lockscope>"
        b"<d:locktype><d:write/></d:locktype>"
        b"<d:depth>infinity</d:depth>"
        b"<d:locktoken><d:href>opaquelocktoken:spoofed</d:href></d:locktoken>"
        b"<d:lockroot><d:href>/other-secret.txt</d:href></d:lockroot>"
        b"</d:activelock></d:lockdiscovery></d:prop>"
    )

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a: object) -> None:
            pass

        def do_LOCK(self) -> None:
            length = int(self.headers.get("Content-Length", 0) or 0)
            self.rfile.read(length) if length else b""
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Lock-Token", "<opaquelocktoken:spoofed>")
            self.send_header("Content-Length", str(len(spoofed_root_body)))
            self.end_headers()
            self.wfile.write(spoofed_root_body)

        def do_UNLOCK(self) -> None:
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()

    with (
        _raw_http_server(Handler) as url,
        Session(url) as client,
        FileSystem.from_session(client).locked(
            "victim.txt", scope="exclusive"
        ) as active_lock,
    ):
        assert active_lock.lock_root == "/other-secret.txt"  # the server's lie
        # Bookkeeping must follow what the caller asked for, not the lie.
        assert client.locks.token_for(client.resolve_url("victim.txt")) is not None
        assert client.locks.token_for(client.resolve_url("other-secret.txt")) is None


# ---------------------------------------------------------------------------
# The trailing-slash-retry usability fix (some servers 301 a collection
# request missing its trailing slash) must never trust the server's
# Location for where to retry.
# ---------------------------------------------------------------------------


def test_missing_trailing_slash_same_origin_redirect_is_followed() -> None:
    """A legitimate same-origin "add a trailing slash" redirect must work.

    Found via comparison with a sibling project's PR: some WebDAV servers
    301 a PROPFIND missing its trailing slash instead of just serving the
    collection - after this library defaulted every request to refuse
    all redirects, that broke info()/exists()/isdir()/get_props() against
    such a server. Superseded by the general same-origin redirect-
    following policy (RedirectPolicy.SAME_ORIGIN, the default): a
    same-origin 301 just adding "/" is simply one instance of "a
    same-origin redirect", nothing trailing-slash-specific about the
    handling anymore. See
    test_cross_origin_redirect_is_refused_even_with_a_plausible_pretext
    for confirmation that an *untrue* same-origin claim (a redirect to an
    unrelated origin, whatever pretext the server gives it) is still
    refused.
    """

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a: object) -> None:
            pass

        def do_PROPFIND(self) -> None:
            length = int(self.headers.get("Content-Length", 0) or 0)
            self.rfile.read(length) if length else b""
            if not self.path.endswith("/"):
                self.send_response(301)
                self.send_header("Location", self.path + "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = (
                b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response>'
                b"<d:href>/somedir/</d:href><d:propstat><d:prop>"
                b"<d:resourcetype><d:collection/></d:resourcetype></d:prop>"
                b"<d:status>HTTP/1.1 200 OK</d:status></d:propstat>"
                b"</d:response></d:multistatus>"
            )
            self.send_response(207)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with _raw_http_server(Handler) as url, FileSystem(url) as fs:
        assert fs.exists("somedir") is True
        assert fs.isdir("somedir") is True


def test_cross_origin_redirect_is_refused_even_with_a_plausible_pretext() -> None:
    """A redirect to an untrusted origin is refused no matter what triggered it.

    Same missing-trailing-slash pretext as the test above, but this time
    the server's Location points at a different origin entirely - the
    plausible-looking pretext must not earn it any more trust than an
    outright cross-host body-exfiltration attempt would get.
    """

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a: object) -> None:
            pass

        def do_PROPFIND(self) -> None:
            length = int(self.headers.get("Content-Length", 0) or 0)
            self.rfile.read(length) if length else b""
            self.send_response(301)
            self.send_header("Location", "http://attacker.invalid/pwned")
            self.send_header("Content-Length", "0")
            self.end_headers()

    with (
        _raw_http_server(Handler) as url,
        FileSystem(url) as fs,
        pytest.raises(RedirectNotFollowedError),
    ):
        fs.exists("somedir")


def test_trusted_cross_origin_redirect_does_not_forward_credentials() -> None:
    """A trusted-but-different redirect target must never receive this client's auth.

    Being trusted enough to receive the request's body (e.g. a
    signed-upload gateway pattern, via RedirectPolicy.WHITELIST) doesn't
    make that origin trusted with this client's separate WebDAV-server
    credentials too - requests' own native redirect-following strips
    Authorization on a host change (Session.rebuild_auth); following
    redirects via this client's own loop instead bypasses that unless it
    replicates the same stripping itself.
    """
    received: dict[str, object] = {}

    class Storage(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a: object) -> None:
            pass

        def do_PROPPATCH(self) -> None:
            length = int(self.headers.get("Content-Length", 0) or 0)
            received["body"] = self.rfile.read(length) if length else b""
            received["had_auth"] = "Authorization" in self.headers
            body = (
                b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"></d:multistatus>'
            )
            self.send_response(207)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with _raw_http_server(Storage) as storage_url:

        class Gateway(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a: object) -> None:
                pass

            def do_PROPPATCH(self) -> None:
                length = int(self.headers.get("Content-Length", 0) or 0)
                self.rfile.read(length) if length else b""
                self.send_response(307)
                self.send_header("Location", f"{storage_url}/upload-target")
                self.send_header("Content-Length", "0")
                self.end_headers()

        with (
            _raw_http_server(Gateway) as gateway_url,
            FileSystem(
                gateway_url,
                auth=("secretuser", "secretpass"),
                redirect_policy=RedirectPolicy.WHITELIST,
                trusted_redirect_origins=[storage_url],
            ) as fs,
        ):
            fs.set_props("victim.txt", set_props={"displayname": "x"})

    assert received["had_auth"] is False
    assert b"displayname" in cast("bytes", received["body"])
