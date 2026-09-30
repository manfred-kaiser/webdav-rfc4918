"""Property-based tests for the parsers that redirect and lock safety rests on.

The security of redirect handling depends on a handful of small functions
agreeing with the HTTP library about what a URL means; example-based tests
only cover the inputs their author thought of, so these throw generated
strings at them and check the *invariants* instead.
"""

import ipaddress
from posixpath import normpath
from urllib.parse import urlsplit

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from webdav import RedirectPolicy, Session
from webdav.dav.locks import LockRegistry
from webdav.dav.urls import join_url_path
from webdav.transport.redirects import effective_origin, redact_url

pytestmark = pytest.mark.filterwarnings("ignore")

FAST = settings(
    max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)

_host = st.from_regex(r"[a-z0-9][a-z0-9.-]{0,12}", fullmatch=True)
_hostile = st.sampled_from(
    ["", "\\", "@", "\t", "\n", "\x00", " ", "%00", "%5c", "#", "?"]
)

#: URLs that are *mostly* well-formed, with hostile pieces spliced in - random
#: text alone almost never reaches the branches that accept a URL at all.
url_like = st.one_of(
    st.text(max_size=80),
    st.builds(
        "{}://{}{}{}{}{}/{}".format,
        st.sampled_from(["http", "https", "HTTP", "ftp", "file", "", "javascript"]),
        st.one_of(
            st.just(""), st.from_regex(r"[a-z]{1,5}(:[a-z]{1,5})?@", fullmatch=True)
        ),
        _hostile,
        _host,
        st.sampled_from(["", ":80", ":443", ":8080", ":0", ":99999", ":x"]),
        _hostile,
        st.text(alphabet="abc/.%?#@\\ \r\n", max_size=10),
    ),
)


@FAST
@given(url=url_like)
def test_effective_origin_never_raises_and_only_accepts_plain_http_urls(
    url: str,
) -> None:
    origin = effective_origin(url)
    if origin is None:
        return
    scheme, host, port = origin
    assert scheme in ("http", "https")
    assert host
    assert 0 < port < 65536
    assert "@" not in urlsplit(url).netloc
    assert "\\" not in url
    assert not any(ord(c) < 0x20 or ord(c) == 0x7F for c in url)


@FAST
@given(
    host=st.from_regex(
        r"[a-z][a-z0-9-]{0,12}(\.[a-z][a-z0-9-]{0,8}){0,2}", fullmatch=True
    ),
    port=st.integers(min_value=1, max_value=65535),
    scheme=st.sampled_from(["http", "https"]),
)
def test_effective_origin_ignores_case_path_and_default_ports(
    host: str, port: int, scheme: str
) -> None:
    default = {"http": 80, "https": 443}[scheme]
    a = effective_origin(f"{scheme}://{host}:{port}/one?x=1")
    b = effective_origin(f"{scheme.upper()}://{host.upper()}:{port}/two#frag")
    assert a is not None
    assert a == b == (scheme, host, port)
    if port == default:
        assert effective_origin(f"{scheme}://{host}/") == a


@FAST
@given(a=st.ip_addresses(v=4) | st.ip_addresses(v=6), port=st.integers(1, 65535))
def test_effective_origin_reads_ip_literals_like_ipaddress(
    a: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int
) -> None:
    literal = f"[{a}]" if a.version == 6 else str(a)
    origin = effective_origin(f"http://{literal}:{port}/")
    assert origin is not None
    assert ipaddress.ip_address(origin[1]) == a


@FAST
@given(
    base=st.sampled_from(["/", "/dav", "/dav/root", "/a b"]),
    parts=st.lists(
        st.sampled_from(["..", ".", "a", "b", "", "a b", "...", "c/../d", "//"]),
        max_size=8,
    ),
)
def test_join_url_path_never_leaves_the_base(base: str, parts: list[str]) -> None:
    try:
        joined = join_url_path(base, "/".join(parts))
    except ValueError:
        return
    normalized = base.rstrip("/") or "/"
    assert joined == normalized or joined.startswith(normalized.rstrip("/") + "/")
    assert ".." not in joined.split("/")


@FAST
@given(url=st.text(max_size=120))
def test_redact_url_never_raises_and_never_keeps_secrets(url: str) -> None:
    out = redact_url(url)
    assert "\n" not in out
    assert "\r" not in out
    assert len(out) <= 200
    if "?" in url and "://" in url:
        assert "?" not in out


@FAST
@given(
    secret=st.from_regex(r"[A-Za-z0-9]{8,20}", fullmatch=True),
    userinfo=st.booleans(),
)
def test_redact_url_removes_query_userinfo_and_fragment(
    secret: str, userinfo: bool
) -> None:
    prefix = f"{secret}:{secret}@" if userinfo else ""
    out = redact_url(f"https://{prefix}host.example/p?sig={secret}#{secret}")
    assert secret not in out
    assert out == "https://host.example/p"


@FAST
@given(target=url_like)
def test_a_redirect_is_only_ever_followed_to_a_trusted_plain_http_url(
    target: str,
) -> None:
    session = Session(
        redirect_policy=RedirectPolicy.ALL,
    )
    verdict = session._may_follow("https://dav.example/f", target, RedirectPolicy.ALL)
    if isinstance(verdict, str):
        return
    origin = effective_origin(target)
    assert origin is not None
    assert origin[0] == "https", "an https -> http downgrade must never be followed"


@FAST
@given(
    locked=st.sampled_from(["/a", "/a/b", "/"]),
    probe=st.lists(
        st.sampled_from(["a", "ab", "b", "a/b", "a/b/c", ".", ".."]), max_size=4
    ),
    depth=st.sampled_from(["0", "infinity"]),
)
def test_a_lock_only_covers_itself_and_for_infinity_its_children(
    locked: str, probe: list[str], depth: str
) -> None:
    registry = LockRegistry()
    registry.add(f"https://dav.example{locked}", "tok", depth)
    path = "/" + "/".join(probe)
    token = registry.token_for(f"https://dav.example{path}")
    if token is None:
        return
    # Whatever the path spelling, a covered path resolves to the locked one or below it.
    resolved = normpath(path)
    prefix = locked.rstrip("/")
    assert resolved == locked or (
        depth == "infinity" and resolved.startswith(prefix + "/")
    )
    # ...and never on another host.
    assert registry.token_for(f"https://other.example{path}") is None
