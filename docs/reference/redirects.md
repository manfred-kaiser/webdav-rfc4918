# Redirects

HTTP permits a server to answer *any* request with a redirect (RFC 9110
§15.4; RFC 7238 defines 308 specifically to preserve the method/body
across one) - a real, legitimate pattern (e.g. a cloud-storage gateway
redirecting `PUT` to a signed upload URL on a different host), but
nothing requires a client to *follow* one. Blindly doing so is unsafe for
a general-purpose client: a malicious or compromised server could
otherwise redirect a write to a different resource - or, via 307/308, to
a completely different host while fully replaying the request body -
with no error raised to the caller.

{class}`~webdav.session.Session` never delegates redirect-following to
`requests` itself (which re-sends a redirected `PROPFIND` without its
body, or as a `GET`, and follows any origin); instead,
{class}`~webdav.transport.redirects.RedirectPolicy` decides, per session (or per
call, with `redirect_policy=`), which redirect targets to follow at all.
The policy is the same for every call made through the session:

```python
from webdav import RedirectPolicy, Session

# Default: only a same-origin redirect is followed automatically.
session = Session("https://webdav.example.org")

# Additionally trust a specific origin - e.g. a signed-upload gateway.
# This client's credentials are never forwarded there, only to its own
# origin.
session = Session(
    "https://webdav.example.org",
    redirect_policy=RedirectPolicy.WHITELIST,
    trusted_redirect_origins=["https://storage.example.com"],
)
```

`trusted_redirect_origins` also accepts a predicate for a redirect target
that isn't a fixed, known-ahead-of-time origin (e.g. a gateway whose
exact hostname varies per bucket/region/tenant):

```python
from urllib.parse import urlsplit

session = Session(
    "https://webdav.example.org",
    redirect_policy=RedirectPolicy.WHITELIST,
    trusted_redirect_origins=lambda url: (
        urlsplit(url).hostname or ""
    ).endswith(".amazonaws.com"),
)
```

One call can use another policy than its session:

```python
r = session.get("Documents/Readme.md", redirect_policy=RedirectPolicy.NEVER)
```

The policies and their exact rules are listed under
[`RedirectPolicy`](api.md#redirects) in the API reference.

## What is and is not followed

Whatever the policy:

- `303 See Other` is only followed for `GET`/`HEAD` (RFC 9110 §15.4.4 says
  to retrieve the result with `GET`; re-sending a write would be wrong,
  and silently turning it into a `GET` would report a write as done).
- A redirect whose body could not be sent again (a generator, a partly
  read file) is not followed. A redirect back to a URL already visited
  is not followed either, and a chain stops after five hops.
- A target is only accepted if `urllib.parse` and `urllib3` agree which
  host it names. Userinfo, control characters, backslashes and any
  scheme but `http`/`https` are refused - an origin is scheme, host and
  port, so `http` -> `https` on the same host is a *different* origin.

```{warning}
`https` -> `http` is never followed - not even with `ALL`, and not even to
an origin explicitly listed in `trusted_redirect_origins`. Trusting a
target with credentials and accepting that the same bytes then cross the
network in clear text are different questions; there is no legitimate
reason to want the second.
```

Every hop is judged against the origin the request *started at*: after
A redirects to B, a further redirect to another path on B is still "another
origin" as far as your credentials are concerned.

A redirect to another origin (only possible with `WHITELIST`/`ALL`) is
sent as a fresh request through a plain adapter of its own: no `auth` (and no
netrc), no cookies (and none set by the answer are kept), no session default
headers, no client certificate, no `If`/`Lock-Token`/`Destination`. Of the
headers you pass to that one call only those describing the representation or
the conditions are forwarded (`Content-Type`, `Content-Encoding`,
`Content-Language`, `Content-MD5`, `Accept*`, `Range`, `If-Match`,
`If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`); a signed upload
that has to repeat others names them in
`session.redirect_forward_headers = frozenset({"x-amz-meta-owner"})`.

A redirect the active policy doesn't allow raises
{class}`~webdav.exceptions.RedirectNotFollowedError` - the server's
requested target is on `exc.response.headers["Location"]`.
