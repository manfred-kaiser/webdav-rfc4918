# Redirects

By default only a redirect to the same origin is followed. Any other
redirect is reported as {class}`~webdav.exceptions.RedirectNotFollowedError`,
with the target the server asked for in `exc.response.headers["Location"]`.
A `FileSystem` call raises it directly. A `Session` verb returns the `3xx`
response, and `raise_for_status()` (or `raise_on_error=True`) raises it.

A {class}`~webdav.transport.redirects.RedirectPolicy` changes which
targets are followed. It is set per session and applies to every call made
through it:

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

`trusted_redirect_origins` also accepts a function, for targets whose
origin is not known in advance (e.g. a gateway whose hostname varies per
bucket, region or tenant):

```python
from urllib.parse import urlsplit


def trusted_origin(url):
    hostname = urlsplit(url).hostname
    if hostname is None:
        return False
    return hostname.endswith(".amazonaws.com")


session = Session(
    "https://webdav.example.org",
    redirect_policy=RedirectPolicy.WHITELIST,
    trusted_redirect_origins=trusted_origin,
)
```

One call can use another policy than its session:

```python
r = session.get("Documents/Readme.md", redirect_policy=RedirectPolicy.NEVER)
```

The policies and their exact rules are listed under
[`RedirectPolicy`](api.md#redirects) in the API reference.

```{note}
A server may answer any request with a redirect, and there are real uses
for it, for example a cloud-storage gateway that redirects a `PUT` to a
signed upload URL on another host. But nothing requires a client to follow
one, and following every one is unsafe: a malicious or compromised server
could send a write to another resource, or with 307/308 to another host
along with the full request body, and the caller would see no error.
```

## What is and is not followed

Whatever the policy:

- `303 See Other` is only followed for `GET`/`HEAD`.
- A redirect whose body could not be sent again (a generator, a partly
  read file) is not followed. A redirect back to a URL already visited
  is not followed either, and a chain stops after five hops.
- A target with userinfo, control characters, backslashes or a scheme
  other than `http`/`https` is not followed.

Each of these is reported as `RedirectNotFollowedError`. An origin is
scheme, host and port, so `http` -> `https` on the same host is a
*different* origin.

```{warning}
`https` -> `http` is never followed, not even with `ALL` or to an origin
listed in `trusted_redirect_origins`. Trusting a host with your
credentials does not mean accepting that the same bytes then cross the
network in clear text.
```

Every hop is judged against the origin the request *started at*: after
A redirects to B, a further redirect to another path on B is still "another
origin" as far as your credentials are concerned.

## Headers on a redirect to another origin

A redirect to another origin (only possible with `WHITELIST`/`ALL`) does
not carry your credentials, cookies or session default headers. Of the
headers you pass to the call, only the content and conditional ones go
along. If the target needs more, for example a signed upload that has to
repeat its metadata headers, name them:

```python
from webdav import RedirectPolicy, Session

session = Session(
    "https://webdav.example.org",
    redirect_policy=RedirectPolicy.WHITELIST,
    trusted_redirect_origins=["https://storage.example.com"],
)
session.redirect_forward_headers = frozenset({"x-amz-meta-owner"})
```

```{warning}
`redirect_forward_headers` cannot forward credentials. `Authorization`,
`Proxy-Authorization`, `Cookie`, `If`, `Lock-Token` and `Destination` are
dropped on a redirect to another origin even if you list them there.
```

```{note}
The redirected request carries no `auth`, no cookies (and none set by the
answer are kept), no session default headers, no client certificate, no
`If`/`Lock-Token`/`Destination`. Of the per-call headers these are always
forwarded: `Content-Type`, `Content-Encoding`, `Content-Language`,
`Content-MD5`, `Accept`, `Accept-Language`, `Range`, `If-Match`, `If-None-Match`,
`If-Modified-Since`, `If-Unmodified-Since`.
```

All security defaults, redirects and otherwise, are listed in the
[README](https://github.com/manfred-kaiser/webdav-rfc4918#security).
