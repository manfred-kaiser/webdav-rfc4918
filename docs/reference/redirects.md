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

`Client` never delegates redirect-following to `requests` itself;
instead, {class}`~webdav.client.RedirectPolicy` decides, per client (or
per call, on the methods that expose their own `redirect_policy`, e.g.
{meth}`~webdav.client.Client.propfind`), which redirect targets to
follow at all:

```python
from webdav import Client, RedirectPolicy

# Default: only a same-origin redirect is followed automatically.
client = Client("https://webdav.example.org")

# Additionally trust a specific origin - e.g. a signed-upload gateway.
# This client's credentials are never forwarded there, only to its own
# origin.
client = Client(
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

client = Client(
    "https://webdav.example.org",
    redirect_policy=RedirectPolicy.WHITELIST,
    trusted_redirect_origins=lambda url: (
        urlsplit(url).hostname or ""
    ).endswith(".amazonaws.com"),
)
```

A redirect the active policy doesn't allow raises
{class}`~webdav.exceptions.RedirectNotFollowedError` - the server's
requested target is on `exc.response.headers["Location"]`.

```{eval-rst}
.. autoclass:: webdav.client.RedirectPolicy
   :members:

.. autoclass:: webdav.exceptions.RedirectNotFollowedError
```
