# Credentials in a URL

A URL with userinfo (`https://user:password@host/`) is refused with
`ClientError`, at every request, not just when a `Session` is built. Pass
`auth=(user, password)` instead. This page is about why: parsing the
credentials out and using the rest of the URL looks like a one-line fix,
and it opens a real hole instead of closing one.

## Two parsers, two opinions on the host

The check lives in {func}`~webdav.transport.guards.require_full_url` and
runs on every call that takes a full URL, in
{func}`~webdav.session.Session._fetch` and
{func}`~webdav.session.Session.features_for`. A URL there is not always
something a human typed. It can be a `base_url` override on a single call,
or a value a caller built from other input.

The library ends up talking to the server through two different parsers:
`urllib.parse.urlsplit`, used to decide the host for policy checks, and
`urllib3`'s own parser, used by `requests` to actually open the
connection. They don't always agree on where the host ends and the
userinfo begins:

```python
from urllib.parse import urlsplit
import urllib3.util

url = r"https://good.example\@evil.example/"

print(urlsplit(url).hostname, urlsplit(url).username)
# evil.example good.example\

print(urllib3.util.parse_url(url).host, urllib3.util.parse_url(url).auth)
# good.example None
```

Same string, two hosts. `urlsplit` reads everything up to the last `@` as
userinfo and lands on `evil.example`. `urllib3` treats the backslash as
the end of the authority and lands on `good.example`. Code that pulls
`(user, password)` out with `urlsplit` and then builds a "clean" URL for
`requests` to connect with is reading one parser's idea of the host while
the connection goes by the other's. An attacker who controls the URL
chooses which one you believe.

This is not a one-off case picked to fit this library. Snyk and Claroty's
2022 survey of 16 URL parsers (including `urllib` and `urllib3`) names
exactly this class "backslash confusion" and found it exploitable across
several real applications and libraries. {func}`~webdav.url_safety.effective_origin`
exists to close it: it parses every URL with both `urlsplit` and
`urllib3.util.parse_url` and refuses anything they disagree on, which is
also why it refuses any `@` in the netloc outright rather than trying to
interpret it.

## It has already been a real CVE, in Python itself

[CVE-2019-9636](https://nvd.nist.gov/vuln/detail/CVE-2019-9636) is this
same bug, inside `urlsplit`/`urlparse` themselves: certain Punycode/IDNA
input normalized under NFKC into a character such as `@` or `:`, so the
netloc Python returned did not match the netloc the string actually
specified. The advisory's own description of the risk is this library's
case word for word: an application that parses a URL to find
"authentication credentials" sends them "to a different host than
intended". Current Python rejects that specific input instead of
returning the wrong answer, which is why the example above needs a
backslash, not Punycode, to reopen the same class of bug today.

## A URL with userinfo lies to a human too

Even with one consistent parser, `https://mybank.example@evil.example/`
reads to a person as a link to `mybank.example`. The actual host is
`evil.example`; `mybank.example` is just a username nobody checks.
PortSwigger's [URL validation bypass cheat
sheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)
lists the same `user@host` construction as a standard SSRF and filter-bypass
technique, for the same reason: whatever looks like the host in the string
is not necessarily what a parser - or a person - resolves it to.

## What this library does instead

- `require_full_url` refuses userinfo in any URL passed to a request,
  before a connection is attempted.
- {func}`~webdav.url_safety.redact_url` strips userinfo, query and
  fragment from every URL that goes into a log line or an exception
  message, so a URL that slips through some other path still doesn't leak
  a credential.
- `auth=(user, password)` is the only way in. It never passes through a
  URL parser that a server, a redirect, or a caller's own code could feed
  a crafted string to.

## The one place `user:pass@host` is read

The `dav` CLI accepts `user:pass@host` in a URL
([CLI reference](cli.md)). That is not the same operation:
`_split_url` runs once, on one string a human typed directly on the
command line, before any request is made, and turns it into a
credential-free `base_url` plus an `auth` tuple. There is no redirect, no
server-returned link and no second caller's input anywhere near it. The
request path this page is about takes a URL on every call, potentially
built from less trusted sources, which is the difference that matters.

All security defaults are listed in the
[README](https://github.com/manfred-kaiser/webdav-rfc4918#security). To
report a vulnerability, see
[SECURITY.md](https://github.com/manfred-kaiser/webdav-rfc4918/blob/main/SECURITY.md).
