# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for a security problem. Use GitHub's private
vulnerability reporting for this repository (Security tab -> "Report a vulnerability"),
or write to the maintainer at manfred.kaiser@ssh-mitm.at.

Include the version, what a malicious server (or caller) can make the client do, and a
minimal reproduction - ideally against a local server such as the one in
`tests/scripted_server.py`. You will get an answer within a week.

## Supported versions

Security fixes go into the latest release only, which is also what `main`
is released from. There are no maintenance branches and no backports: if you
run an older release, upgrade first. A report against an old release is
welcome, but please check it against the latest release (or `main`) too, and say
which you tested. The CHANGELOG tells you what to expect from an upgrade.

## Advisories, CVEs and disclosure

A confirmed vulnerability is handled as a coordinated disclosure:

1. You report it privately (see above). It is acknowledged within a week.
2. The maintainer reproduces and assesses it, and works on a fix in a private
   branch or fork of the advisory. You are kept informed, and may review the fix.
3. The fix is released, and a GitHub Security Advisory is published for the
   repository, with a CVE requested through GitHub as the CNA when the issue
   warrants one. The advisory names the affected and the fixed releases, a
   workaround where there is one, and credits the reporter unless you prefer
   not to be named. The CHANGELOG entry links to it.
4. Public details are held back until a fixed release is on PyPI. The target is
   a fix within 90 days of the report; if that is not possible, a date is agreed
   with you. If the issue is already being exploited, or you must publish
   earlier for another reason, say so in your report.

## Scope

This is a client library, so the interesting attacker is an **untrusted or compromised
WebDAV server** (or a network path to one). In scope: leaking credentials, cookies, lock
tokens or client certificates to another origin; a request being sent somewhere the caller
did not name; certificate verification being bypassed; a resource other than the one named
being read or written (including local files written by downloads); unbounded memory, time
or output caused by a response; an exception that is not a `WebDAVError`/`requests`
exception escaping from server-controlled data.

## What the library promises

Credentials do not leak into the exception messages, warnings or log lines the library
itself writes: a URL's userinfo and the query of a signed URL are redacted before either
is built (also in the connection errors it passes on), and an `InsecureTransportWarning`
(credentials about to go out over plain `http`) names the host and port only. This does
not cover the loggers of `urllib3` and `requests`: at DEBUG level `urllib3` prints every
requested path and query.

XML from the server (multistatus, lock and error bodies) is parsed with the standard
library's expat parser. External entities are never resolved, so a response cannot make
the client read a local file or send a request. A document that declares an entity at all
is refused before it is parsed, so the protection against "billion laughs" does not depend
on the expat your Python links. A multistatus or lock response that does either raises
`MalformedResponseError`.

The parser itself is still expat's: the Python floor is 3.11, and a Python that links an
old system expat (a distribution's, or a container image's) lacks the fixes of later
releases. If you parse responses from servers you do not trust, make sure
`pyexpat.EXPAT_VERSION` is 2.7.2 or newer (the Python documentation's threshold). The
library logs a warning, once, when it parses a response with an older one; keeping the
Python current is up to whoever provides it.

The complete list of security defaults is in the
[README](https://github.com/manfred-kaiser/webdav-rfc4918#security). The redirect, TLS
and session reference pages have the details, and the "Security" sections of the
CHANGELOG list what has been fixed and how.
