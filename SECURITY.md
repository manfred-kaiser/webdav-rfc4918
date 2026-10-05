# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for a security problem. Use GitHub's private
vulnerability reporting for this repository (Security tab -> "Report a vulnerability"),
or write to the maintainer at manfred.kaiser@ssh-mitm.at.

Include the version, what a malicious server (or caller) can make the client do, and a
minimal reproduction - ideally against a local server such as the one in
`tests/scripted_server.py`. You will get an answer within a week.

## Scope

This is a client library, so the interesting attacker is an **untrusted or compromised
WebDAV server** (or a network path to one). In scope: leaking credentials, cookies, lock
tokens or client certificates to another origin; a request being sent somewhere the caller
did not name; certificate verification being bypassed; a resource other than the one named
being read or written (including local files written by downloads); unbounded memory, time
or output caused by a response; an exception that is not a `WebDAVError`/`requests`
exception escaping from server-controlled data.

## What the library promises

Credentials do not leak into exception messages, warnings or logs: a URL's userinfo and
the query of a signed URL are redacted before either is built, and an
`InsecureTransportWarning` (credentials about to go out over plain `http`) names the host
and port only.

XML from the server (multistatus, lock and error bodies) is parsed with the standard
library's expat parser. External entities are never resolved, so a response cannot make
the client read a local file or send a request. Expat 2.4.0 and newer rejects entity
expansion attacks ("billion laughs"). A multistatus or lock response that tries either
raises `MalformedResponseError`. If your Python links an older system expat, check
`pyexpat.EXPAT_VERSION`.

The complete list of security defaults is in the
[README](https://github.com/manfred-kaiser/webdav-rfc4918#security). The redirect, TLS
and session reference pages have the details, and the "Security" sections of the
CHANGELOG list what has been fixed and how.
