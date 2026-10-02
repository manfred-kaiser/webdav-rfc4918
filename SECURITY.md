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

See "Security" in the README and the redirect/TLS/session reference pages, and the
"Security" sections of the CHANGELOG for what has been fixed and how.
