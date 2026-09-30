"""Generic HTTP/socket-level transport mechanics, not WebDAV-specific.

Deadlines, TLS/mTLS setup, retry policy, bounded/streamed reading and
redirect-security (origin/trust checks) - everything here would be equally
at home in a plain HTTP client. Nothing in this package parses or builds
WebDAV wire format; see :mod:`webdav.dav` for that.
"""
