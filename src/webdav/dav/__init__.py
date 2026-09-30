"""RFC 4918 wire-format layer: parsing and building WebDAV XML/headers.

URLs, the ``If`` header grammar, lock tokens, ``<propstat>``/``<response>``
elements, ``207 Multi-Status`` bodies and the small XML/date/parsing
helpers they share all live here. This is the domain layer that
:class:`webdav.session.Session` and :class:`webdav.fs.FileSystem` compose
against; it does not itself send or receive HTTP.
"""
