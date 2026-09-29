# Client

```{eval-rst}
.. autoclass:: webdav.client.Client
   :members:
   :undoc-members:
   :exclude-members: lock
```

See {doc}`locking` for `Client.lock()`.

## Exceptions

Every exception raised by this library derives from
{class}`webdav.exceptions.WebDAVError`, which itself derives from
{class}`requests.exceptions.RequestException` - code that already broadly
catches requests' own exception hierarchy also catches everything this
library raises.

```{eval-rst}
.. automodule:: webdav.exceptions
   :members:
   :undoc-members:
   :exclude-members: WebDAVError
```
