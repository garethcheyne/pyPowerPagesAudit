"""ppaudit — Power Pages / Dataverse exposure audit.

An outside-in anonymous scanner (a reimplemented, extended power-pwn Power
Pages module), an inside-out authenticated Dataverse permission audit, and a
correlation layer that ties each external leak to the permission that causes it.
"""

from .report import Finding, Report, Severity
from .anonscan import AnonScanner
from .dataverse import DataverseClient, DataverseError
from .audit import DataverseAudit

__version__ = "0.1.0"
__all__ = [
    "AnonScanner",
    "DataverseClient",
    "DataverseError",
    "DataverseAudit",
    "Report",
    "Finding",
    "Severity",
]
