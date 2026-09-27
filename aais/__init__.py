"""Agent Approval Interchange Specification support library."""

from .core import (
    ApprovalError,
    ApprovalStore,
    ConflictError,
    ValidationError,
    action_digest,
    create_decision,
    create_request,
    validate,
)
from .liveness import Liveness, OwnerIdentity
from .store import (
    ApprovalAuthority,
    FileApprovalStore,
    RecoveryRequired,
    RetentionPolicy,
    StoreError,
)

__all__ = [
    "ApprovalAuthority",
    "ApprovalError",
    "ApprovalStore",
    "ConflictError",
    "FileApprovalStore",
    "Liveness",
    "OwnerIdentity",
    "RecoveryRequired",
    "RetentionPolicy",
    "StoreError",
    "ValidationError",
    "action_digest",
    "create_decision",
    "create_request",
    "validate",
]

__version__ = "0.2.0"
