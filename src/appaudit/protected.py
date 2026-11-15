"""A folder only administrators can write, for what the elevated helper must be able to trust.

The dashboard's data folder belongs to the signed-in user, so any program the user runs can edit
it. The helper runs elevated; if it read undo values or firewall rule names from there, a program
running as the user could make it write any value or delete any rule. So the helper keeps its own
record in %ProgramData%\\AppAudit, whose access list allows writing only to SYSTEM and
Administrators (users may read).

If the folder cannot be made safe (for example someone else created it first and it cannot be
reset), the helper refuses to record administrator changes rather than trusting it.
"""

from __future__ import annotations

import os
from pathlib import Path

SDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"
_SAFE_OWNERS = {"S-1-5-18", "S-1-5-32-544"}          # SYSTEM, Administrators


class Unsafe(RuntimeError):
    """The protected folder cannot be trusted."""


def folder() -> Path:
    override = os.environ.get("APPAUDIT_PROTECTED")
    if override:
        return Path(override)
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "AppAudit"


def _owner_sid(path: Path) -> str:
    import win32security

    descriptor = win32security.GetFileSecurity(str(path), win32security.OWNER_SECURITY_INFORMATION)
    return win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())


def _apply_acl(path: Path) -> None:
    import win32security

    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(SDDL, win32security.SDDL_REVISION_1)
    win32security.SetFileSecurity(
        str(path), win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION, descriptor)


def ensure() -> Path:
    """The protected folder, created and locked down. Raises Unsafe if that is not possible.

    With APPAUDIT_PROTECTED set (tests), the folder is used as it is.
    """
    target = folder()
    if os.environ.get("APPAUDIT_PROTECTED"):
        target.mkdir(parents=True, exist_ok=True)
        return target
    from .winutil import is_admin

    if not is_admin():
        raise Unsafe("only the elevated helper may write the protected record")
    target.mkdir(parents=True, exist_ok=True)
    try:
        _apply_acl(target)                           # also resets a folder someone else made first
        if _owner_sid(target) not in _SAFE_OWNERS:
            raise Unsafe(f"{target} is owned by someone else")
    except Unsafe:
        raise
    except Exception as error:  # noqa: BLE001
        raise Unsafe(f"{target} could not be locked down: {error}") from error
    return target


def journal_file() -> Path:
    return ensure() / "journal.db"
