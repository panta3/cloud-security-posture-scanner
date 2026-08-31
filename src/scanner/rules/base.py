from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    rule_id: str
    resource_id: str
    severity: Severity
    message: str


class Rule(ABC):
    """
    Every CIS check implements this. Adding a new check means adding a
    new file here, not touching the engine.
    """

    id: str
    severity: Severity

    # Most checks are detection-only by default — remediation is only
    # safe for a small, deliberate subset of findings where the fix is a
    # simple, reversible setting toggle (not, say, deleting a resource or
    # rewriting an IAM policy that something else might depend on).
    # Rules that override this to True must also override remediate().
    remediable: bool = False

    @abstractmethod
    def check(self, session) -> list[Finding]:
        """
        session: a boto3.Session for the account being scanned.
        Returns a Finding for every resource that fails this check.
        """
        raise NotImplementedError

    def remediate(self, session, resource_id: str) -> None:
        """
        Only called for findings from rules with remediable=True, and
        only when the caller has explicitly opted this rule ID into
        auto-remediation (see remediation.py) — never automatic by default.
        """
        raise NotImplementedError(f"{self.id} does not support remediation")
