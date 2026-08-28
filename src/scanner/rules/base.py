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

    @abstractmethod
    def check(self, session) -> list[Finding]:
        """
        session: a boto3.Session for the account being scanned.
        Returns a Finding for every resource that fails this check.
        """
        raise NotImplementedError
