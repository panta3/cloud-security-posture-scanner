from abc import ABC, abstractmethod

from scanner.rules.base import Finding, Severity

# Namespaces that belong to the cluster's own control plane / add-ons, not
# to anything a user deployed. Flagging kube-system's own pods as
# "privileged" would just be noise — those components legitimately need
# that access, and nobody scanning their own workloads can fix them.
SYSTEM_NAMESPACES = {"kube-system", "kube-node-lease", "kube-public", "local-path-storage"}


class KubernetesRule(ABC):
    """
    Mirrors scanner.rules.base.Rule's shape (same Finding/Severity types,
    same "one file per check" layout) but for a Kubernetes cluster instead
    of an AWS account — kept as a separate hierarchy rather than forcing
    both into one Rule.check(session) signature, since a kubeconfig-based
    client and a boto3.Session aren't actually interchangeable.
    """

    id: str
    severity: Severity

    @abstractmethod
    def check(self, k8s: "K8sClients") -> list[Finding]:
        """
        k8s: a K8sClients bundle for the cluster/context being scanned.
        Returns a Finding for every resource that fails this check.
        """
        raise NotImplementedError


class K8sClients:
    """Small bundle of the API clients the checks need, built once per scan."""

    def __init__(self, core_v1, rbac_v1, networking_v1):
        self.core_v1 = core_v1
        self.rbac_v1 = rbac_v1
        self.networking_v1 = networking_v1
