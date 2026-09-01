from kubernetes import client, config

from .k8s_rules.base import K8sClients
from .k8s_rules.network_policy import MissingNetworkPolicyRule
from .k8s_rules.pod_security import PrivilegedContainerRule, RunAsRootRule
from .k8s_rules.rbac_wildcard import ClusterAdminBindingRule
from .rules.base import Finding

ALL_K8S_RULES = [
    ClusterAdminBindingRule(),
    PrivilegedContainerRule(),
    RunAsRootRule(),
    MissingNetworkPolicyRule(),
]


def run_k8s_scan(context: str | None = None) -> list[Finding]:
    # Local-only stretch goal, not wired into the Lambda pipeline — a
    # Lambda has no route to a cluster's API server unless it's on the
    # same VPC, and standing that up is out of scope for what this check
    # is meant to demonstrate. Loads whatever kubeconfig kubectl itself
    # would use (~/.kube/config by default).
    config.load_kube_config(context=context)

    k8s = K8sClients(
        core_v1=client.CoreV1Api(),
        rbac_v1=client.RbacAuthorizationV1Api(),
        networking_v1=client.NetworkingV1Api(),
    )

    findings: list[Finding] = []
    for rule in ALL_K8S_RULES:
        findings.extend(rule.check(k8s))
    return findings
