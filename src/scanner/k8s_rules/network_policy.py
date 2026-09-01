from scanner.rules.base import Finding, Severity

from .base import KubernetesRule, SYSTEM_NAMESPACES


class MissingNetworkPolicyRule(KubernetesRule):
    """
    CIS Kubernetes Benchmark 5.3.2: a namespace with zero NetworkPolicy
    objects has no traffic restrictions at all — every pod in it can
    reach, and be reached by, every other pod in the cluster by default.
    Kubernetes ships with no default-deny; a namespace has to opt in.
    """

    id = "NET.1"
    severity = Severity.MEDIUM

    def check(self, k8s) -> list[Finding]:
        findings: list[Finding] = []

        namespaces = k8s.core_v1.list_namespace().items
        for ns in namespaces:
            name = ns.metadata.name
            if name in SYSTEM_NAMESPACES:
                continue

            pods = k8s.core_v1.list_namespaced_pod(namespace=name).items
            if not pods:
                # Nothing running here — no attack surface to restrict yet.
                continue

            policies = k8s.networking_v1.list_namespaced_network_policy(namespace=name).items
            if policies:
                continue

            findings.append(
                Finding(
                    rule_id=self.id,
                    resource_id=name,
                    severity=self.severity,
                    message=(
                        f"Namespace '{name}' has {len(pods)} pod(s) and no "
                        "NetworkPolicy — all traffic to/from them is unrestricted."
                    ),
                )
            )

        return findings
