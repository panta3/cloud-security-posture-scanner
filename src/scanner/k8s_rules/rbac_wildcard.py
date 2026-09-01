from scanner.rules.base import Finding, Severity

from .base import KubernetesRule, SYSTEM_NAMESPACES

# CIS Kubernetes Benchmark 5.1.x: cluster-admin should be bound as rarely
# as possible, and never to a namespace's default ServiceAccount — every
# pod in that namespace that doesn't explicitly request a different SA
# gets it automatically, so this one binding silently grants
# cluster-admin to workloads nobody meant to trust that much.
CLUSTER_ADMIN_ROLE = "cluster-admin"


class ClusterAdminBindingRule(KubernetesRule):
    id = "RBAC.1"
    severity = Severity.CRITICAL

    def check(self, k8s) -> list[Finding]:
        findings: list[Finding] = []

        bindings = k8s.rbac_v1.list_cluster_role_binding().items
        for binding in bindings:
            role_ref = binding.role_ref
            if role_ref.kind != "ClusterRole" or role_ref.name != CLUSTER_ADMIN_ROLE:
                continue

            for subject in binding.subjects or []:
                if not self._is_risky_subject(subject):
                    continue
                findings.append(
                    Finding(
                        rule_id=self.id,
                        resource_id=f"{binding.metadata.name}/{subject.kind}:{subject.namespace or '-'}/{subject.name}",
                        severity=self.severity,
                        message=(
                            f"ClusterRoleBinding '{binding.metadata.name}' grants "
                            f"cluster-admin to {subject.kind} "
                            f"'{subject.namespace or ''}/{subject.name}'."
                        ),
                    )
                )

        return findings

    @staticmethod
    def _is_risky_subject(subject) -> bool:
        # system:masters / kube-system service accounts are the cluster's
        # own legitimately-privileged identities — not what this check is
        # trying to catch. Anything else bound to cluster-admin is a
        # workload or user that almost certainly doesn't need it.
        if subject.namespace in SYSTEM_NAMESPACES:
            return False
        if subject.name in ("system:masters", "system:admin"):
            return False
        return True
