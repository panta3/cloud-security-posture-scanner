from scanner.rules.base import Finding, Severity

from .base import KubernetesRule, SYSTEM_NAMESPACES


class PrivilegedContainerRule(KubernetesRule):
    """
    CIS Kubernetes Benchmark 5.2.1/5.2.5: containers should never run
    privileged (full host access — bypasses namespace isolation almost
    entirely) or with allowPrivilegeEscalation, since a compromised
    container in either mode can trivially escape to the host.
    """

    id = "PodSecurity.1"
    severity = Severity.CRITICAL

    def check(self, k8s) -> list[Finding]:
        findings: list[Finding] = []

        pods = k8s.core_v1.list_pod_for_all_namespaces().items
        for pod in pods:
            namespace = pod.metadata.namespace
            if namespace in SYSTEM_NAMESPACES:
                continue

            for container in pod.spec.containers:
                ctx = container.security_context
                if ctx is None:
                    continue
                privileged = bool(ctx.privileged)
                escalation = ctx.allow_privilege_escalation is not False and bool(
                    ctx.allow_privilege_escalation
                )
                if not (privileged or escalation):
                    continue

                reason = "privileged" if privileged else "allows privilege escalation"
                findings.append(
                    Finding(
                        rule_id=self.id,
                        resource_id=f"{namespace}/{pod.metadata.name}/{container.name}",
                        severity=self.severity,
                        message=(
                            f"Container '{container.name}' in pod "
                            f"'{namespace}/{pod.metadata.name}' is {reason}."
                        ),
                    )
                )

        return findings


class RunAsRootRule(KubernetesRule):
    """
    CIS Kubernetes Benchmark 5.2.6: containers should set
    runAsNonRoot=true (or an explicit non-zero runAsUser). Leaving it
    unset defaults to whatever the container image's own USER is —
    root, for most public images — which means a container breakout
    starts with root inside the container too.
    """

    id = "PodSecurity.2"
    severity = Severity.MEDIUM

    def check(self, k8s) -> list[Finding]:
        findings: list[Finding] = []

        pods = k8s.core_v1.list_pod_for_all_namespaces().items
        for pod in pods:
            namespace = pod.metadata.namespace
            if namespace in SYSTEM_NAMESPACES:
                continue

            pod_level_non_root = bool(
                pod.spec.security_context and pod.spec.security_context.run_as_non_root
            )
            if pod_level_non_root:
                continue

            for container in pod.spec.containers:
                ctx = container.security_context
                if ctx and (ctx.run_as_non_root or (ctx.run_as_user or 0) != 0):
                    continue

                findings.append(
                    Finding(
                        rule_id=self.id,
                        resource_id=f"{namespace}/{pod.metadata.name}/{container.name}",
                        severity=self.severity,
                        message=(
                            f"Container '{container.name}' in pod "
                            f"'{namespace}/{pod.metadata.name}' has no runAsNonRoot "
                            "restriction and may run as root."
                        ),
                    )
                )

        return findings
