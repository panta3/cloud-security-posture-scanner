# K8s audit — demo

Validated against a real local cluster (`kind`), not just unit tests.

## Setup
```bash
kind create cluster --name posture-scanner-demo
kubectl apply -f docs/k8s-demo-manifests.yaml   # deliberately misconfigured resources
python -m scanner.k8s_cli --context kind-posture-scanner-demo
```

## Positive case — real output against the misconfigured resources
```
[CRITICAL] RBAC.1 — demo-default-sa-cluster-admin/ServiceAccount:posture-demo/default: ClusterRoleBinding 'demo-default-sa-cluster-admin' grants cluster-admin to ServiceAccount 'posture-demo/default'.
[CRITICAL] RBAC.1 — kubeadm:cluster-admins/Group:-/kubeadm:cluster-admins: ClusterRoleBinding 'kubeadm:cluster-admins' grants cluster-admin to Group '/kubeadm:cluster-admins'.
[CRITICAL] PodSecurity.1 — posture-demo/privileged-pod/app: Container 'app' in pod 'posture-demo/privileged-pod' is privileged.
[MEDIUM] PodSecurity.2 — posture-demo/privileged-pod/app: Container 'app' in pod 'posture-demo/privileged-pod' has no runAsNonRoot restriction and may run as root.
[MEDIUM] PodSecurity.2 — posture-demo/root-pod/app: Container 'app' in pod 'posture-demo/root-pod' has no runAsNonRoot restriction and may run as root.
[MEDIUM] NET.1 — posture-demo: Namespace 'posture-demo' has 2 pod(s) and no NetworkPolicy — all traffic to/from them is unrestricted.
```

## Negative case — after `kubectl delete -f docs/k8s-demo-manifests.yaml`
```
[CRITICAL] RBAC.1 — kubeadm:cluster-admins/Group:-/kubeadm:cluster-admins: ClusterRoleBinding 'kubeadm:cluster-admins' grants cluster-admin to Group '/kubeadm:cluster-admins'.
```
All the demo findings disappeared, exactly as expected. One finding
remains: `kubeadm:cluster-admins`, a `ClusterRoleBinding` `kind` (and any
kubeadm-based cluster) creates itself for cluster bootstrap/admin access.
It's not a false positive — that Group genuinely does hold cluster-admin
— but it's also not something a workload owner introduced, and it'll show
up on effectively every kubeadm-based cluster. `RBAC.1` already allowlists
the analogous `system:masters`/`system:admin` identities; a real
deployment of this check would want the same treatment for
`kubeadm:cluster-admins` (or any cluster-specific bootstrap group) rather
than hardcoding it here, since the "right" set of legitimate cluster-admin
holders is genuinely cluster-specific — left as a known, documented
tradeoff rather than silently allowlisted just to make the demo output
look cleaner.

## Checks implemented
- **RBAC.1** (CIS 5.1.x) — `ClusterRoleBinding`s granting `cluster-admin`
  to anything other than the cluster's own system identities.
- **PodSecurity.1** (CIS 5.2.1/5.2.5) — privileged containers or
  containers allowing privilege escalation.
- **PodSecurity.2** (CIS 5.2.6) — containers with no `runAsNonRoot`
  restriction (defaults to whatever the image's own `USER` is — root,
  for most public images).
- **NET.1** (CIS 5.3.2) — namespaces with running pods and zero
  `NetworkPolicy` objects (Kubernetes has no default-deny; a namespace
  has to opt in).

## Scope note
This is local-only, detection-only, and separate from the AWS pipeline
by design: a Lambda has no route to a cluster's API server unless it's
on the same VPC, and this check is meant to demonstrate breadth (an
account-level scanner that also understands cluster-level posture), not
to be wired into the scheduled Lambda run.
