import argparse

from scanner.k8s_engine import run_k8s_scan
from scanner.report import print_report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kubernetes cluster audit (CIS Kubernetes Benchmark subset)"
    )
    parser.add_argument("--context", default=None, help="kubeconfig context to use")
    args = parser.parse_args()

    findings = run_k8s_scan(context=args.context)
    print_report(findings)


if __name__ == "__main__":
    main()
