import argparse

from scanner.engine import run_scan
from scanner.report import print_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Cloud Security Posture Scanner")
    parser.add_argument("--profile", default=None, help="AWS CLI profile to use")
    parser.add_argument("--region", default=None, help="AWS region to scan")
    args = parser.parse_args()

    findings = run_scan(profile=args.profile, region=args.region)
    print_report(findings)


if __name__ == "__main__":
    main()
