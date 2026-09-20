"""CLI entry point: `python -m hostharden` / the `host-harden` console script."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import checks, parsers
from .models import Report
from .report import to_json, to_markdown

_FAIL_ON_ORDER = ["low", "medium", "high", "none"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="host-harden",
        description="Offline Linux host-hardening auditor for sshd_config, sysctl, login.defs, PAM, and auditd rules.",
    )
    parser.add_argument("--sshd-config", type=Path, help="Path to sshd_config")
    parser.add_argument("--sysctl", type=Path, help="Path to a sysctl.conf file or a saved `sysctl -a` dump")
    parser.add_argument("--login-defs", type=Path, help="Path to /etc/login.defs")
    parser.add_argument("--pam-password", type=Path, help="Path to a PAM service file, e.g. common-password")
    parser.add_argument("--auditd-rules", type=Path, nargs="+", help="One or more auditd rules.d files")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output", type=Path, help="Write report to this path instead of stdout")
    parser.add_argument(
        "--fail-on",
        choices=_FAIL_ON_ORDER,
        default="high",
        help="Exit non-zero if a finding at or above this severity exists (default: high). 'none' always exits 0.",
    )
    return parser


def run(args: argparse.Namespace) -> Report:
    report = Report()

    if args.sshd_config:
        text = args.sshd_config.read_text()
        report.extend(checks.check_sshd(parsers.parse_sshd_config(text), source=str(args.sshd_config)))

    if args.sysctl:
        text = args.sysctl.read_text()
        report.extend(checks.check_sysctl(parsers.parse_sysctl(text), source=str(args.sysctl)))

    if args.login_defs:
        text = args.login_defs.read_text()
        report.extend(checks.check_login_defs(parsers.parse_login_defs(text), source=str(args.login_defs)))

    if args.pam_password:
        text = args.pam_password.read_text()
        report.extend(checks.check_pam(parsers.parse_pam(text), source=str(args.pam_password)))

    if args.auditd_rules:
        combined: list[str] = []
        for path in args.auditd_rules:
            combined.extend(parsers.parse_auditd_rules(path.read_text()))
        report.extend(checks.check_auditd(combined, source=", ".join(str(p) for p in args.auditd_rules)))

    return report


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    inputs = (args.sshd_config, args.sysctl, args.login_defs, args.pam_password, args.auditd_rules)
    if not any(inputs):
        parser.error("at least one input (--sshd-config, --sysctl, --login-defs, --pam-password, --auditd-rules) is required")

    report = run(args)
    output = to_json(report) if args.format == "json" else to_markdown(report)

    if args.output:
        args.output.write_text(output)
    else:
        print(output)

    if args.fail_on == "none":
        return 0
    threshold_index = _FAIL_ON_ORDER.index(args.fail_on)
    worst = report.highest_severity_failed()
    if worst is None:
        return 0
    worst_index = _FAIL_ON_ORDER.index(worst)
    return 1 if worst_index >= threshold_index else 0


if __name__ == "__main__":
    sys.exit(main())
