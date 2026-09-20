"""Markdown and JSON report formatting."""

from __future__ import annotations

import json
from dataclasses import asdict

from .models import Report

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def to_json(report: Report) -> str:
    payload = {
        "score": report.score(),
        "summary": report.counts_by_severity(),
        "totals": {
            "pass": len(report.passed),
            "fail": len(report.failed),
            "unknown": len(report.unknown),
        },
        "results": [asdict(r) for r in report.results],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def to_markdown(report: Report) -> str:
    lines: list[str] = []
    counts = report.counts_by_severity()
    lines.append("# host-harden report")
    lines.append("")
    lines.append(f"**Score:** {report.score()}% of evaluated checks passed")
    lines.append("")
    lines.append(
        f"- High: {counts['high']}  \n"
        f"- Medium: {counts['medium']}  \n"
        f"- Low: {counts['low']}  \n"
        f"- Passed: {len(report.passed)}  \n"
        f"- Unknown/not evaluated: {len(report.unknown)}"
    )
    lines.append("")

    failed = sorted(report.failed, key=lambda r: _SEVERITY_ORDER.get(r.severity, 9))
    if failed:
        lines.append("## Findings")
        lines.append("")
        for r in failed:
            lines.append(f"### [{r.severity.upper()}] {r.id} — {r.title}")
            lines.append("")
            lines.append(r.detail)
            if r.remediation:
                lines.append("")
                lines.append(f"**Remediation:** {r.remediation}")
            if r.source:
                lines.append("")
                lines.append(f"*Source: `{r.source}`*")
            lines.append("")
    else:
        lines.append("No failing checks.")
        lines.append("")

    if report.unknown:
        lines.append("## Not evaluated")
        lines.append("")
        for r in report.unknown:
            lines.append(f"- {r.id}: {r.detail}")
        lines.append("")

    return "\n".join(lines)
