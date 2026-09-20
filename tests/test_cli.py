import json
from pathlib import Path

from hostharden.__main__ import main

FIXTURES = Path(__file__).parent / "fixtures"


def _argv(fixture_dir: str, extra: list[str] | None = None) -> list[str]:
    base = FIXTURES / fixture_dir
    argv = [
        "--sshd-config", str(base / "sshd_config"),
        "--sysctl", str(base / "sysctl.conf"),
        "--login-defs", str(base / "login.defs"),
        "--pam-password", str(base / "common-password"),
        "--auditd-rules", str(base / "audit.rules"),
    ]
    return argv + (extra or [])


def test_cli_hardened_exits_zero(capsys):
    exit_code = main(_argv("hardened", ["--format", "json"]))
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["summary"]["high"] == 0


def test_cli_vulnerable_exits_nonzero(capsys):
    exit_code = main(_argv("vulnerable", ["--format", "json"]))
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 1
    assert payload["summary"]["high"] > 0


def test_cli_fail_on_none_always_exits_zero(capsys):
    exit_code = main(_argv("vulnerable", ["--format", "json", "--fail-on", "none"]))
    capsys.readouterr()
    assert exit_code == 0


def test_cli_markdown_output_contains_score(capsys):
    main(_argv("vulnerable", ["--format", "markdown"]))
    captured = capsys.readouterr()
    assert "# host-harden report" in captured.out
    assert "Score" in captured.out


def test_cli_requires_at_least_one_input(capsys):
    try:
        main([])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("expected SystemExit from argparse.error")


def test_cli_writes_to_output_file(tmp_path):
    out_file = tmp_path / "report.json"
    main(_argv("hardened", ["--format", "json", "--output", str(out_file)]))
    payload = json.loads(out_file.read_text())
    assert "score" in payload
