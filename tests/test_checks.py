from pathlib import Path

from hostharden import checks, parsers

FIXTURES = Path(__file__).parent / "fixtures"


def _ids_by_status(results, status):
    return {r.id for r in results if r.status == status}


def test_check_sshd_hardened_all_pass():
    text = (FIXTURES / "hardened" / "sshd_config").read_text()
    results = checks.check_sshd(parsers.parse_sshd_config(text))
    failed = [r for r in results if r.status == "fail"]
    assert failed == [], failed


def test_check_sshd_vulnerable_flags_everything():
    text = (FIXTURES / "vulnerable" / "sshd_config").read_text()
    results = checks.check_sshd(parsers.parse_sshd_config(text))
    failed_ids = _ids_by_status(results, "fail")
    assert failed_ids == {f"SSH-{i:03d}" for i in range(1, 13)}
    high = {r.id for r in results if r.status == "fail" and r.severity == "high"}
    assert "SSH-001" in high  # root login
    assert "SSH-003" in high  # empty passwords
    assert "SSH-005" in high  # protocol 1
    assert "SSH-007" in high  # weak ciphers


def test_check_sshd_unset_tcp_forwarding_does_not_false_pass():
    results = checks.check_sshd({})
    failed_ids = _ids_by_status(results, "fail")
    assert "SSH-011" in failed_ids  # AllowTcpForwarding defaults to yes


def test_check_sysctl_hardened_all_pass():
    text = (FIXTURES / "hardened" / "sysctl.conf").read_text()
    results = checks.check_sysctl(parsers.parse_sysctl(text))
    assert _ids_by_status(results, "fail") == set()
    assert _ids_by_status(results, "unknown") == set()


def test_check_sysctl_vulnerable_flags_everything():
    text = (FIXTURES / "vulnerable" / "sysctl.conf").read_text()
    results = checks.check_sysctl(parsers.parse_sysctl(text))
    assert _ids_by_status(results, "fail") == {f"SYSCTL-{i:03d}" for i in range(1, 11)}


def test_check_sysctl_missing_key_is_unknown_not_fail():
    results = checks.check_sysctl({})
    assert _ids_by_status(results, "fail") == set()
    assert len(_ids_by_status(results, "unknown")) == len(results)


def test_check_login_defs_hardened_all_pass():
    text = (FIXTURES / "hardened" / "login.defs").read_text()
    results = checks.check_login_defs(parsers.parse_login_defs(text))
    assert _ids_by_status(results, "fail") == set()


def test_check_login_defs_vulnerable_flags_everything():
    text = (FIXTURES / "vulnerable" / "login.defs").read_text()
    results = checks.check_login_defs(parsers.parse_login_defs(text))
    assert _ids_by_status(results, "fail") == {f"PWPOLICY-{i:03d}" for i in range(1, 6)}


def test_check_pam_hardened_all_pass():
    text = (FIXTURES / "hardened" / "common-password").read_text()
    results = checks.check_pam(parsers.parse_pam(text))
    assert _ids_by_status(results, "fail") == set()


def test_check_pam_vulnerable_flags_everything():
    text = (FIXTURES / "vulnerable" / "common-password").read_text()
    results = checks.check_pam(parsers.parse_pam(text))
    assert _ids_by_status(results, "fail") == {"PAM-001", "PAM-002", "PAM-003"}


def test_check_auditd_hardened_all_pass():
    text = (FIXTURES / "hardened" / "audit.rules").read_text()
    results = checks.check_auditd(parsers.parse_auditd_rules(text))
    assert _ids_by_status(results, "fail") == set()


def test_check_auditd_vulnerable_flags_everything():
    text = (FIXTURES / "vulnerable" / "audit.rules").read_text()
    results = checks.check_auditd(parsers.parse_auditd_rules(text))
    assert _ids_by_status(results, "fail") == {f"AUDITD-{i:03d}" for i in range(1, 8)}
