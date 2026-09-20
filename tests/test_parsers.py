from hostharden import parsers


def test_parse_sshd_config_basic():
    text = "PermitRootLogin no\nPasswordAuthentication no\n"
    config = parsers.parse_sshd_config(text)
    assert config["permitrootlogin"] == "no"
    assert config["passwordauthentication"] == "no"


def test_parse_sshd_config_first_value_wins():
    text = "MaxAuthTries 3\nMaxAuthTries 10\n"
    config = parsers.parse_sshd_config(text)
    assert config["maxauthtries"] == "3"


def test_parse_sshd_config_stops_at_match_block():
    text = "PermitRootLogin no\nMatch User backup\n    PasswordAuthentication yes\n"
    config = parsers.parse_sshd_config(text)
    assert "passwordauthentication" not in config
    assert config["permitrootlogin"] == "no"


def test_parse_sshd_config_ignores_comments_and_blanks():
    text = "# comment\n\nPermitRootLogin no\n"
    config = parsers.parse_sshd_config(text)
    assert config == {"permitrootlogin": "no"}


def test_parse_sysctl_equals_form():
    config = parsers.parse_sysctl("net.ipv4.ip_forward = 1\n# comment\n")
    assert config["net.ipv4.ip_forward"] == "1"


def test_parse_sysctl_space_form():
    config = parsers.parse_sysctl("net.ipv4.ip_forward 1\n")
    assert config["net.ipv4.ip_forward"] == "1"


def test_parse_login_defs():
    config = parsers.parse_login_defs("PASS_MAX_DAYS   90\n# comment\nPASS_MIN_LEN 14\n")
    assert config["PASS_MAX_DAYS"] == "90"
    assert config["PASS_MIN_LEN"] == "14"


def test_parse_pam():
    text = "password requisite pam_pwquality.so retry=3 minlen=14\n@include common-auth\n"
    rules = parsers.parse_pam(text)
    assert len(rules) == 1
    assert rules[0] == {
        "type": "password",
        "control": "requisite",
        "module": "pam_pwquality.so",
        "args": "retry=3 minlen=14",
    }


def test_parse_pam_bracketed_control():
    text = "password [success=1 default=ignore] pam_unix.so obscure nullok md5\n"
    rules = parsers.parse_pam(text)
    assert len(rules) == 1
    assert rules[0]["control"] == "[success=1 default=ignore]"
    assert rules[0]["module"] == "pam_unix.so"
    assert rules[0]["args"] == "obscure nullok md5"


def test_parse_auditd_rules_strips_comments_and_blanks():
    text = "# header\n-w /etc/shadow -p wa -k identity\n\n-e 2\n"
    rules = parsers.parse_auditd_rules(text)
    assert rules == ["-w /etc/shadow -p wa -k identity", "-e 2"]
