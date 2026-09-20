"""Hardening checks for each config category.

Each ``check_*`` function takes the parsed config for one file and
returns a list of :class:`~hostharden.models.CheckResult`. The checks
themselves are independently written against well-known, publicly
documented hardening concepts (not copied from any benchmark's text) --
see NOTICE.md for the tools that inspired the general approach.
"""

from __future__ import annotations

from .models import CheckResult

_WEAK_CIPHERS = ("arcfour", "3des", "blowfish", "cbc", "des")
_WEAK_MACS = ("md5", "hmac-sha1", "umac-64")
_WEAK_KEX = ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "gss-group1")


def _yes(value: str | None) -> bool:
    return (value or "").strip().lower() == "yes"


def check_sshd(config: dict[str, str], source: str = "") -> list[CheckResult]:
    results: list[CheckResult] = []

    root_login = config.get("permitrootlogin")
    if root_login is None:
        results.append(
            CheckResult(
                "SSH-001", "ssh", "PermitRootLogin not explicitly set", "fail",
                "PermitRootLogin is not set; the distro default may permit root login.",
                severity="medium", remediation="Set 'PermitRootLogin no'.", source=source,
            )
        )
    elif root_login.lower() == "yes":
        results.append(
            CheckResult(
                "SSH-001", "ssh", "Root login permitted over SSH", "fail",
                "PermitRootLogin yes allows direct root logins.",
                severity="high", remediation="Set 'PermitRootLogin no'.", source=source,
            )
        )
    else:
        results.append(CheckResult("SSH-001", "ssh", "Root login restricted", "pass", f"PermitRootLogin {root_login}.", source=source))

    pw_auth = config.get("passwordauthentication")
    if pw_auth is None or pw_auth.lower() == "yes":
        results.append(
            CheckResult(
                "SSH-002", "ssh", "Password authentication allowed", "fail",
                "PasswordAuthentication is 'yes' or unset (defaults vary by distro).",
                severity="medium", remediation="Set 'PasswordAuthentication no' and use key-based auth.", source=source,
            )
        )
    else:
        results.append(CheckResult("SSH-002", "ssh", "Password authentication disabled", "pass", "PasswordAuthentication no.", source=source))

    if _yes(config.get("permitemptypasswords")):
        results.append(
            CheckResult(
                "SSH-003", "ssh", "Empty passwords permitted", "fail",
                "PermitEmptyPasswords yes allows accounts with blank passwords to log in.",
                severity="high", remediation="Set 'PermitEmptyPasswords no'.", source=source,
            )
        )
    else:
        results.append(CheckResult("SSH-003", "ssh", "Empty passwords rejected", "pass", "PermitEmptyPasswords not enabled.", source=source))

    if _yes(config.get("x11forwarding")):
        results.append(
            CheckResult(
                "SSH-004", "ssh", "X11 forwarding enabled", "fail",
                "X11Forwarding yes increases attack surface unnecessarily for most servers.",
                severity="low", remediation="Set 'X11Forwarding no' unless required.", source=source,
            )
        )
    else:
        results.append(CheckResult("SSH-004", "ssh", "X11 forwarding disabled", "pass", "X11Forwarding not enabled.", source=source))

    protocol = config.get("protocol")
    if protocol and "1" in [p.strip() for p in protocol.split(",")]:
        results.append(
            CheckResult(
                "SSH-005", "ssh", "Legacy SSH protocol 1 enabled", "fail",
                f"Protocol directive includes '1': {protocol!r}.",
                severity="high", remediation="Remove Protocol 1; use Protocol 2 (or omit, modern OpenSSH is v2-only).", source=source,
            )
        )
    else:
        results.append(CheckResult("SSH-005", "ssh", "No legacy SSH protocol", "pass", "Protocol 1 not configured.", source=source))

    max_auth = config.get("maxauthtries")
    try:
        max_auth_val = int(max_auth) if max_auth else None
    except ValueError:
        max_auth_val = None
    if max_auth_val is None or max_auth_val > 4:
        results.append(
            CheckResult(
                "SSH-006", "ssh", "MaxAuthTries too permissive", "fail",
                f"MaxAuthTries is {max_auth or 'unset (default 6)'}.",
                severity="medium", remediation="Set 'MaxAuthTries 4' or lower.", source=source,
            )
        )
    else:
        results.append(CheckResult("SSH-006", "ssh", "MaxAuthTries reasonable", "pass", f"MaxAuthTries {max_auth_val}.", source=source))

    ciphers = config.get("ciphers")
    if ciphers:
        weak = [c for c in ciphers.split(",") if any(w in c.lower() for w in _WEAK_CIPHERS)]
        if weak:
            results.append(
                CheckResult(
                    "SSH-007", "ssh", "Weak SSH ciphers enabled", "fail",
                    f"Weak cipher(s) in Ciphers directive: {', '.join(weak)}.",
                    severity="high", remediation="Remove legacy ciphers (arcfour/3des/blowfish/cbc/des); use AES-GCM or ChaCha20-Poly1305.", source=source,
                )
            )
        else:
            results.append(CheckResult("SSH-007", "ssh", "No weak SSH ciphers configured", "pass", "Ciphers directive has no known-weak entries.", source=source))
    else:
        results.append(CheckResult("SSH-007", "ssh", "Ciphers not overridden", "unknown", "No explicit Ciphers directive; relying on OpenSSH's built-in defaults.", source=source))

    macs = config.get("macs")
    if macs:
        weak = [m for m in macs.split(",") if any(w in m.lower() for w in _WEAK_MACS) and "etm" not in m.lower()]
        if weak:
            results.append(
                CheckResult(
                    "SSH-008", "ssh", "Weak SSH MACs enabled", "fail",
                    f"Weak MAC(s) in MACs directive: {', '.join(weak)}.",
                    severity="medium", remediation="Remove md5/sha1/umac-64 MACs; prefer *-etm variants.", source=source,
                )
            )
        else:
            results.append(CheckResult("SSH-008", "ssh", "No weak SSH MACs configured", "pass", "MACs directive has no known-weak entries.", source=source))
    else:
        results.append(CheckResult("SSH-008", "ssh", "MACs not overridden", "unknown", "No explicit MACs directive; relying on OpenSSH's built-in defaults.", source=source))

    kex = config.get("kexalgorithms")
    if kex:
        weak = [k for k in kex.split(",") if k.lower() in _WEAK_KEX]
        if weak:
            results.append(
                CheckResult(
                    "SSH-009", "ssh", "Weak key exchange algorithms enabled", "fail",
                    f"Weak KexAlgorithms: {', '.join(weak)}.",
                    severity="medium", remediation="Remove group1/group14-sha1 KEX; prefer curve25519-sha256.", source=source,
                )
            )
        else:
            results.append(CheckResult("SSH-009", "ssh", "No weak KEX algorithms configured", "pass", "KexAlgorithms directive has no known-weak entries.", source=source))
    else:
        results.append(CheckResult("SSH-009", "ssh", "KexAlgorithms not overridden", "unknown", "No explicit KexAlgorithms directive; relying on OpenSSH's built-in defaults.", source=source))

    grace = config.get("logingracetime")
    if grace is not None and grace.strip() in ("0",):
        results.append(
            CheckResult(
                "SSH-010", "ssh", "Unlimited login grace time", "fail",
                "LoginGraceTime 0 lets unauthenticated connections stay open indefinitely.",
                severity="medium", remediation="Set 'LoginGraceTime 30' (or similarly small).", source=source,
            )
        )
    else:
        results.append(CheckResult("SSH-010", "ssh", "Login grace time bounded", "pass", f"LoginGraceTime {grace or 'default'}.", source=source))

    if _yes(config.get("allowtcpforwarding")):
        results.append(
            CheckResult(
                "SSH-011", "ssh", "TCP forwarding enabled", "fail",
                "AllowTcpForwarding yes lets SSH be used as a generic tunnel/pivot.",
                severity="low", remediation="Set 'AllowTcpForwarding no' unless required.", source=source,
            )
        )
    else:
        results.append(CheckResult("SSH-011", "ssh", "TCP forwarding disabled", "pass", "AllowTcpForwarding not enabled.", source=source))

    if _yes(config.get("gatewayports")):
        results.append(
            CheckResult(
                "SSH-012", "ssh", "GatewayPorts enabled", "fail",
                "GatewayPorts yes lets forwarded ports bind to all interfaces, not just localhost.",
                severity="medium", remediation="Set 'GatewayPorts no'.", source=source,
            )
        )
    else:
        results.append(CheckResult("SSH-012", "ssh", "GatewayPorts disabled", "pass", "GatewayPorts not enabled.", source=source))

    return results


_SYSCTL_CHECKS = [
    ("SYSCTL-001", "net.ipv4.ip_forward", "0", "medium", "IP forwarding enabled", "Host will route packets between interfaces; disable unless this is intentionally a router."),
    ("SYSCTL-002", "net.ipv4.conf.all.accept_source_route", "0", "high", "Source-routed packets accepted", "Accepting source-routed packets allows IP spoofing/route manipulation."),
    ("SYSCTL-003", "net.ipv4.conf.all.accept_redirects", "0", "medium", "ICMP redirects accepted", "Accepting ICMP redirects allows a MITM to alter routing."),
    ("SYSCTL-004", "net.ipv4.conf.all.send_redirects", "0", "low", "ICMP redirects sent", "Sending ICMP redirects is unnecessary for a non-router host."),
    ("SYSCTL-005", "net.ipv4.tcp_syncookies", "1", "medium", "SYN cookies disabled", "SYN cookies mitigate SYN-flood denial of service."),
    ("SYSCTL-006", "kernel.randomize_va_space", "2", "high", "ASLR not fully enabled", "Full address-space layout randomization makes memory-corruption exploits harder."),
    ("SYSCTL-007", "fs.suid_dumpable", "0", "medium", "setuid process core dumps allowed", "Core dumps from setuid processes can leak sensitive memory contents."),
    ("SYSCTL-008", "kernel.dmesg_restrict", "1", "low", "dmesg exposed to unprivileged users", "Kernel log can leak addresses useful for exploitation."),
    ("SYSCTL-009", "net.ipv4.conf.all.rp_filter", "1", "medium", "Reverse path filtering disabled", "rp_filter helps prevent IP spoofing on multi-homed hosts."),
]


def check_sysctl(config: dict[str, str], source: str = "") -> list[CheckResult]:
    results: list[CheckResult] = []
    for check_id, key, expected, severity, fail_title, fail_detail in _SYSCTL_CHECKS:
        value = config.get(key)
        if value is None:
            results.append(
                CheckResult(check_id, "sysctl", f"{key} not present", "unknown", f"{key} not found in the provided sysctl data.", source=source)
            )
            continue
        if value.strip() == expected:
            results.append(CheckResult(check_id, "sysctl", f"{key} correctly set", "pass", f"{key} = {value}.", source=source))
        else:
            results.append(
                CheckResult(
                    check_id, "sysctl", fail_title, "fail",
                    f"{fail_detail} ({key} = {value}, expected {expected}).",
                    severity=severity, remediation=f"Set '{key} = {expected}' in sysctl.conf and reload.", source=source,
                )
            )

    kptr = config.get("kernel.kptr_restrict")
    if kptr is None:
        results.append(CheckResult("SYSCTL-010", "sysctl", "kernel.kptr_restrict not present", "unknown", "kernel.kptr_restrict not found in the provided sysctl data.", source=source))
    elif kptr.strip() in ("0",):
        results.append(
            CheckResult(
                "SYSCTL-010", "sysctl", "Kernel pointers exposed", "fail",
                f"kernel.kptr_restrict = {kptr}; kernel pointers are readable by unprivileged users.",
                severity="medium", remediation="Set 'kernel.kptr_restrict = 1' (or 2).", source=source,
            )
        )
    else:
        results.append(CheckResult("SYSCTL-010", "sysctl", "Kernel pointers restricted", "pass", f"kernel.kptr_restrict = {kptr}.", source=source))

    return results


def check_login_defs(config: dict[str, str], source: str = "") -> list[CheckResult]:
    results: list[CheckResult] = []

    def _int(key: str) -> int | None:
        try:
            return int(config[key])
        except (KeyError, ValueError):
            return None

    max_days = _int("PASS_MAX_DAYS")
    if max_days is None or max_days > 90:
        results.append(
            CheckResult(
                "PWPOLICY-001", "password-policy", "Password max age too long", "fail",
                f"PASS_MAX_DAYS is {config.get('PASS_MAX_DAYS', 'unset')}.",
                severity="medium", remediation="Set 'PASS_MAX_DAYS 90' or lower.", source=source,
            )
        )
    else:
        results.append(CheckResult("PWPOLICY-001", "password-policy", "Password max age acceptable", "pass", f"PASS_MAX_DAYS {max_days}.", source=source))

    min_days = _int("PASS_MIN_DAYS")
    if min_days is None or min_days < 1:
        results.append(
            CheckResult(
                "PWPOLICY-002", "password-policy", "Password min age too short", "fail",
                f"PASS_MIN_DAYS is {config.get('PASS_MIN_DAYS', 'unset')}; users can cycle passwords instantly to defeat reuse checks.",
                severity="low", remediation="Set 'PASS_MIN_DAYS 1' or higher.", source=source,
            )
        )
    else:
        results.append(CheckResult("PWPOLICY-002", "password-policy", "Password min age acceptable", "pass", f"PASS_MIN_DAYS {min_days}.", source=source))

    min_len = _int("PASS_MIN_LEN")
    if min_len is None or min_len < 14:
        results.append(
            CheckResult(
                "PWPOLICY-003", "password-policy", "Password min length too short", "fail",
                f"PASS_MIN_LEN is {config.get('PASS_MIN_LEN', 'unset')}.",
                severity="medium", remediation="Set 'PASS_MIN_LEN 14' (note: PAM pwquality minlen usually takes precedence today).", source=source,
            )
        )
    else:
        results.append(CheckResult("PWPOLICY-003", "password-policy", "Password min length acceptable", "pass", f"PASS_MIN_LEN {min_len}.", source=source))

    warn_age = _int("PASS_WARN_AGE")
    if warn_age is None or warn_age < 7:
        results.append(
            CheckResult(
                "PWPOLICY-004", "password-policy", "Password expiry warning too short", "fail",
                f"PASS_WARN_AGE is {config.get('PASS_WARN_AGE', 'unset')}.",
                severity="low", remediation="Set 'PASS_WARN_AGE 7' or higher.", source=source,
            )
        )
    else:
        results.append(CheckResult("PWPOLICY-004", "password-policy", "Password expiry warning acceptable", "pass", f"PASS_WARN_AGE {warn_age}.", source=source))

    encrypt = config.get("ENCRYPT_METHOD", "").upper()
    if encrypt in ("SHA512", "YESCRYPT"):
        results.append(CheckResult("PWPOLICY-005", "password-policy", "Strong password hash configured", "pass", f"ENCRYPT_METHOD {encrypt}.", source=source))
    else:
        results.append(
            CheckResult(
                "PWPOLICY-005", "password-policy", "Weak or unset password hash method", "fail",
                f"ENCRYPT_METHOD is {config.get('ENCRYPT_METHOD', 'unset')}.",
                severity="high", remediation="Set 'ENCRYPT_METHOD SHA512' or 'YESCRYPT'.", source=source,
            )
        )

    return results


def check_pam(rules: list[dict[str, str]], source: str = "") -> list[CheckResult]:
    results: list[CheckResult] = []

    quality_rules = [r for r in rules if r["type"] == "password" and r["module"].split("/")[-1] in ("pam_pwquality.so", "pam_cracklib.so")]
    if not quality_rules:
        results.append(
            CheckResult(
                "PAM-001", "pam", "No password quality module configured", "fail",
                "Neither pam_pwquality.so nor pam_cracklib.so appears in a 'password' rule.",
                severity="high", remediation="Add 'password requisite pam_pwquality.so retry=3 minlen=14'.", source=source,
            )
        )
    else:
        args = quality_rules[0]["args"]
        minlen = None
        for token in args.split():
            if token.startswith("minlen="):
                try:
                    minlen = int(token.split("=", 1)[1])
                except ValueError:
                    pass
        if minlen is None or minlen < 14:
            results.append(
                CheckResult(
                    "PAM-001", "pam", "Password quality module has weak minlen", "fail",
                    f"minlen is {minlen if minlen is not None else 'unset'} in: {args!r}.",
                    severity="medium", remediation="Set 'minlen=14' or higher on the pwquality/cracklib line.", source=source,
                )
            )
        else:
            results.append(CheckResult("PAM-001", "pam", "Password quality module enforces length", "pass", f"minlen={minlen}.", source=source))

    lockout_rules = [r for r in rules if r["module"].split("/")[-1] in ("pam_faillock.so", "pam_tally2.so")]
    if not lockout_rules:
        results.append(
            CheckResult(
                "PAM-002", "pam", "No account lockout module configured", "fail",
                "Neither pam_faillock.so nor pam_tally2.so is configured; repeated failed logins are not throttled.",
                severity="medium", remediation="Add pam_faillock.so (or pam_tally2.so) to the auth stack with a deny threshold.", source=source,
            )
        )
    else:
        results.append(CheckResult("PAM-002", "pam", "Account lockout module configured", "pass", f"Found {lockout_rules[0]['module']}.", source=source))

    unix_rules = [r for r in rules if r["module"].split("/")[-1] == "pam_unix.so"]
    nullok_rules = [r for r in unix_rules if "nullok" in r["args"]]
    if nullok_rules:
        results.append(
            CheckResult(
                "PAM-003", "pam", "pam_unix.so allows empty passwords", "fail",
                "'nullok' argument on pam_unix.so permits accounts with blank passwords to authenticate.",
                severity="high", remediation="Remove 'nullok' from the pam_unix.so line.", source=source,
            )
        )
    elif unix_rules:
        results.append(CheckResult("PAM-003", "pam", "pam_unix.so does not allow empty passwords", "pass", "No 'nullok' argument found.", source=source))
    else:
        results.append(CheckResult("PAM-003", "pam", "pam_unix.so not found", "unknown", "pam_unix.so rule not present in this file.", source=source))

    return results


_AUDITD_CHECKS = [
    ("AUDITD-001", ("/etc/shadow",), "high", "No audit watch on /etc/shadow", "Changes to the shadow password file are not audited."),
    ("AUDITD-002", ("/etc/passwd",), "medium", "No audit watch on /etc/passwd", "Changes to the passwd file are not audited."),
    ("AUDITD-003", ("/etc/sudoers", "/etc/sudoers.d"), "high", "No audit watch on sudoers", "Changes to sudo privilege configuration are not audited."),
    ("AUDITD-004", ("/etc/group", "/etc/gshadow"), "medium", "No audit watch on group files", "Changes to group membership/authentication are not audited."),
]


def check_auditd(rules: list[str], source: str = "") -> list[CheckResult]:
    results: list[CheckResult] = []
    joined = "\n".join(rules)

    for check_id, paths, severity, fail_title, fail_detail in _AUDITD_CHECKS:
        if any(path in joined for path in paths):
            results.append(CheckResult(check_id, "auditd", f"Audit watch present for {'/'.join(paths)}", "pass", f"Found a rule referencing {paths[0]}.", source=source))
        else:
            results.append(
                CheckResult(
                    check_id, "auditd", fail_title, "fail", fail_detail,
                    severity=severity, remediation=f"Add: -w {paths[0]} -p wa -k identity", source=source,
                )
            )

    module_syscalls = ("init_module", "delete_module", "finit_module")
    if any(s in joined for s in module_syscalls):
        results.append(CheckResult("AUDITD-005", "auditd", "Kernel module load/unload audited", "pass", "Found a syscall rule for module loading.", source=source))
    else:
        results.append(
            CheckResult(
                "AUDITD-005", "auditd", "Kernel module loading not audited", "fail",
                "No syscall rule watches init_module/delete_module/finit_module.",
                severity="medium", remediation="Add: -a always,exit -F arch=b64 -S init_module,delete_module,finit_module -k modules", source=source,
            )
        )

    time_syscalls = ("adjtimex", "settimeofday", "clock_settime")
    if any(s in joined for s in time_syscalls) or "/etc/localtime" in joined:
        results.append(CheckResult("AUDITD-006", "auditd", "Time changes audited", "pass", "Found a time-change audit rule.", source=source))
    else:
        results.append(
            CheckResult(
                "AUDITD-006", "auditd", "Time changes not audited", "fail",
                "No syscall rule watches adjtimex/settimeofday/clock_settime, and /etc/localtime is not watched.",
                severity="low", remediation="Add: -a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change", source=source,
            )
        )

    if "-e 2" in rules:
        results.append(CheckResult("AUDITD-007", "auditd", "Audit configuration locked", "pass", "'-e 2' makes the running audit configuration immutable.", source=source))
    else:
        results.append(
            CheckResult(
                "AUDITD-007", "auditd", "Audit configuration not locked", "fail",
                "No '-e 2' directive; an attacker with root could disable or alter auditing at runtime.",
                severity="low", remediation="Add '-e 2' as the last line of the audit rules (requires reboot to change again).", source=source,
            )
        )

    return results
