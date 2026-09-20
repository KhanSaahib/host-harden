# host-harden

[![CI](https://github.com/KhanSaahib/host-harden/actions/workflows/ci.yml/badge.svg)](https://github.com/KhanSaahib/host-harden/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

An offline, dependency-free Linux host-hardening auditor. It reads the
config files that actually control a host's security posture — the SSH
daemon, kernel network parameters, password aging policy, PAM modules,
and auditd rules — and checks them against well-known hardening practices.

## Why this exists

Container and cloud posture scanning is well covered by existing tooling
(Trivy, kube-bench, checkov, and friends). Plain **host-level** OS
hardening — is root SSH login disabled, is ASLR on, is there a password
quality module, are `/etc/shadow` changes audited — tends to get checked
manually with a checklist, or not at all until an auditor asks. Lynis and
OpenSCAP already do this well as full agents; `host-harden` is a much
smaller, pure-stdlib tool that works from **copies of the config files**
(no root, no agent install, no live system access required), so it fits
naturally into a CI pipeline that lints golden AMI/image configs, or a
one-off audit where you've pulled files off a box for review.

## What it checks

- **sshd_config** — root login, password auth, empty passwords, X11
  forwarding, legacy protocol 1, `MaxAuthTries`, weak ciphers/MACs/KEX,
  login grace time, TCP forwarding, `GatewayPorts`.
- **sysctl** — IP forwarding, source-routed packets, ICMP redirects,
  SYN cookies, ASLR (`kernel.randomize_va_space`), setuid core dumps,
  `dmesg` restriction, reverse-path filtering, kernel pointer exposure.
- **login.defs** — password max/min age, minimum length, expiry warning,
  hash algorithm (`ENCRYPT_METHOD`).
- **PAM** (e.g. `common-password`) — password quality module and minimum
  length, account lockout module, `pam_unix.so nullok` (empty passwords).
- **auditd rules** — watches on `/etc/shadow`, `/etc/passwd`, sudoers,
  group files; syscall audit rules for kernel module loading and time
  changes; whether the running audit config is locked (`-e 2`).

Every check is one of three states: `pass`, `fail` (with a severity —
`high`/`medium`/`low` — and a remediation), or `unknown` (the check
couldn't be evaluated, e.g. a sysctl key that simply isn't in the file
you gave it). Nothing is scored as a failure just because data was missing.

## Install

Stdlib only — no runtime dependencies. Python 3.10 or newer is required.

```bash
git clone https://github.com/KhanSaahib/host-harden.git
cd host-harden
python -m pip install -e ".[dev]"  # or: pip install .
python -m pytest -q               # optional: run the test suite
host-harden --help
```

## Usage

```bash
host-harden \
  --sshd-config /etc/ssh/sshd_config \
  --sysctl <(sysctl -a) \
  --login-defs /etc/login.defs \
  --pam-password /etc/pam.d/common-password \
  --auditd-rules /etc/audit/rules.d/*.rules \
  --format markdown
```

Every input flag is optional and independent — pass only the files you
have; only the corresponding checks run. `--format json` emits a machine
-readable report (score, per-severity summary, full result list) suitable
for CI or feeding into another tool. `--output PATH` writes the report to
a file instead of stdout.

`--fail-on {low,medium,high,none}` (default `high`) controls the exit
code: the process exits `1` if any failing check at or above that
severity exists, so `host-harden ... --fail-on high` is a clean CI gate.

### Example

```bash
$ host-harden --sshd-config tests/fixtures/vulnerable/sshd_config --format markdown
# host-harden report

**Score:** 0.0% of evaluated checks passed

- High: 4
- Medium: 6
- Low: 2
...
### [HIGH] SSH-001 — Root login permitted over SSH

PermitRootLogin yes allows direct root logins.

**Remediation:** Set 'PermitRootLogin no'.
...
```

## Design notes

- **No live system access.** Every check runs against a file path you
  provide, so it works equally well against a running host's `/etc`, a
  golden image mounted read-only, or files pulled down for offline review.
- **First-value-wins for sshd_config**, matching real OpenSSH behavior
  (the first occurrence of a global directive is used; a `Match` block
  ends the audited global section).
- **Unknown, not failed, when data is missing.** A sysctl parameter not
  present in the file you passed is reported as `unknown`, not `fail` —
  it isn't scored against you, but it's called out so you know to verify
  it another way (e.g. against the running kernel).

## Testing

```bash
python3 -m pytest tests/ -q
```

Tests cover each parser, each check category against both a fully
hardened and a fully vulnerable fixture set (`tests/fixtures/`), and an
end-to-end CLI pass covering exit codes, `--fail-on`, and both output
formats.

## License

MIT — see `LICENSE`. See `NOTICE.md` for the tools that inspired this
project's approach and their licenses; no code was copied from them.
