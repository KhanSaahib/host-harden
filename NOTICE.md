# Notice / attributions

`host-harden` is original code, written from scratch for this repository,
released under the MIT License (see `LICENSE`). No source code was copied
from any other project.

## Conceptual inspiration

The general idea of statically auditing Linux configuration files against
known hardening guidance is a long-established, widely documented practice.
This project's *approach* (not its code or check text) was inspired by:

- **[Lynis](https://github.com/CISOfy/lynis)** (CISOfy) — a mature, popular
  Linux/Unix security auditing tool, licensed GPLv3. `host-harden` does not
  use, vendor, or derive from any Lynis source code or output text; only the
  general concept "audit sshd/sysctl/PAM/auditd configuration for known-weak
  settings" is shared. Because no GPLv3 code was copied, `host-harden`
  carries no copyleft obligation, but Lynis is credited here as the tool
  that made this category of auditing well known.
- **CIS Benchmarks** (Center for Internet Security) — the general categories
  of checks performed here (SSH daemon hardening, kernel network parameters,
  password aging, PAM quality/lockout modules, auditd watch rules) mirror
  well-known industry hardening themes covered by CIS Benchmarks. No CIS
  Benchmark text, scoring logic, or proprietary content was copied; all
  check descriptions and remediation text in this repository were written
  independently.

## Third-party dependencies

None at runtime. The package uses only the Python 3.10+ standard library.
`pytest` is used for the test suite (dev-only dependency, not shipped).
