# Security policy

## Supported versions

| Version | Security fixes |
|---|---|
| `0.1.x` | Supported |
| Earlier versions | Not supported |

Only the latest patch release on the current minor line receives security
fixes. The `main` branch may contain unreleased changes.

## Reporting a vulnerability

Please use the repository's **Security** tab to submit a private vulnerability
report. If private reporting is unavailable, open a minimal issue requesting a
private contact channel and do not include exploit details. Include the
affected version, a minimal reproduction, and the impact you observed.
Please also describe any suggested remediation or embargo needs. The maintainer
will acknowledge reports on a best-effort basis, validate the impact, and
coordinate disclosure before publishing details.

This project performs static analysis of user-supplied text files. Reports may
contain file paths and configuration values, so review generated output before
sharing it publicly.

## Scope

`host-harden` does not modify the audited host or claim conformance with a
specific compliance framework. Findings are decision support and should be
validated against the target distribution, OpenSSH version, and local policy.
