# Security policy

## Reporting a vulnerability

Please use the repository's **Security** tab to submit a private vulnerability
report. If private reporting is unavailable, open a minimal issue requesting a
private contact channel and do not include exploit details. Include the
affected version, a minimal reproduction, and the impact you observed.

This project performs static analysis of user-supplied text files. Reports may
contain file paths and configuration values, so review generated output before
sharing it publicly.

## Scope

`host-harden` does not modify the audited host or claim conformance with a
specific compliance framework. Findings are decision support and should be
validated against the target distribution, OpenSSH version, and local policy.
