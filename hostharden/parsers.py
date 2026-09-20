"""Parsers for the config file formats host-harden audits.

All parsers are intentionally forgiving: they are reading configuration
that may come from many distros and OpenSSH/PAM/audit versions, so the
goal is "extract what's there" rather than strict validation.
"""

from __future__ import annotations


def _strip_inline_comment(line: str) -> str:
    """Remove an unquoted, whitespace-delimited ``#`` comment."""
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote == '"':
            escaped = True
            continue
        if char in ("'", '"'):
            quote = None if quote == char else char if quote is None else quote
            continue
        if char == "#" and quote is None and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
    return line


def parse_sshd_config(text: str) -> dict[str, str]:
    """Parse global (pre-``Match``) sshd_config directives.

    OpenSSH uses the *first* value seen for most keywords in the global
    section, so later duplicate keys are ignored -- matching real sshd
    behavior rather than naively overwriting with the last line.
    """
    config: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = _strip_inline_comment(raw_line).strip()
        if not line or line.startswith("#"):
            continue
        if line.split(None, 1)[0].lower() == "match":
            break  # stop at the first Match block; only audit the global config
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts[0], parts[1].strip()
        key_lower = key.lower()
        if key_lower not in config:
            config[key_lower] = value
    return config


def parse_sysctl(text: str) -> dict[str, str]:
    """Parse ``key = value`` (or ``key value``, as in ``sysctl -a`` output)."""
    config: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = _strip_inline_comment(raw_line).strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
        else:
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, value = parts
        config[key.strip()] = value.strip()
    return config


def parse_login_defs(text: str) -> dict[str, str]:
    """Parse ``/etc/login.defs`` (whitespace-separated KEY VALUE lines)."""
    config: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = _strip_inline_comment(raw_line).strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        config[parts[0].strip()] = parts[1].strip()
    return config


def parse_pam(text: str) -> list[dict[str, str]]:
    """Parse a PAM service file (e.g. ``common-password``) into rule dicts.

    Each rule dict has keys: ``type``, ``control``, ``module``, ``args``.
    Lines beginning with ``@include``/``@`` are skipped as unresolvable
    references to other PAM files.
    """
    rules: list[dict[str, str]] = []
    for raw_line in text.splitlines():
        line = _strip_inline_comment(raw_line).strip()
        if not line or line.startswith("#") or line.startswith("@"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        # A leading dash asks PAM to ignore a missing module; it is not part of
        # the management group name.
        ptype = parts[0].lstrip("-")
        rest = parts[1:]
        if rest[0].startswith("["):
            # Bracketed control syntax, e.g. "[success=1 default=ignore]",
            # can contain spaces -- rejoin until the closing bracket.
            control_tokens = []
            for i, token in enumerate(rest):
                control_tokens.append(token)
                if token.endswith("]"):
                    rest = rest[i + 1 :]
                    break
            else:
                rest = []
            control = " ".join(control_tokens)
        else:
            control, *rest = rest
        if not rest:
            continue
        module, *args = rest
        rules.append(
            {
                "type": ptype.lower(),
                "control": control,
                "module": module,
                "args": " ".join(args),
            }
        )
    return rules


def parse_auditd_rules(text: str) -> list[str]:
    """Parse an auditd rules file into a list of normalized rule lines."""
    rules: list[str] = []
    for raw_line in text.splitlines():
        line = _strip_inline_comment(raw_line).strip()
        if not line or line.startswith("#"):
            continue
        rules.append(line)
    return rules
