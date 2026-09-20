# Contributing

Thanks for helping improve `host-harden`.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
For usage questions, read [SUPPORT.md](SUPPORT.md). Report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md).

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
python -m pytest -q
```

Keep checks deterministic, offline, and based only on the supplied files.
New checks should include hardened, vulnerable, and missing-data test cases.
Avoid presenting distro-dependent defaults as universal facts; document any
default that a check relies on.

## Pull requests

- Keep each pull request focused.
- Add or update tests for behavior changes.
- Update the README when adding a CLI flag, input format, or check category.
- Add user-visible changes to the `[Unreleased]` section of `CHANGELOG.md`.
- Confirm `python -m build` succeeds before requesting a release.
- Do not copy benchmark text or rules whose license is incompatible with MIT.

Maintainers may request changes when evidence is incomplete, behavior is not
deterministic, or a contribution expands the project's stated scope.
