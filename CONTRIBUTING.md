# Contributing

Thanks for helping improve `host-harden`.

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
- Do not copy benchmark text or rules whose license is incompatible with MIT.
