# Contributing

Thanks for your interest!

## Dev setup
```bash
pip install -r requirements.txt
```

## Before opening a PR
- `ruff check .` — lint
- `bandit -r src` — security scan
- `pytest -q` — tests (positive + negative cases)

## Conventions
- Conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`)
- This is educational crypto — keep it readable and well-commented; don't use it as production crypto.
