# Contributing to Tblue

Thanks for wanting to contribute. Tblue is a defensive security tool and every contribution needs to stay within that scope.

## What we welcome

- New passive scanner modules (for example: CORS misconfiguration checker, CSP analyzer)
- Improvements to existing scanners
- Better report formatting
- Documentation improvements
- Bug fixes
- More test coverage

## What we do not accept

- Offensive capabilities like payload generation, WAF evasion, or exploitation
- Scanners that actively probe sites in ways that could cause harm
- Anything that goes beyond read-only configuration and reflection checking

## How to contribute

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Add or update tests in `tests/`
5. Run the test suite: `pytest tests/`
6. Open a pull request with a clear description of what you changed and why

## Adding a new scanner module

1. Create your file in `tblue/scanner/your_module.py`
2. Inherit from `BaseScanner` in `tblue/scanner/base.py`
3. Implement the `scan(url)` method and return a list of result dicts
4. Register it in `tblue/cli.py` by importing it, adding the key to ALL_MODULES, and adding the tuple to _SCANNER_REGISTRY
5. Add definitions to `tblue/definitions/` if needed
6. Write tests in `tests/test_your_module.py` with at least one PASS case, one FAIL case, and one null-response case

## Code style

- Follow PEP 8
- Use descriptive variable names
- Keep functions small and focused

## Commit messages

Write clear, descriptive commit messages. Some examples:

- `feat: add CORS misconfiguration scanner`
- `fix: handle timeout on slow sites`
- `docs: improve installation guide`
