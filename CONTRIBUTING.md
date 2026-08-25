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

- Offensive capabilities like exploitation, WAF evasion, or credential brute-forcing
- Anything that damages, defaces, or persists changes on a target
- Scanners that cannot be assigned honestly to one of the three tiers below

Tblue does ship modules that send more than a GET, but they are gated and
labelled, never run by default, and never named "passive" when they are not.
A contribution that sends traffic is welcome — a contribution that hides what
it sends is not.

## How to contribute

1. Fork the repository and clone your fork
2. Install it with the dev extras — this is what puts `pytest` on your path:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate        # Windows: .venv\Scripts\activate
   pip install -e ".[dev]"
   ```

3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Add or update tests in `tests/`
6. Run the test suite: `pytest`

   It takes about ten minutes and should end with every test passing. To iterate
   faster, run one file: `pytest tests/test_your_module.py`

7. Open a pull request with a clear description of what you changed and why

## Adding a new scanner module

1. Create your file in `tblue/scanner/your_module.py`
2. Inherit from `BaseScanner` in `tblue/scanner/base.py`
3. Implement the `scan(url)` method and return a list of result dicts
4. Register it in `tblue/cli.py`: import it, add the key to `ALL_MODULES`, and add
   the tuple to `_SCANNER_REGISTRY`
5. **Choose a tier.** If your scanner sends anything beyond GET/HEAD, or a GET
   carrying a payload, it does not belong in the default set:

   | Tier | Where | For |
   |------|-------|-----|
   | Passive | `_SCANNER_REGISTRY` only | GET/HEAD, no payloads |
   | Probe | also add the key to `PROBE_MODULES` | crafted but side-effect-free |
   | Intrusive | also add the key to `INTRUSIVE_MODULES` | submissions, payloads, port scans |

   This is enforced, not advisory: `tests/test_passive_by_default.py` runs every
   default scanner against an instrumented server and fails the build if one
   issues a POST/PUT/PATCH/DELETE or sends a traversal, XXE, CRLF or injection
   payload. If that test fails on your PR, your module needs a tier, not an
   exception.
6. Add definitions to `tblue/definitions/` if needed
7. Write tests in `tests/test_your_module.py` with at least one PASS case, one FAIL case, and one null-response case

## Code style

- Follow PEP 8
- Use descriptive variable names
- Keep functions small and focused

## Commit messages

Write clear, descriptive commit messages. Some examples:

- `feat: add CORS misconfiguration scanner`
- `fix: handle timeout on slow sites`
- `docs: improve installation guide`
