# AIegis

AIegis is a security harness for AI agents. It protects the boundary between untrusted
external content and trusted agent context, tools, memory, and outbound actions.

The first build slice provides:

- trust-labeled content models
- HTML ingestion with hidden-content quarantine
- deterministic policy decisions for risky actions
- audit-ready JSON records
- a small CLI for inspecting HTML input

The project standard is production code only: no throwaway hacks, no speculative
abstractions, and every behavioral change starts with a failing test. The test suite
must maintain at least 90% coverage.

## Verification

```bash
python -m pip install -e '.[dev]'
pytest --cov=aiegis --cov-report=term-missing --cov-fail-under=90
ruff check .
mypy src
```
