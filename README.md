# AIegis

AIegis is a security harness for AI agents. It protects the boundary between untrusted
external content and trusted agent context, tools, memory, and outbound actions.

The first build slice provides:

- trust-labeled content models
- HTML ingestion with hidden-content quarantine
- email ingestion with header checks, body extraction, HTML-part inspection, and attachment quarantine
- deterministic policy decisions for risky actions
- audit-ready JSON records
- a small CLI for inspecting HTML and email input

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

## CLI

Inspect HTML from stdin:

```bash
printf '<p>Visible</p>' | aiegis inspect-html
```

Inspect email from stdin:

```bash
printf 'From: sender@example.test\nSubject: Hi\n\nBody' | aiegis inspect-email
```

Use a named policy profile:

```bash
printf '<p>Send this</p>' | aiegis inspect-html \
  --action send_email \
  --target external \
  --policy-file examples/policies.yaml \
  --policy-profile review_only
```

Policy profile files are YAML:

```yaml
profiles:
  review_only:
    approval_required_actions:
      - send_email
    blocked_actions_on_prompt_injection: []
```

Append metadata-only audit events to a Zaxy Eventloom log:

```bash
printf '<p>Send this</p>' | aiegis inspect-html \
  --action send_email \
  --eventloom-log .eventloom/aiegis.jsonl \
  --eventloom-thread aiegis-default
```

Eventloom audit payloads store content hashes, finding metadata, counts, policy
profile names, and decisions. They do not store raw inspected content or
quarantined segments.
