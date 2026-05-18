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
- an MCP stdio server exposing guarded inspection tools to agents

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

Inspect outbound text before returning or sending it:

```bash
printf 'api_key = sk-test-1234567890abcdef' | aiegis inspect-output
```

Output inspection blocks secret-like material and returns redacted text. Finding
evidence names the matched pattern, not the secret value.

Use a named policy profile:

```bash
printf '<p>Send this</p>' | aiegis inspect-html \
  --action send_email \
  --target external \
  --policy-file examples/policies.yaml \
  --policy-profile review_only
```

Limit untrusted input before parsing:

```bash
cat large-email.eml | aiegis inspect-email --max-input-chars 100000
```

Inputs longer than the configured limit are truncated before HTML or email
parsing and receive an `input_truncated` finding. The discarded tail is not
stored in audit payloads.

Policy profile files are YAML:

```yaml
profiles:
  review_only:
    approval_required_actions:
      - send_email
    blocked_actions_on_prompt_injection: []
    approval_required_tools:
      - send_email
      - file_upload
    blocked_tools:
      - shell
      - filesystem.delete
    sensitive_argument_keys:
      - api_key
      - token
```

Append metadata-only audit events to a Zaxy Eventloom log:

```bash
printf '<p>Send this</p>' | aiegis inspect-html \
  --action send_email \
  --audit-log .aiegis/audit.jsonl \
  --eventloom-log .eventloom/aiegis.jsonl \
  --eventloom-thread aiegis-default
```

`--audit-log` appends minimized JSONL audit events to a local file and creates
parent directories when needed. Content audit logs omit raw text and quarantined
segments, and tool-call audit logs redact sensitive argument values such as
tokens, passwords, secrets, credentials, and API keys.

Local JSONL audit events are sealed with a hash chain. Each event stores the
previous event hash and its own event hash, making edits, deletion, or reordering
detectable by verification.

Use `--audit-include-raw` only for local debugging sessions that explicitly need
the full inspected payload. It stores raw untrusted content, quarantined
segments, links, and unredacted tool arguments in the local JSONL audit log.

Verify a local audit log:

```bash
aiegis verify-audit-log .aiegis/audit.jsonl
```

Eventloom audit payloads store content hashes, finding metadata, counts, policy
profile names, and decisions. They do not store raw inspected content or
quarantined segments.

## MCP Server

Run AIegis as a local MCP stdio server:

```bash
aiegis mcp-stdio
```

Run the MCP server with the same policy and audit controls as CLI inspection:

```bash
aiegis mcp-stdio \
  --policy-file examples/policies.yaml \
  --policy-profile review_only \
  --max-input-chars 100000 \
  --audit-log .aiegis/audit.jsonl \
  --eventloom-log .eventloom/aiegis.jsonl \
  --eventloom-thread aiegis-default
```

For short-lived local debugging, add `--audit-include-raw` to the CLI or MCP
server command to include raw payloads in `--audit-log`. Leave it unset for
normal operation.

The server exposes:

- `aiegis.inspect_html`
- `aiegis.inspect_email`
- `aiegis.evaluate_tool_call`
- `aiegis.inspect_output`

The inspection tools accept `content`, optional `action`, and optional `target`
arguments. They return the same audit structure as the CLI in
`structuredContent`, with a JSON text copy for MCP clients that only render text
tool results.

`aiegis.evaluate_tool_call` accepts `tool_name`, optional `target`, and optional
`arguments`. It returns an allow, approval, or block decision for the proposed
agent tool call before execution.

`aiegis.inspect_output` accepts `content` and returns an allow or block decision
with redacted text for outbound responses.

When `--audit-log` is configured for the MCP server, minimized content
inspection records and redacted tool firewall decisions are appended to the
local JSONL audit log.
