# AIegis Core Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first tested AIegis package: trust-labeled content ingestion, HTML/email threat detection, policy decisions, audit records, and CLI inspection entrypoints.

**Architecture:** Keep the first slice deliberately small: pure Python modules with deterministic behavior and no network calls. HTML ingestion produces a `GuardedContent` value; policy evaluation consumes content plus proposed actions; audit code serializes decisions for later MCP gateway integration.

**Tech Stack:** Python 3.11+, BeautifulSoup/html5lib for tolerant HTML parsing, pytest/pytest-cov for tests and 90% coverage enforcement, Ruff/mypy for production hygiene.

---

### Task 1: Project Harness

**Files:**
- Create: `pyproject.toml`
- Create: `README.md`
- Create: `src/aiegis/__init__.py`

- [ ] **Step 1: Add package and tool configuration**

Create `pyproject.toml` with project metadata, dependencies, coverage gate, Ruff, and mypy settings.

- [ ] **Step 2: Add initial README**

Document the boundary AIegis protects, the current MVP scope, and the required verification commands.

### Task 2: Trust-Labeled Domain Model

**Files:**
- Create: `tests/test_models.py`
- Create: `src/aiegis/models.py`

- [ ] **Step 1: Write failing tests**

Tests cover immutable findings, guarded content serialization, trust labels, and risk aggregation.

- [ ] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_models.py -q`

- [ ] **Step 3: Implement minimal model code**

Implement the dataclasses and enums needed by the tests.

- [ ] **Step 4: Run tests and verify pass**

Run: `pytest tests/test_models.py -q`

### Task 3: HTML Ingestion Guard

**Files:**
- Create: `tests/test_html_guard.py`
- Create: `src/aiegis/html_guard.py`

- [ ] **Step 1: Write failing tests**

Tests cover script removal, visible text extraction, hidden text quarantine, prompt-injection phrase detection, metadata quarantine, and safe link extraction.

- [ ] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_html_guard.py -q`

- [ ] **Step 3: Implement minimal HTML guard**

Use BeautifulSoup/html5lib, deterministic style checks, and explicit findings.

- [ ] **Step 4: Run tests and verify pass**

Run: `pytest tests/test_html_guard.py -q`

### Task 4: Policy Decisions And Audit Records

**Files:**
- Create: `tests/test_policy.py`
- Create: `tests/test_audit.py`
- Create: `src/aiegis/policy.py`
- Create: `src/aiegis/audit.py`

- [ ] **Step 1: Write failing tests**

Tests cover allowed decisions, quarantine decisions, approval-required tool actions, blocked exfiltration attempts, and stable audit JSON.

- [ ] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_policy.py tests/test_audit.py -q`

- [ ] **Step 3: Implement minimal policy and audit modules**

Implement deterministic policy evaluation without model calls or external services.

- [ ] **Step 4: Run tests and verify pass**

Run: `pytest tests/test_policy.py tests/test_audit.py -q`

### Task 5: CLI Inspection Entrypoint

**Files:**
- Create: `tests/test_cli.py`
- Create: `src/aiegis/cli.py`

- [ ] **Step 1: Write failing tests**

Tests cover inspecting HTML from stdin and returning JSON with text, findings, quarantine state, and policy decision.

- [ ] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_cli.py -q`

- [ ] **Step 3: Implement minimal CLI**

Implement `aiegis inspect-html` with stdin/file input and JSON output.

- [ ] **Step 4: Run tests and verify pass**

Run: `pytest tests/test_cli.py -q`

### Task 6: Full Verification

**Files:**
- Modify: none unless verification exposes defects.

- [ ] **Step 1: Run full suite**

Run: `pytest --cov=aiegis --cov-report=term-missing --cov-fail-under=90`

- [ ] **Step 2: Run lint and type checks**

Run: `ruff check .`

Run: `mypy src`

- [ ] **Step 3: Fix only verified defects**

Any fix must be covered by a failing test first unless it is purely configuration or formatting.

### Task 7: Email Ingestion Guard

**Files:**
- Create: `tests/test_email_guard.py`
- Create: `src/aiegis/email_guard.py`
- Modify: `tests/test_cli.py`
- Modify: `src/aiegis/cli.py`
- Modify: `README.md`

- [x] **Step 1: Write failing tests**

Tests cover plain body extraction, HTML part inspection through the existing HTML guard,
attachment quarantine, Reply-To mismatch findings, prompt-injection phrase findings, and
`aiegis inspect-email`.

- [x] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_email_guard.py tests/test_cli.py -q`

Observed: failed with `ModuleNotFoundError: No module named 'aiegis.email_guard'`.

- [x] **Step 3: Implement minimal email guard and CLI command**

Implemented `inspect_email()` with stdlib email parsing and added `inspect-email` to the CLI.

- [x] **Step 4: Run tests and verify pass**

Run: `pytest tests/test_email_guard.py tests/test_cli.py -q`

Observed: `8 passed`.

### Task 8: Configurable Policy Profiles

**Files:**
- Create: `tests/test_policy_profiles.py`
- Create: `src/aiegis/policy_profiles.py`
- Create: `examples/policies.yaml`
- Modify: `pyproject.toml`
- Modify: `tests/test_cli.py`
- Modify: `src/aiegis/cli.py`
- Modify: `README.md`

- [x] **Step 1: Write failing tests**

Tests cover loading a named YAML profile, rejecting unknown profiles, rejecting non-string
actions, rejecting unknown keys, and CLI selection with `--policy-file` and
`--policy-profile`.

- [x] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_policy_profiles.py tests/test_cli.py -q`

Observed: failed with `ModuleNotFoundError: No module named 'aiegis.policy_profiles'`.

- [x] **Step 3: Implement minimal policy profile loader and CLI flags**

Implemented strict YAML loading with `PyYAML`, profile validation, and CLI policy selection.

- [x] **Step 4: Run focused tests and verify pass**

Run: `pytest tests/test_policy_profiles.py tests/test_cli.py -q`

Observed: `10 passed`.

### Task 9: Zaxy Eventloom Audit Sink

**Files:**
- Create: `tests/test_eventloom_sink.py`
- Create: `src/aiegis/eventloom_sink.py`
- Modify: `tests/test_cli.py`
- Modify: `src/aiegis/cli.py`
- Modify: `README.md`

- [x] **Step 1: Write failing tests**

Tests cover metadata-only Eventloom payload construction, optional Zaxy dependency
failure, EventLog append arguments, and CLI wiring through `--eventloom-log` and
`--eventloom-thread`.

- [x] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_eventloom_sink.py tests/test_cli.py -q`

Observed: failed with `ModuleNotFoundError: No module named 'aiegis.eventloom_sink'`.

- [x] **Step 3: Implement minimal sink and CLI flags**

Implemented `EventloomSink`, metadata-first payload building, optional import of
`zaxy.event.EventLog`, and CLI append support.

- [x] **Step 4: Run focused tests and verify pass**

Run: `pytest tests/test_eventloom_sink.py tests/test_cli.py -q`

Observed: `10 passed`.

### Task 10: MCP Stdio Guard Server

**Files:**
- Create: `tests/test_mcp_server.py`
- Create: `src/aiegis/mcp_server.py`
- Modify: `tests/test_cli.py`
- Modify: `src/aiegis/cli.py`
- Modify: `README.md`

- [x] **Step 1: Write failing tests**

Tests cover MCP `initialize`, `tools/list`, `tools/call` for HTML and email
inspection, unknown-tool JSON-RPC errors, stdio notification handling, parse-error
handling, and CLI wiring through `aiegis mcp-stdio`.

- [x] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_mcp_server.py -q`

Observed: failed with `ModuleNotFoundError: No module named 'aiegis.mcp_server'`.

- [x] **Step 3: Implement minimal MCP stdio server**

Implemented a stdlib JSON-RPC stdio server exposing `aiegis.inspect_html` and
`aiegis.inspect_email`. Tool calls delegate to existing ingestion guards and
policy evaluation, returning both `structuredContent` and a JSON text result.

- [x] **Step 4: Run focused tests and verify pass**

Run: `pytest tests/test_mcp_server.py tests/test_cli.py -q`

Observed: `15 passed`.

### Task 16: Explicit Raw JSONL Audit Opt-In

**Files:**
- Modify: `tests/test_jsonl_audit_sink.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_mcp_server.py`
- Modify: `src/aiegis/jsonl_audit_sink.py`
- Modify: `src/aiegis/cli.py`
- Modify: `src/aiegis/mcp_server.py`
- Modify: `README.md`

- [x] **Step 1: Write failing tests**

Tests cover `JsonlAuditSink(include_raw=True)`, CLI `--audit-include-raw`, MCP
`audit_include_raw` configuration, and raw content/tool argument capture only
when explicitly enabled.

- [x] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_jsonl_audit_sink.py tests/test_cli.py tests/test_mcp_server.py -q`

Observed: failed because `include_raw`, `--audit-include-raw`, and
`McpServerConfig.audit_include_raw` were not implemented.

- [x] **Step 3: Implement raw audit opt-in**

Added the `include_raw` sink option, CLI flag, MCP config field, and README
warning. Minimized/redacted audit payloads remain the default.

- [x] **Step 4: Run focused tests and verify pass**

Run: `pytest tests/test_jsonl_audit_sink.py tests/test_cli.py tests/test_mcp_server.py -q`

Observed: `33 passed`.

### Task 17: Tamper-Evident JSONL Audit Logs

**Files:**
- Create: `src/aiegis/audit_integrity.py`
- Modify: `tests/test_jsonl_audit_sink.py`
- Modify: `tests/test_cli.py`
- Modify: `src/aiegis/jsonl_audit_sink.py`
- Modify: `src/aiegis/cli.py`
- Modify: `README.md`

- [x] **Step 1: Write failing tests**

Tests cover first-event integrity fields, chained second events, verification of
valid audit logs, tamper detection, and CLI `verify-audit-log` behavior.

- [x] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_jsonl_audit_sink.py tests/test_cli.py -q`

Observed: failed with `ModuleNotFoundError: No module named 'aiegis.audit_integrity'`.

- [x] **Step 3: Implement audit integrity**

Added reusable audit sealing and verification helpers, wired `JsonlAuditSink` to
seal every event with `previous_event_hash` and `event_hash`, and added
`aiegis verify-audit-log`.

- [x] **Step 4: Run focused tests and verify pass**

Run: `pytest tests/test_jsonl_audit_sink.py tests/test_cli.py -q`

Observed: `23 passed`.

### Task 18: Input Flood Protection

**Files:**
- Create: `src/aiegis/input_limits.py`
- Modify: `tests/test_html_guard.py`
- Modify: `tests/test_email_guard.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_mcp_server.py`
- Modify: `src/aiegis/html_guard.py`
- Modify: `src/aiegis/email_guard.py`
- Modify: `src/aiegis/cli.py`
- Modify: `src/aiegis/mcp_server.py`
- Modify: `README.md`

- [x] **Step 1: Write failing tests**

Tests cover configured truncation for HTML and email ingestion, CLI
`--max-input-chars`, and MCP `McpServerConfig.max_input_chars`.

- [x] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_html_guard.py tests/test_email_guard.py tests/test_cli.py tests/test_mcp_server.py -q`

Observed: failed because `max_input_chars`, CLI flag parsing, and MCP config
support were not implemented.

- [x] **Step 3: Implement input limit guard**

Added shared input-limit handling with an `input_truncated` finding, wired the
limit through HTML/email ingestion, CLI commands, and MCP runtime config.

- [x] **Step 4: Run focused tests and verify pass**

Run: `pytest tests/test_html_guard.py tests/test_email_guard.py tests/test_cli.py tests/test_mcp_server.py -q`

Observed: `44 passed`.

### Task 19: Output Egress Guard

**Files:**
- Create: `tests/test_egress_guard.py`
- Create: `src/aiegis/egress_guard.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_mcp_server.py`
- Modify: `src/aiegis/cli.py`
- Modify: `src/aiegis/mcp_server.py`
- Modify: `README.md`

- [x] **Step 1: Write failing tests**

Tests cover allowing ordinary outbound text, blocking and redacting secret-like
output, avoiding raw secret values in serialized inspection results, CLI
`inspect-output`, and MCP `aiegis.inspect_output`.

- [x] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_egress_guard.py tests/test_cli.py tests/test_mcp_server.py -q`

Observed: failed with `ModuleNotFoundError: No module named 'aiegis.egress_guard'`.

- [x] **Step 3: Implement egress inspection**

Added deterministic egress scanning for private key blocks, common token
prefixes, and secret-like assignments. The guard returns redacted text, finding
metadata without raw secret evidence, and a block/allow decision.

- [x] **Step 4: Run focused tests and verify pass**

Run: `pytest tests/test_egress_guard.py tests/test_cli.py tests/test_mcp_server.py -q`

Observed: `38 passed`.

### Task 20: Configurable Egress Policy Profiles

**Files:**
- Modify: `tests/test_egress_guard.py`
- Modify: `tests/test_policy_profiles.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_mcp_server.py`
- Modify: `src/aiegis/egress_guard.py`
- Modify: `src/aiegis/policy_profiles.py`
- Modify: `src/aiegis/cli.py`
- Modify: `src/aiegis/mcp_server.py`
- Modify: `examples/policies.yaml`
- Modify: `README.md`

- [x] **Step 1: Write failing tests**

Tests cover `EgressPolicy`, YAML `blocked_egress_patterns`, unknown pattern
validation, CLI `inspect-output` profile selection, and MCP egress policy
configuration.

- [x] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_egress_guard.py tests/test_policy_profiles.py tests/test_cli.py tests/test_mcp_server.py -q`

Observed: failed because `EgressPolicy` did not exist and policy profiles did
not load egress settings.

- [x] **Step 3: Implement profile-driven egress policy**

Added `EgressPolicy`, known egress pattern validation, profile loading through
`LoadedPolicyProfile`, and CLI/MCP propagation.

- [x] **Step 4: Run focused tests and verify pass**

Run: `pytest tests/test_egress_guard.py tests/test_policy_profiles.py tests/test_cli.py tests/test_mcp_server.py -q`

Observed: `49 passed`.

### Task 14: Local JSONL Audit Sink

**Files:**
- Create: `tests/test_jsonl_audit_sink.py`
- Create: `src/aiegis/jsonl_audit_sink.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_mcp_server.py`
- Modify: `src/aiegis/cli.py`
- Modify: `src/aiegis/mcp_server.py`
- Modify: `README.md`

- [x] **Step 1: Write failing tests**

Tests cover appending content audit records and tool-call decisions to local
JSONL, CLI `--audit-log` wiring for inspection commands, MCP `--audit-log`
configuration, and MCP audit writes for content and tool decisions.

- [x] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_jsonl_audit_sink.py -q`

Observed: failed with `ModuleNotFoundError: No module named 'aiegis.jsonl_audit_sink'`.

- [x] **Step 3: Implement JSONL sink and runtime wiring**

Implemented `JsonlAuditSink`, added `--audit-log`, appended content inspection
records from CLI and MCP, and appended MCP tool firewall decisions when a local
audit log is configured.

- [x] **Step 4: Run focused tests and verify pass**

Run: `pytest tests/test_mcp_server.py tests/test_cli.py tests/test_jsonl_audit_sink.py -q`

Observed: `26 passed`.

### Task 15: Minimized And Redacted JSONL Audits

**Files:**
- Modify: `tests/test_jsonl_audit_sink.py`
- Modify: `src/aiegis/jsonl_audit_sink.py`
- Modify: `README.md`

- [x] **Step 1: Write failing tests**

Tests cover omitting raw content text and quarantined segment bodies from local
content audit payloads, and redacting sensitive tool argument values from local
tool-call audit payloads.

- [x] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_jsonl_audit_sink.py -q`

Observed: failed because raw content text and raw `token` values were present in
JSONL payloads.

- [x] **Step 3: Implement minimized/redacted JSONL payloads**

Changed `JsonlAuditSink` to emit minimized content payloads with counts and
finding metadata instead of raw bodies, and to redact sensitive tool argument
values by key before writing JSONL.

- [x] **Step 4: Run focused tests and verify pass**

Run: `pytest tests/test_jsonl_audit_sink.py tests/test_cli.py tests/test_mcp_server.py -q`

Observed: `28 passed`.

### Task 13: Configurable Tool Firewall Profiles

**Files:**
- Modify: `tests/test_policy_profiles.py`
- Modify: `src/aiegis/policy_profiles.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_mcp_server.py`
- Modify: `src/aiegis/cli.py`
- Modify: `examples/policies.yaml`
- Modify: `README.md`

- [x] **Step 1: Write failing tests**

Tests cover loading `approval_required_tools`, `blocked_tools`, and
`sensitive_argument_keys` from YAML profiles, rejecting non-string tool lists,
passing configured tool policy into `mcp-stdio`, and MCP evaluation under a
custom firewall policy.

- [x] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_policy_profiles.py -q`

Observed: failed with `ImportError: cannot import name 'LoadedPolicyProfile'`.

- [x] **Step 3: Implement profile loading and MCP wiring**

Implemented `LoadedPolicyProfile`, added strict validation for tool firewall
profile keys, kept existing content-policy callers backward-compatible, and
wired `mcp-stdio` to load both content and tool policies.

- [x] **Step 4: Run focused tests and verify pass**

Run: `pytest tests/test_mcp_server.py tests/test_cli.py tests/test_policy_profiles.py -q`

Observed: `26 passed`.

### Task 11: MCP Runtime Policy And Audit Configuration

**Files:**
- Modify: `tests/test_mcp_server.py`
- Modify: `src/aiegis/mcp_server.py`
- Modify: `tests/test_cli.py`
- Modify: `src/aiegis/cli.py`
- Modify: `README.md`

- [x] **Step 1: Write failing tests**

Tests cover custom `McpServerConfig` policy evaluation, metadata-only Eventloom
append behavior for MCP tool calls, and CLI propagation of `--policy-file`,
`--policy-profile`, `--eventloom-log`, and `--eventloom-thread` to `mcp-stdio`.

- [x] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_mcp_server.py -q`

Observed: failed with `ImportError: cannot import name 'McpServerConfig'`.

- [x] **Step 3: Implement MCP server runtime config**

Implemented `McpServerConfig`, routed policy evaluation through it, appended
Eventloom audits for MCP tool calls when configured, and wired the same flags
onto `aiegis mcp-stdio`.

- [x] **Step 4: Run focused tests and verify pass**

Run: `pytest tests/test_mcp_server.py tests/test_cli.py -q`

Observed: `18 passed`.

### Task 12: Tool-Call Policy Firewall

**Files:**
- Create: `tests/test_tool_firewall.py`
- Create: `src/aiegis/tool_firewall.py`
- Modify: `tests/test_mcp_server.py`
- Modify: `src/aiegis/mcp_server.py`
- Modify: `README.md`

- [x] **Step 1: Write failing tests**

Tests cover blocked tools, secret-bearing external tool calls, approval-required
tools, external target approval, low-risk local allow decisions, MCP tool
discovery, and MCP `tools/call` behavior for `aiegis.evaluate_tool_call`.

- [x] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_tool_firewall.py -q`

Observed: failed with `ModuleNotFoundError: No module named 'aiegis.tool_firewall'`.

- [x] **Step 3: Implement firewall evaluator and MCP tool**

Implemented `ToolCallRequest`, `ToolCallPolicy`, `ToolCallDecision`, deterministic
tool-call evaluation, and exposed the evaluator through MCP as
`aiegis.evaluate_tool_call`.

- [x] **Step 4: Run focused tests and verify pass**

Run: `pytest tests/test_mcp_server.py tests/test_tool_firewall.py -q`

Observed: `15 passed`.

### Task 21: MCP Backend Proxy Core

**Files:**
- Create: `tests/test_mcp_proxy.py`
- Create: `src/aiegis/mcp_proxy.py`
- Modify: `README.md`
- Modify: `docs/superpowers/plans/2026-05-17-aiegis-core-harness.md`

- [x] **Step 1: Write failing tests**

Tests cover backend `tools/list` forwarding, blocked backend `tools/call`
requests, allowed backend tool forwarding, outbound secret-like backend response
blocking, and local handling of `aiegis.*` guard tools without forwarding.

- [x] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_mcp_proxy.py`

Observed: failed with `ModuleNotFoundError: No module named 'aiegis.mcp_proxy'`.

- [x] **Step 3: Implement MCP proxy core**

Implemented `McpProxyConfig`, the backend protocol, JSON-RPC proxy handling,
pre-forward tool firewall evaluation, local AIegis guard tool delegation, and
post-backend egress inspection with redacted blocked responses.

- [x] **Step 4: Run focused tests and verify pass**

Run: `pytest tests/test_mcp_proxy.py`

Observed: `5 passed`.
