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
