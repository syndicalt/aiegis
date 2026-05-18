# GitHub Pages Site Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a public GitHub Pages site for AIegis that explains the agent-security problem, the harness architecture, production posture, and how to try the project.

**Architecture:** Publish a no-build static site from `docs/index.html` with styling in `docs/site.css`. Add artifact tests that enforce required sections, links, concrete security terms, and avoidance of generic AI SaaS copy.

**Tech Stack:** Static HTML, CSS, pytest artifact tests, existing `scripts/release-check.sh`.

---

## File Structure

- Create `tests/test_github_pages_site.py`: verifies site artifacts and copy requirements.
- Create `docs/index.html`: single-page GitHub Pages site with semantic sections.
- Create `docs/site.css`: responsive professional security/infrastructure styling.
- Modify `.gitignore`: ignore `.superpowers/` visual brainstorming artifacts.

## Task 1: Site Artifact Tests

**Files:**
- Create: `tests/test_github_pages_site.py`

- [ ] **Step 1: Write the failing tests**

```python
from pathlib import Path


SITE = Path("docs/index.html")
CSS = Path("docs/site.css")


def test_github_pages_site_artifacts_exist() -> None:
    assert SITE.exists()
    assert CSS.exists()


def test_github_pages_site_has_required_sections() -> None:
    html = SITE.read_text(encoding="utf-8")

    for section_id in [
        'id="problem"',
        'id="architecture"',
        'id="guards"',
        'id="quick-start"',
        'id="production"',
        'id="docs"',
    ]:
        assert section_id in html


def test_github_pages_site_links_to_project_docs() -> None:
    html = SITE.read_text(encoding="utf-8")

    for link in [
        "../README.md",
        "deployment-runbook.md",
        "security-assumptions.md",
        "production-readiness.md",
        "../examples/policies.yaml",
    ]:
        assert link in html


def test_github_pages_site_uses_concrete_security_language() -> None:
    html = SITE.read_text(encoding="utf-8").lower()

    for phrase in [
        "indirect prompt injection",
        "memory poisoning",
        "mcp stdio proxy",
        "eventloom",
        "audit log",
        "approval queue",
    ]:
        assert phrase in html


def test_github_pages_site_avoids_generic_ai_saas_copy() -> None:
    html = SITE.read_text(encoding="utf-8").lower()

    forbidden = [
        "unlock your ai workforce",
        "10x productivity",
        "supercharge your agents",
        "autonomous workforce",
    ]
    for phrase in forbidden:
        assert phrase not in html
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_github_pages_site.py -q`

Expected: FAIL because `docs/index.html` and `docs/site.css` do not exist yet.

## Task 2: Static Site Implementation

**Files:**
- Create: `docs/index.html`
- Create: `docs/site.css`

- [ ] **Step 1: Implement `docs/index.html`**

Create a semantic static page with:

- navigation links to `#problem`, `#architecture`, `#guards`, `#quick-start`, `#production`, and `#docs`
- a compact incident-style hero
- concrete problem description
- architecture diagram made from HTML elements
- guard surface grid
- command examples for CLI, MCP stdio server, MCP stdio proxy, and Docker Compose
- production posture and docs links

- [ ] **Step 2: Implement `docs/site.css`**

Create responsive CSS with:

- light, professional security/infrastructure palette
- no gradient orb or decorative blob treatment
- stable card, grid, and code block dimensions
- mobile-friendly navigation and typography
- accessible focus states

- [ ] **Step 3: Run focused tests**

Run: `pytest tests/test_github_pages_site.py -q`

Expected: PASS.

## Task 3: Repository Hygiene

**Files:**
- Modify: `.gitignore`

- [ ] **Step 1: Ignore visual brainstorming artifacts**

Add:

```gitignore
.superpowers/
```

- [ ] **Step 2: Run status check**

Run: `git status --short`

Expected: `.superpowers/` does not appear as an untracked directory.

## Task 4: Full Verification And Commit

**Files:**
- Verify all changed files.

- [ ] **Step 1: Run release gate**

Run: `scripts/release-check.sh`

Expected: PASS with coverage at or above 90%, ruff passing, mypy passing, package build passing, and twine check passing.

- [ ] **Step 2: Run whitespace check**

Run: `git diff --check`

Expected: no output and exit code 0.

- [ ] **Step 3: Commit**

```bash
git add .gitignore docs/index.html docs/site.css docs/superpowers/specs/2026-05-18-github-pages-site-design.md docs/superpowers/plans/2026-05-18-github-pages-site.md tests/test_github_pages_site.py
git commit -m "docs: add github pages site"
```

Expected: one local commit containing the site, tests, spec, plan, and repo hygiene update.

## Self-Review

- Spec coverage: the plan covers the single-page site, hybrid incident/control-plane structure, concrete docs links, tests, responsive styling, and verification.
- Placeholder scan: no task relies on unspecified implementation details for the testable deliverables.
- Scope check: this is a single static site with no runtime build, no analytics, no deployment automation, and no separate documentation generator.
