# GitHub Pages Site Design

## Goal

Build a public GitHub Pages site for AIegis that explains the agent-security
problem, presents AIegis as a production-ready harness for untrusted content and
tool boundaries, and gives technical visitors a clear path to try the project.

## Audience

The primary audience is a balanced mix of technical/security readers and
hands-on adopters. The page should first satisfy people evaluating the threat
model and architecture, then make it easy for developers to run the CLI, MCP
server, MCP proxy, and container runtime.

## Positioning

The site should not look or sound like a generic AI SaaS landing page. It should
feel like a serious open-source infrastructure/security project: direct,
specific, evidence-led, and operationally grounded.

The opening should use a tight incident narrative: hostile external content
tries to instruct an agent to leak or misuse data, and AIegis intercepts the
content before it reaches trusted context or tool execution. This narrative must
stay compact. Most of the page should explain the harness architecture and
deployment model.

## Information Architecture

The site is a single static page published from `docs/index.html`.

Sections:

1. Hero: concise incident narrative, clear one-sentence product definition,
   primary links to GitHub/source and documentation.
2. Problem: indirect prompt injection, data/memory poisoning, egress attempts,
   tool exploitation, and rendering/tool boundary risks.
3. Harness architecture: untrusted content enters AIegis, guards inspect and
   label it, policy decides allow/block/approval, MCP/tool boundaries are
   mediated, outputs are inspected, and audit logs record decisions.
4. Guard surfaces: HTML, email, memory, document, tool firewall, browser command
   planning, output egress, approval queue, JSONL audit, Eventloom sink.
5. Quick start: install/development command, CLI examples, MCP stdio server,
   MCP stdio proxy, Docker Compose.
6. Production posture: release gate, 90% coverage requirement, red-team corpus,
   container runtime, audit verification, security assumptions.
7. Documentation links: README, deployment runbook, security assumptions,
   production-readiness checklist, example policies.

## Visual Direction

Use the selected hybrid direction:

- C for the first impression: a short attack/incident example in the hero.
- B for the majority of the site: control-plane architecture, policy decisions,
  and deployment modes.

The visual language should be restrained and technical: light background,
high-contrast text, compact panels, structured diagrams made with HTML/CSS, and
code examples. Avoid oversized glossy gradients, dark purple AI themes, floating
orbs, stock imagery, fake dashboards, fake metrics, mascot language, or broad
claims that the tool makes agents safe by itself.

## Implementation

Create a static GitHub Pages site with:

- `docs/index.html`: semantic page structure and copy.
- `docs/site.css`: responsive styling for the page.
- `tests/test_github_pages_site.py`: artifact tests that verify the page has
  required sections, links, and non-generic positioning language.

The site must use relative links so it works on GitHub Pages without a build
step. It should link to existing project docs and files in the repository.

## Testing

Add tests before the site implementation. The tests should verify:

- `docs/index.html` and `docs/site.css` exist.
- The page includes the required problem, architecture, guard surface, quick
  start, production posture, and documentation sections.
- The page links to README, deployment runbook, security assumptions,
  production readiness, and example policies.
- The page includes concrete product terms such as indirect prompt injection,
  memory poisoning, MCP stdio proxy, Eventloom, audit log, and approval queue.
- The page avoids generic AI SaaS phrases such as "unlock your AI workforce" and
  "10x productivity".

Run the focused site tests first, then run `scripts/release-check.sh`.
