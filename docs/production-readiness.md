# AIegis Production Readiness

This checklist tracks the remaining work needed to move AIegis from a complete
local harness into an operational production deployment.

- [x] CI quality gate
  - GitHub Actions runs the release check on Python 3.11, 3.12, and 3.13.
  - `scripts/release-check.sh` runs coverage, lint, type checks, package build,
    and distribution metadata checks.
- [x] Container runtime
  - Provide a minimal runtime image for the CLI and MCP stdio entrypoints.
  - Run as a non-root user and keep mutable audit/approval data in mounted
    volumes.
- [x] Red-team regression corpus
  - Add fixture-driven tests for known HTML, email, memory, document, tool, and
    egress attack patterns.
- [ ] Deployment runbook
  - Document local, sidecar, and service deployment modes with policy, audit,
    approval, and sandbox guidance.
- [ ] Security assumptions
  - Document trust boundaries, unsupported cases, operational responsibilities,
    and failure modes.
