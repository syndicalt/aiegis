# Deployment Runbook

This runbook covers the supported production deployment modes for AIegis. Keep
policy files read-only, keep audit and approval logs on durable storage, and run
the release check before promoting a new build.

## Local CLI

Use the CLI for operator-driven inspection, red-team replay, and incident
triage. External files should be treated as untrusted inputs and inspected
before their content is copied into an agent context.

```bash
aiegis inspect-html suspicious.html --policy-file deploy/policies/policies.yaml
aiegis inspect-email message.eml --policy-file deploy/policies/policies.yaml
aiegis inspect-memory memory.txt --policy-file deploy/policies/policies.yaml
aiegis inspect-document report.pdf --policy-file deploy/policies/policies.yaml
aiegis inspect-output response.txt --policy-file deploy/policies/policies.yaml
```

Store CLI audit output in a controlled path when preserving evidence:

```bash
aiegis inspect-html suspicious.html \
  --policy-file deploy/policies/policies.yaml \
  --audit-log .aiegis/audit.jsonl
```

Verify append-only audit integrity after inspections and before archiving logs:

```bash
aiegis verify-audit-log .aiegis/audit.jsonl
```

## MCP Stdio Server

Run the MCP stdio server when an agent can connect directly to AIegis as a
guarded tool server. The server should receive policy from a read-only path and
write logs to durable storage owned by the AIegis runtime user.

```bash
aiegis mcp-stdio \
  --policy-file /etc/aiegis/policies.yaml \
  --policy-profile default \
  --audit-log /var/lib/aiegis/audit.jsonl \
  --eventloom-log /var/lib/aiegis/eventloom.jsonl
```

Use the eventloom sink when the deployment already has an Eventloom-compatible
log pipeline. Otherwise, the JSONL audit log remains the authoritative local
record.

## MCP Stdio Proxy

Run the proxy when an agent needs access to another MCP stdio server through
AIegis policy enforcement. The backend command is passed after `--`, and AIegis
records both guard decisions and approval queue entries.

```bash
aiegis mcp-proxy-stdio \
  --policy-file /etc/aiegis/policies.yaml \
  --policy-profile default \
  --audit-log /var/lib/aiegis/audit.jsonl \
  --approval-log /var/lib/aiegis/approvals.jsonl \
  -- python backend_mcp_server.py
```

Approval logs are records, not an execution engine. Operators must wire approved
actions into their own workflow and preserve the approval log with the matching
audit log.

## Container Runtime

Use the checked-in Docker Compose example for local sidecar testing and as the
baseline for orchestrated deployments.

```bash
docker compose -f deploy/docker-compose.yml up --build
```

Production containers should run as the non-root `aiegis` user, keep the root
filesystem read-only, mount policy files read-only, and provide a writable
volume for `/var/lib/aiegis`. Preserve `no-new-privileges` and add network
egress restrictions at the orchestrator or service-mesh layer.

## Operational Checks

Run the release gate before shipping an image or package:

```bash
scripts/release-check.sh
```

For deployments that render HTML, browse the web, or execute generated code,
run those tools outside AIegis in a hardened sandbox such as a locked-down
container, gVisor, Firecracker, or an equivalent platform control. AIegis can
build and audit guarded commands, but the host deployment must provide the
actual sandbox runtime.
