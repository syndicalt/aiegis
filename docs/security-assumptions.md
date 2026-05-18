# Security Assumptions

This document states the boundaries AIegis relies on in production. It is a
guard harness, not a replacement for host isolation, credential scoping, or
operator review.

## Trust Boundaries

External content is untrusted. HTML, email, document text, tool responses,
memory records, metadata, and model output can all contain malicious
instructions or exfiltration attempts.

AIegis assumes system prompts, policy files, operator configuration, and
deployment credentials are controlled by the operator. Policy files must be
mounted read-only for the runtime process. Audit and approval logs must be
written to storage that untrusted tools cannot modify.

Backend MCP servers, browser processes, document parsers, and shell commands are
outside the AIegis trust boundary. AIegis can mediate inputs and command
construction, but the deployment must isolate those processes.

## Operator Responsibilities

Operators are responsible for least-privilege credentials, network egress
controls, durable log storage, log rotation, audit verification, and human
approval workflows for high-risk actions. They must run the release gate before
upgrades and replay red-team fixtures when changing policy.

Operators must choose and maintain any browser, PDF, attachment, or code
execution sandbox. The browser sandbox command builder requires a real sandbox
wrapper and browser binary supplied by the deployment.

## Unsupported Cases

AIegis does not guarantee detection of every prompt injection, poisoned memory
record, malicious document, or secret exfiltration attempt. Detection rules and
classifiers reduce risk; they do not prove content is safe.

AIegis does not safely execute untrusted code by itself. It does not provide a
network firewall, a kernel sandbox, a browser isolation layer, a secrets
manager, or an enterprise identity system.

PDF and attachment handling depend on the configured extractor. If no trusted
extractor is configured, operators should quarantine the file or inspect it in a
separate sandbox.

The MCP stdio proxy supports stdio mediation. HTTP, SSE, hosted MCP gateways,
and remote transport authentication require separate deployment controls until
explicitly integrated.

## Failure Modes

When AIegis blocks or quarantines content, downstream agents may receive less
context than expected. Operators should make block decisions visible in the
agent workflow instead of silently replacing content.

When AIegis allows content, the content is still untrusted. Agents must continue
to separate instructions from data and require approval for sensitive actions.

If audit writes fail, deployments should fail closed for autonomous workflows
that require accountability. If approval writes fail, high-risk actions should
remain pending rather than executing without a record.
