# AI Agent & MCP Security Checklist

Use this checklist before connecting an AI agent to a repository, secrets, external services, or MCP tools.

> **Scope:** this is a practical preflight checklist, not a certification. A clean result does not prove that an agent or MCP deployment is secure.

## 1. Minimize capabilities

Give the agent only the commands, files, tools, and services it actually needs.

A shell tool, filesystem access, network access, or external service can be legitimate on its own. Risk increases when unnecessary capabilities are combined.

**AgentGuard signals:** `AG-EXEC-001`, `AG-FS-001`.

## 2. Treat external instructions as untrusted

Repository files, issue text, web content, tool results, and other external inputs can contain instructions that attempt to redirect the agent.

Separate trusted policy from untrusted content and review instruction files for prompt-injection patterns.

**AgentGuard signal:** `AG-PROMPT-001`.

## 3. Keep sensitive data out of tracked configuration

Do not put API keys, passwords, private keys, or other credentials in agent or MCP configuration committed to source control.

Use an appropriate secret manager or CI secret mechanism instead.

**AgentGuard signal:** `AG-SEC-001`.

## 4. Require approval for privileged actions

Commands that can modify files, delete data, publish content, spend money, or change infrastructure deserve stronger approval boundaries.

Avoid configurations that combine broad access with automatic approval.

**AgentGuard signals:** `AG-CODEX-001`, `AG-OPENCODE-001`, `AG-OPENCODE-002`.

## 5. Review MCP trust and confirmation settings

A configuration that disables or bypasses confirmation for tool execution should be an explicit, reviewed decision.

**AgentGuard signal:** `AG-MCP-001`.

## 6. Protect remote transport

Prefer encrypted transport for remote MCP services and verify certificates.

**AgentGuard signal:** `AG-MCP-002`.

## 7. Record provenance for remote MCP servers

Make it possible for users and maintainers to understand where a remote MCP server comes from and which project or repository owns it.

**AgentGuard signal:** `AG-MCP-003`.

## 8. Watch for dangerous capability chains

Risk can emerge from a combination such as:

**untrusted input → access to private data → outbound action**

Review these combinations as a single security boundary rather than evaluating each capability independently.

**AgentGuard signal:** `AG-POLICY-001`.

## 9. Keep agent context focused

Remove obsolete or duplicated instructions and keep context within an intentional budget.

Oversized instruction files increase cost and make review harder.

**AgentGuard signals:** `AG-CONTEXT-001`, `AG-CONTEXT-002`.

## 10. Put the check in CI

Run the same preflight review before changes are merged.

For AgentGuard:

```yaml
- uses: atilaamorim/agentguard@v0.3.1
  with:
    fail-on-severity: "high"
```

For high-assurance supply-chain environments, pin Actions to an immutable commit SHA rather than a moving tag.

## A practical preflight

Before enabling a new agent or MCP integration:

1. Scan the repository locally.
2. Review every High/Critical finding.
3. Add a baseline only for findings you have explicitly accepted.
4. Add the scan to CI.
5. Re-run the scan whenever agent permissions, MCP configuration, or instruction files change.

## How this maps to current agentic-security guidance

OWASP's 2026 Agentic Applications guidance emphasizes risks including **Agent Goal Hijack, Tool Misuse & Exploitation, Identity & Privilege Abuse, Agentic Supply Chain Vulnerabilities,** and **Human-Agent Trust Exploitation**.

AgentGuard is intentionally narrower: it is a deterministic static configuration auditor. It helps surface configuration signals related to these broader risk classes; it is not a complete implementation of the OWASP framework.

- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP MCP Top 10: https://owasp.org/projects/mcp-top-10
- OWASP GenAI Top 10 for 2026: https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/

## Run the checklist against a repository

```bash
python -m pip install agentconfigguard
agentguard scan .
```

To produce machine-readable reports:

```bash
agentguard scan . --json
agentguard scan . --sarif agentguard-results.sarif
agentguard scan . --html agentguard-report.html
```
