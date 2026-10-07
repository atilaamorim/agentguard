# 🛡️ AgentGuard

![Tests](https://github.com/atilaamorim/agentguard/actions/workflows/test.yml/badge.svg) [![PyPI](https://img.shields.io/pypi/v/agentconfigguard.svg)](https://pypi.org/project/agentconfigguard/) [![PyPI downloads](https://img.shields.io/pypi/dm/agentconfigguard.svg)](https://pypi.org/project/agentconfigguard/) ![License](https://img.shields.io/github/license/atilaamorim/agentguard)

**Security and context auditor for AI agents and MCP servers.**

> **Audit your AI agents before they audit your code.**

AgentGuard is an open-source CLI that scans agent instructions, MCP configuration, and project text for common security risks and produces machine-readable reports for CI.

**Static and local by design:** the scanner analyzes files without connecting to agents or invoking MCP tools during the audit.

## Where AgentGuard fits

AgentGuard is intentionally narrow. It is a **local, deterministic configuration auditor** for AI agents and MCP — especially useful as a CI gate before an agent runs.

| Capability | AgentGuard |
| --- | --- |
| Local, read-only configuration audit | ✅ |
| Deterministic rule-based findings | ✅ |
| MCP trust / transport / provenance checks | ✅ |
| Dangerous capability-chain detection | ✅ |
| Provider-specific configuration checks | ✅ |
| JSON / SARIF / HTML output | ✅ |
| GitHub Actions integration | ✅ |
| Policy-as-code and baselines | ✅ |
| Runtime tool-call enforcement | ❌ |
| Live MCP probing | ❌ |
| LLM-powered verdicts | ❌ |
| Security certification or guarantee | ❌ |

This scope is deliberate. AgentGuard should be easy to run in CI, easy to reproduce, and easy to inspect when a finding fires. Runtime enforcement, active probing, and model-backed analysis are better treated as complementary layers rather than silently mixed into a static configuration audit.


## What it checks

| Rule | What it looks for | Severity |
| --- | --- | --- |
| `AG-SEC-001` | API keys, tokens, passwords and private-key material | High |
| `AG-EXEC-001` | Shell, terminal and command-execution capabilities | High |
| `AG-FS-001` | Broad filesystem/workspace access in config | High |
| `AG-MCP-001` | MCP servers configured with `trust=true` | High |
| `AG-MCP-002` | MCP servers using unencrypted `http://` endpoints | Medium |
| `AG-MCP-003` | Remote MCP servers without declared provenance metadata | Low |
| `AG-POLICY-001` | Dangerous combination of untrusted input, private data access and outbound actions | Critical |
| `AG-GEMINI-001` | Gemini CLI persistent approval default | Medium |
| `AG-CODEX-001` | Codex full-access approval combination | High |
| `AG-PROMPT-001` | Common prompt-injection instruction patterns | Medium |
| `AG-CONTEXT-001` | Oversized agent instruction files | Low |
| `AG-CONTEXT-002` | Agent context above a configured token budget | Medium |

The scanner also understands common agent instruction files such as `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `CODEX.md`, and `CURSOR.md`.

## Quick start

Install the latest public release from PyPI:

```bash
python -m pip install agentconfigguard
agentguard --version
agentguard scan .
```

The PyPI distribution is named `agentconfigguard`; the CLI command remains `agentguard`.

For development or unreleased code:

```bash
git clone https://github.com/atilaamorim/agentguard.git
cd agentguard
python -m pip install -e .
agentguard scan .
```

For a development install directly from GitHub:

```bash
python -m pip install git+https://github.com/atilaamorim/agentguard.git
agentguard --version
```

You can also run:

```bash
python -m agentguard scan .
```

### Try it in 10 seconds

Run the built-in local demonstration:

```bash
agentguard demo
```

**Example safe configuration (no findings):**
```bash
echo "## Agent Instructions" > SAFE_AGENT.md
echo "Only read from approved directories" >> SAFE_AGENT.md
agentguard scan SAFE_AGENT.md
```

**Example risky configuration (will show findings):**
```bash
echo "trust_all_connections: true" > UNSAFE_CONFIG.yml
agentguard demo --json
```

The demo uses a synthetic MCP configuration and performs no network access or file writes. Use `agentguard demo --json` for machine-readable output or `agentguard demo --html` for formatted reports.

### CI/CD Integration

**GitHub Actions:**
```yaml
- name: AgentGuard Security Scan
  uses: atilaamorim/agentguard@main
  with:
    path: .
    output-format: sarif
  env:
    AGENTGUARD_CI: "true"
```

**CircleCI:**
```yaml
- run:
    name: AgentGuard Security Scan
    command: |
      python -m pip install agentconfigguard
      agentguard scan . --json > agentguard-report.json
```

### JSON output

```bash
agentguard scan . --json
```

### SARIF output

SARIF works well with GitHub code-scanning workflows:

```bash
agentguard scan . --sarif
