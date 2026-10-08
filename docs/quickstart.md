# Quick start

## Install

Using pip:

```bash
python -m pip install agentconfigguard
```

For an isolated CLI install, pipx also works:

```bash
pipx install agentconfigguard
```

## Run the local demo

```bash
agentguard demo
```

The demo uses synthetic configuration and does not connect to an MCP server.

## Scan a repository

```bash
agentguard scan .
```

Useful machine-readable outputs:

```bash
agentguard scan . --json
agentguard scan . --sarif agentguard-results.sarif
agentguard scan . --html agentguard-report.html
```

## Add a CI gate

```yaml
- uses: actions/checkout@v7
- uses: atilaamorim/agentguard@v0.3.1
  with:
    fail-on-severity: "high"
```

## Adopt an existing repository gradually

Generate a baseline:

```bash
agentguard scan . --write-baseline agentguard-baseline.json
```

Then report only new findings:

```bash
agentguard scan . --baseline agentguard-baseline.json
```

## Next steps

Use the rule reference in [docs/rules.md](rules.md) to understand each finding and its recommended remediation.

For security vulnerabilities, use the repository's private vulnerability reporting flow instead of opening a public issue.
