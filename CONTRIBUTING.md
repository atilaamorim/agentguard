# Contributing to AgentGuard

Thanks for helping make AI-agent and MCP security tooling better.

## Development

1. Fork the repository.
2. Create a focused branch.
3. Install the project with `pip install -e .`.
4. Run `pytest -q`.
5. Add tests for new detection rules or behavior.
6. Add or update a regression fixture when a rule affects MCP policy analysis.
7. Open a pull request explaining the security problem or use case.

## Good places to start

New contributors can start with these focused issues:

- [#12 — Add more MCP provenance regression cases](https://github.com/atilaamorim/agentguard/issues/12)
- [#13 — Improve AgentGuard demo and onboarding examples](https://github.com/atilaamorim/agentguard/issues/13)

These tasks are intentionally scoped to make small, reviewable contributions easy.

## Detection rules

Rules live in `agentguard/rules.py`. Prefer:

- a stable rule ID;
- a clear severity;
- a concise user-facing message;
- a focused pattern or structured check;
- actionable remediation guidance;
- a positive regression test;
- a negative/safe regression case when practical.

False positives matter. A rule should be conservative enough to be useful in real projects.

See [docs/rules.md](docs/rules.md) for the public rule catalog and [docs/threat-model.md](docs/threat-model.md) for scope and limitations.

## Benchmark fixtures

MCP regression fixtures live under `tests/fixtures/`. Keep them:

- small and deterministic;
- free of real credentials or sensitive data;
- representative of a specific policy condition;
- paired with an expected safe or risky outcome.

## Scope

AgentGuard is an auditing aid, not a guarantee that an agent, MCP server, repository, or deployment is secure.
