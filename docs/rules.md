# AgentGuard rule reference

AgentGuard's rules are heuristic static checks. A finding is a signal for review, not proof of a vulnerability.

| Rule | Severity | What it detects | Recommended action |
| --- | --- | --- | --- |
| `AG-SEC-001` | High | Credential-like values in tracked configuration | Move secrets to a secret manager or CI secret and remove them from tracked files. |
| `AG-EXEC-001` | High | Shell, terminal, exec, or command-execution capability | Restrict execution to an explicit allowlist and require approval for privileged operations. |
| `AG-FS-001` | High | Broad filesystem or workspace access | Narrow access to the minimum required directories. |
| `AG-MCP-001` | High | MCP `trust=true` | Disable trust bypass unless it is explicitly required; prefer confirmation or allowlists. |
| `AG-MCP-002` | Medium | MCP endpoints using cleartext `http://` | Use HTTPS with certificate validation. |
| `AG-MCP-003` | Low | Remote MCP servers without declared provenance metadata | Declare repository/source or project metadata where available so users can inspect provenance. |
| `AG-POLICY-001` | Critical | Untrusted input + private-data access + outbound action in one MCP server configuration | Separate the trust boundary, minimize private-data access, and gate outbound actions. |
| `AG-CODEX-001` | High | Codex `approval_policy=never` + `sandbox_mode=danger-full-access` | Prefer `on-request` with a restricted sandbox; reserve full access for explicit, reviewed cases. |
| `AG-GEMINI-001` | Medium | Gemini CLI persistent approval default (`security.autoAddToPolicyByDefault`) | Disable it unless persistent approval is an intentional, reviewed policy choice. |
| `AG-OPENCODE-001` | High | OpenCode `permission.bash` allows all commands without approval | Use `ask`/`deny` or a narrow command allowlist. |
| `AG-OPENCODE-002` | High | OpenCode `permission.edit` allows all file edits without approval | Use `ask`/`deny` or a narrow path allowlist. |
| `AG-PROMPT-001` | Medium | Common prompt-injection instruction patterns | Treat external instructions as untrusted and isolate system policy from user-controlled content. |
| `AG-CONTEXT-001` | Low | Oversized supported agent instruction files | Remove duplication and obsolete guidance; keep context focused. |
| `AG-CONTEXT-002` | Medium | Instruction files above the configured estimated-token budget | Reduce context or raise the budget deliberately with review. |

## Severity semantics

**Critical** means the configuration combines multiple capabilities across a trust boundary and deserves immediate review.

**High** means a capability or configuration can create meaningful security exposure on its own.

**Medium** means the configuration increases risk or weakens a security boundary but may be legitimate in context.

**Low** means the finding is primarily an efficiency, maintainability, or context-cost concern.

## Design principle

AgentGuard favors **high-signal policy combinations** over blindly flagging every capability. A shell, filesystem, or network tool may be legitimate independently. The risk can change substantially when those capabilities are combined with untrusted input or sensitive data.

## Regression fixtures

The benchmark fixtures in [tests/fixtures](../tests/fixtures/) intentionally include both risky and safe MCP configurations. New rules should add at least one positive and one negative regression case whenever practical.
