from __future__ import annotations

import re

RULES = {
    "AG-SEC-001": {
        "severity": "high",
        "message": "Potential secret detected",
        "remediation": "Remove the credential from tracked configuration and load it from a secret manager or CI secret.",
        "pattern": re.compile(
            r"""(api[_-]?key|secret|token|password|private[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9_./+=-]{12,}""",
            re.I,
        ),
    },
    "AG-PROMPT-001": {
        "severity": "medium",
        "message": "Prompt-injection pattern detected",
        "remediation": "Treat external instructions as untrusted and keep system-level policy separate from user-controlled content.",
        "pattern": re.compile(
            r"(ignore (all|any|previous|prior) instructions|reveal (the )?system prompt|disregard (all|any|previous) instructions|do not follow (the )?rules|override (the )?system)",
            re.I,
        ),
    },
    "AG-EXEC-001": {
        "severity": "high",
        "message": "Potential command execution capability",
        "remediation": "Restrict command execution to an explicit allowlist and require confirmation for privileged operations.",
        "pattern": re.compile(
            r"(shell|terminal|subprocess|bash|powershell|cmd\.exe|exec(?:ute|ution)?|command\s+(?:execution|execute))",
            re.I,
        ),
    },
    "AG-FS-001": {
        "severity": "high",
        "message": "Broad filesystem access may expose sensitive files",
        "remediation": "Limit filesystem access to the smallest required directories and avoid home-directory or root-level access.",
        "pattern": re.compile(r"(?!)"),
    },
    "AG-MCP-001": {
        "severity": "high",
        "message": "MCP server enables trusted tool execution without confirmation",
        "remediation": "Disable trust mode unless required and restore explicit tool-call confirmation or an allowlist.",
        "pattern": re.compile(r"(?!)"),
    },
    "AG-MCP-002": {
        "severity": "medium",
        "message": "MCP server uses an unencrypted HTTP endpoint",
        "remediation": "Use an HTTPS endpoint with certificate validation instead of cleartext HTTP.",
        "pattern": re.compile(r"(?!)"),
    },
    "AG-MCP-003": {
        "severity": "low",
        "message": "Remote MCP server has no declared provenance metadata",
        "remediation": "Where available, declare repository/source or project metadata so users can inspect the server's provenance.",
        "pattern": re.compile(r"(?!)"),
    },
    "AG-POLICY-001": {
        "severity": "critical",
        "message": "Agent configuration combines untrusted input, private data access, and outbound actions",
        "remediation": "Separate untrusted input from privileged tools, minimize private-data access, and require explicit approval for outbound actions.",
        "pattern": re.compile(r"(?!)"),
    },
    "AG-GEMINI-001": {
        "severity": "medium",
        "message": "Gemini CLI auto-adds allowed tools to future policy by default",
        "remediation": "Disable security.autoAddToPolicyByDefault unless persistent tool approval is an intentional, reviewed policy choice.",
        "pattern": re.compile(r"(?!)"),
    },
    "AG-CODEX-001": {
        "severity": "high",
        "message": "Codex combines approval_policy=never with sandbox_mode=danger-full-access",
        "remediation": "Prefer approval_policy=on-request and a restricted sandbox; use full access only for an explicit, reviewed need.",
        "pattern": re.compile(r"(?!)"),
    },
    "AG-OPENCODE-001": {
        "severity": "high",
        "message": "OpenCode allows unrestricted shell commands without approval",
        "remediation": "Set the OpenCode bash permission to ask or deny, or replace the wildcard allow rule with a narrow command allowlist.",
        "pattern": re.compile(r"(?!)"),
    },
    "AG-OPENCODE-002": {
        "severity": "high",
        "message": "OpenCode allows unrestricted file edits without approval",
        "remediation": "Set the OpenCode edit permission to ask or deny, or replace the wildcard allow rule with a narrow path allowlist.",
        "pattern": re.compile(r"(?!)"),
    },
    "AG-CONTEXT-001": {
        "severity": "low",
        "message": "Agent instruction file is unusually large and may increase context cost",
        "remediation": "Remove duplicated or obsolete instructions and split large policies into focused, reusable guidance.",
        "pattern": re.compile(r"(?!)"),
    },
    "AG-CONTEXT-002": {
        "severity": "medium",
        "message": "Agent context exceeds the configured token budget",
        "remediation": "Reduce instruction size or increase the configured budget only when the additional context is justified.",
        "pattern": re.compile(r"(?!)"),
    },
}

AGENT_INSTRUCTION_FILES = {
    "CLAUDE.md",
    "AGENTS.md",
    "GEMINI.md",
    "CODEX.md",
    "CURSOR.md",
    ".cursorrules",
    ".windsurfrules",
}

TEXT_EXTENSIONS = {
    ".md",
    ".txt",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".json",
    ".yaml",
    ".yml",
}
