# Provider configuration fixtures

These fixtures are sanitized examples for regression coverage across supported AI-agent ecosystems.

## Gemini

- gemini/settings.json exercises the persistent approval rule.
- gemini/settings-safe.json is the corresponding safe configuration.

## Codex

- codex/config.toml exercises the explicit full-access approval combination.
- codex/config-safe.toml is the corresponding restricted configuration.

## OpenCode

- opencode/opencode.json exercises unrestricted `bash` and `edit` permissions.
- opencode-safe/opencode.json uses approval prompts and a narrow `git status` exception.
- opencode-jsonc/opencode.jsonc and opencode-jsonc-safe/opencode.jsonc exercise JSONC comments, trailing commas, string literals, and risky versus safe permissions.

## Claude and Cursor

The Claude and Cursor instruction fixtures are intentionally benign. They protect adapter/path handling and demonstrate that normal instruction content does not need to trigger provider-specific security rules.

No fixture contains real credentials, private endpoints, or production configuration.
