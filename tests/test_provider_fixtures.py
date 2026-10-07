from pathlib import Path

from agentguard.scanner import scan_config, scan_path


FIXTURES = Path(__file__).parent / "fixtures" / "providers"


def ids(findings):
    return {item.rule_id for item in findings}


def test_gemini_fixture_triggers_provider_rule():
    path = FIXTURES / "gemini" / ".gemini" / "settings.json"
    findings = scan_path(path)
    assert "AG-GEMINI-001" in ids(findings)


def test_gemini_safe_fixture_has_no_provider_finding():
    path = FIXTURES / "gemini-safe" / ".gemini" / "settings.json"
    findings = scan_path(path)
    assert "AG-GEMINI-001" not in ids(findings)


def test_codex_fixture_triggers_full_access_rule():
    path = FIXTURES / "codex" / ".codex" / "config.toml"
    findings = scan_path(path)
    assert "AG-CODEX-001" in ids(findings)


def test_codex_safe_fixture_has_no_full_access_finding():
    path = FIXTURES / "codex-safe" / ".codex" / "config.toml"
    findings = scan_path(path)
    assert "AG-CODEX-001" not in ids(findings)


def test_opencode_fixture_triggers_permission_rules():
    path = FIXTURES / "opencode" / "opencode.json"
    findings = scan_path(path)
    assert {"AG-OPENCODE-001", "AG-OPENCODE-002"} <= ids(findings)


def test_opencode_safe_fixture_has_no_permission_findings():
    path = FIXTURES / "opencode-safe" / "opencode.json"
    findings = scan_path(path)
    assert "AG-OPENCODE-001" not in ids(findings)
    assert "AG-OPENCODE-002" not in ids(findings)


def test_benign_claude_fixture_is_clean():
    findings = scan_path(FIXTURES / "claude" / "CLAUDE.md")
    assert findings == []


def test_benign_cursor_fixture_is_clean():
    findings = scan_path(FIXTURES / "cursor" / "CURSOR.md")
    assert findings == []


def test_mcp_https_inside_provider_fixture_is_not_flagged():
    path = FIXTURES / "gemini" / ".gemini" / "settings.json"
    findings = scan_config(path.read_text(encoding="utf-8"), str(path))
    assert "AG-MCP-002" not in ids(findings)


def test_opencode_jsonc_fixture_triggers_permission_rules():
    path = FIXTURES / "opencode-jsonc" / "opencode.jsonc"
    findings = scan_path(path)
    assert "AG-OPENCODE-001" in ids(findings)
    assert "AG-OPENCODE-002" not in ids(findings)


def test_opencode_jsonc_safe_fixture_has_no_permission_findings():
    path = FIXTURES / "opencode-jsonc-safe" / "opencode.jsonc"
    findings = scan_path(path)
    assert "AG-OPENCODE-001" not in ids(findings)
    assert "AG-OPENCODE-002" not in ids(findings)
