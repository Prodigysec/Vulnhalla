"""
src/php/progpilot_adapter.py
============================
Normalize triaged progpilot findings to the Vulnhalla issue dict schema.

Progpilot finding dicts (post-triage) have a different shape from the issue
dicts IssueAnalyzer expects. This module bridges the two schemas so
PHPIssueAnalyzer receives a list of standard issue dicts — one per finding
that passed the rule-based pre-filter — with PHP-specific metadata attached
in extra fields that travel alongside but do not conflict with Vulnhalla's
generic code.

Confidence thresholds:
  "high"   → always sent to LLM
  "medium" → sent to LLM (default threshold)
  "low"    → skipped by default; include with triage_threshold={"high","medium","low"}
  "false_positive" → always dropped; never reaches LLM

Design invariant: this module is stateless. Every function is a pure
transformation. No I/O, no caches.
"""

from pathlib import Path
from typing import Optional

# ─── Vuln name mapping: progpilot → human-readable (matches template filenames) ──
_VULN_NAME_MAP: dict[str, str] = {
    "sql_injection":             "SQL Injection",
    "xss":                       "Cross-site Scripting",
    "path_traversal":            "Path Traversal",
    "code_injection":            "Code Injection",
    "command_injection":         "Command Injection",
    "ssrf":                      "Server-Side Request Forgery",
    "xxe":                       "XML External Entity",
    "open_redirect":             "Open Redirect",
    "security misconfiguration": "Security Misconfiguration",
}

# Default confidence levels that proceed to LLM triage
DEFAULT_THRESHOLD: frozenset[str] = frozenset({"high", "medium"})


def normalize_findings(
    triaged: list[dict],
    plugins_dir: Path,
    triage_threshold: Optional[frozenset[str]] = None,
) -> list[dict]:
    """
    Convert a list of triaged progpilot findings to Vulnhalla issue dicts,
    dropping any findings below the confidence threshold.

    Args:
        triaged:          Output of wp_progpilot_hunter.triage().
        plugins_dir:      Root directory containing plugin subdirectories.
        triage_threshold: Set of confidence levels to include.
                          Defaults to {"high", "medium"}.

    Returns:
        List of Vulnhalla-compatible issue dicts, ordered by:
          1. Confidence (high before medium)
          2. Active installs (descending) — highest-impact first
    """
    threshold = triage_threshold if triage_threshold is not None else DEFAULT_THRESHOLD

    normalized = []
    for f in triaged:
        if f.get("__is_probe__"):
            continue
        issue = normalize_finding(f, plugins_dir, threshold)
        if issue is not None:
            normalized.append(issue)

    # Sort: high confidence first, then by active installs descending
    _CONF_RANK = {"high": 0, "medium": 1, "low": 2}
    normalized.sort(
        key=lambda x: (
            _CONF_RANK.get(x.get("triage_confidence", "low"), 2),
            -(x.get("active_installs") or 0),
        )
    )

    return normalized


def normalize_finding(
    f: dict,
    plugins_dir: Path,
    threshold: frozenset[str] = DEFAULT_THRESHOLD,
) -> Optional[dict]:
    """
    Normalize a single triaged finding to a Vulnhalla issue dict.

    Returns None if:
      - finding is below threshold
      - finding is false_positive
      - finding lacks a sink file (non-taint finding with no locatable source)
      - vuln_id already seen (caller responsibility to deduplicate if needed)

    Issue dict field mapping to IssueAnalyzer expectations:
      name        ← display name from vuln_name
      help        ← description / CWE
      type        ← raw vuln_name (used as template filename key)
      message     ← formatted taint path string (replaces CodeQL bracket message)
      file        ← absolute path to sink file
      start_line  ← sink line number (string, matching CSV convention)
      start_offset← sink column (string)
      end_line    ← same as start_line (progpilot is line-granular)
      end_offset  ← same as start_offset
      db_path     ← plugin root directory (replaces CodeQL DB path)
    """
    triage = f.get("triage", {})
    confidence = triage.get("confidence", "low")

    if confidence not in threshold:
        return None

    sink_file = f.get("sink_file") or f.get("vuln_file", "")
    if not sink_file:
        return None

    plugin_slug = f.get("plugin", "")
    vuln_raw = f.get("vuln_name", "unknown")
    vuln_display = _VULN_NAME_MAP.get(vuln_raw, vuln_raw.replace("_", " ").title())

    source_names: list[str] = f.get("source_name") or []
    if isinstance(source_names, str):
        source_names = [source_names]
    source = source_names[0] if source_names else "unknown"

    sink = f.get("sink_name", "unknown")
    channel = triage.get("reachability_channel")

    # Resolve plugin root — handles double-nested structure (C6 from SKILL.md)
    plugin_dir = _resolve_plugin_dir(plugin_slug, plugins_dir)

    return {
        # ── Core Vulnhalla issue fields (IssueAnalyzer interface) ─────────────
        "name":         vuln_display,
        "help":         _build_help(f),
        "type":         vuln_raw,
        "message":      _build_message(f, source, sink, channel, triage),
        "file":         sink_file,
        "start_line":   str(f.get("sink_line") or f.get("vuln_line") or "0"),
        "start_offset": str(f.get("sink_column") or f.get("vuln_column") or "0"),
        "end_line":     str(f.get("sink_line") or f.get("vuln_line") or "0"),
        "end_offset":   str(f.get("sink_column") or f.get("vuln_column") or "0"),
        "db_path":      str(plugin_dir),

        # ── PHP-specific extensions (travel alongside, ignored by generic code) ─
        "plugin":               plugin_slug,
        "source_file":          _first(f.get("source_file")),
        "source_line":          str(_first(f.get("source_line")) or "0"),
        "progpilot_source":     source,
        "progpilot_sink":       sink,
        "triage_confidence":    confidence,
        "reachability_channel": channel,
        "second_order":         triage.get("second_order", False),
        "vuln_id":              f.get("vuln_id", ""),
        "active_installs":      f.get("active_installs", 0),
        "scanned_version":      f.get("scanned_version", "unknown"),
        "fp_reason":            triage.get("fp_reason"),
        "vuln_cwe":             f.get("vuln_cwe", ""),
    }


# ─── Private helpers ──────────────────────────────────────────────────────────

def _build_message(
    f: dict,
    source: str,
    sink: str,
    channel: Optional[str],
    triage: dict,
) -> str:
    """
    Build a human-readable message analogous to a CodeQL issue message.
    The message is injected as {message} in the prompt template, giving
    the LLM the pre-triage context computed by the rule-based filter.
    """
    parts = [f"Tainted value flows from `{source}` to `{sink}`."]

    if channel:
        parts.append(f"Reachable via: {channel}.")

    if triage.get("second_order"):
        parts.append("Second-order source: verify write-path authorization.")

    confidence = triage.get("confidence", "?")
    parts.append(f"Pre-filter confidence: {confidence}.")

    cwe = f.get("vuln_cwe", "")
    if cwe:
        parts.append(f"CWE: {cwe}.")

    fp_reason = triage.get("fp_reason")
    if fp_reason and confidence in ("low", "medium"):
        # Surface the pre-filter's reasoning so the LLM has context on why
        # confidence was lowered — it can agree or escalate.
        parts.append(f"Pre-filter note: {fp_reason}")

    return " ".join(parts)


def _build_help(f: dict) -> str:
    """Build a description string from vuln_description and CWE."""
    desc = f.get("vuln_description", "")
    cwe = f.get("vuln_cwe", "")
    if desc and cwe:
        return f"{desc} ({cwe})"
    return desc or cwe or f.get("vuln_name", "")


def _resolve_plugin_dir(plugin_slug: str, plugins_dir: Path) -> Path:
    """
    Resolve plugin root directory. Handles:
      - Double-nested: plugins_dir/slug/slug/
      - Single-nested: plugins_dir/slug/
      - slug with version: plugins_dir/slug.1.2.3/
    Returns the most specific existing directory, or plugins_dir/slug as fallback.
    """
    if not plugin_slug:
        return plugins_dir

    # Try exact match first
    candidate = plugins_dir / plugin_slug
    if candidate.exists():
        # Check for double-nesting (C6)
        inner = candidate / plugin_slug
        if inner.exists():
            return inner
        return candidate

    # Try prefix match (handles slug.version directories)
    for child in plugins_dir.iterdir():
        if child.is_dir() and child.name.startswith(plugin_slug.split('.')[0]):
            inner = child / child.name
            if inner.exists():
                return inner
            return child

    return plugins_dir / plugin_slug


def _first(value) -> Optional[str]:
    """Return first element if list, or value itself if scalar, or None."""
    if isinstance(value, list):
        return value[0] if value else None
    return value
