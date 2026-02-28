"""
src/php/verdict_exporter.py
============================
Export TUI manual decisions to wp_progpilot_hunter.ANALYST_VERDICTS format.

The TUI stores analyst decisions in output/results/manual_decisions.json,
keyed by final_path with values "True Positive" | "False Positive" | "Uncertain".
The progpilot pipeline stores analyst verdicts in the ANALYST_VERDICTS dict
inside wp_progpilot_hunter.py, keyed by "plugin::file:line".

These are two separate review stages:
  - ANALYST_VERDICTS: pre-LLM rule-based filter (fast, batch)
  - TUI decisions:    post-LLM analyst verdict (deliberate, single finding)

This module bridges them in one direction: TUI "False Positive" decisions
are converted to ANALYST_VERDICTS entries, ready to paste into
wp_progpilot_hunter.py to prevent those findings from reaching the LLM
in future scans of the same plugin corpus.

Usage:
  from src.php.verdict_exporter import export_tui_fps_to_analyst_verdicts
  verdict_dict = export_tui_fps_to_analyst_verdicts(
      manual_decisions_path=Path("output/results/manual_decisions.json"),
      results_dir=Path("output/results/php"),
  )
  # Print as Python dict literal ready for pasting
  print(format_for_paste(verdict_dict))
"""

import json
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# TUI decision values that map to ANALYST_VERDICTS FP entries
_FP_DECISIONS = {"False Positive", "false_positive"}
_TP_DECISIONS = {"True Positive", "true_positive"}


def export_tui_fps_to_analyst_verdicts(
    manual_decisions_path: Path,
    results_dir: Path,
) -> dict[str, str]:
    """
    Read TUI manual_decisions.json and convert False Positive decisions
    to ANALYST_VERDICTS-format entries.

    Each TUI FP decision is mapped to a verdict string that documents:
      - Disposition (FP)
      - LLM triage reasoning (from _final.json conversation summary)
      - Taint source and sink

    Args:
        manual_decisions_path: Path to output/results/manual_decisions.json.
        results_dir:           Root of PHP results (output/results/php/).

    Returns:
        Dict mapping "plugin::file:line" → verdict reason string.
        Ready to paste into ANALYST_VERDICTS in wp_progpilot_hunter.py.
    """
    if not manual_decisions_path.exists():
        log.warning(f"manual_decisions.json not found: {manual_decisions_path}")
        return {}

    decisions = json.loads(manual_decisions_path.read_text())
    verdicts: dict[str, str] = {}

    for final_path_str, decision in decisions.items():
        if decision not in _FP_DECISIONS:
            continue

        final_path = Path(final_path_str)
        if not final_path.exists():
            log.debug(f"Final path not found: {final_path_str}")
            continue

        raw_path = final_path.with_name(
            final_path.name.replace("_final.json", "_raw.json")
        )
        if not raw_path.exists():
            log.debug(f"Raw path not found: {raw_path}")
            continue

        key, reason = _build_verdict_entry(raw_path, final_path)
        if key:
            verdicts[key] = reason

    log.info(f"Exported {len(verdicts)} FP analyst verdicts from TUI decisions")
    return verdicts


def export_tui_tps_to_report(
    manual_decisions_path: Path,
    results_dir: Path,
) -> list[dict]:
    """
    Extract True Positive TUI decisions for CVE drafting.

    Returns a list of dicts with:
      key, plugin, file, line, vuln_name, source, sink, channel, reason
    Sorted by active_installs descending.
    """
    if not manual_decisions_path.exists():
        return []

    decisions = json.loads(manual_decisions_path.read_text())
    tps = []

    for final_path_str, decision in decisions.items():
        if decision not in _TP_DECISIONS:
            continue

        final_path = Path(final_path_str)
        raw_path = final_path.with_name(
            final_path.name.replace("_final.json", "_raw.json")
        )
        if not raw_path.exists():
            continue

        raw = json.loads(raw_path.read_text())
        sink_file = raw.get("file", "")
        sink_line = raw.get("start_line", "?")
        plugin = raw.get("plugin", "")

        tps.append({
            "key":             f"{plugin}::{Path(sink_file).name}:{sink_line}",
            "plugin":          plugin,
            "file":            sink_file,
            "line":            sink_line,
            "vuln_name":       raw.get("type", "?"),
            "source":          raw.get("progpilot_source", "?"),
            "sink":            raw.get("progpilot_sink", "?"),
            "channel":         raw.get("reachability_channel"),
            "active_installs": raw.get("active_installs", 0),
            "scanned_version": raw.get("scanned_version", "?"),
        })

    tps.sort(key=lambda x: -(x.get("active_installs") or 0))
    return tps


def format_for_paste(verdicts: dict[str, str]) -> str:
    """
    Format an ANALYST_VERDICTS dict as a Python literal ready for
    pasting into wp_progpilot_hunter.py.

    Output format matches existing ANALYST_VERDICTS style:
        "plugin.version::file.php:line": "FP — reason",
    """
    if not verdicts:
        return "# No FP verdicts to export"

    lines = ["# Exported from TUI manual decisions — paste into ANALYST_VERDICTS\n"]
    for key, reason in sorted(verdicts.items()):
        # Use parenthesized string for long reasons (matches existing style)
        if len(reason) > 80:
            lines.append(f'    "{key}": (\n        "{reason}"\n    ),')
        else:
            lines.append(f'    "{key}": "{reason}",')

    return "\n".join(lines)


# ─── Private helpers ──────────────────────────────────────────────────────────

def _build_verdict_entry(
    raw_path: Path,
    final_path: Path,
) -> tuple[Optional[str], str]:
    """
    Build a (key, reason) pair for ANALYST_VERDICTS from a raw+final JSON pair.

    Key format: "plugin::file.php:line"  (matches legacy ANALYST_VERDICTS format)
    Reason: "FP — [source] → [sink]: [LLM summary or default reason]"
    """
    try:
        raw = json.loads(raw_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        log.debug(f"Could not read raw JSON {raw_path}: {e}")
        return (None, "")

    plugin    = raw.get("plugin", "")
    sink_file = raw.get("file", "")
    sink_line = raw.get("start_line", "?")
    source    = raw.get("progpilot_source", "?")
    sink      = raw.get("progpilot_sink", "?")
    channel   = raw.get("reachability_channel")

    if not sink_file:
        return (None, "")

    key = f"{plugin}::{Path(sink_file).name}:{sink_line}"

    # Extract LLM reasoning from final conversation if available
    llm_reason = _extract_llm_reason(final_path)

    parts = [f"FP — analyst reviewed post-LLM triage"]
    if source and sink:
        parts = [f"FP — {source} → {sink}: analyst reviewed post-LLM triage"]
    if channel:
        parts.append(f"channel: {channel}")
    if llm_reason:
        parts.append(llm_reason)

    reason = "; ".join(parts)
    return (key, reason)


def _extract_llm_reason(final_path: Path) -> str:
    """
    Extract a brief reason string from the last assistant message in the LLM
    conversation. Used to populate the ANALYST_VERDICTS reason field.
    Returns "" if not parseable.
    """
    try:
        messages = json.loads(final_path.read_text())
    except (json.JSONDecodeError, OSError):
        return ""

    if not isinstance(messages, list):
        return ""

    # Find last assistant message
    for msg in reversed(messages):
        if not isinstance(msg, dict):
            continue
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content", "")
        if isinstance(content, list):
            # Handle content blocks
            content = " ".join(
                block.get("text", "") for block in content
                if isinstance(block, dict)
            )
        if not content:
            continue
        # Return first sentence (up to 120 chars) as the summary
        first_sentence = content.split('.')[0].strip()
        return first_sentence[:120] if first_sentence else ""

    return ""
