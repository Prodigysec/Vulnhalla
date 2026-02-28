"""
src/php
=======
PHP/WordPress analysis backend for Vulnhalla.

Provides a Progpilot-based replacement for the CodeQL pipeline layer,
preserving the LLM triage and TUI layers unchanged.

Public surface:
  PHPDBLookup       — grep-based code intelligence (replaces CodeQLDBLookup)
  PHPIssueAnalyzer  — filesystem-aware IssueAnalyzer subclass
  progpilot_adapter — progpilot finding → Vulnhalla issue dict normalization
  plugin_downloader — optional WP.org plugin acquisition
  verdict_exporter  — TUI manual decisions → ANALYST_VERDICTS format
"""

from src.php.php_db_lookup import PHPDBLookup
from src.php.php_issue_analyzer import PHPIssueAnalyzer
from src.php import progpilot_adapter

__all__ = [
    "PHPDBLookup",
    "PHPIssueAnalyzer",
    "progpilot_adapter",
]
