"""
src/php/php_issue_analyzer.py
==============================
PHP-specific IssueAnalyzer subclass.

Overrides only the code extraction and DB-lookup initialization methods.
All LLM orchestration, prompt building, result persistence, and issue-type
grouping logic are inherited unchanged from IssueAnalyzer.

Architecture contract:
  - PHPIssueAnalyzer receives issues pre-built from progpilot_adapter,
    bypassing collect_issues_from_databases() entirely.
  - Code is read from the filesystem via PHPDBLookup, not from src.zip.
  - LLMAnalyzer receives tool definitions backed by PHPDBLookup. The
    LLMAnalyzer itself has zero awareness of the language backend.
  - Results are written to output/results/php/ in the same JSON schema
    used for C/C++, so ResultsLoader and VulnhallaUI require no changes.

Required changes to vulnhalla.py (two method extractions):
  1. extract_code_snippet(issue, db_path) — overridable code extraction
  2. get_db_lookup(db_path) — overridable lookup factory

These two extractions are the only modifications to existing Vulnhalla files.
"""

import json
import logging
from pathlib import Path
from typing import Any, Optional

from src.vulnhalla import IssueAnalyzer
from src.php.php_db_lookup import PHPDBLookup

log = logging.getLogger(__name__)

# Maximum context lines above/below a taint sink/source for the initial prompt
_SINK_CONTEXT_LINES_BEFORE = 8
_SINK_CONTEXT_LINES_AFTER  = 15
_SOURCE_CONTEXT_LINES_BEFORE = 3
_SOURCE_CONTEXT_LINES_AFTER  = 8


class PHPIssueAnalyzer(IssueAnalyzer):
    """
    PHP-specific IssueAnalyzer that reads source from the filesystem
    and uses PHPDBLookup for all LLM tool-call resolutions.

    Constructor accepts a pre-built list of issue dicts (from progpilot_adapter)
    rather than a path to CodeQL databases. All other IssueAnalyzer behavior
    is inherited.
    """

    def __init__(self, issues: list[dict], lang: str = "php"):
        """
        Args:
            issues: Normalized issue dicts from progpilot_adapter.normalize_findings().
                    Each dict must have at minimum: name, type, file, start_line,
                    db_path, message. See progpilot_adapter for full schema.
            lang:   Language key. Must be "php" to select correct templates.
        """
        # Do NOT call super().__init__() — that expects CodeQL DB paths.
        # We initialize only the fields IssueAnalyzer.run() and
        # process_issue_type() actually read.
        self.lang = lang
        self.issues = issues
        self.results_dir = Path("output") / "results" / lang
        self.results_dir.mkdir(parents=True, exist_ok=True)

        # Group issues by type upfront (mirrors IssueAnalyzer.collect_issues)
        self._issues_by_type: dict[str, list[dict]] = {}
        for issue in issues:
            issue_type = issue.get("type", issue.get("name", "unknown"))
            self._issues_by_type.setdefault(issue_type, []).append(issue)

        log.info(
            f"PHPIssueAnalyzer initialized: {len(issues)} issues across "
            f"{len(self._issues_by_type)} issue types"
        )

    # =========================================================================
    # Override: issue collection
    # =========================================================================

    def collect_issues_from_databases(self) -> dict[str, list[dict]]:
        """
        Override: return the pre-built issue dict (progpilot output) instead
        of parsing CodeQL issues.csv files.

        IssueAnalyzer.run() calls this method first. By returning self._issues_by_type
        here, we preserve the run() → process_issue_type() call chain unchanged.
        """
        return self._issues_by_type

    # =========================================================================
    # Override: DB lookup factory
    # =========================================================================

    def get_db_lookup(self, db_path: str) -> PHPDBLookup:
        """
        Override: return a PHPDBLookup backed by the plugin directory at db_path
        instead of a CodeQLDBLookup backed by a CodeQL database directory.

        Called by process_issue_type() once per issue to obtain the lookup
        instance used by both code extraction and LLM tool calls.
        """
        return PHPDBLookup(db_path)

    # =========================================================================
    # Override: code extraction
    # =========================================================================

    def extract_code_snippet(self, issue: dict, lookup: PHPDBLookup) -> str:
        """
        Override: extract the initial code context for the LLM prompt.

        For PHP, reads from the filesystem directly instead of src.zip.
        Extracts:
          1. The enclosing function at the sink location (primary context)
          2. The taint source location if in a different file (secondary context)

        The result is injected as {code} in the prompt template.
        """
        sink_file = issue.get("file", "")
        sink_line = int(issue.get("start_line") or 0)

        if not sink_file or not sink_line:
            return "// No sink location available"

        # Primary context: enclosing function at sink
        func_code, func_meta = lookup.find_function_by_line(sink_file, sink_line)

        if func_code:
            primary = (
                f"[Sink context — enclosing function: "
                f"{func_meta.get('function_name', '?')} "
                f"({Path(sink_file).name}:"
                f"{func_meta.get('start_line', '?')})]\n"
                f"{func_code}"
            )
        else:
            # Fall back to raw line range if function boundary not found
            primary = (
                f"[Sink context — {Path(sink_file).name}:{sink_line}]\n"
                + lookup.read_file_lines(
                    sink_file,
                    max(1, sink_line - _SINK_CONTEXT_LINES_BEFORE),
                    sink_line + _SINK_CONTEXT_LINES_AFTER,
                )
            )

        # Secondary context: taint source if in a different file
        source_file = issue.get("source_file")
        source_line = int(issue.get("source_line") or 0)
        secondary = ""

        if source_file and source_file != sink_file and source_line:
            source_code = lookup.read_file_lines(
                source_file,
                max(1, source_line - _SOURCE_CONTEXT_LINES_BEFORE),
                source_line + _SOURCE_CONTEXT_LINES_AFTER,
            )
            secondary = (
                f"\n\n[Taint source — {Path(source_file).name}:{source_line}]\n"
                f"{source_code}"
            )

        return primary + secondary

    # =========================================================================
    # Override: find enclosing function by line
    # =========================================================================

    def find_function_by_line(
        self, filepath: str, target_line: int, lookup: PHPDBLookup
    ) -> dict:
        """
        Override: find the smallest enclosing PHP function via PHPDBLookup
        instead of CodeQL's FunctionTree.csv.

        Returns a function meta dict matching FunctionTree.csv row schema so
        the rest of IssueAnalyzer's prompt-building code requires no changes.
        Returns {} if not found.
        """
        _, meta = lookup.find_function_by_line(filepath, target_line)
        return meta


    def _prepare_issue_context(
        self, issue: dict
    ) -> tuple[list[str], str, str]:
        """
        Override: set db_path and code_path from the issue dict (already
        resolved by progpilot_adapter). Read source lines from filesystem.
        Returns (code_file_lines, function_tree_file=None, src_zip_path=None).
        """
        self.db_path = issue["db_path"]
        self.code_path = ""

        sink_file = issue.get("file", "")
        try:
            lines = Path(sink_file).read_text(errors="replace").splitlines()
        except OSError:
            lines = []

        # function_tree_file and src_zip_path are None — not used in PHP path.
        # _find_current_function and append_extra_functions are also overridden
        # so these None values never reach their CodeQL consumers.
        return lines, None, None

    def _find_current_function(
        self, function_tree_file: str, issue: dict
    ) -> dict:
        """
        Override: find enclosing PHP function via PHPDBLookup instead of
        FunctionTree.csv.
        """
        lookup = PHPDBLookup(self.db_path)
        sink_file = issue.get("file", "")
        sink_line = int(issue.get("start_line") or 0)
        _, meta = lookup.find_function_by_line(sink_file, sink_line)
        return meta if meta else {}

    # =========================================================================
    # Override: LLM tool definitions
    # =========================================================================

    def build_llm_tools(self, lookup: PHPDBLookup) -> list[dict]:
        """
        Override: build LiteLLM tool definitions backed by PHPDBLookup.

        The tool names, descriptions, and parameter schemas match the C/C++
        tool definitions exactly — LLMAnalyzer is unaware of the backend.
        Only the handler closures are different (call PHPDBLookup methods).

        These are passed to LLMAnalyzer alongside the tool handler dict so the
        tool-call loop can dispatch to the correct PHP implementation.
        """
        return [
            {
                "type": "function",
                "function": {
                    "name": "get_function_code",
                    "description": (
                        "Retrieve the complete source code of a PHP function or method "
                        "by its name. Use this to examine callee implementations, "
                        "sanitization functions, or any function referenced in the code."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "function_name": {
                                "type": "string",
                                "description": "The name of the PHP function or method to retrieve.",
                            }
                        },
                        "required": ["function_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_caller_function",
                    "description": (
                        "Retrieve the enclosing function at a given file:line location. "
                        "Use this to walk up the call chain and find where tainted data "
                        "originates or how a function is invoked."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "function_id": {
                                "type": "string",
                                "description": (
                                    "File path and line number in the format "
                                    "'/abs/path/to/file.php:LINE'."
                                ),
                            }
                        },
                        "required": ["function_id"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_class",
                    "description": (
                        "Retrieve a PHP class, interface, or trait definition by name. "
                        "Use this to examine class structure, property declarations, "
                        "or to understand the type of an object used at a sink."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "object_name": {
                                "type": "string",
                                "description": "The class, interface, or trait name to retrieve.",
                            }
                        },
                        "required": ["object_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_global_var",
                    "description": (
                        "Retrieve the declaration or assignment of a PHP global variable. "
                        "Use this to determine where a global is set and what value it holds."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "global_var_name": {
                                "type": "string",
                                "description": "The global variable name (with or without leading $).",
                            }
                        },
                        "required": ["global_var_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_macro",
                    "description": (
                        "Retrieve a PHP constant definition (define() or class const). "
                        "PHP has no preprocessor macros — this searches define() calls "
                        "and const declarations."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "macro_name": {
                                "type": "string",
                                "description": "The constant name to retrieve.",
                            }
                        },
                        "required": ["macro_name"],
                    },
                },
            },
        ]

    def build_llm_tool_handlers(self, lookup: PHPDBLookup) -> dict:
        """
        Return a dict mapping tool name → callable.
        LLMAnalyzer dispatches tool calls through this dict.

        Each handler returns a string that is sent back to the LLM as
        the tool result. Matches the handler interface from the C/C++ backend.
        """
        return {
            "get_function_code":  lambda args: self._tool_get_function(lookup, args),
            "get_caller_function":lambda args: self._tool_get_caller(lookup, args),
            "get_class":          lambda args: self._tool_get_class(lookup, args),
            "get_global_var":     lambda args: self._tool_get_global_var(lookup, args),
            "get_macro":          lambda args: self._tool_get_macro(lookup, args),
        }

    # ─── Tool handler implementations ─────────────────────────────────────────

    def _tool_get_function(self, lookup: PHPDBLookup, args: dict) -> str:
        name = args.get("function_name", "")
        if not name:
            return "// Error: function_name argument is required"
        code, meta = lookup.get_function_by_name(name)
        if not code:
            return f"// Function '{name}' not found in plugin source"
        location = f"{meta.get('file', '?')}:{meta.get('start_line', '?')}"
        return f"// {name} — {location}\n{code}"

    def _tool_get_caller(self, lookup: PHPDBLookup, args: dict) -> str:
        fid = args.get("function_id", "")
        if not fid:
            return "// Error: function_id argument is required"
        code, meta = lookup.get_caller_function(fid)
        if not code:
            return f"// No enclosing function found at {fid}"
        name = meta.get("function_name", "?")
        location = f"{meta.get('file', '?')}:{meta.get('start_line', '?')}"
        return f"// Enclosing function: {name} — {location}\n{code}"

    def _tool_get_class(self, lookup: PHPDBLookup, args: dict) -> str:
        name = args.get("object_name", "")
        if not name:
            return "// Error: object_name argument is required"
        code, meta = lookup.get_class(name)
        if not code:
            return f"// Class/interface/trait '{name}' not found in plugin source"
        kind = meta.get("type", "Class")
        location = f"{meta.get('file', '?')}:{meta.get('start_line', '?')}"
        return f"// {kind}: {name} — {location}\n{code}"

    def _tool_get_global_var(self, lookup: PHPDBLookup, args: dict) -> str:
        name = args.get("global_var_name", "")
        if not name:
            return "// Error: global_var_name argument is required"
        code, meta = lookup.get_global_var(name)
        if not code:
            return f"// Global variable '{name}' not found in plugin source"
        location = f"{meta.get('file', '?')}:{meta.get('start_line', '?')}"
        return f"// Global: {name} — {location}\n{code}"

    def _tool_get_macro(self, lookup: PHPDBLookup, args: dict) -> str:
        name = args.get("macro_name", "")
        if not name:
            return "// Error: macro_name argument is required"
        code, _ = lookup.get_macro(name)
        return code
