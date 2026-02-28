#!/usr/bin/env python3
"""
Pipeline orchestration for Vulnhalla.
This module coordinates the complete analysis pipeline:
1. Fetch CodeQL databases
2. Run CodeQL queries
3. Classify results with LLM
4. Open UI (optional)
"""
# Ignore pydantic warnings
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="pydantic")

import argparse
import sys
from pathlib import Path
from typing import Optional

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.codeql.fetch_repos import fetch_codeql_dbs
from src.codeql.run_codeql_queries import compile_and_run_codeql_queries
from src.utils.config import get_codeql_path
from src.utils.config_validator import validate_and_exit_on_error
from src.utils.logger import setup_logging, get_logger
from src.utils.exceptions import (
    CodeQLError, CodeQLConfigError, CodeQLExecutionError,
    LLMError, LLMConfigError, LLMApiError,
    VulnhallaError
)
from src.vulnhalla import IssueAnalyzer
from src.ui.ui_app import main as ui_main

# Initialize logging
setup_logging()
logger = get_logger(__name__)


def _log_exception_cause(e: Exception) -> None:
    """
    Log the cause of an exception if available and not already included in the exception message.
    Checks both e.cause (if set via constructor) and e.__cause__ (if set via 'from e').
    """
    cause = getattr(e, 'cause', None) or getattr(e, '__cause__', None)
    if cause:
        # Only log cause if it's not already included in the exception message
        cause_str = str(cause)
        error_str = str(e)
        if cause_str not in error_str:
            logger.error("   Cause: %s", cause)


def step1_fetch_codeql_dbs(lang: str, threads: int, repo: str, force: bool = False) -> str:
    """
    Step 1: Fetch CodeQL databases from GitHub.
    
    Args:
        lang: Programming language code.
        threads: Number of threads for download operations.
        repo: Repository name (e.g., "redis/redis").
    
    Returns:
        str: Path to the directory containing downloaded databases.
    
    Raises:
        CodeQLConfigError: If configuration is invalid (e.g., missing GitHub token).
        CodeQLError: If database download or extraction fails.
    """
    logger.info("\nStep 1: Fetching CodeQL Databases")
    logger.info("-" * 60)
    logger.info("Fetching database for: %s", repo)
    
    try:
        dbs_dir = fetch_codeql_dbs(lang=lang, threads=threads, repo_name=repo, force=force)
        if not dbs_dir:
            raise CodeQLError(f"No CodeQL databases were downloaded/found for {repo}")
        return dbs_dir
    except CodeQLConfigError as e:
        logger.error("[-] Step 1: Configuration error while fetching CodeQL databases: %s", e)
        _log_exception_cause(e)
        logger.error("   Please check your GitHub token and permissions.")
        sys.exit(1)
    except CodeQLError as e:
        logger.error("[-] Step 1: Failed to fetch CodeQL databases: %s", e)
        _log_exception_cause(e)
        logger.error("   Please check file permissions, disk space, and GitHub API access.")
        sys.exit(1)


def step2_run_codeql_queries(dbs_dir: str, lang: str, threads: int) -> None:
    """
    Step 2: Run CodeQL queries on the downloaded databases.
    
    Args:
        dbs_dir: Path to the directory containing CodeQL databases.
        lang: Programming language code.
        threads: Number of threads for query execution.
    
    Raises:
        CodeQLConfigError: If CodeQL path configuration is invalid.
        CodeQLExecutionError: If query execution fails.
        CodeQLError: If other CodeQL-related errors occur (e.g., database access issues).
    """
    logger.info("\nStep 2: Running CodeQL Queries")
    logger.info("-" * 60)
    
    try:
        compile_and_run_codeql_queries(
            codeql_bin=get_codeql_path(),
            lang=lang,
            threads=threads,
            timeout=300,
            dbs_dir=dbs_dir
        )
    except CodeQLConfigError as e:
        logger.error("[-] Step 2: Configuration error while running CodeQL queries: %s", e)
        _log_exception_cause(e)
        logger.error("   Please check your CODEQL_PATH configuration.")
        sys.exit(1)
    except CodeQLExecutionError as e:
        logger.error("[-] Step 2: Failed to execute CodeQL queries: %s", e)
        _log_exception_cause(e)
        logger.error("   Please check your CodeQL installation and database files.")
        sys.exit(1)
    except CodeQLError as e:
        logger.error("[-] Step 2: CodeQL error while running queries: %s", e)
        _log_exception_cause(e)
        logger.error("   Please check your CodeQL database files and query syntax.")
        sys.exit(1)
    

def step3_classify_results_with_llm(dbs_dir: str, lang: str) -> None:
    """
    Step 3: Classify CodeQL results using LLM analysis.
    
    Args:
        dbs_dir: Path to the directory containing CodeQL databases.
        lang: Programming language code.
    
    Raises:
        LLMConfigError: If LLM configuration is invalid (e.g., missing API credentials).
        LLMApiError: If LLM API call fails (e.g., network issues, rate limits).
        LLMError: If other LLM-related errors occur.
        CodeQLError: If reading CodeQL database files fails (YAML, ZIP, CSV).
        VulnhallaError: If saving analysis results to disk fails.
    """
    logger.info("\nStep 3: Classifying Results with LLM")
    logger.info("-" * 60)
    
    try:
        analyzer = IssueAnalyzer(lang=lang)
        analyzer.run(dbs_dir)
    except LLMConfigError as e:
        logger.error("[-] Step 3: LLM configuration error: %s", e)
        _log_exception_cause(e)
        logger.error("   Please check your LLM configuration and API credentials in .env file.")
        sys.exit(1)
    except LLMApiError as e:
        logger.error("[-] Step 3: LLM API error: %s", e)
        _log_exception_cause(e)
        logger.error("   Please check your API key, network connection, and rate limits.")
        sys.exit(1)
    except LLMError as e:
        logger.error("[-] Step 3: LLM error: %s", e)
        _log_exception_cause(e)
        logger.error("   Please check your LLM provider settings and API status.")
        sys.exit(1)
    except CodeQLError as e:
        logger.error("[-] Step 3: CodeQL error while reading database files: %s", e)
        _log_exception_cause(e)
        logger.error("   This step reads CodeQL database files (YAML, ZIP, CSV) to prepare data for LLM analysis.")
        logger.error("   Please check your CodeQL databases and files are accessible.")
        sys.exit(1)
    except VulnhallaError as e:
        logger.error("[-] Step 3: File system error while saving results: %s", e)
        _log_exception_cause(e)
        logger.error("   This step writes analysis results to disk and creates output directories.")
        logger.error("   Please check file permissions and disk space.")
        sys.exit(1)


def step4_open_ui() -> None:
    """
    Step 4: Open the results UI (optional).

    Note:
        This function does not raise exceptions. UI errors are handled internally by the UI module.
    """
    logger.info("\n[4/4] Opening UI")
    logger.info("-" * 60)
    logger.info("[+] Pipeline completed successfully!")
    logger.info("Opening results UI...")
    ui_main()


def main_analyze() -> None:
    """
    CLI entry point for the complete analysis pipeline.
    
    Expected usage: 
        vulnhalla <org/repo> [--force]           # Fetch from GitHub
        vulnhalla --local <path/to/db>           # Use local CodeQL database
    """
    parser = argparse.ArgumentParser(
        prog="vulnhalla",
        description="Vulnhalla - Automated CodeQL Analysis with LLM Classification"
    )
    parser.add_argument("repo", nargs="?", help="GitHub repository in 'org/repo' format")
    parser.add_argument("--force", "-f", action="store_true", help="Re-download even if database exists")
    parser.add_argument("--local", "-l", metavar="PATH", help="Path to local CodeQL database (skips GitHub fetch)")
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.local:
        # Local database mode
        local_path = Path(args.local)
        if not local_path.exists():
            parser.error(f"Local database path does not exist: {args.local}")
        analyze_pipeline(repo=None, local_db_path=str(local_path))
    elif args.repo:
        # GitHub fetch mode
        if "/" not in args.repo:
            parser.error("Repository must be in format 'org/repo'")
        analyze_pipeline(repo=args.repo, force=args.force)
    else:
        parser.error("Either provide a repository (org/repo) or use --local <path>")


def main_analyze_php() -> None:
    """
    CLI entry point for the PHP/WordPress analysis pipeline.

    Expected usage:
        vulnhalla-php --plugins-dir /path/to/plugins
        vulnhalla-php --progpilot-findings /path/to/findings.json
        vulnhalla-php --progpilot-findings /path/to/findings.json --threshold high
    """
    parser = argparse.ArgumentParser(
        prog="vulnhalla-php",
        description="Vulnhalla PHP — WordPress plugin analysis via Progpilot + LLM triage"
    )
    parser.add_argument(
        "--plugins-dir", "-p",
        metavar="PATH",
        help="Root directory containing unzipped WordPress plugins"
    )
    parser.add_argument(
        "--progpilot-findings", "-f",
        metavar="PATH",
        help="Path to pre-computed progpilot findings JSON (skips scan + triage)"
    )
    parser.add_argument(
        "--threshold", "-t",
        default="high,medium",
        metavar="LEVELS",
        help="Comma-separated confidence levels to forward to LLM (default: high,medium)"
    )
    parser.add_argument(
        "--no-ui",
        action="store_true",
        help="Skip opening the UI after analysis"
    )

    args = parser.parse_args()

    if not args.plugins_dir and not args.progpilot_findings:
        parser.error("Either --plugins-dir or --progpilot-findings is required")

    _run_php_pipeline(
        plugins_dir=Path(args.plugins_dir) if args.plugins_dir else None,
        progpilot_findings=Path(args.progpilot_findings) if args.progpilot_findings else None,
        triage_threshold=args.threshold,
        open_ui=not args.no_ui,
    )


def analyze_pipeline(
    repo: Optional[str] = None,
    lang: str = "c",
    threads: int = 16,
    open_ui: bool = True,
    force: bool = False,
    local_db_path: Optional[str] = None
) -> None:
    """
    Run the complete Vulnhalla pipeline: fetch, analyze, classify, and optionally open UI.
    
    Args:
        repo: GitHub repository name (e.g., "redis/redis"). Required if local_db_path not provided.
        lang: Programming language code. Defaults to "c".
        threads: Number of threads for CodeQL operations. Defaults to 16.
        open_ui: Whether to open the UI after completion. Defaults to True.
        force: If True, re-download even if database exists. Defaults to False.
        local_db_path: Path to local CodeQL database. If provided, skips GitHub fetch.
    
    Note:
        This function catches and handles all exceptions internally, logging errors
        and exiting with code 1 on failure. It does not raise exceptions.
    """
    logger.info("🚀 Starting Vulnhalla Analysis Pipeline")
    logger.info("=" * 60)
    
    # Validate configuration before starting
    try:
        validate_and_exit_on_error()
    except (CodeQLConfigError, LLMConfigError, VulnhallaError) as e:
        # Format error message for display
        message = f"""
[-] Configuration Validation Failed
============================================================
{str(e)}
============================================================
Please fix the configuration errors above and try again.
See README.md for configuration reference.
"""
        logger.error(message)
        _log_exception_cause(e)
        sys.exit(1)
    
    # Step 1: Fetch CodeQL databases (or use local path)
    if local_db_path:
        logger.info("\nStep 1: Using Local CodeQL Database")
        logger.info("-" * 60)
        logger.info("Database path: %s", local_db_path)
        dbs_dir = local_db_path
    else:
        dbs_dir = step1_fetch_codeql_dbs(lang, threads, repo, force)
    
    # Step 2: Run CodeQL queries
    step2_run_codeql_queries(dbs_dir, lang, threads)
    
    # Step 3: Classify results with LLM
    step3_classify_results_with_llm(dbs_dir, lang)
    
    # Step 4: Open UI (optional)
    if open_ui:
        step4_open_ui()


def main_ui() -> None:
    """
    CLI entry point to open the UI without running analysis.
    
    Expected usage: vulnhalla-ui
    """
    logger.info("Opening Vulnhalla UI...")
    ui_main()


def main_validate() -> None:
    """
    CLI entry point to validate configuration.
    
    Expected usage: vulnhalla-validate
    """
    from src.utils.config_validator import validate_all_config
    
    is_valid, errors = validate_all_config()
    
    if is_valid:
        logger.info("[+] All configurations are valid!")
    else:
        for error in errors:
            logger.error(error)
        sys.exit(1)


def main_list() -> None:
    """
    CLI entry point to list analyzed repositories.
    
    Expected usage: vulnhalla-list
    """
    from src.ui.results_loader import ResultsLoader
    
    results_dir = Path("output/results")
    if not results_dir.exists():
        logger.info("No results found. Run 'vulnhalla <org/repo>' first.")
        return
    
    loader = ResultsLoader()
    
    # Currently only 'c' language is supported
    lang = "c"
    issues, _ = loader.load_all_issues(lang)
    
    if not issues:
        logger.info("No analyzed repositories found.")
        return
    
    # Group issues by repo
    repos = {}
    for issue in issues:
        repo = issue.repo
        if repo not in repos:
            repos[repo] = {"true": 0, "false": 0, "needs_more_data to decide": 0}
        repos[repo][issue.status] += 1
    
    logger.info("Analyzed repositories:")
    logger.info("-" * 50)
    for repo, counts in sorted(repos.items()):
        total = counts["true"] + counts["false"] + counts["needs_more_data to decide"]
        logger.info(
            "  %-30s %3d issues (%d True positive, %d False positive, %d Needs more data to decide)",
            repo, total, counts["true"], counts["false"], counts["needs_more_data to decide"]
        )


def main_example() -> None:
    """
    CLI entry point to run the example pipeline.
    
    Expected usage: vulnhalla-example
    """
    from examples.example import main as example_main
    example_main()
    
def _run_php_pipeline(
    plugins_dir: Optional[Path],
    progpilot_findings: Optional[Path],
    triage_threshold: str = "high,medium",
    open_ui: bool = True,
) -> None:
    """
    PHP/WordPress analysis pipeline using Progpilot + PHPIssueAnalyzer.

    Args:
        plugins_dir:        Root directory of unzipped WordPress plugins.
        progpilot_findings: Path to pre-computed progpilot findings JSON.
                            If provided, skips scan and triage steps.
        triage_threshold:   Comma-separated confidence levels to pass to LLM.
        open_ui:            Whether to open the UI after completion.
    """
    import json
    from src.php.progpilot_adapter import normalize_findings
    from src.php.php_issue_analyzer import PHPIssueAnalyzer

    threshold = frozenset(triage_threshold.split(","))

    # ── Step 1: Load or compute findings ─────────────────────────────────────
    if progpilot_findings and progpilot_findings.exists():
        logger.info("\nStep 1: Loading pre-computed Progpilot findings")
        logger.info("-" * 60)
        logger.info("Findings file: %s", progpilot_findings)
        try:
            raw = json.loads(progpilot_findings.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.error("[-] Failed to load findings file: %s", e)
            sys.exit(1)
        triaged = raw  # pre-computed findings are already triaged
    else:
        if not plugins_dir or not plugins_dir.exists():
            logger.error("[-] --plugins-dir is required when no --progpilot-findings provided")
            sys.exit(1)

        logger.info("\nStep 1: Running Progpilot scan + triage")
        logger.info("-" * 60)
        logger.info("Plugins directory: %s", plugins_dir)

        try:
            import wp_progpilot_hunter as wph
        except ImportError:
            logger.error("[-] wp_progpilot_hunter not found — ensure it is on PYTHONPATH")
            sys.exit(1)

        findings_path = Path("output/progpilot_raw.json")
        findings_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            wph.scan(plugins_dir, findings_path)
            raw = json.loads(findings_path.read_text())
            triaged = wph.triage(raw, plugins_dir)
            wph.report(triaged, Path("output/progpilot_findings.json"))
        except Exception as e:
            logger.error("[-] Progpilot scan/triage failed: %s", e)
            sys.exit(1)

    # ── Step 2: Normalize to Vulnhalla issue format ───────────────────────────
    logger.info("\nStep 2: Normalizing findings")
    logger.info("-" * 60)

    resolve_dir = plugins_dir or progpilot_findings.parent
    issues = normalize_findings(triaged, resolve_dir, threshold)

    if not issues:
        logger.info("[+] No findings above triage threshold — nothing to send to LLM.")
        if open_ui:
            step4_open_ui()
        return

    logger.info("[+] %d findings above threshold → proceeding to LLM triage", len(issues))

    # ── Step 3: LLM triage via PHPIssueAnalyzer ───────────────────────────────
    logger.info("\nStep 3: Classifying results with LLM")
    logger.info("-" * 60)

    try:
        from src.llm.llm_analyzer import LLMAnalyzer
        analyzer = PHPIssueAnalyzer(issues, lang="php")
        llm_analyzer = LLMAnalyzer()
        llm_analyzer.init_llm_client()

        issues_by_type = analyzer.collect_issues_from_databases()
        for issue_type, issues_of_type in issues_by_type.items():
            analyzer.process_issue_type(issue_type, issues_of_type, llm_analyzer)

    except LLMConfigError as e:
        logger.error("[-] Step 3: LLM configuration error: %s", e)
        _log_exception_cause(e)
        sys.exit(1)
    except LLMApiError as e:
        logger.error("[-] Step 3: LLM API error: %s", e)
        _log_exception_cause(e)
        sys.exit(1)
    except VulnhallaError as e:
        logger.error("[-] Step 3: File system error: %s", e)
        _log_exception_cause(e)
        sys.exit(1)

    # ── Step 4: Open UI ───────────────────────────────────────────────────────
    if open_ui:
        step4_open_ui()


if __name__ == '__main__':
    main_analyze()