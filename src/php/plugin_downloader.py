"""
src/php/plugin_downloader.py
============================
Optional WordPress plugin acquisition layer.

Downloads plugins from wordpress.org/plugins for local analysis.
Used when a plugins directory does not already exist. Handles:
  - Single plugin download by slug
  - Batch download from a slug list file
  - Resume: skips slugs already present in output directory
  - Version pinning: download a specific version instead of latest

This module is entirely optional in the pipeline — if plugins are already
present on disk, progpilot_adapter.normalize_findings() and
PHPIssueAnalyzer work directly against the local files.

Requires: pySmartDL (already in pyproject.toml dependencies).

Usage:
  from src.php.plugin_downloader import download_plugins
  download_plugins(["contact-form-7", "yoast-seo"], output_dir)
"""

import json
import logging
import re
import zipfile
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

log = logging.getLogger(__name__)

# WordPress.org plugin API and download base URL
_WP_API_URL  = "https://api.wordpress.org/plugins/info/1.0/{slug}.json"
_WP_DL_URL   = "https://downloads.wordpress.org/plugin/{slug}.{version}.zip"
_WP_DL_LATEST= "https://downloads.wordpress.org/plugin/{slug}.zip"

# Request timeout in seconds
_TIMEOUT = 30


def download_plugins(
    slugs: list[str],
    output_dir: Path,
    version_map: Optional[dict[str, str]] = None,
    force: bool = False,
    ssl_verify: bool = True,
) -> dict[str, str]:
    """
    Download and unzip WordPress plugins by slug.

    Args:
        slugs:       List of plugin slugs (e.g., ["contact-form-7"]).
        output_dir:  Directory to unzip plugins into. Created if absent.
        version_map: Optional dict mapping slug → specific version to download.
                     If absent for a slug, the latest version is downloaded.
        force:       If True, re-download even if already present.
        ssl_verify:  If False, skip SSL certificate verification.

    Returns:
        Dict mapping slug → absolute path of unzipped plugin directory,
        or slug → "" if download failed.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    version_map = version_map or {}
    results: dict[str, str] = {}

    for slug in slugs:
        target_dir = output_dir / slug
        if target_dir.exists() and not force:
            log.info(f"  SKIP  {slug} — already present at {target_dir}")
            results[slug] = str(target_dir)
            continue

        version = version_map.get(slug)
        log.info(f"  DOWNLOADING  {slug}" + (f" @ {version}" if version else " (latest)"))

        try:
            plugin_path = _download_one(slug, output_dir, version, ssl_verify)
            results[slug] = str(plugin_path) if plugin_path else ""
        except Exception as e:
            log.warning(f"  FAILED  {slug}: {e}")
            results[slug] = ""

    succeeded = sum(1 for v in results.values() if v)
    log.info(f"  Download complete: {succeeded}/{len(slugs)} succeeded")
    return results


def download_from_file(
    slugs_file: Path,
    output_dir: Path,
    force: bool = False,
) -> dict[str, str]:
    """
    Download plugins listed in a text file (one slug per line).
    Lines starting with # are treated as comments.

    Args:
        slugs_file: Path to a newline-separated slug list.
        output_dir: Directory to unzip plugins into.
        force:      Re-download even if present.

    Returns:
        Dict mapping slug → unzipped path or "".
    """
    lines = slugs_file.read_text().splitlines()
    slugs = [
        line.strip()
        for line in lines
        if line.strip() and not line.strip().startswith('#')
    ]
    log.info(f"  Loaded {len(slugs)} slugs from {slugs_file}")
    return download_plugins(slugs, output_dir, force=force)


def fetch_plugin_info(slug: str) -> dict:
    """
    Query the WordPress.org plugin API for metadata.
    Returns dict with current_version, active_installs, last_updated, etc.
    Returns {} on network failure or unknown plugin.
    """
    url = _WP_API_URL.format(slug=slug)
    try:
        req = Request(url, headers={"User-Agent": "Vulnhalla/1.0"})
        with urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
            return {
                "current_version": data.get("version", "unknown"),
                "last_updated":    data.get("last_updated", "unknown"),
                "tested_up_to":    data.get("tested", "unknown"),
                "download_link":   data.get("download_link", ""),
                "active_installs": data.get("active_installs", 0),
            }
    except (URLError, HTTPError, json.JSONDecodeError, Exception) as e:
        log.debug(f"WP API lookup failed for {slug}: {e}")
        return {}


# ─── Private helpers ──────────────────────────────────────────────────────────

def _download_one(
    slug: str,
    output_dir: Path,
    version: Optional[str],
    ssl_verify: bool,
) -> Optional[Path]:
    """
    Download and unzip a single plugin. Returns the unzipped directory path.
    Uses pySmartDL for parallel chunk downloading with resume support.
    Falls back to urllib if pySmartDL is unavailable.
    """
    if version:
        url = _WP_DL_URL.format(slug=slug, version=version)
    else:
        url = _WP_DL_LATEST.format(slug=slug)

    zip_path = output_dir / f"{slug}.zip"

    # Prefer pySmartDL (already in pyproject.toml) for robust downloading
    try:
        from pySmartDL import SmartDL
        dl = SmartDL(url, str(zip_path), progress_bar=False)
        dl.start()
        if not dl.isSuccessful():
            raise RuntimeError(f"SmartDL failed for {slug}: {dl.get_errors()}")
    except ImportError:
        # Fallback: plain urllib
        _urllib_download(url, zip_path)

    if not zip_path.exists() or zip_path.stat().st_size == 0:
        raise RuntimeError(f"Downloaded zip is empty or missing: {zip_path}")

    plugin_dir = _unzip_plugin(zip_path, output_dir)
    zip_path.unlink(missing_ok=True)
    return plugin_dir


def _urllib_download(url: str, dest: Path) -> None:
    """Simple urllib fallback downloader."""
    req = Request(url, headers={"User-Agent": "Vulnhalla/1.0"})
    with urlopen(req, timeout=_TIMEOUT) as resp, open(dest, 'wb') as f:
        while chunk := resp.read(65536):
            f.write(chunk)


def _unzip_plugin(zip_path: Path, output_dir: Path) -> Path:
    """
    Unzip plugin archive. WordPress.org zips contain a single top-level
    directory named after the plugin slug.
    Returns the path to the extracted plugin directory.
    """
    with zipfile.ZipFile(zip_path, 'r') as zf:
        # Determine top-level directory name
        names = zf.namelist()
        if not names:
            raise RuntimeError(f"Empty zip: {zip_path}")
        top_level = names[0].split('/')[0]
        zf.extractall(output_dir)

    extracted = output_dir / top_level
    if not extracted.exists():
        raise RuntimeError(f"Expected {extracted} after unzip but not found")

    log.debug(f"    Unzipped to: {extracted}")
    return extracted
