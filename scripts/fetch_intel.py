"""
CYBERWATCH DASHBOARD — fetch_intel.py
======================================
Fetches threat intelligence from multiple free sources:
  - NVD (NIST) CVE API        → Latest vulnerabilities
  - CISA Alerts RSS           → US government advisories
  - The Hacker News RSS       → Cybersecurity news
  - Bleeping Computer RSS     → Incidents & breaches
  - Krebs on Security RSS     → Investigative news
  - SANS ISC RSS              → Threat diaries
  - Reddit r/netsec JSON      → Community intel
  - AlienVault OTX API        → Threat pulse (if API key set)
  - Gemini AI                 → AI enrichment for top 15 items

Output: data/intel.json  +  data/archive/YYYY-MM-DD.json

Run manually:
  pip install requests feedparser google-generativeai
  python scripts/fetch_intel.py

Run via GitHub Actions: automatically on schedule (see update.yml)
"""

import json
import os
import re
import sys
import time
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
import feedparser

# MITRE ATT&CK full database (246 techniques + 445 sub-techniques)
# Imported from the companion module in the same directory
try:
    from mitre_ttps import MITRE_TECHNIQUES, TACTIC_ORDER, map_ttps
except ImportError:
    import importlib.util, pathlib
    _spec = importlib.util.spec_from_file_location(
        "mitre_ttps",
        pathlib.Path(__file__).parent / "mitre_ttps.py"
    )
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    MITRE_TECHNIQUES = _mod.MITRE_TECHNIQUES
    TACTIC_ORDER     = _mod.TACTIC_ORDER
    map_ttps         = _mod.map_ttps

# ─── Logging Setup ───────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("cyberwatch")

# ─── Configuration ───────────────────────────────────────────────────────────

# Output paths (relative to repo root)
OUTPUT_PATH  = Path("data/intel.json")
ARCHIVE_DIR  = Path("data/archive")

# How many items to keep per source
MAX_ITEMS_PER_SOURCE = 10

# NVD API: fetch CVEs published in the last N days
NVD_LOOKBACK_DAYS = 10

# Request timeout in seconds
REQUEST_TIMEOUT = 30

# API keys — set as GitHub Actions Secrets
OTX_API_KEY    = os.environ.get("OTX_API_KEY", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

# User-Agent header
HEADERS = {
    "User-Agent": "CyberWatch/1.0 (GitHub personal project)"
}

# Default Mermaid graph used when AI enrichment fails
DEFAULT_WORKFLOW_GRAPH = (
    "graph LR\n"
    "    A[Threat Actor] --> B[Initial Access]\n"
    "    B --> C[Execution]\n"
    "    C --> D[Impact]"
)

# ─── RSS Feed Sources ─────────────────────────────────────────────────────────

RSS_SOURCES = [
    {
        "name":     "CISA",
        "url":      "https://www.cisa.gov/news.xml",
        "category": "advisory",
        "severity": "high",
    },
    {
        "name":     "The Hacker News",
        "url":      "https://feeds.feedburner.com/TheHackersNews",
        "category": "news",
        "severity": "medium",
    },
    {
        "name":     "Bleeping Computer",
        "url":      "https://www.bleepingcomputer.com/feed/",
        "category": "news",
        "severity": "medium",
    },
    {
        "name":     "Krebs on Security",
        "url":      "https://krebsonsecurity.com/feed/",
        "category": "news",
        "severity": "medium",
    },
    {
        "name":     "SANS ISC",
        "url":      "https://isc.sans.edu/rssfeed_full.xml",
        "category": "news",
        "severity": "low",
    },
    {
        "name":     "TheRecord Media",
        "url":      "https://therecord.media/feed",
        "category": "news",
        "severity": "high",
    },
]


# ─── Helpers ─────────────────────────────────────────────────────────────────

def now_utc() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def parse_date(date_str: str) -> str:
    """Try to parse a date string into ISO 8601 format."""
    if not date_str:
        return now_utc()
    try:
        if hasattr(date_str, 'tm_year'):
            dt = datetime(*date_str[:6], tzinfo=timezone.utc)
            return dt.isoformat()
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
            try:
                return datetime.strptime(date_str, fmt).replace(
                    tzinfo=timezone.utc
                ).isoformat()
            except ValueError:
                continue
    except Exception:
        pass
    return now_utc()


def clean_html(text: str) -> str:
    """Rudimentary HTML tag stripper for RSS descriptions."""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:999]


def make_request(url: str, headers: dict = None, params: dict = None) -> dict | None:
    """Make an HTTP GET request with error handling."""
    try:
        resp = requests.get(
            url,
            headers=headers or HEADERS,
            params=params,
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.Timeout:
        log.warning(f"Timeout fetching: {url}")
    except requests.exceptions.HTTPError as e:
        log.warning(f"HTTP error {e.response.status_code} for: {url}")
    except requests.exceptions.RequestException as e:
        log.warning(f"Request failed for {url}: {e}")
    except json.JSONDecodeError:
        log.warning(f"Invalid JSON from: {url}")
    return None


# ─── AI Severity Scoring Helper ──────────────────────────────────────────────

def ai_score_to_severity(score: float) -> str:
    """
    Convert a Gemini AI severity score (0.0–10.0) into a categorical
    severity string that matches the dashboard UI colour scheme.

      9.0–10.0  →  critical  (red)
      7.0– 8.9  →  high      (orange)
      4.0– 6.9  →  medium    (yellow)
      0.0– 3.9  →  low       (cyan)
    """
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


# ─── AI Enrichment ───────────────────────────────────────────────────────────

def enrich_with_ai(items: list[dict]) -> list[dict]:
    """
    Use Gemini gemini-2.5-flash-lite to enrich the top 15 items with:
      - ai_summary      : 2-3 sentence threat analysis + mitigations
      - severity_score  : float 0.0–10.0
      - workflow_graph  : Mermaid LR diagram of the attack flow

    Strict 6-second sleep between calls to avoid 429 rate-limit errors.
    Robust regex stripping handles markdown code-fence wrapping.
    On any failure the item gets safe fallback values.
    """
    if not GEMINI_API_KEY:
        log.info("GEMINI_API_KEY not set — skipping AI enrichment")
        # Apply fallback defaults to all items
        for item in items:
            item.setdefault("ai_summary",     "AI analysis pending")
            item.setdefault("severity_score", None)
            item.setdefault("workflow_graph", DEFAULT_WORKFLOW_GRAPH)
        return items

    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel("gemini-2.5-flash-lite")
    except ImportError:
        log.warning("google-generativeai not installed — skipping AI enrichment")
        for item in items:
            item.setdefault("ai_summary",     "AI analysis pending")
            item.setdefault("severity_score", None)
            item.setdefault("workflow_graph", DEFAULT_WORKFLOW_GRAPH)
        return items

    log.info(f"Starting AI enrichment for top {min(15, len(items))} items...")

    for i, item in enumerate(items[:15]):
        try:
            ttp_str = ", ".join(
                f"{t['id']} {t['name']}"
                for t in item.get("ttps", [])[:5]
            ) or "None detected"

            prompt = f"""You are a senior threat intelligence analyst. Analyze the following cybersecurity item and respond ONLY with a valid JSON object — no markdown, no code fences, no extra text before or after the JSON.

Return exactly this structure:
{{
  "ai_summary": "2-3 sentence analysis covering: what the threat is, its real-world impact, and recommended mitigations for defenders",
  "severity_score": <float between 0.0 and 10.0 representing overall threat severity>,
  "workflow_graph": "a Mermaid graph LR diagram (single line using \\n for newlines) showing the attack kill chain"
}}

THREAT ITEM:
Title: {item.get('title', '')}
Description: {item.get('description', '')}
Category: {item.get('category', '')}
MITRE TTPs: {ttp_str}
CVE ID: {item.get('cve_id') or 'N/A'}
CVSS Score: {item.get('cvss_score') or 'N/A'}"""

            response = model.generate_content(prompt)
            raw = response.text.strip()

            # ── Robust JSON extraction: strip ALL markdown code fences ────────
            # Handles ```json ... ```, ``` ... ```, leading/trailing whitespace
            raw = re.sub(r"^```(?:json)?\s*\n?", "", raw, flags=re.MULTILINE)
            raw = re.sub(r"\n?```\s*$",           "", raw, flags=re.MULTILINE)
            raw = raw.strip()

            # Extract just the JSON object in case there's surrounding text
            json_match = re.search(r'\{.*\}', raw, re.DOTALL)
            if json_match:
                raw = json_match.group(0)

            parsed = json.loads(raw)

            # ── Apply AI results ──────────────────────────────────────────────
            item["ai_summary"] = str(
                parsed.get("ai_summary", "AI analysis pending")
            )

            item["workflow_graph"] = str(
                parsed.get("workflow_graph", DEFAULT_WORKFLOW_GRAPH)
            )

            raw_score = parsed.get("severity_score", 5.0)
            try:
                score = float(raw_score)
                score = max(0.0, min(10.0, score))   # clamp to valid range
            except (TypeError, ValueError):
                score = 5.0

            item["severity_score"] = round(score, 1)
            # Overwrite keyword-based severity with AI-derived one
            item["severity"] = ai_score_to_severity(score)

            log.info(
                f"  ✓ AI [{i+1:02d}/15] score={score:.1f} "
                f"sev={item['severity']} | {item['title'][:55]}"
            )

        except json.JSONDecodeError as e:
            log.warning(f"  ✗ AI [{i+1:02d}/15] JSON parse error: {e} — using fallback")
            item["ai_summary"]     = "AI analysis pending"
            item["workflow_graph"] = DEFAULT_WORKFLOW_GRAPH
            item["severity_score"] = None

        except Exception as e:
            log.warning(f"  ✗ AI [{i+1:02d}/15] enrichment failed: {e} — using fallback")
            item["ai_summary"]     = "AI analysis pending"
            item["workflow_graph"] = DEFAULT_WORKFLOW_GRAPH
            item["severity_score"] = None

        # ── Strict rate limiting: 6 seconds between each Gemini call ─────────
        # This keeps us well under the free-tier RPM limit (10 RPM for Flash).
        # Total delay for 15 items: ~90 seconds — acceptable for a daily job.
        if i < min(14, len(items) - 1):
            time.sleep(6)

    # Apply fallback defaults to items beyond the top 15
    for item in items[15:]:
        item.setdefault("ai_summary",     "AI analysis pending")
        item.setdefault("severity_score", None)
        item.setdefault("workflow_graph", DEFAULT_WORKFLOW_GRAPH)

    log.info("AI enrichment complete.")
    return items


# ─── Fetchers ────────────────────────────────────────────────────────────────

def fetch_rss(source: dict) -> list[dict]:
    """Fetch and parse an RSS/Atom feed."""
    log.info(f"Fetching RSS: {source['name']} ({source['url']})")
    items = []

    try:
        feed = feedparser.parse(source["url"])

        if feed.bozo and not feed.entries:
            log.warning(f"Feed parse error for {source['name']}: {feed.bozo_exception}")
            return items

        for entry in feed.entries[:MAX_ITEMS_PER_SOURCE]:
            title = entry.get("title", "Untitled")
            link  = entry.get("link", "")

            description = ""
            if hasattr(entry, "summary"):
                description += clean_html(entry.summary)
            elif hasattr(entry, "content"):
                description += " " + clean_html(entry.content[0].get("value", ""))
            description = description.strip()[:999]

            pub_date = parse_date(
                entry.get("published_parsed") or entry.get("updated_parsed")
            )

            severity = infer_severity(title + " " + description, source["severity"])
            category = infer_category(title + " " + description, source["category"])

            items.append({
                "title":       title,
                "description": description,
                "url":         link,
                "cve_id":      extract_cve_id(title + " " + description),
                "source":      source["name"],
                "category":    category,
                "severity":    severity,
                "cvss_score":  None,
                "published":   pub_date,
            })

    except Exception as e:
        log.error(f"Unexpected error fetching {source['name']}: {e}")

    log.info(f"  Got {len(items)} items from {source['name']}")
    return items


def fetch_nvd_cves() -> list[dict]:
    """Fetch recent CVEs from the NIST NVD API (free, no key needed)."""
    log.info("Fetching CVEs from NVD API...")
    items = []

    end_date   = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=NVD_LOOKBACK_DAYS)

    params = {
        "pubStartDate":   start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":     end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": MAX_ITEMS_PER_SOURCE,
    }

    data = make_request(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params=params
    )

    if not data:
        log.warning("NVD API returned no data")
        return items

    vulnerabilities = data.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")

        descriptions = cve.get("descriptions", [])
        description  = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )[:400]

        cvss_score = None
        severity   = "medium"
        metrics    = cve.get("metrics", {})

        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data  = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity   = cvss_to_severity(cvss_score)
                break

        published = parse_date(cve.get("published", ""))

        items.append({
            "title":       f"{cve_id}: {description[:80]}...",
            "description": description,
            "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "cve_id":      cve_id,
            "source":      "NVD",
            "category":    "cve",
            "severity":    severity,
            "cvss_score":  cvss_score,
            "published":   published,
        })

    log.info(f"  Got {len(items)} CVEs from NVD")
    return items


def fetch_reddit_netsec() -> list[dict]:
    """Fetch top posts from r/netsec using Reddit's public JSON endpoint."""
    log.info("Fetching Reddit r/netsec...")
    items = []

    headers = {**HEADERS, "User-Agent": "CyberWatch/1.0 (personal dashboard)"}
    data    = make_request(
        "https://www.reddit.com/r/netsec.json?limit=15", headers=headers
    )

    if not data:
        log.warning("Reddit r/netsec returned no data")
        return items

    posts = data.get("data", {}).get("children", [])

    for post in posts:
        p = post.get("data", {})

        if p.get("stickied"):
            continue

        title     = p.get("title", "Untitled")
        url       = p.get("url", "")
        selftext  = clean_html(p.get("selftext", ""))
        created   = p.get("created_utc")
        published = (
            datetime.fromtimestamp(created, tz=timezone.utc).isoformat()
            if created else now_utc()
        )
        score = p.get("score", 0)

        items.append({
            "title":       title,
            "description": selftext or f"Reddit discussion (score: {score})",
            "url":         url,
            "cve_id":      extract_cve_id(title),
            "source":      "Reddit/netsec",
            "category":    infer_category(title, "news"),
            "severity":    infer_severity(title, "low"),
            "cvss_score":  None,
            "published":   published,
        })

    log.info(f"  Got {len(items)} posts from Reddit r/netsec")
    return items


def fetch_otx_pulse(api_key: str) -> list[dict]:
    """Fetch recent threat pulses from AlienVault OTX."""
    if not api_key:
        log.info("OTX_API_KEY not set — skipping AlienVault OTX")
        return []

    log.info("Fetching AlienVault OTX pulses...")
    items = []

    headers = {**HEADERS, "X-OTX-API-KEY": api_key}
    data    = make_request(
        "https://otx.alienvault.com/api/v1/pulses/subscribed",
        headers=headers,
        params={"limit": MAX_ITEMS_PER_SOURCE}
    )

    if not data:
        log.warning("OTX API returned no data")
        return items

    for pulse in data.get("results", []):
        name        = pulse.get("name", "Untitled")
        description = (pulse.get("description") or "")[:400]
        created     = pulse.get("created", now_utc())
        pulse_id    = pulse.get("id", "")

        items.append({
            "title":       name,
            "description": description,
            "url":         f"https://otx.alienvault.com/pulse/{pulse_id}",
            "cve_id":      None,
            "source":      "AlienVault OTX",
            "category":    "incident",
            "severity":    infer_severity(name + " " + description, "medium"),
            "cvss_score":  None,
            "published":   parse_date(created),
        })

    log.info(f"  Got {len(items)} pulses from AlienVault OTX")
    return items


# ─── Intel Inference Helpers ─────────────────────────────────────────────────

def cvss_to_severity(score: float | None) -> str:
    """Convert a CVSS numeric score to a severity label."""
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def infer_severity(text: str, default: str = "medium") -> str:
    """Guess severity from keywords in the text."""
    t = text.lower()
    if any(kw in t for kw in [
        "critical", "zero-day", "0-day", "actively exploited",
        "rce", "remote code execution", "unauthenticated", "wormable"
    ]):
        return "critical"
    if any(kw in t for kw in [
        "high", "privilege escalation", "authentication bypass",
        "ransomware", "data breach", "nation-state", "apt"
    ]):
        return "high"
    if any(kw in t for kw in [
        "medium", "xss", "csrf", "injection", "phishing", "malware"
    ]):
        return "medium"
    if any(kw in t for kw in [
        "low", "informational", "advisory", "guide", "best practice"
    ]):
        return "low"
    return default


def infer_category(text: str, default: str = "news") -> str:
    """Guess the item category from keywords."""
    t = text.lower()
    if any(kw in t for kw in ["cve-", "vulnerability", "patch", "exploit", "nvd"]):
        return "cve"
    if any(kw in t for kw in [
        "breach", "attack", "ransomware", "hack", "intrusion",
        "stolen", "compromised", "leaked", "incident"
    ]):
        return "incident"
    if any(kw in t for kw in [
        "advisory", "alert", "directive", "guidance", "warning",
        "cisa", "recommendation", "patch tuesday"
    ]):
        return "advisory"
    return default


def extract_cve_id(text: str) -> str | None:
    """Extract the first CVE ID found in text."""
    match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return match.group(0).upper() if match else None


def deduplicate(items: list[dict]) -> list[dict]:
    """Remove duplicate items by title similarity."""
    seen_titles = set()
    unique      = []

    for item in items:
        title_key = item["title"].lower().strip()[:80]
        if title_key not in seen_titles:
            seen_titles.add(title_key)
            unique.append(item)

    return unique


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    log.info("═" * 60)
    log.info("CYBERWATCH — Starting intel fetch")
    log.info("═" * 60)

    all_items = []

    # 1. RSS feeds
    for source in RSS_SOURCES:
        try:
            items = fetch_rss(source)
            all_items.extend(items)
        except Exception as e:
            log.error(f"Failed fetching {source['name']}: {e}")
        time.sleep(1)

    # 2. NVD CVE API
    try:
        all_items.extend(fetch_nvd_cves())
    except Exception as e:
        log.error(f"NVD fetch failed: {e}")

    time.sleep(1)

    # 3. Reddit r/netsec
    try:
        all_items.extend(fetch_reddit_netsec())
    except Exception as e:
        log.error(f"Reddit fetch failed: {e}")

    # 4. AlienVault OTX (only if API key is set)
    try:
        all_items.extend(fetch_otx_pulse(OTX_API_KEY))
    except Exception as e:
        log.error(f"OTX fetch failed: {e}")

    # Deduplicate
    all_items = deduplicate(all_items)

    # ── Map MITRE ATT&CK TTPs ─────────────────────────────────────────────────
    log.info("Mapping MITRE ATT&CK TTPs...")
    for item in all_items:
        text = item.get("title", "") + " " + item.get("description", "")
        item["ttps"] = map_ttps(text)

    ttp_total = sum(len(i["ttps"]) for i in all_items)
    log.info(f"  Mapped {ttp_total} TTP associations across {len(all_items)} items")

    # Sort by published date descending (newest first, so AI enriches top items)
    all_items.sort(key=lambda x: x.get("published", ""), reverse=True)

    # ── AI Enrichment (Gemini gemini-2.5-flash-lite) ──────────────────────────
    # Enriches the top 15 items with ai_summary, severity_score, workflow_graph.
    # Overwrites the keyword-based severity with AI-derived severity.
    # Falls back gracefully if GEMINI_API_KEY is not set or calls fail.
    try:
        all_items = enrich_with_ai(all_items)
    except Exception as e:
        log.error(f"AI enrichment pipeline failed: {e}")
        for item in all_items:
            item.setdefault("ai_summary",     "AI analysis pending")
            item.setdefault("severity_score", None)
            item.setdefault("workflow_graph", DEFAULT_WORKFLOW_GRAPH)

    # Build final output payload
    output = {
        "last_updated": now_utc(),
        "total_items":  len(all_items),
        "items":        all_items,
    }

    # ── Save primary intel.json ───────────────────────────────────────────────
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    log.info(f"✓ Wrote {len(all_items)} items to {OUTPUT_PATH}")

    # ── Save dated archive copy ───────────────────────────────────────────────
    # Creates data/archive/YYYY-MM-DD.json for historical tracking.
    # The directory is created automatically if it doesn't exist yet.
    today_str    = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    archive_path = ARCHIVE_DIR / f"{today_str}.json"
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    with open(archive_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    log.info(f"✓ Archived to {archive_path}")

    log.info("═" * 60)
    log.info(f"CYBERWATCH — Fetch complete. {len(all_items)} items ready.")
    log.info("═" * 60)


if __name__ == "__main__":
    main()
