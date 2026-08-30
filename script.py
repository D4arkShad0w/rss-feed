"""
RSS Security News Bot - Ultimate Edition (Final)
===================================================
- Groq SDK رسمی بدون http_client سفارشی
- .strip() روی همه‌ی API Keys
- 3-Layer HTTP: requests → curl_cffi → verify=False
- Smart URL Variants: fix typos, RSSHub alternatives, WordPress ?format=xml
- RSS Feed Discovery: پیدا کردن RSS در HTML <link>
- Site Scraping: وقتی RSS نیست، خود سایت را scrap می‌کند
- Triple Dedup: entry_id + normalized URL + title hash
- Title Translation: ترجمه‌ی عنوان به فارسی با حفظ لغات تخصصی
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

import feedparser
import listparser
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

warnings.filterwarnings("ignore", message="Unverified HTTPS request")
requests.packages.urllib3.disable_warnings()

from google import genai
from google.genai import types

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

from curl_cffi import requests as cffi_requests

import logging
logging_format = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.INFO, format=logging_format, datefmt="%H:%M:%S")
logger = logging.getLogger("rss_security_bot")

# ============================================================
# CONFIG
# ============================================================

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
CHAT_ID = os.getenv("CHAT_ID", "").strip()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()

OPML_FILE = "feeds.opml"
STATE_FILE = "seen_ids.json"

MAX_WORKERS = 20
POSTS_PER_FEED = int(os.getenv("POSTS_PER_FEED", "50"))
MAX_AGE_DAYS = int(os.getenv("MAX_AGE_DAYS", "7"))
FUTURE_TOLERANCE = timedelta(hours=6)
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "5"))
MAX_ENTRIES_PER_RUN = int(os.getenv("MAX_ENTRIES_PER_RUN", "60"))

FEED_TIMEOUT = 20
ARTICLE_TIMEOUT = 25
TELEGRAM_TIMEOUT = 10
GEMINI_DELAY = 5.0
MODEL_COOLDOWN_SECONDS = 1800
TRANSIENT_COOLDOWN_SECONDS = 300
TELEGRAM_MAX_LEN = 4096

MAX_URL_VARIANTS = 15
MAX_DISCOVERED_FEEDS = 8

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
)

# ============================================================
# MODEL CONFIGURATION
# ============================================================

FILTER_MODELS = [
    {"provider": "groq", "model": "openai/gpt-oss-20b"},
    {"provider": "gemini", "model": "gemini-3.5-flash-lite"},
    {"provider": "groq", "model": "qwen/qwen3.6-27b"},
    {"provider": "gemini", "model": "gemini-3.1-flash-lite"},
    {"provider": "groq", "model": "groq/compound-mini"},
]

ANALYSIS_MODELS = [
    {"provider": "groq", "model": "openai/gpt-oss-120b"},
    {"provider": "gemini", "model": "gemini-3.5-flash-lite"},
    {"provider": "groq", "model": "qwen/qwen3.8-27b"},
    {"provider": "gemini", "model": "gemini-3.1-flash-lite"},
    {"provider": "groq", "model": "groq/compound"},
    {"provider": "groq", "model": "openai/gpt-oss-20b"},
]

# ============================================================
# MODEL COOLDOWN
# ============================================================

class NoModelsAvailable(RuntimeError):
    pass

model_error_state: Dict[str, Tuple[float, int]] = {}

def is_transient_error(reason: str) -> bool:
    r = reason.lower()
    return ("connection" in r or "429" in reason or "timeout" in r or "rate limit" in r)

def cooldown_for(reason: str) -> int:
    if "Invalid filter" in reason or "Empty analysis" in reason:
        return 0
    if is_transient_error(reason):
        return TRANSIENT_COOLDOWN_SECONDS
    return MODEL_COOLDOWN_SECONDS

def should_skip_model(model_key: str) -> bool:
    provider = model_key.split("/", 1)[0]
    for key in (model_key, f"__provider__/{provider}"):
        entry = model_error_state.get(key)
        if entry and (time.time() - entry[0]) < entry[1]:
            return True
    return False

def mark_model_error(model_key: str, reason: str = "") -> None:
    cooldown = cooldown_for(reason)
    if cooldown == 0:
        return
    model_error_state[model_key] = (time.time(), cooldown)
    if "connection" in reason.lower():
        provider = model_key.split("/", 1)[0]
        model_error_state[f"__provider__/{provider}"] = (time.time(), cooldown)
    logger.warning("[COOLDOWN] %s for %d min%s", model_key, cooldown // 60, f" — {reason[:300]}" if reason else "")

# ============================================================
# INTERESTS
# ============================================================

INTEREST_CATEGORIES: Dict[str, List[str]] = {
    "LOW-LEVEL SECURITY": ["Exploit Development", "Memory Corruption", "Use-After-Free", "Heap Exploitation", "Kernel Exploitation", "Privilege Escalation", "Sandbox Escape", "Mitigation Bypass", "PatchGuard Bypass", "Windows Defender / EDR Bypass", "0-day/1-day با تحلیل فنی"],
    "WINDOWS INTERNALS": ["Windows Internals", "Windows Kernel Security", "Driver Security", "Code Integrity", "PatchGuard", "PPL", "VBS", "Credential Guard", "ETW Security", "Security Mitigations"],
    "EDR / ENDPOINT": ["EDR Evasion", "EDR Bypass", "Detection Engineering", "Telemetry Evasion", "AMSI Bypass", "Security Product Internals"],
    "REVERSE ENGINEERING": ["Reverse Engineering", "Binary Analysis", "Malware Reverse Engineering", "Static/Dynamic Analysis", "Binary Instrumentation"],
    "FUZZING": ["Fuzzing", "Kernel Fuzzing", "Coverage-Guided Fuzzing", "Hybrid Fuzzing", "Automated Vulnerability Discovery"],
    "ROOTKIT / FIRMWARE": ["Rootkit", "Bootkit", "UEFI Security", "Firmware Security", "Secure Boot", "Hardware Root of Trust"],
    "MALWARE / ATTACK TECHNIQUES": ["Advanced Malware Analysis", "Malware Techniques", "Persistence Techniques", "Defense Evasion", "Living-off-the-Land"],
    "OS / LOW-LEVEL CS": ["Operating Systems Internals", "Computer Architecture", "Compiler Internals", "ELF/PE Internals", "Kernel Design"],
    "NETWORK / PROTOCOL SECURITY": ["Protocol Security", "Network Exploitation", "DNS Security", "SMB Security", "Authentication Protocol Security"],
    "ADVANCED CS": ["Computer Science Research", "Systems Research", "Programming Languages", "Computer Architecture", "Unusual CS Projects"],
    "MATHEMATICS": ["Pure Mathematics", "Applied Mathematics", "Number Theory", "Algebra", "Analysis", "Topology", "Geometry", "Discrete Mathematics", "Combinatorics", "Mathematical Logic", "Category Theory", "Graph Theory", "Mathematical Physics", "Dynamical Systems", "Mathematical Proofs", "Famous Mathematical Problems", "New Mathematical Discoveries"],
    "AI & MATHEMATICS": ["Mathematical Foundations of AI", "Mathematical Foundations of Machine Learning", "Learning Theory", "Optimization Theory", "Probability and Statistics for AI", "Information Theory", "Linear Algebra for AI", "Algebraic Geometry in ML", "Topological Data Analysis", "Geometric Deep Learning", "Mathematical AI Research", "Theoretical Computer Science and AI"],
    "AI SKEPTICISM / REALISM": ["AI Limitations", "LLM Limitations", "AI Hype Criticism", "AI Reality Check", "Skepticism about AGI", "AI Bubble Analysis", "Critical AI Analysis", "AI Overclaiming", "AI Evaluation Challenges", "AI Benchmark Limitations", "Empirical AI Analysis", "AI Scaling Laws Debate", "Rational AI Discourse"],
    "SECURITY CONFERENCES": ["Black Hat", "DEF CON", "USENIX Security", "NDSS", "IEEE S&P", "Pwn2Own", "Security Conference Research"],
    "THREAT INTEL / APT": ["APT", "Cyber Espionage", "State-Sponsored Cyber Operations", "Cyber Warfare", "APT Campaign Analysis", "TTP Analysis"],
    "IRAN": ["امنیت سایبری ایران", "حملات سایبری مرتبط با ایران", "گروه‌های تهدید ایرانی", "زیرساخت‌های حیاتی ایران", "تحریم‌های فناوری علیه ایران", "تحولات راهبردی ایران"],
    "CHINA": ["China Cyber Operations", "Chinese APT Groups", "China Semiconductor", "US-China Tech Competition", "China AI Strategy"],
    "MIDDLE EAST / ISRAEL": ["Middle East Cybersecurity", "Israel Cyber Operations", "Iran-Israel Cyber Conflict", "Regional Strategic Security"],
    "US NATIONAL SECURITY": ["US Cybersecurity Policy", "CISA", "Technology Export Controls", "Semiconductor Sanctions", "AI Regulation"],
    "STRATEGIC TECH": ["Semiconductor Industry", "Chip Design/Manufacturing", "AI Hardware", "GPU Architecture", "Geopolitical Technology Competition"],
    "CYBERSECURITY INDUSTRY": ["Cybersecurity Startups", "EDR/XDR Products", "Security Research Companies", "Vulnerability Research Companies", "Security Funding"],
    "DEEP TECHNICAL CONTENT": ["Technical Deep Dive", "Post-Mortem Attacks", "Root Cause Analysis", "Unusual Security Techniques", "Creative Systems Projects"],
}

def build_interests_prompt() -> str:
    return "\n".join(f"{cat}: {', '.join(ints)}" for cat, ints in INTEREST_CATEGORIES.items())

INTERESTS_PROMPT = build_interests_prompt()

# ============================================================
# HTTP SESSION & ADVANCED FETCH (3-Layer)
# ============================================================

def build_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })
    retry = Retry(total=2, connect=2, read=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504], allowed_methods=frozenset(["GET", "POST"]))
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

HTTP = build_session()

def is_safe_url(url: Optional[str]) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False

# ✅ URL Normalization برای جلوگیری از تکراری
def normalize_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc.lower().rstrip("/")
        if netloc.startswith("www."):
            netloc = netloc[4:]
        path = parsed.path.rstrip("/")
        if not path:
            path = "/"
        query = ""
        if parsed.query:
            params = []
            for param in parsed.query.split("&"):
                key = param.split("=")[0].lower()
                if not any(t in key for t in ["utm_", "fbclid", "gclid", "ref", "source", "campaign", "alt"]):
                    params.append(param)
            if params:
                query = "?" + "&".join(params)
        return f"{scheme}://{netloc}{path}{query}"
    except Exception:
        return url

# ✅ 3-Layer fetch: requests → curl_cffi → verify=False
def fetch_url(url: str, timeout: int) -> Optional[requests.Response]:
    # Layer 1: Standard requests
    try:
        response = HTTP.get(url, timeout=timeout, allow_redirects=True)
        if response.status_code == 200:
            return response
        if response.status_code in (403, 418, 503, 401):
            logger.info("  [HTTP] %d → curl_cffi for %s", response.status_code, url)
        else:
            logger.warning("[FETCH] %s | HTTP %d | requests", url, response.status_code)
    except Exception as e:
        error_msg = str(e)
        if "SSL" in error_msg or "CERTIFICATE_VERIFY_FAILED" in error_msg:
            logger.info("  [HTTP] SSL Error → will bypass for %s", url)
        else:
            logger.info("  [HTTP] requests failed: %s | %s", url, error_msg[:100])

    # Layer 2: curl_cffi — برای همه‌ی خطاها
    try:
        response = cffi_requests.get(url, impersonate="chrome", timeout=timeout, allow_redirects=True)
        if response.status_code == 200:
            logger.info("  [HTTP] ✅ curl_cffi succeeded: %s", url)
            return response
        logger.warning("[FETCH] %s | HTTP %d | curl_cffi", url, response.status_code)
    except Exception as e:
        logger.info("  [HTTP] curl_cffi failed: %s | %s", url, str(e)[:100])

    # Layer 3: verify=False (SSL bypass)
    try:
        response = HTTP.get(url, timeout=timeout, allow_redirects=True, verify=False)
        if response.status_code == 200:
            logger.info("  [HTTP] ✅ verify=False succeeded: %s", url)
            return response
        logger.warning("[FETCH] %s | HTTP %d | verify=False", url, response.status_code)
    except Exception as e:
        logger.warning("[FETCH] %s | ALL methods failed | %s", url, str(e)[:100])

    return None

# ============================================================
# CLIENT INITIALIZATION
# ============================================================

gemini_client = None
groq_client = None

if GEMINI_API_KEY:
    try:
        gemini_client = genai.Client(api_key=GEMINI_API_KEY)
        logger.info("Gemini initialized.")
    except Exception as e:
        logger.error("Gemini init failed: %s", e)
else:
    logger.warning("GEMINI_API_KEY missing.")

if GROQ_AVAILABLE and GROQ_API_KEY:
    try:
        groq_client = Groq(api_key=GROQ_API_KEY)
        logger.info("Groq initialized via official Groq SDK.")
    except Exception as e:
        logger.error("Groq init failed: %s", e)
        groq_client = None
else:
    logger.warning("GROQ_API_KEY missing or groq package not installed.")

# ============================================================
# STATE
# ============================================================

def load_state() -> Tuple[Set[str], Dict[str, int], Set[str], Set[str]]:
    if not os.path.exists(STATE_FILE):
        return set(), {}, set(), set()
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return (
                set(data.get("seen", [])),
                dict(data.get("retries", {})),
                set(data.get("seen_urls", [])),
                set(data.get("seen_titles", [])),
            )
    except Exception as e:
        logger.error("State load error: %s", e)
    return set(), {}, set(), set()

def save_state(seen_ids: Set[str], retry_counts: Dict[str, int],
               seen_urls: Set[str], seen_titles: Set[str]) -> None:
    try:
        temp = STATE_FILE + ".tmp"
        payload = {
            "seen": sorted(seen_ids),
            "retries": retry_counts,
            "seen_urls": sorted(seen_urls),
            "seen_titles": sorted(seen_titles),
        }
        with open(temp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(temp, STATE_FILE)
    except Exception as e:
        logger.error("State save error: %s", e)

# ============================================================
# TEXT CLEANING
# ============================================================

def clean_html(text: Any) -> str:
    if not text:
        return ""
    try:
        text = html.unescape(str(text))
        soup = BeautifulSoup(text, "html.parser")
        text = soup.get_text(" ", strip=True)
        return re.sub(r"\s+", " ", text).strip()
    except Exception:
        return str(text).strip()

def escape_html_text(text: Any) -> str:
    if not text:
        return ""
    return html.escape(str(text), quote=False)

# ============================================================
# TELEGRAM
# ============================================================

def _post_telegram(payload: Dict[str, Any]) -> bool:
    if not BOT_TOKEN or not CHAT_ID:
        return False
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    try:
        response = HTTP.post(url, json=payload, timeout=TELEGRAM_TIMEOUT)
        if response.ok:
            return True
        logger.error("Telegram error: %s %s", response.status_code, response.text[:500])
    except Exception as e:
        logger.error("Telegram exception: %s", e)
    return False

def send_status_message(text: str) -> bool:
    if len(text) > 4000:
        text = text[:4000] + "\n... (Truncated)"
    payload = {"chat_id": CHAT_ID, "text": text, "parse_mode": "Markdown", "disable_notification": True}
    return _post_telegram(payload)

def send_telegram(title: str, analysis: str, link: str, category: str, source: str = "") -> bool:
    if not BOT_TOKEN or not CHAT_ID:
        return False
    title_e = escape_html_text(title)
    analysis_e = escape_html_text(analysis)
    category_e = escape_html_text(category)
    source_e = escape_html_text(source)
    if not is_safe_url(link):
        link = "https://unsafe.sh"
    link_e = html.escape(link, quote=True)

    def build(analysis_text: str) -> str:
        source_line = f"🌐 <b>منبع:</b> {source_e}\n\n" if source_e else ""
        return (f"📌 <b>[{category_e}]</b>\n\n🔹 <b>{title_e}</b>\n\n{source_line}{analysis_text}\n\n🔗 <a href=\"{link_e}\">مطالعه مطلب اصلی</a>")

    text = build(analysis_e)
    if len(text) > TELEGRAM_MAX_LEN:
        overflow = len(text) - TELEGRAM_MAX_LEN + 20
        trimmed = analysis_e[:max(0, len(analysis_e) - overflow)] + "…"
        text = build(trimmed)

    payload = {"chat_id": CHAT_ID, "text": text, "parse_mode": "HTML", "disable_web_page_preview": False}
    ok = _post_telegram(payload)
    if ok:
        logger.info("Telegram message sent.")
    return ok

# ============================================================
# SMART URL VARIANTS — اصلاح هوشمند URL
# ============================================================

# ✅ تولید URL های جایگزین وقتی URL اصلی fail می‌شود
def generate_url_variants(url: str) -> List[str]:
    """Generate URL variants to try when the original fails."""
    variants: List[str] = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip("/")

    # 1. Fix common typos
    if "sympoium" in url:
        variants.append(url.replace("sympoium", "symposium"))
    if "sympozium" in url:
        variants.append(url.replace("sympozium", "symposium"))

    # 2. RSSHub alternative instances
    if "rsshub.app" in url:
        for alt in ["rsshub.rssforever.com", "rss.shab.fun", "rsshub.feeded.xyz"]:
            variants.append(url.replace("rsshub.app", alt))

    # 3. WordPress ?format=xml
    if "wordpress.com" in parsed.netloc:
        sep = "&" if "?" in url else "?"
        variants.append(url + sep + "format=xml")

    # 4. Remove ?alt=rss
    if "alt=rss" in url:
        cleaned = url.replace("?alt=rss", "").replace("&alt=rss", "").replace("?&", "?").rstrip("?")
        variants.append(cleaned)

    # 5. Add /feed/ if not present
    if not path.endswith("/feed") and not path.endswith("/feed/"):
        if not path.endswith(".xml") and not path.endswith(".rss"):
            variants.append(base + path + "/feed/")

    # 6. Common RSS paths (for homepages)
    if path in ["", "/", "/index.php", "/index.html", "/blog"]:
        for p in ["/feed", "/feed/", "/rss", "/rss.xml", "/atom.xml",
                  "/feeds/posts/default", "/index.xml", "/feed.xml",
                  "/blog/feed", "/news/rss", "/?feed=rss2", "/?feed=atom"]:
            variants.append(base + p)

    # 7. Try http:// instead of https:// (SSL workaround)
    if parsed.scheme == "https":
        variants.append(url.replace("https://", "http://", 1))

    # 8. Try with www. if not present
    if not parsed.netloc.startswith("www."):
        variants.append(url.replace(f"://{parsed.netloc}", f"://www.{parsed.netloc}", 1))

    # 9. Try without www. if present
    if parsed.netloc.startswith("www."):
        variants.append(url.replace("://www.", "://", 1))

    # Deduplicate
    seen = set()
    unique = []
    for v in variants:
        nv = normalize_url(v)
        if nv not in seen and nv != normalize_url(url):
            seen.add(nv)
            unique.append(v)

    return unique[:MAX_URL_VARIANTS]

# ============================================================
# RSS FEED DISCOVERY + SITE SCRAPING
# ============================================================

def discover_rss_feeds(html_text: str, base_url: str) -> List[str]:
    """Find RSS feed links in HTML <link> tags + try common paths."""
    feeds = []
    try:
        soup = BeautifulSoup(html_text, "html.parser")
        for link in soup.find_all("link", attrs={"rel": "alternate"}):
            link_type = link.get("type", "")
            href = link.get("href", "")
            if href and ("rss" in link_type or "atom" in link_type):
                if href.startswith("/"):
                    parsed = urlparse(base_url)
                    href = f"{parsed.scheme}://{parsed.netloc}{href}"
                elif not href.startswith("http"):
                    href = urljoin(base_url, href)
                feeds.append(href)
        # Also try <a> tags with "rss" or "feed" in href
        for a in soup.find_all("a", href=True):
            href = a.get("href", "")
            if "rss" in href.lower() or "feed" in href.lower() or "atom" in href.lower():
                if href.startswith("/"):
                    parsed = urlparse(base_url)
                    href = f"{parsed.scheme}://{parsed.netloc}{href}"
                elif not href.startswith("http"):
                    href = urljoin(base_url, href)
                if is_safe_url(href):
                    feeds.append(href)
        # Common RSS paths
        parsed = urlparse(base_url)
        b = f"{parsed.scheme}://{parsed.netloc}"
        for path in ["/feed", "/rss", "/rss.xml", "/atom.xml",
                      "/feeds/posts/default", "/index.xml", "/feed.xml",
                      "/blog/feed", "/news/rss", "/feed/", "/rss/"]:
            feeds.append(f"{b}{path}")
    except Exception:
        pass
    return feeds[:MAX_DISCOVERED_FEEDS]

def scrape_site_articles(html_text: str, base_url: str) -> List[Dict[str, Any]]:
    """Scrape article links from a website when no RSS is available."""
    entries = []
    try:
        soup = BeautifulSoup(html_text, "html.parser")
        seen_links: Set[str] = set()
        selectors = [
            "article h2 a", "article h3 a", "article h1 a", "article a[href]",
            ".post-title a", ".entry-title a", ".article-title a",
            "h2.title a", "h3.title a", ".post h2 a", ".post h3 a",
            ".entry h2 a", ".entry h3 a", ".blog-post h2 a", ".blog-post h3 a",
            ".news-item h3 a", ".news-item h2 a", ".card-title a",
            "main h2 a", "main h3 a", ".list-item a", ".item-title a",
            ".post-list a[href]", ".article-list a[href]",
        ]
        for selector in selectors:
            try:
                for link in soup.select(selector):
                    href = link.get("href", "")
                    title = clean_html(link.get_text(" ", strip=True))
                    if not href or not title or len(title) < 10:
                        continue
                    if href.startswith("/"):
                        parsed = urlparse(base_url)
                        href = f"{parsed.scheme}://{parsed.netloc}{href}"
                    elif not href.startswith("http"):
                        href = urljoin(base_url, href)
                    href = normalize_url(href)
                    if href in seen_links or not is_safe_url(href):
                        continue
                    skip = ["facebook.com", "twitter.com", "linkedin.com",
                            "instagram.com", "youtube.com", "#", "mailto:",
                            "javascript:", "tel:", "share", "comment"]
                    if any(p in href.lower() for p in skip):
                        continue
                    seen_links.add(href)
                    entries.append({
                        "title": title, "link": href, "summary": "",
                        "description": "", "id": href,
                        "published_parsed": None, "updated_parsed": None,
                    })
            except Exception:
                pass
        if not entries:
            for link in soup.find_all("a", href=True):
                href = link.get("href", "")
                title = clean_html(link.get_text(" ", strip=True))
                if not href or not title or len(title) < 20:
                    continue
                if not any(kw in href.lower() for kw in
                           ["/post/", "/article/", "/blog/", "/news/",
                            "/2020/", "/2021/", "/2022/", "/2023/",
                            "/2024/", "/2025/", "/p/", "/entry/"]):
                    continue
                if href.startswith("/"):
                    parsed = urlparse(base_url)
                    href = f"{parsed.scheme}://{parsed.netloc}{href}"
                elif not href.startswith("http"):
                    href = urljoin(base_url, href)
                href = normalize_url(href)
                if href in seen_links or not is_safe_url(href):
                    continue
                skip = ["facebook.com", "twitter.com", "linkedin.com",
                        "instagram.com", "youtube.com", "#", "mailto:"]
                if any(p in href.lower() for p in skip):
                    continue
                seen_links.add(href)
                entries.append({
                    "title": title, "link": href, "summary": "",
                    "description": "", "id": href,
                    "published_parsed": None, "updated_parsed": None,
                })
        if entries:
            logger.info("  [SCRAPE] Found %d articles from %s", len(entries), base_url)
    except Exception as e:
        logger.warning("Site scrape error: %s", e)
    return entries

# ============================================================
# FEED FETCH — با Smart URL Variants + RSS Discovery + Scraping
# ============================================================

ARTICLE_SELECTORS = [
    "article", "main", "[role='main']", ".article", ".article-content",
    ".post-content", ".entry-content", ".content", "#content",
]
STRIP_TAGS = ["script", "style", "noscript", "svg", "nav", "footer", "header", "form", "aside"]

# ✅ تلاش برای یک URL — fetch + parse + discovery + scrape
def try_fetch_feed_url(url: str) -> List[Any]:
    """Try to fetch and parse a feed URL with RSS discovery and scraping."""
    response = fetch_url(url, FEED_TIMEOUT)
    if not response:
        return []

    # مرحله 1: feedparser
    parsed = feedparser.parse(response.content)
    if parsed.entries:
        return parsed.entries[:POSTS_PER_FEED]

    # مرحله 2: RSS Discovery
    discovered = discover_rss_feeds(response.text, url)
    for rss_url in discovered:
        if normalize_url(rss_url) == normalize_url(url):
            continue
        rss_response = fetch_url(rss_url, FEED_TIMEOUT)
        if rss_response:
            rss_parsed = feedparser.parse(rss_response.content)
            if rss_parsed.entries:
                logger.info("  [DISCOVERY] ✅ Found RSS: %s (%d entries)", rss_url, len(rss_parsed.entries))
                return rss_parsed.entries[:POSTS_PER_FEED]

    # مرحله 3: Site Scraping
    scraped = scrape_site_articles(response.text, url)
    if scraped:
        return scraped[:POSTS_PER_FEED]

    return []

# ✅ fetch_single_feed — اصلی‌ترین تابع با Smart Variants
def fetch_single_feed(feed: Any) -> Tuple[List[Any], bool]:
    feed_url = feed.get("url") if isinstance(feed, dict) else getattr(feed, "url", None)
    if not feed_url or not is_safe_url(feed_url):
        return [], False
    try:
        # مرحله 1: URL اصلی
        entries = try_fetch_feed_url(feed_url)
        if entries:
            return entries, True

        # مرحله 2: URL Variants (اصلاح هوشمند)
        variants = generate_url_variants(feed_url)
        if variants:
            logger.info("  [FEED] Original failed, trying %d variants for %s", len(variants), feed_url)

        for variant_url in variants:
            entries = try_fetch_feed_url(variant_url)
            if entries:
                logger.info("  [FEED] ✅ Variant succeeded: %s", variant_url)
                return entries, True

        return [], False
    except Exception as e:
        logger.warning("Feed error %s: %s", feed_url, e)
        return [], False

def fetch_raw_html(url: str) -> Optional[str]:
    if not url or not is_safe_url(url):
        return None
    try:
        response = fetch_url(url, ARTICLE_TIMEOUT)
        if not response:
            return None
        return response.text
    except Exception as e:
        logger.warning("Article fetch error for %s: %s", url, e)
        return None

def extract_article_text(raw_html: Optional[str]) -> Optional[str]:
    if not raw_html:
        return None
    try:
        soup = BeautifulSoup(raw_html, "html.parser")
        for tag in soup(STRIP_TAGS):
            tag.decompose()
        candidates = []
        for selector in ARTICLE_SELECTORS:
            try:
                for node in soup.select(selector):
                    text = clean_html(node.get_text(" ", strip=True))
                    if len(text) > 300:
                        candidates.append(text)
            except Exception:
                pass
        if not candidates and soup.body:
            candidates.append(clean_html(soup.body.get_text(" ", strip=True)))
        if not candidates:
            return None
        text = max(candidates, key=len)
        if len(text) > 20000:
            text = text[:20000]
        if len(text) < 300:
            return None
        return text
    except Exception as e:
        logger.warning("Article parse error: %s", e)
        return None

# ============================================================
# SOURCE / WECHAT
# ============================================================

def detect_source(entry: Any) -> str:
    raw = " ".join([str(entry.get("title", "")), str(entry.get("summary", "")), str(entry.get("description", "")), str(entry.get("source", ""))])
    raw_lower = raw.lower()
    if "mp.weixin.qq.com" in raw_lower or "微信公众号" in raw or "微信" in raw or "wechat" in raw_lower:
        return "WeChat"
    return ""

def extract_original_link(fallback_url: str, *html_sources: Optional[str]) -> str:
    for source_html in html_sources:
        if not source_html:
            continue
        match = re.search(r'https?://mp\.weixin\.qq\.com/[^\s"<>]+', source_html, re.IGNORECASE)
        if match:
            return html.unescape(match.group(0)).rstrip(".,);]")
    return fallback_url

# ============================================================
# ENTRY ID & DATE
# ============================================================

def get_entry_id(entry: Any) -> Optional[str]:
    value = entry.get("id") or entry.get("guid") or entry.get("link")
    if value:
        return str(value).strip()
    title = clean_html(entry.get("title", ""))
    link = entry.get("link", "")
    raw = f"{title}|{link}"
    if raw != "|":
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return None

def is_recent(entry: Any, max_age_days: int = MAX_AGE_DAYS) -> bool:
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if not parsed:
        return True
    try:
        date = datetime(*parsed[:6], tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - date
        return -FUTURE_TOLERANCE <= age <= timedelta(days=max_age_days)
    except Exception:
        return True

def entry_sort_key(entry: Any) -> datetime:
    p = entry.get("published_parsed") or entry.get("updated_parsed")
    return datetime(*p[:6], tzinfo=timezone.utc) if p else datetime.min.replace(tzinfo=timezone.utc)

# ============================================================
# GROQ / GEMINI CALLS
# ============================================================

def call_groq(model_name: str, prompt: str, max_tokens: int = 700) -> str:
    if not groq_client:
        raise RuntimeError("Groq client unavailable")
    kwargs: Dict[str, Any] = {"max_tokens": max(max_tokens, 512)}
    if "gpt-oss" in model_name:
        kwargs["reasoning_effort"] = "low"
    response = groq_client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": "You are a senior cybersecurity and computer science analyst."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        **kwargs,
    )
    if not response or not response.choices:
        raise RuntimeError("Empty Groq response")
    content = response.choices[0].message.content
    if not content:
        raise RuntimeError("Empty Groq content")
    return content.strip()

def call_gemini(model_name: str, prompt: str, max_tokens: int = 700) -> str:
    if not gemini_client:
        raise RuntimeError("Gemini client unavailable")
    kwargs: Dict[str, Any] = {"max_output_tokens": max(max_tokens, 512)}
    if model_name.startswith("gemini-3"):
        kwargs["thinking_config"] = types.ThinkingConfig(thinking_level="low")
    else:
        kwargs["temperature"] = 0.2
    response = gemini_client.models.generate_content(
        model=model_name, contents=prompt,
        config=types.GenerateContentConfig(**kwargs),
    )
    text = getattr(response, "text", None)
    if not text:
        cand = (getattr(response, "candidates", None) or [None])[0]
        reason = getattr(cand, "finish_reason", "UNKNOWN")
        raise RuntimeError(f"Empty Gemini response (finish_reason={reason})")
    return text.strip()

def call_model(provider: str, model: str, prompt: str, max_tokens: int = 700) -> str:
    if provider == "groq":
        return call_groq(model, prompt, max_tokens)
    if provider == "gemini":
        return call_gemini(model, prompt, max_tokens)
    raise RuntimeError(f"Unknown provider: {provider}")

# ============================================================
# FILTER & ANALYSIS LOGIC (با Title Translation)
# ============================================================

def build_filter_prompt(title: str, summary: str, source: str = "") -> str:
    return f"""
تو وظیفه فیلتر کردن یک فید خبری تخصصی را داری.

حوزه‌های مورد علاقه کاربر:

{INTERESTS_PROMPT}

خبر:

TITLE:
{title}

SUMMARY:
{summary}

SOURCE:
{source}

فقط مشخص کن که خبر برای این کاربر ارزش پیگیری دارد یا نه.

RELEVANT: اگر ارتباط واقعی و معنادار با یکی از حوزه‌های بالا دارد.
REJECT: اگر عمومی، بی‌ربط، تبلیغاتی یا کم‌ارزش است.

فقط یکی از این دو کلمه را خروجی بده: RELEVANT یا REJECT
هیچ توضیح دیگری ننویس.
"""

def parse_filter_result(result: Optional[str]) -> Optional[bool]:
    if not result:
        return None
    text = re.sub(r"```", "", result).strip().upper()
    stripped = text.strip(" .!\n\t")
    if stripped == "RELEVANT":
        return True
    if stripped == "REJECT":
        return False
    match = re.search(r"\b(RELEVANT|REJECT)\b", text)
    if match:
        return match.group(1) == "RELEVANT"
    return None

def filter_article(title: str, summary: str, source: str) -> Optional[bool]:
    prompt = build_filter_prompt(title, summary, source)
    attempted_any = False
    for item in FILTER_MODELS:
        provider, model = item["provider"], item["model"]
        key = f"{provider}/{model}"
        if should_skip_model(key):
            continue
        attempted_any = True
        try:
            logger.info("  [FILTER] trying %s", key)
            result = call_model(provider, model, prompt, max_tokens=50)
            decision = parse_filter_result(result)
            if decision is None:
                raise RuntimeError(f"Invalid filter output: {result[:200]}")
            logger.info("  [FILTER] %s -> %s", key, "RELEVANT" if decision else "REJECT")
            return decision
        except Exception as e:
            logger.warning("  [FILTER ERROR] %s: %s", key, e)
            mark_model_error(key, str(e))
            continue
    if not attempted_any:
        raise NoModelsAvailable("No models available for filtering")
    return None

# ✅ Analysis Prompt با Title Translation
def build_analysis_prompt(title: str, article_text: str, link: str, source: str) -> str:
    if len(article_text) > 18000:
        article_text = article_text[:18000]
    return f"""
تو یک تحلیلگر ارشد امنیت سایبری، Reverse Engineering، Windows Internals، Computer Science و فناوری هستی.

مطلب زیر قبلاً توسط فیلتر تایید شده است.

وظایف:

۱. ابتدا عنوان این مطلب را به فارسی ترجمه کن.
   - لغات تخصصی امنیتی و کامپیوتری (مانند EDR, APT, CVE, RCE, XSS, Buffer Overflow, Use-After-Free, Kernel, UEFI, Rootkit, PatchGuard, PPL, VBS, AMSI) را به انگلیسی نگه دار.
   - نام‌های خاص (مانند Black Hat, DEF CON, Windows, Linux, Google, Microsoft, Intel, AMD) را به انگلیسی نگه دار.
   - برای اصطلاحات عمومی معادل فارسی استفاده کن.

۲. سپس تحلیل ۱۰ تا ۱۵ خطی فارسی بنویس.

فرمت دقیق خروجی:

TITLE_FA: [عنوان ترجمه‌شده به فارسی]

---

[تحلیل فارسی]

در تحلیل این موارد را پوشش بده:
- موضوع اصلی مطلب
- مسئله‌ای که نویسنده بررسی کرده
- یافته یا ادعای اصلی
- نکات فنی مهم
- تکنیک یا روش مورد استفاده
- اگر مربوط به حمله است: مهاجم، هدف و تکنیک
- اگر مربوط به آسیب‌پذیری است: علت فنی و impact
- اگر مقاله پژوهشی است: contribution اصلی
- تفاوت یا اهمیت آن نسبت به وضعیت قبلی
- نتیجه‌ای که از مطلب می‌توان گرفت
- چرا برای کاربر ارزش خواندن دارد

قوانین مهم:
1. چیزی را که در متن نیست اختراع نکن.
2. اطلاعات عمومی خودت را به جای محتوای مقاله قرار نده.
3. اگر متن ناقص است، صریحاً بگو.
4. عنوان انگلیسی را دوباره کپی نکن — فقط نسخه‌ی ترجمه‌شده بده.
5. از bulletهای خیلی کوتاه استفاده نکن؛ متن باید خوانا و تحلیلی باشد.
6. خروجی فقط فارسی باشد (به جز لغات تخصصی انگلیسی).
7. حدود ۱۰ تا ۱۵ خط بنویس.

TITLE:
{title}

SOURCE:
{source}

URL:
{link}

ARTICLE:
{article_text}
"""

# ✅ استخراج عنوان ترجمه‌شده و تحلیل از پاسخ AI
def parse_analysis_response(response: str) -> Tuple[str, str]:
    """Extract translated title and analysis from AI response."""
    title_fa = ""
    analysis = response.strip()

    # تلاش برای استخراج TITLE_FA
    match = re.search(r'TITLE_FA:\s*(.+?)(?:\n---|\n\n|\nANALYSIS:)', response, re.DOTALL | re.IGNORECASE)
    if match:
        title_fa = match.group(1).strip()
        remaining = response[match.end():].strip()
        # حذف جداکننده‌های ابتدایی
        analysis = re.sub(r'^[-=*\s\n]+', '', remaining).strip()
        # حذف "ANALYSIS:" اگر وجود داشت
        analysis = re.sub(r'^ANALYSIS:\s*', '', analysis, flags=re.IGNORECASE).strip()
    else:
        # اگر فرمت رعایت نشد، خط اول را title فرض کن
        lines = response.strip().split('\n')
        if lines and not lines[0].startswith('TITLE_FA'):
            # کل response را به‌عنوان analysis بگذار
            pass

    return title_fa, analysis

# ✅ deep_analyze حالا (title_fa, analysis) برمی‌گرداند
def deep_analyze(title: str, article_text: str, link: str, source: str) -> Optional[Tuple[str, str]]:
    """Returns (title_fa, analysis) or None."""
    prompt = build_analysis_prompt(title, article_text, link, source)
    attempted_any = False
    for item in ANALYSIS_MODELS:
        provider, model = item["provider"], item["model"]
        key = f"{provider}/{model}"
        if should_skip_model(key):
            continue
        attempted_any = True
        try:
            logger.info("  [ANALYSIS] trying %s", key)
            result = call_model(provider, model, prompt, max_tokens=1500)
            if not result:
                raise RuntimeError("Empty analysis")

            # ✅ استخراج title_fa و analysis
            title_fa, analysis = parse_analysis_response(result)
            if not analysis:
                analysis = result  # fallback: کل response را analysis بگذار

            logger.info("  [ANALYSIS] success: %s | title_fa: %s", key, title_fa[:60] if title_fa else "(none)")
            return (title_fa, analysis)
        except Exception as e:
            logger.warning("  [ANALYSIS ERROR] %s: %s", key, e)
            mark_model_error(key, str(e))
            continue
    if not attempted_any:
        raise NoModelsAvailable("No models available for deep analysis")
    return None

# ============================================================
# PROCESS ENTRY (با Title Translation)
# ============================================================

def process_entry(entry: Any, index: int, total: int) -> Dict[str, str]:
    title = clean_html(entry.get("title", ""))
    raw_summary_html = entry.get("summary") or entry.get("description") or ""
    rss_summary = clean_html(raw_summary_html)
    link = entry.get("link", "")

    logger.info("=" * 70)
    logger.info("[%d/%d] %s", index, total, title[:100])
    logger.info("URL: %s", link)

    source = detect_source(entry)
    raw_html = None
    article_text = None

    if is_safe_url(link):
        logger.info("  [ARTICLE] Fetching full article...")
        raw_html = fetch_raw_html(link)
        article_text = extract_article_text(raw_html)

    if article_text:
        content_for_filter = article_text[:6000]
        logger.info("  [ARTICLE] Full text: %d chars", len(article_text))
    else:
        content_for_filter = rss_summary[:5000]
        logger.info("  [ARTICLE] Using RSS summary.")

    is_wechat = bool(
        source or "weixin" in str(link).lower() or "wechat" in str(link).lower()
        or "微信" in title or "微信" in content_for_filter
    )
    if is_wechat:
        source = source or "WeChat"
        original_link = extract_original_link(link, raw_html, raw_summary_html)
        if original_link and original_link != link and is_safe_url(original_link):
            logger.info("  [SOURCE] Recovered original WeChat link.")
            link = original_link

    decision = filter_article(title, content_for_filter, source)
    if decision is None:
        logger.info("  [RESULT] FILTER FAILED")
        return {"status": "retry"}
    if decision is False:
        logger.info("  [RESULT] REJECT")
        return {"status": "rejected"}

    logger.info("  [RESULT] RELEVANT")
    if not article_text:
        article_text = rss_summary
    if not article_text:
        logger.info("  [RESULT] No article text available.")
        return {"status": "retry"}

    # ✅ deep_analyze حالا (title_fa, analysis) برمی‌گرداند
    result = deep_analyze(title, article_text, link, source)
    if not result:
        logger.info("  [RESULT] DEEP ANALYSIS FAILED")
        return {"status": "retry"}

    title_fa, analysis = result

    # ✅ اگر ترجمه‌ی عنوان موفق نبود، عنوان اصلی را استفاده کن
    final_title = title_fa if title_fa else title

    success = send_telegram(title=final_title, analysis=analysis, link=link, category="اخبار منتخب", source=source)
    if not success:
        logger.info("  [RESULT] Telegram failed.")
        return {"status": "retry"}
    return {"status": "sent"}

# ============================================================
# MAIN
# ============================================================

def main() -> None:
    start = time.time()
    logger.info("=" * 70)
    logger.info("RSS SECURITY NEWS BOT (ULTIMATE EDITION)")
    logger.info("=" * 70)
    logger.info("Filter models: %s", [m["model"] for m in FILTER_MODELS])
    logger.info("Analysis models: %s", [m["model"] for m in ANALYSIS_MODELS])
    logger.info("BOT_TOKEN: %s", "OK" if BOT_TOKEN else "MISSING")
    logger.info("CHAT_ID: %s", "OK" if CHAT_ID else "MISSING")
    logger.info("GEMINI_API_KEY: %s", "OK" if GEMINI_API_KEY else "MISSING")
    logger.info("GROQ_API_KEY: %s", "OK" if GROQ_API_KEY else "MISSING")

    if not gemini_client and not groq_client:
        msg = "No AI provider configured."
        logger.error(msg)
        send_status_message(f"❌ {msg}")
        return

    if not os.path.exists(OPML_FILE):
        logger.error("feeds.opml not found.")
        send_status_message("❌ feeds.opml پیدا نشد.")
        return

    try:
        with open(OPML_FILE, "r", encoding="utf-8") as f:
            opml = f.read()
        parsed = listparser.parse(opml)
    except Exception as e:
        logger.error("OPML error: %s", e)
        return

    feeds = parsed.feeds
    logger.info("Feeds loaded: %d", len(feeds))

    seen_ids, retry_counts, seen_urls, seen_titles = load_state()
    logger.info("Previously seen: %d IDs | %d URLs | %d titles | Pending retries: %d",
                len(seen_ids), len(seen_urls), len(seen_titles), len(retry_counts))

    all_entries: List[Any] = []
    successful_feeds = 0
    failed_urls: List[str] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_single_feed, feed): feed for feed in feeds}
        for future in as_completed(futures):
            try:
                entries, success = future.result()
                feed_url = futures[future].get("url") if isinstance(futures[future], dict) else getattr(futures[future], "url", None)
                if success:
                    successful_feeds += 1
                    all_entries.extend(entries)
                else:
                    if feed_url:
                        failed_urls.append(feed_url)
            except Exception as e:
                logger.error("Feed worker error: %s", e)

    logger.info("Successful feeds: %d/%d", successful_feeds, len(feeds))
    logger.info("Downloaded entries: %d", len(all_entries))

    # ✅ Triple Dedup
    candidates: List[Tuple[str, Any]] = []
    current_ids: Set[str] = set()
    current_urls: Set[str] = set()
    current_titles: Set[str] = set()
    skipped_seen = skipped_old = skipped_duplicate = 0

    for entry in all_entries:
        entry_id = get_entry_id(entry)
        if not entry_id:
            continue
        if entry_id in seen_ids:
            skipped_seen += 1
            continue
        if entry_id in current_ids:
            skipped_duplicate += 1
            continue

        link = entry.get("link", "")
        norm_link = normalize_url(link) if link else ""
        if norm_link:
            if norm_link in seen_urls or norm_link in current_urls:
                skipped_duplicate += 1
                continue
            current_urls.add(norm_link)

        title = clean_html(entry.get("title", ""))
        title_hash = hashlib.sha256(title.lower().strip().encode("utf-8")).hexdigest() if title else ""
        if title_hash:
            if title_hash in seen_titles or title_hash in current_titles:
                skipped_duplicate += 1
                continue
            current_titles.add(title_hash)

        if not is_recent(entry):
            skipped_old += 1
            seen_ids.add(entry_id)
            retry_counts.pop(entry_id, None)
            continue

        current_ids.add(entry_id)
        candidates.append((entry_id, entry))

    logger.info("Candidates before cap: %d", len(candidates))
    logger.info("Seen: %d | Old: %d | Duplicates: %d", skipped_seen, skipped_old, skipped_duplicate)

    failed_str = "\n".join(failed_urls) if failed_urls else "None"
    status_msg = (
        f"📥 *RSS دریافت شد*\n\n"
        f"▫️ فیدهای موفق: {successful_feeds}/{len(feeds)}\n"
        f"▫️ مطالب جدید: {len(candidates)}\n"
        f"▫️ قدیمی: {skipped_old}\n"
        f"▫️ تکراری: {skipped_seen + skipped_duplicate}\n\n"
        f"❌ *فیدهای ناموفق:*\n{failed_str}"
    )
    send_status_message(status_msg)

    candidates.sort(key=lambda pair: entry_sort_key(pair[1]), reverse=True)
    deferred = candidates[MAX_ENTRIES_PER_RUN:]
    candidates = candidates[:MAX_ENTRIES_PER_RUN]

    sent = rejected = failed = 0
    successfully_processed: Set[str] = set()
    new_urls: Set[str] = set()
    new_titles: Set[str] = set()
    total = len(candidates)

    for index, (entry_id, entry) in enumerate(candidates, start=1):
        try:
            result = process_entry(entry, index, total)
            status = result.get("status")
            if status in ("sent", "rejected"):
                if status == "sent":
                    sent += 1
                else:
                    rejected += 1
                successfully_processed.add(entry_id)
                retry_counts.pop(entry_id, None)
                link = entry.get("link", "")
                norm_link = normalize_url(link) if link else ""
                if norm_link:
                    new_urls.add(norm_link)
                title = clean_html(entry.get("title", ""))
                title_hash = hashlib.sha256(title.lower().strip().encode("utf-8")).hexdigest() if title else ""
                if title_hash:
                    new_titles.add(title_hash)
            else:
                failed += 1
                count = retry_counts.get(entry_id, 0) + 1
                if count >= MAX_RETRIES:
                    logger.warning("Giving up after %d retries: %s", count, entry_id)
                    successfully_processed.add(entry_id)
                    retry_counts.pop(entry_id, None)
                else:
                    retry_counts[entry_id] = count
        except NoModelsAvailable:
            logger.error("All providers unavailable — aborting run, state preserved.")
            break
        except Exception as e:
            logger.error("[FATAL ENTRY ERROR] %s", e)
            failed += 1
            successfully_processed.add(entry_id)
            retry_counts.pop(entry_id, None)

        if index % 10 == 0:
            seen_ids.update(successfully_processed)
            seen_urls.update(new_urls)
            seen_titles.update(new_titles)
            save_state(seen_ids, retry_counts, seen_urls, seen_titles)

        time.sleep(GEMINI_DELAY)

    seen_ids.update(successfully_processed)
    seen_urls.update(new_urls)
    seen_titles.update(new_titles)
    save_state(seen_ids, retry_counts, seen_urls, seen_titles)

    cooling = [key for key in model_error_state if should_skip_model(key)]
    elapsed = round(time.time() - start, 1)

    logger.info("=" * 70)
    logger.info("Finished in %ss", elapsed)
    logger.info("Sent: %d | Rejected: %d | Failed/retry: %d", sent, rejected, failed)
    logger.info("Deferred for next run: %d", len(deferred))
    logger.info("Cooldown models: %d", len(cooling))
    logger.info("Total seen: %d IDs | %d URLs | %d titles", len(seen_ids), len(seen_urls), len(seen_titles))
    logger.info("=" * 70)

    finish_msg = (
        f"✅ *اجرای ربات تمام شد*\n\n"
        f"▫️ زمان: {elapsed} ثانیه\n"
        f"▫️ بررسی‌شده: {total}\n"
        f"▫️ ارسال‌شده: {sent}\n"
        f"▫️ ردشده: {rejected}\n"
        f"▫️ ناموفق/برای retry: {failed}\n"
        f"▫️ مدل‌های cooldown: {len(cooling)}"
    )
    send_status_message(finish_msg)

# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Interrupted.")
    except Exception as e:
        logger.exception("FATAL: %s", e)
        send_status_message("❌ خطای Fatal در ربات:\n" + str(e)[:500])
        raise
