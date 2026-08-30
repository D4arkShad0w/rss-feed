"""
RSS Security News Bot
======================

Fetches feeds from an OPML file, filters entries against a set of interest
categories using a cascade of LLMs (Groq -> Gemini, weak -> strong), runs a
deep analysis pass on anything relevant, and posts the result to Telegram.

Changes vs. the previous version (see PR/diff for details):
  - Telegram messages now use HTML parse mode instead of Markdown. Markdown
    broke (and silently failed to send) whenever a title/analysis/URL
    contained characters like `)`, `[`, `*`, etc. HTML only needs `&`, `<`,
    `>` escaped, which is trivial to get right.
  - `extract_original_link` (WeChat original-link recovery) was dead code:
    it was never called, and even if it had been, it was being fed
    *cleaned* text with all HTML tags (and therefore all hrefs) stripped.
    It's now wired in and given real raw HTML to search.
  - `parse_filter_result` now checks for an exact "RELEVANT"/"REJECT"
    response first, only falling back to substring search if the model
    didn't follow instructions exactly.
  - Entries that fail repeatedly (bad page, model can't parse it, etc.) are
    now capped at MAX_RETRIES attempts instead of retrying forever.
  - If neither GROQ_API_KEY nor GEMINI_API_KEY is configured, the bot now
    fails fast with a clear message instead of silently "retrying" every
    candidate all the way through the run.
  - Future-dated / clock-skewed entries are no longer permanently
    blacklisted by a single bad timestamp.
  - HTTP calls go through a shared `requests.Session` with retry/backoff,
    and article URLs are checked to be http(s) before being fetched.
  - `print()` calls replaced with the `logging` module.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import feedparser
import listparser
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from google import genai
from google.genai import types

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False


# ============================================================
# LOGGING
# ============================================================

logging_format = "%(asctime)s [%(levelname)s] %(message)s"
import logging  # noqa: E402  (kept near other stdlib imports intentionally)

logging.basicConfig(level=logging.INFO, format=logging_format, datefmt="%H:%M:%S")
logger = logging.getLogger("rss_security_bot")


# ============================================================
# CONFIG
# ============================================================

BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY") or os.getenv("GROQ_API")

OPML_FILE = "feeds.opml"
STATE_FILE = "seen_ids.json"

MAX_WORKERS = 20
POSTS_PER_FEED = int(os.getenv("POSTS_PER_FEED", "50"))

MAX_AGE_DAYS = int(os.getenv("MAX_AGE_DAYS", "7"))
FUTURE_TOLERANCE = timedelta(hours=6)  # forgive minor feed clock-skew

MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))

FEED_TIMEOUT = 15
ARTICLE_TIMEOUT = 20
TELEGRAM_TIMEOUT = 10

GEMINI_DELAY = 0.3
MODEL_COOLDOWN_SECONDS = 1800

TELEGRAM_MAX_LEN = 4096

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
)


# ============================================================
# MODEL CONFIGURATION
# ============================================================

# weak -> strong. The next model is used ONLY when the previous model
# raises/fails. A normal RELEVANT / REJECT response never triggers fallback.

FILTER_MODELS = [
    {"provider": "groq", "model": "llama-3.1-8b-instant"},
    {"provider": "groq", "model": "openai/gpt-oss-20b"},
    {"provider": "groq", "model": "llama-3.3-70b-versatile"},
    {"provider": "groq", "model": "openai/gpt-oss-120b"},
    {"provider": "gemini", "model": "gemini-2.5-flash-lite"},
    {"provider": "gemini", "model": "gemini-2.5-flash"},
    {"provider": "gemini", "model": "gemini-2.5-pro"},
]

# 8B is intentionally NOT used here; deep analysis starts from GPT-OSS 20B.
ANALYSIS_MODELS = [
    {"provider": "groq", "model": "openai/gpt-oss-20b"},
    {"provider": "groq", "model": "llama-3.3-70b-versatile"},
    {"provider": "groq", "model": "openai/gpt-oss-120b"},
    {"provider": "gemini", "model": "gemini-2.5-flash-lite"},
    {"provider": "gemini", "model": "gemini-2.5-flash"},
    {"provider": "gemini", "model": "gemini-2.5-pro"},
]


# ============================================================
# MODEL COOLDOWN
# ============================================================

model_error_times: Dict[str, float] = {}


def should_skip_model(model_key: str) -> bool:
    last_error = model_error_times.get(model_key)
    if last_error is None:
        return False
    return (time.time() - last_error) < MODEL_COOLDOWN_SECONDS


def mark_model_error(model_key: str, reason: str = "") -> None:
    model_error_times[model_key] = time.time()
    logger.warning(
        "[COOLDOWN] %s for %d min%s",
        model_key,
        MODEL_COOLDOWN_SECONDS // 60,
        f" — {reason[:300]}" if reason else "",
    )


# ============================================================
# INTERESTS
# ============================================================

INTEREST_CATEGORIES: Dict[str, List[str]] = {
    "LOW-LEVEL SECURITY": [
        "Exploit Development", "Memory Corruption", "Use-After-Free",
        "Heap Exploitation", "Kernel Exploitation", "Privilege Escalation",
        "Sandbox Escape", "Mitigation Bypass", "PatchGuard Bypass",
        "Windows Defender / EDR Bypass", "0-day/1-day با تحلیل فنی",
    ],
    "WINDOWS INTERNALS": [
        "Windows Internals", "Windows Kernel Security", "Driver Security",
        "Code Integrity", "PatchGuard", "PPL", "VBS", "Credential Guard",
        "ETW Security", "Security Mitigations",
    ],
    "EDR / ENDPOINT": [
        "EDR Evasion", "EDR Bypass", "Detection Engineering",
        "Telemetry Evasion", "AMSI Bypass", "Security Product Internals",
    ],
    "REVERSE ENGINEERING": [
        "Reverse Engineering", "Binary Analysis",
        "Malware Reverse Engineering", "Static/Dynamic Analysis",
        "Binary Instrumentation",
    ],
    "FUZZING": [
        "Fuzzing", "Kernel Fuzzing", "Coverage-Guided Fuzzing",
        "Hybrid Fuzzing", "Automated Vulnerability Discovery",
    ],
    "ROOTKIT / FIRMWARE": [
        "Rootkit", "Bootkit", "UEFI Security", "Firmware Security",
        "Secure Boot", "Hardware Root of Trust",
    ],
    "MALWARE / ATTACK TECHNIQUES": [
        "Advanced Malware Analysis", "Malware Techniques",
        "Persistence Techniques", "Defense Evasion",
        "Living-off-the-Land",
    ],
    "OS / LOW-LEVEL CS": [
        "Operating Systems Internals", "Computer Architecture",
        "Compiler Internals", "ELF/PE Internals", "Kernel Design",
    ],
    "NETWORK / PROTOCOL SECURITY": [
        "Protocol Security", "Network Exploitation", "DNS Security",
        "SMB Security", "Authentication Protocol Security",
    ],
    "ADVANCED CS": [
        "Computer Science Research", "Systems Research",
        "Programming Languages", "Computer Architecture",
        "Unusual CS Projects",
    ],
    "MATHEMATICS": [
        "Pure Mathematics", "Applied Mathematics", "Number Theory",
        "Algebra", "Analysis", "Topology", "Geometry",
        "Discrete Mathematics", "Combinatorics", "Mathematical Logic",
        "Category Theory", "Graph Theory", "Mathematical Physics",
        "Dynamical Systems", "Mathematical Proofs",
        "Famous Mathematical Problems", "New Mathematical Discoveries",
    ],
    "AI & MATHEMATICS": [
        "Mathematical Foundations of AI",
        "Mathematical Foundations of Machine Learning", "Learning Theory",
        "Optimization Theory", "Probability and Statistics for AI",
        "Information Theory", "Linear Algebra for AI",
        "Algebraic Geometry in ML", "Topological Data Analysis",
        "Geometric Deep Learning", "Mathematical AI Research",
        "Theoretical Computer Science and AI",
    ],
    "AI SKEPTICISM / REALISM": [
        "AI Limitations", "LLM Limitations", "AI Hype Criticism",
        "AI Reality Check", "Skepticism about AGI", "AI Bubble Analysis",
        "Critical AI Analysis", "AI Overclaiming",
        "AI Evaluation Challenges", "AI Benchmark Limitations",
        "Empirical AI Analysis", "AI Scaling Laws Debate",
        "Rational AI Discourse",
    ],
    "SECURITY CONFERENCES": [
        "Black Hat", "DEF CON", "USENIX Security", "NDSS", "IEEE S&P",
        "Pwn2Own", "Security Conference Research",
    ],
    "THREAT INTEL / APT": [
        "APT", "Cyber Espionage", "State-Sponsored Cyber Operations",
        "Cyber Warfare", "APT Campaign Analysis", "TTP Analysis",
    ],
    "IRAN": [
        "امنیت سایبری ایران", "حملات سایبری مرتبط با ایران",
        "گروه‌های تهدید ایرانی", "زیرساخت‌های حیاتی ایران",
        "تحریم‌های فناوری علیه ایران", "تحولات راهبردی ایران",
    ],
    "CHINA": [
        "China Cyber Operations", "Chinese APT Groups",
        "China Semiconductor", "US-China Tech Competition",
        "China AI Strategy",
    ],
    "MIDDLE EAST / ISRAEL": [
        "Middle East Cybersecurity", "Israel Cyber Operations",
        "Iran-Israel Cyber Conflict", "Regional Strategic Security",
    ],
    "US NATIONAL SECURITY": [
        "US Cybersecurity Policy", "CISA", "Technology Export Controls",
        "Semiconductor Sanctions", "AI Regulation",
    ],
    "STRATEGIC TECH": [
        "Semiconductor Industry", "Chip Design/Manufacturing",
        "AI Hardware", "GPU Architecture",
        "Geopolitical Technology Competition",
    ],
    "CYBERSECURITY INDUSTRY": [
        "Cybersecurity Startups", "EDR/XDR Products",
        "Security Research Companies", "Vulnerability Research Companies",
        "Security Funding",
    ],
    "DEEP TECHNICAL CONTENT": [
        "Technical Deep Dive", "Post-Mortem Attacks",
        "Root Cause Analysis", "Unusual Security Techniques",
        "Creative Systems Projects",
    ],
}


def build_interests_prompt() -> str:
    return "\n".join(
        f"{category}: {', '.join(interests)}"
        for category, interests in INTEREST_CATEGORIES.items()
    )


INTERESTS_PROMPT = build_interests_prompt()


# ============================================================
# HTTP SESSION
# ============================================================

def build_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    retry = Retry(
        total=2,
        connect=2,
        read=2,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "POST"]),
    )
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
        logger.info("Groq initialized.")
    except Exception as e:
        logger.error("Groq init failed: %s", e)
else:
    logger.warning("GROQ_API_KEY missing or groq package not installed.")


# ============================================================
# STATE
# ============================================================
# State file format: {"seen": [ids...], "retries": {id: count}}
# Older files (a bare JSON list of ids) are still read correctly.

def load_state() -> Tuple[Set[str], Dict[str, int]]:
    if not os.path.exists(STATE_FILE):
        return set(), {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return set(data), {}
        if isinstance(data, dict):
            return set(data.get("seen", [])), dict(data.get("retries", {}))
    except Exception as e:
        logger.error("State load error: %s", e)
    return set(), {}


def save_state(seen_ids: Set[str], retry_counts: Dict[str, int]) -> None:
    try:
        temp = STATE_FILE + ".tmp"
        payload = {"seen": sorted(seen_ids), "retries": retry_counts}
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
    """Escape text for Telegram HTML parse mode (only &, <, > matter)."""
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
        logger.error(
            "Telegram error: %s %s", response.status_code, response.text[:500]
        )
    except Exception as e:
        logger.error("Telegram exception: %s", e)
    return False


def send_status_message(text: str) -> bool:
    payload = {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "Markdown",
        "disable_notification": True,
    }
    return _post_telegram(payload)


def send_telegram(
    title: str,
    analysis: str,
    link: str,
    category: str,
    source: str = "",
) -> bool:
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
        return (
            f"📌 <b>[{category_e}]</b>\n\n"
            f"🔹 <b>{title_e}</b>\n\n"
            f"{source_line}"
            f"{analysis_text}\n\n"
            f'🔗 <a href="{link_e}">مطالعه مطلب اصلی</a>'
        )

    text = build(analysis_e)
    if len(text) > TELEGRAM_MAX_LEN:
        overflow = len(text) - TELEGRAM_MAX_LEN + 20
        trimmed = analysis_e[: max(0, len(analysis_e) - overflow)] + "…"
        text = build(trimmed)

    payload = {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": False,
    }

    ok = _post_telegram(payload)
    if ok:
        logger.info("Telegram message sent.")
    return ok


# ============================================================
# FEED FETCH
# ============================================================

def fetch_single_feed(feed: Any) -> List[Any]:
    feed_url = feed.get("url") if isinstance(feed, dict) else getattr(feed, "url", None)
    if not feed_url or not is_safe_url(feed_url):
        return []
    try:
        response = HTTP.get(feed_url, timeout=FEED_TIMEOUT)
        if response.status_code != 200:
            logger.info("Feed HTTP %s: %s", response.status_code, feed_url)
            return []
        parsed = feedparser.parse(response.content)
        return parsed.entries[:POSTS_PER_FEED]
    except Exception as e:
        logger.warning("Feed error %s: %s", feed_url, e)
        return []


# ============================================================
# ARTICLE FETCHING
# ============================================================

ARTICLE_SELECTORS = [
    "article", "main", "[role='main']", ".article", ".article-content",
    ".post-content", ".entry-content", ".content", "#content",
]

STRIP_TAGS = ["script", "style", "noscript", "svg", "nav", "footer", "header", "form", "aside"]


def fetch_raw_html(url: str) -> Optional[str]:
    if not url or not is_safe_url(url):
        return None
    try:
        response = HTTP.get(url, timeout=ARTICLE_TIMEOUT, allow_redirects=True)
        if response.status_code != 200:
            logger.info("Article HTTP %s: %s", response.status_code, url)
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
# SOURCE / WECHAT LINK EXTRACTION
# ============================================================

def detect_source(entry: Any) -> str:
    raw = " ".join([
        str(entry.get("title", "")),
        str(entry.get("summary", "")),
        str(entry.get("description", "")),
        str(entry.get("source", "")),
    ])
    raw_lower = raw.lower()
    if (
        "mp.weixin.qq.com" in raw_lower
        or "微信公众号" in raw
        or "微信" in raw
        or "wechat" in raw_lower
    ):
        return "WeChat"
    return ""


def extract_original_link(fallback_url: str, *html_sources: Optional[str]) -> str:
    """Search raw HTML (article page and/or RSS summary HTML) for a direct
    mp.weixin.qq.com link. Falls back to fallback_url if none is found."""
    for source_html in html_sources:
        if not source_html:
            continue
        match = re.search(
            r'https?://mp\.weixin\.qq\.com/[^\s"<>]+', source_html, re.IGNORECASE
        )
        if match:
            return html.unescape(match.group(0)).rstrip(".,);]")
    return fallback_url


# ============================================================
# ENTRY ID
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


# ============================================================
# DATE
# ============================================================

def is_recent(entry: Any, max_age_days: int = MAX_AGE_DAYS) -> bool:
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if not parsed:
        return True
    try:
        date = datetime(*parsed[:6], tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - date
        # Allow a little slack for future-dated / clock-skewed entries
        # instead of permanently blacklisting them on a bad timestamp.
        return -FUTURE_TOLERANCE <= age <= timedelta(days=max_age_days)
    except Exception:
        return True


# ============================================================
# GROQ / GEMINI CALLS
# ============================================================

def call_groq(model_name: str, prompt: str, max_tokens: int = 700) -> str:
    if not groq_client:
        raise RuntimeError("Groq client unavailable")

    response = groq_client.chat.completions.create(
        model=model_name,
        messages=[
            {
                "role": "system",
                "content": "You are a senior cybersecurity and computer science analyst.",
            },
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        max_tokens=max_tokens,
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

    response = gemini_client.models.generate_content(
        model=model_name,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.2, max_output_tokens=max_tokens
        ),
    )

    text = getattr(response, "text", None)
    if not text:
        raise RuntimeError("Empty Gemini response")

    return text.strip()


def call_model(provider: str, model: str, prompt: str, max_tokens: int = 700) -> str:
    if provider == "groq":
        return call_groq(model, prompt, max_tokens)
    if provider == "gemini":
        return call_gemini(model, prompt, max_tokens)
    raise RuntimeError(f"Unknown provider: {provider}")


# ============================================================
# FILTER PROMPT / PARSER
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

RELEVANT:
اگر ارتباط واقعی و معنادار با یکی از حوزه‌های بالا دارد.

REJECT:
اگر عمومی، بی‌ربط، تبلیغاتی یا کم‌ارزش است.

فقط یکی از این دو کلمه را خروجی بده:

RELEVANT

یا

REJECT

هیچ توضیح دیگری ننویس.
"""


def parse_filter_result(result: Optional[str]) -> Optional[bool]:
    if not result:
        return None

    text = re.sub(r"```", "", result).strip().upper()

    # Prefer an exact match on the whole trimmed response — this is what
    # the prompt asks for and avoids substring false-positives (e.g. a
    # stray "NOT RELEVANT" still containing the word "RELEVANT").
    stripped = text.strip(" .!\n\t")
    if stripped == "RELEVANT":
        return True
    if stripped == "REJECT":
        return False

    # Fallback for models that didn't follow instructions exactly.
    match = re.search(r"\b(RELEVANT|REJECT)\b", text)
    if match:
        return match.group(1) == "RELEVANT"

    return None


def filter_article(title: str, summary: str, source: str) -> Optional[bool]:
    prompt = build_filter_prompt(title, summary, source)

    for item in FILTER_MODELS:
        provider, model = item["provider"], item["model"]
        key = f"{provider}/{model}"

        if should_skip_model(key):
            logger.info("  [FILTER] skip cooldown: %s", key)
            continue

        try:
            logger.info("  [FILTER] trying %s", key)
            result = call_model(provider, model, prompt, max_tokens=50)
            decision = parse_filter_result(result)

            if decision is None:
                raise RuntimeError(f"Invalid filter output: {result[:200]}")

            logger.info(
                "  [FILTER] %s -> %s", key, "RELEVANT" if decision else "REJECT"
            )
            return decision

        except Exception as e:
            logger.warning("  [FILTER ERROR] %s: %s", key, e)
            mark_model_error(key, str(e))
            continue

    logger.error("  [FILTER] All models failed.")
    # If filtering itself fails, don't silently reject the article —
    # signal "unknown" so the caller can retry it next run.
    return None


# ============================================================
# DEEP ANALYSIS PROMPT
# ============================================================

def build_analysis_prompt(title: str, article_text: str, link: str, source: str) -> str:
    if len(article_text) > 18000:
        article_text = article_text[:18000]

    return f"""
تو یک تحلیلگر ارشد امنیت سایبری، Reverse Engineering، Windows Internals،
Computer Science و فناوری هستی.

مطلب زیر قبلاً توسط فیلتر تایید شده است.

وظیفه:

به زبان فارسی توضیح بده که این مطلب دقیقاً درباره چیست و چه نکات مهمی دارد.

خروجی باید حدود 10 تا 15 خط باشد.

در تحلیل، تا جایی که متن اجازه می‌دهد، این موارد را پوشش بده:

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

قوانین بسیار مهم:

1. چیزی را که در متن نیست اختراع نکن.
2. اطلاعات عمومی خودت را به جای محتوای مقاله قرار نده.
3. اگر متن ناقص است، صریحاً بگو.
4. اگر یک بخش استنباطی است، آن را به عنوان استنباط بیان کن.
5. عنوان را دوباره کپی نکن.
6. از bulletهای خیلی کوتاه استفاده نکن؛ متن باید خوانا و تحلیلی باشد.
7. خروجی فقط تحلیل فارسی باشد.
8. حدود 10 تا 15 خط بنویس.

TITLE:
{title}

SOURCE:
{source}

URL:
{link}

ARTICLE:
{article_text}
"""


def deep_analyze(title: str, article_text: str, link: str, source: str) -> Optional[str]:
    prompt = build_analysis_prompt(title, article_text, link, source)

    for item in ANALYSIS_MODELS:
        provider, model = item["provider"], item["model"]
        key = f"{provider}/{model}"

        if should_skip_model(key):
            logger.info("  [ANALYSIS] skip cooldown: %s", key)
            continue

        try:
            logger.info("  [ANALYSIS] trying %s", key)
            result = call_model(provider, model, prompt, max_tokens=1200)
            if not result:
                raise RuntimeError("Empty analysis")

            logger.info("  [ANALYSIS] success: %s", key)
            return result

        except Exception as e:
            logger.warning("  [ANALYSIS ERROR] %s: %s", key, e)
            mark_model_error(key, str(e))
            continue

    return None


# ============================================================
# PROCESS ENTRY
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

    # --------------------------------------------------------
    # Fetch article page (raw HTML kept around for link recovery)
    # --------------------------------------------------------
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

    # --------------------------------------------------------
    # WeChat detection + original-link recovery
    # --------------------------------------------------------
    is_wechat = bool(
        source
        or "weixin" in str(link).lower()
        or "wechat" in str(link).lower()
        or "微信" in title
        or "微信" in content_for_filter
    )

    if is_wechat:
        source = source or "WeChat"
        original_link = extract_original_link(link, raw_html, raw_summary_html)
        if original_link and original_link != link and is_safe_url(original_link):
            logger.info("  [SOURCE] Recovered original WeChat link.")
            link = original_link
        logger.info("  [SOURCE] WeChat content detected.")

    # --------------------------------------------------------
    # FILTER
    # --------------------------------------------------------
    decision = filter_article(title, content_for_filter, source)

    if decision is None:
        logger.info("  [RESULT] FILTER FAILED")
        return {"status": "retry"}

    if decision is False:
        logger.info("  [RESULT] REJECT")
        return {"status": "rejected"}

    logger.info("  [RESULT] RELEVANT")

    # --------------------------------------------------------
    # Deep analysis
    # --------------------------------------------------------
    if not article_text:
        article_text = rss_summary

    if not article_text:
        logger.info("  [RESULT] No article text available.")
        return {"status": "retry"}

    analysis = deep_analyze(title, article_text, link, source)

    if not analysis:
        logger.info("  [RESULT] DEEP ANALYSIS FAILED")
        return {"status": "retry"}

    # --------------------------------------------------------
    # Telegram
    # --------------------------------------------------------
    success = send_telegram(
        title=title,
        analysis=analysis,
        link=link,
        category="اخبار منتخب",
        source=source,
    )

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
    logger.info("RSS SECURITY NEWS BOT")
    logger.info("=" * 70)

    logger.info("BOT_TOKEN: %s", "OK" if BOT_TOKEN else "MISSING")
    logger.info("CHAT_ID: %s", "OK" if CHAT_ID else "MISSING")
    logger.info("GEMINI_API_KEY: %s", "OK" if GEMINI_API_KEY else "MISSING")
    logger.info("GROQ_API_KEY: %s", "OK" if GROQ_API_KEY else "MISSING")

    if not gemini_client and not groq_client:
        msg = "No AI provider configured (GROQ_API_KEY / GEMINI_API_KEY both missing)."
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

    seen_ids, retry_counts = load_state()
    logger.info("Previously seen: %d | Pending retries: %d", len(seen_ids), len(retry_counts))

    # --------------------------------------------------------
    # Download RSS (threaded)
    # --------------------------------------------------------
    all_entries: List[Any] = []
    successful_feeds = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_single_feed, feed): feed for feed in feeds}
        for future in as_completed(futures):
            try:
                entries = future.result()
                if entries:
                    successful_feeds += 1
                all_entries.extend(entries)
            except Exception as e:
                logger.error("Feed worker error: %s", e)

    logger.info("Successful feeds: %d/%d", successful_feeds, len(feeds))
    logger.info("Downloaded entries: %d", len(all_entries))

    # --------------------------------------------------------
    # Deduplicate
    # --------------------------------------------------------
    candidates: List[Tuple[str, Any]] = []
    current_ids: Set[str] = set()

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

        if not is_recent(entry):
            skipped_old += 1
            seen_ids.add(entry_id)  # old items never need retry
            retry_counts.pop(entry_id, None)
            continue

        current_ids.add(entry_id)
        candidates.append((entry_id, entry))

    logger.info("Candidates: %d", len(candidates))
    logger.info("Seen: %d | Old: %d | Duplicates: %d", skipped_seen, skipped_old, skipped_duplicate)

    send_status_message(
        f"📥 *RSS دریافت شد*\n\n"
        f"▫️ فیدهای موفق: {successful_feeds}/{len(feeds)}\n"
        f"▫️ مطالب جدید: {len(candidates)}\n"
        f"▫️ قدیمی: {skipped_old}\n"
        f"▫️ تکراری: {skipped_seen + skipped_duplicate}"
    )

    # --------------------------------------------------------
    # Process sequentially (AI calls stay sequential to avoid rate limits)
    # --------------------------------------------------------
    sent = rejected = failed = 0
    successfully_processed: Set[str] = set()
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
            else:
                failed += 1
                count = retry_counts.get(entry_id, 0) + 1
                if count >= MAX_RETRIES:
                    logger.warning(
                        "Giving up on entry after %d retries: %s", count, entry_id
                    )
                    successfully_processed.add(entry_id)
                    retry_counts.pop(entry_id, None)
                else:
                    retry_counts[entry_id] = count

        except Exception as e:
            logger.error("[FATAL ENTRY ERROR] %s", e)
            failed += 1

        time.sleep(GEMINI_DELAY)

    # --------------------------------------------------------
    # Save state
    # --------------------------------------------------------
    seen_ids.update(successfully_processed)
    save_state(seen_ids, retry_counts)

    cooling = [key for key in model_error_times if should_skip_model(key)]
    elapsed = round(time.time() - start, 1)

    logger.info("=" * 70)
    logger.info("Finished in %ss", elapsed)
    logger.info("Sent: %d | Rejected: %d | Failed/retry: %d", sent, rejected, failed)
    logger.info("Cooldown models: %d", len(cooling))
    logger.info("=" * 70)

    send_status_message(
        f"✅ *اجرای ربات تمام شد*\n\n"
        f"▫️ زمان: {elapsed} ثانیه\n"
        f"▫️ بررسی‌شده: {total}\n"
        f"▫️ ارسال‌شده: {sent}\n"
        f"▫️ ردشده: {rejected}\n"
        f"▫️ ناموفق/برای retry: {failed}\n"
        f"▫️ مدل‌های cooldown: {len(cooling)}"
    )


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
