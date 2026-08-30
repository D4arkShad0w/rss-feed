````python
import os
import json
import time
import re
import html
import hashlib
import requests
import feedparser
import listparser

from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from google import genai
from google.genai import types

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    print("[-] Groq library not installed.")


# ============================================================
# CONFIG
# ============================================================

BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Accept both names
GROQ_API_KEY = (
    os.getenv("GROQ_API_KEY")
    or os.getenv("GROQ_API")
)

OPML_FILE = "feeds.opml"
STATE_FILE = "seen_ids.json"

MAX_WORKERS = 20
POSTS_PER_FEED = 50

MAX_AGE_DAYS = 7

FEED_TIMEOUT = 15
ARTICLE_TIMEOUT = 20
TELEGRAM_TIMEOUT = 10

GEMINI_DELAY = 0.3

MODEL_COOLDOWN_SECONDS = 1800


# ============================================================
# MODEL CONFIGURATION
# ============================================================

# IMPORTANT:
#
# FILTER:
# weak -> strong
#
# The next model is used ONLY when the previous model fails.
#
# A normal RELEVANT / REJECT response does NOT trigger fallback.
#
# ============================================================

FILTER_MODELS = [

    {
        "provider": "groq",
        "model": "llama-3.1-8b-instant"
    },

    {
        "provider": "groq",
        "model": "openai/gpt-oss-20b"
    },

    {
        "provider": "groq",
        "model": "llama-3.3-70b-versatile"
    },

    {
        "provider": "groq",
        "model": "openai/gpt-oss-120b"
    },

    {
        "provider": "gemini",
        "model": "gemini-2.5-flash-lite"
    },

    {
        "provider": "gemini",
        "model": "gemini-2.5-flash"
    },

    {
        "provider": "gemini",
        "model": "gemini-2.5-pro"
    },
]


# ============================================================
# DEEP ANALYSIS MODELS
# ============================================================

# 8B is intentionally NOT used here.
#
# Deep analysis starts from GPT-OSS 20B.
#
# weak -> strong
# ============================================================

ANALYSIS_MODELS = [

    {
        "provider": "groq",
        "model": "openai/gpt-oss-20b"
    },

    {
        "provider": "groq",
        "model": "llama-3.3-70b-versatile"
    },

    {
        "provider": "groq",
        "model": "openai/gpt-oss-120b"
    },

    {
        "provider": "gemini",
        "model": "gemini-2.5-flash-lite"
    },

    {
        "provider": "gemini",
        "model": "gemini-2.5-flash"
    },

    {
        "provider": "gemini",
        "model": "gemini-2.5-pro"
    },
]


# ============================================================
# MODEL COOLDOWN
# ============================================================

model_error_times = {}


def should_skip_model(model_key):

    last_error = model_error_times.get(model_key)

    if last_error is None:
        return False

    return (
        time.time() - last_error
        < MODEL_COOLDOWN_SECONDS
    )


def mark_model_error(
    model_key,
    reason=""
):

    model_error_times[model_key] = time.time()

    print(
        f"    [COOLDOWN] {model_key} "
        f"for {MODEL_COOLDOWN_SECONDS // 60} min"
    )

    if reason:
        print(
            f"                {reason[:300]}"
        )


# ============================================================
# INTERESTS
# ============================================================

INTEREST_CATEGORIES = {

    "LOW-LEVEL SECURITY": [
        "Exploit Development",
        "Memory Corruption",
        "Use-After-Free",
        "Heap Exploitation",
        "Kernel Exploitation",
        "Privilege Escalation",
        "Sandbox Escape",
        "Mitigation Bypass",
        "PatchGuard Bypass",
        "Windows Defender / EDR Bypass",
        "0-day/1-day با تحلیل فنی"
    ],

    "WINDOWS INTERNALS": [
        "Windows Internals",
        "Windows Kernel Security",
        "Driver Security",
        "Code Integrity",
        "PatchGuard",
        "PPL",
        "VBS",
        "Credential Guard",
        "ETW Security",
        "Security Mitigations"
    ],

    "EDR / ENDPOINT": [
        "EDR Evasion",
        "EDR Bypass",
        "Detection Engineering",
        "Telemetry Evasion",
        "AMSI Bypass",
        "Security Product Internals"
    ],

    "REVERSE ENGINEERING": [
        "Reverse Engineering",
        "Binary Analysis",
        "Malware Reverse Engineering",
        "Static/Dynamic Analysis",
        "Binary Instrumentation"
    ],

    "FUZZING": [
        "Fuzzing",
        "Kernel Fuzzing",
        "Coverage-Guided Fuzzing",
        "Hybrid Fuzzing",
        "Automated Vulnerability Discovery"
    ],

    "ROOTKIT / FIRMWARE": [
        "Rootkit",
        "Bootkit",
        "UEFI Security",
        "Firmware Security",
        "Secure Boot",
        "Hardware Root of Trust"
    ],

    "MALWARE / ATTACK TECHNIQUES": [
        "Advanced Malware Analysis",
        "Malware Techniques",
        "Persistence Techniques",
        "Defense Evasion",
        "Living-off-the-Land"
    ],

    "OS / LOW-LEVEL CS": [
        "Operating Systems Internals",
        "Computer Architecture",
        "Compiler Internals",
        "ELF/PE Internals",
        "Kernel Design"
    ],

    "NETWORK / PROTOCOL SECURITY": [
        "Protocol Security",
        "Network Exploitation",
        "DNS Security",
        "SMB Security",
        "Authentication Protocol Security"
    ],

    "ADVANCED CS": [
        "Computer Science Research",
        "Systems Research",
        "Programming Languages",
        "Computer Architecture",
        "Unusual CS Projects"
    ],

    "MATHEMATICS": [
        "Pure Mathematics",
        "Applied Mathematics",
        "Number Theory",
        "Algebra",
        "Analysis",
        "Topology",
        "Geometry",
        "Discrete Mathematics",
        "Combinatorics",
        "Mathematical Logic",
        "Category Theory",
        "Graph Theory",
        "Mathematical Physics",
        "Dynamical Systems",
        "Mathematical Proofs",
        "Famous Mathematical Problems",
        "New Mathematical Discoveries"
    ],

    "AI & MATHEMATICS": [
        "Mathematical Foundations of AI",
        "Mathematical Foundations of Machine Learning",
        "Learning Theory",
        "Optimization Theory",
        "Probability and Statistics for AI",
        "Information Theory",
        "Linear Algebra for AI",
        "Algebraic Geometry in ML",
        "Topological Data Analysis",
        "Geometric Deep Learning",
        "Mathematical AI Research",
        "Theoretical Computer Science and AI"
    ],

    "AI SKEPTICISM / REALISM": [
        "AI Limitations",
        "LLM Limitations",
        "AI Hype Criticism",
        "AI Reality Check",
        "Skepticism about AGI",
        "AI Bubble Analysis",
        "Critical AI Analysis",
        "AI Overclaiming",
        "AI Evaluation Challenges",
        "AI Benchmark Limitations",
        "Empirical AI Analysis",
        "AI Scaling Laws Debate",
        "Rational AI Discourse"
    ],

    "SECURITY CONFERENCES": [
        "Black Hat",
        "DEF CON",
        "USENIX Security",
        "NDSS",
        "IEEE S&P",
        "Pwn2Own",
        "Security Conference Research"
    ],

    "THREAT INTEL / APT": [
        "APT",
        "Cyber Espionage",
        "State-Sponsored Cyber Operations",
        "Cyber Warfare",
        "APT Campaign Analysis",
        "TTP Analysis"
    ],

    "IRAN": [
        "امنیت سایبری ایران",
        "حملات سایبری مرتبط با ایران",
        "گروه‌های تهدید ایرانی",
        "زیرساخت‌های حیاتی ایران",
        "تحریم‌های فناوری علیه ایران",
        "تحولات راهبردی ایران"
    ],

    "CHINA": [
        "China Cyber Operations",
        "Chinese APT Groups",
        "China Semiconductor",
        "US-China Tech Competition",
        "China AI Strategy"
    ],

    "MIDDLE EAST / ISRAEL": [
        "Middle East Cybersecurity",
        "Israel Cyber Operations",
        "Iran-Israel Cyber Conflict",
        "Regional Strategic Security"
    ],

    "US NATIONAL SECURITY": [
        "US Cybersecurity Policy",
        "CISA",
        "Technology Export Controls",
        "Semiconductor Sanctions",
        "AI Regulation"
    ],

    "STRATEGIC TECH": [
        "Semiconductor Industry",
        "Chip Design/Manufacturing",
        "AI Hardware",
        "GPU Architecture",
        "Geopolitical Technology Competition"
    ],

    "CYBERSECURITY INDUSTRY": [
        "Cybersecurity Startups",
        "EDR/XDR Products",
        "Security Research Companies",
        "Vulnerability Research Companies",
        "Security Funding"
    ],

    "DEEP TECHNICAL CONTENT": [
        "Technical Deep Dive",
        "Post-Mortem Attacks",
        "Root Cause Analysis",
        "Unusual Security Techniques",
        "Creative Systems Projects"
    ]
}


def build_interests_prompt():

    parts = []

    for category, interests in INTEREST_CATEGORIES.items():

        parts.append(
            f"{category}: "
            f"{', '.join(interests)}"
        )

    return "\n".join(parts)


INTERESTS_PROMPT = build_interests_prompt()


# ============================================================
# CLIENT INITIALIZATION
# ============================================================

gemini_client = None
groq_client = None


if GEMINI_API_KEY:

    try:

        gemini_client = genai.Client(
            api_key=GEMINI_API_KEY
        )

        print("[+] Gemini initialized.")

    except Exception as e:

        print(
            f"[-] Gemini init failed: {e}"
        )

else:

    print(
        "[-] GEMINI_API_KEY missing."
    )


if GROQ_AVAILABLE and GROQ_API_KEY:

    try:

        groq_client = Groq(
            api_key=GROQ_API_KEY
        )

        print("[+] Groq initialized.")

    except Exception as e:

        print(
            f"[-] Groq init failed: {e}"
        )

else:

    print(
        "[-] GROQ_API_KEY missing."
    )


# ============================================================
# STATE
# ============================================================

def load_seen_ids():

    if not os.path.exists(STATE_FILE):
        return set()

    try:

        with open(
            STATE_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            data = json.load(f)

        if isinstance(data, list):
            return set(data)

    except Exception as e:

        print(
            f"[-] State load error: {e}"
        )

    return set()


def save_seen_ids(seen_ids):

    try:

        temp = STATE_FILE + ".tmp"

        with open(
            temp,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                list(seen_ids),
                f,
                ensure_ascii=False,
                indent=2
            )

        os.replace(
            temp,
            STATE_FILE
        )

    except Exception as e:

        print(
            f"[-] State save error: {e}"
        )


# ============================================================
# TEXT CLEANING
# ============================================================

def clean_html(text):

    if not text:
        return ""

    try:

        text = html.unescape(
            str(text)
        )

        soup = BeautifulSoup(
            text,
            "html.parser"
        )

        text = soup.get_text(
            " ",
            strip=True
        )

        text = re.sub(
            r"\s+",
            " ",
            text
        )

        return text.strip()

    except Exception:

        return str(text).strip()


# ============================================================
# TELEGRAM
# ============================================================

def escape_markdown(text):

    if not text:
        return ""

    # Telegram Markdown V1
    for char in [
        "_",
        "*",
        "`",
        "["
    ]:

        text = text.replace(
            char,
            "\\" + char
        )

    return text


def send_status_message(text):

    if not BOT_TOKEN or not CHAT_ID:
        return False

    url = (
        f"https://api.telegram.org/"
        f"bot{BOT_TOKEN}/sendMessage"
    )

    payload = {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "Markdown",
        "disable_notification": True
    }

    try:

        response = requests.post(
            url,
            json=payload,
            timeout=TELEGRAM_TIMEOUT
        )

        if response.ok:
            return True

        print(
            f"[-] Telegram status error: "
            f"{response.status_code} "
            f"{response.text[:500]}"
        )

    except Exception as e:

        print(
            f"[-] Telegram status exception: "
            f"{e}"
        )

    return False


def send_telegram(
    title,
    analysis,
    link,
    category,
    source=""
):

    if not BOT_TOKEN or not CHAT_ID:
        return False

    title = escape_markdown(
        title
    )

    analysis = escape_markdown(
        analysis
    )

    category = escape_markdown(
        category
    )

    source = escape_markdown(
        source
    )

    if not link:
        link = "https://unsafe.sh"

    source_line = ""

    if source:

        source_line = (
            f"🌐 *منبع:* {source}\n\n"
        )

    text = (
        f"📌 *[{category}]*\n\n"
        f"🔹 *{title}*\n\n"
        f"{source_line}"
        f"{analysis}\n\n"
        f"🔗 [مطالعه مطلب اصلی]({link})"
    )

    url = (
        f"https://api.telegram.org/"
        f"bot{BOT_TOKEN}/sendMessage"
    )

    payload = {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": False
    }

    try:

        response = requests.post(
            url,
            json=payload,
            timeout=TELEGRAM_TIMEOUT
        )

        if response.ok:

            print(
                "[+] Telegram message sent."
            )

            return True

        print(
            f"[-] Telegram error: "
            f"{response.status_code}"
        )

        print(
            response.text[:1000]
        )

    except Exception as e:

        print(
            f"[-] Telegram exception: "
            f"{e}"
        )

    return False


# ============================================================
# FEED FETCH
# ============================================================

def fetch_single_feed(feed):

    feed_url = feed.get("url")

    if not feed_url:
        return []

    headers = {
        "User-Agent":
            "Mozilla/5.0 "
            "(Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 "
            "(KHTML, like Gecko) "
            "Chrome/131.0 Safari/537.36"
    }

    try:

        response = requests.get(
            feed_url,
            headers=headers,
            timeout=FEED_TIMEOUT
        )

        if response.status_code != 200:

            print(
                f"[-] Feed HTTP "
                f"{response.status_code}: "
                f"{feed_url}"
            )

            return []

        parsed = feedparser.parse(
            response.content
        )

        return parsed.entries[
            :POSTS_PER_FEED
        ]

    except Exception as e:

        print(
            f"[-] Feed error "
            f"{feed_url}: {e}"
        )

        return []


# ============================================================
# ARTICLE FETCHING
# ============================================================

def extract_article_text(
    url
):

    if not url:
        return None

    headers = {
        "User-Agent":
            "Mozilla/5.0 "
            "(Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 "
            "(KHTML, like Gecko) "
            "Chrome/131.0 Safari/537.36"
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=ARTICLE_TIMEOUT,
            allow_redirects=True
        )

        if response.status_code != 200:

            print(
                f"    [ARTICLE] HTTP "
                f"{response.status_code}: "
                f"{url}"
            )

            return None

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        # Remove useless elements
        for tag in soup([
            "script",
            "style",
            "noscript",
            "svg",
            "nav",
            "footer",
            "header",
            "form",
            "aside"
        ]):

            tag.decompose()

        # Try article/main first
        candidates = []

        for selector in [
            "article",
            "main",
            "[role='main']",
            ".article",
            ".article-content",
            ".post-content",
            ".entry-content",
            ".content",
            "#content"
        ]:

            try:

                for node in soup.select(
                    selector
                ):

                    text = clean_html(
                        node.get_text(
                            " ",
                            strip=True
                        )
                    )

                    if len(text) > 300:
                        candidates.append(text)

            except Exception:
                pass

        # Fallback: body
        if not candidates:

            body = soup.body

            if body:

                candidates.append(
                    clean_html(
                        body.get_text(
                            " ",
                            strip=True
                        )
                    )
                )

        if not candidates:
            return None

        # Longest candidate usually contains
        # the actual article.
        text = max(
            candidates,
            key=len
        )

        # Avoid sending gigantic navigation/pages
        if len(text) > 20000:

            text = text[:20000]

        if len(text) < 300:

            return None

        return text

    except Exception as e:

        print(
            f"    [ARTICLE] Fetch error: "
            f"{e}"
        )

        return None


# ============================================================
# SOURCE EXTRACTION
# ============================================================

def detect_source(
    entry,
    article_text=""
):

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


def extract_original_link(
    url,
    html_text
):

    if not html_text:
        return url

    # Direct WeChat URL
    match = re.search(
        r'https?://mp\.weixin\.qq\.com/[^\s"<>]+',
        html_text,
        re.IGNORECASE
    )

    if match:

        candidate = html.unescape(
            match.group(0)
        )

        return candidate.rstrip(
            ".,);]"
        )

    return url


# ============================================================
# ENTRY ID
# ============================================================

def get_entry_id(entry):

    value = (
        entry.get("id")
        or entry.get("guid")
        or entry.get("link")
    )

    if value:

        return str(
            value
        ).strip()

    title = clean_html(
        entry.get(
            "title",
            ""
        )
    )

    link = entry.get(
        "link",
        ""
    )

    raw = (
        title
        + "|"
        + link
    )

    if raw != "|":

        return hashlib.sha256(
            raw.encode(
                "utf-8"
            )
        ).hexdigest()

    return None


# ============================================================
# DATE
# ============================================================

def is_recent(
    entry,
    max_age_days=MAX_AGE_DAYS
):

    parsed = (
        entry.get(
            "published_parsed"
        )
        or
        entry.get(
            "updated_parsed"
        )
    )

    if not parsed:
        return True

    try:

        date = datetime(
            *parsed[:6],
            tzinfo=timezone.utc
        )

        now = datetime.now(
            timezone.utc
        )

        age = now - date

        return (
            timedelta(0)
            <= age
            <= timedelta(
                days=max_age_days
            )
        )

    except Exception:

        return True


# ============================================================
# GROQ CALL
# ============================================================

def call_groq(
    model_name,
    prompt,
    max_tokens=700
):

    if not groq_client:

        raise RuntimeError(
            "Groq client unavailable"
        )

    response = (
        groq_client
        .chat
        .completions
        .create(
            model=model_name,

            messages=[
                {
                    "role": "system",
                    "content":
                        "You are a senior "
                        "cybersecurity and "
                        "computer science "
                        "analyst."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],

            temperature=0.2,

            max_tokens=max_tokens
        )
    )

    if (
        not response
        or not response.choices
    ):

        raise RuntimeError(
            "Empty Groq response"
        )

    content = (
        response
        .choices[0]
        .message
        .content
    )

    if not content:

        raise RuntimeError(
            "Empty Groq content"
        )

    return content.strip()


# ============================================================
# GEMINI CALL
# ============================================================

def call_gemini(
    model_name,
    prompt,
    max_tokens=700
):

    if not gemini_client:

        raise RuntimeError(
            "Gemini client unavailable"
        )

    response = (
        gemini_client
        .models
        .generate_content(
            model=model_name,

            contents=prompt,

            config=types.GenerateContentConfig(
                temperature=0.2,
                max_output_tokens=max_tokens
            )
        )
    )

    text = getattr(
        response,
        "text",
        None
    )

    if not text:

        raise RuntimeError(
            "Empty Gemini response"
        )

    return text.strip()


# ============================================================
# GENERIC MODEL CALL
# ============================================================

def call_model(
    provider,
    model,
    prompt,
    max_tokens=700
):

    if provider == "groq":

        return call_groq(
            model,
            prompt,
            max_tokens
        )

    if provider == "gemini":

        return call_gemini(
            model,
            prompt,
            max_tokens
        )

    raise RuntimeError(
        f"Unknown provider: {provider}"
    )


# ============================================================
# FILTER PROMPT
# ============================================================

def build_filter_prompt(
    title,
    summary,
    source=""
):

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

فقط مشخص کن که خبر برای این کاربر ارزش
پیگیری دارد یا نه.

RELEVANT:
اگر ارتباط واقعی و معنادار با یکی از
حوزه‌های بالا دارد.

REJECT:
اگر عمومی، بی‌ربط، تبلیغاتی یا کم‌ارزش است.

فقط یکی از این دو کلمه را خروجی بده:

RELEVANT

یا

REJECT

هیچ توضیح دیگری ننویس.
"""


# ============================================================
# FILTER PARSER
# ============================================================

def parse_filter_result(
    result
):

    if not result:
        return None

    text = result.strip().upper()

    text = re.sub(
        r"```",
        "",
        text
    ).strip()

    if re.search(
        r"\bRELEVANT\b",
        text
    ):

        return True

    if re.search(
        r"\bREJECT\b",
        text
    ):

        return False

    return None


# ============================================================
# FILTER WITH FALLBACK
# ============================================================

def filter_article(
    title,
    summary,
    source
):

    prompt = build_filter_prompt(
        title,
        summary,
        source
    )

    for item in FILTER_MODELS:

        provider = item["provider"]
        model = item["model"]

        key = (
            f"{provider}/{model}"
        )

        if should_skip_model(key):

            print(
                f"    [FILTER] "
                f"skip cooldown: {key}"
            )

            continue

        try:

            print(
                f"    [FILTER] "
                f"trying {key}"
            )

            result = call_model(
                provider,
                model,
                prompt,
                max_tokens=50
            )

            decision = parse_filter_result(
                result
            )

            if decision is None:

                raise RuntimeError(
                    f"Invalid filter output: "
                    f"{result[:200]}"
                )

            print(
                f"    [FILTER] "
                f"{key} -> "
                f"{'RELEVANT' if decision else 'REJECT'}"
            )

            return decision

        except Exception as e:

            print(
                f"    [FILTER ERROR] "
                f"{key}: {e}"
            )

            mark_model_error(
                key,
                str(e)
            )

            continue

    print(
        "    [FILTER] "
        "All models failed."
    )

    # IMPORTANT:
    # If filtering itself fails, don't silently
    # reject the article.
    return None


# ============================================================
# DEEP ANALYSIS PROMPT
# ============================================================

def build_analysis_prompt(
    title,
    article_text,
    link,
    source
):

    if len(article_text) > 18000:

        article_text = (
            article_text[:18000]
        )

    return f"""
تو یک تحلیلگر ارشد امنیت سایبری،
Reverse Engineering، Windows Internals،
Computer Science و فناوری هستی.

مطلب زیر قبلاً توسط فیلتر تایید شده است.

وظیفه:

به زبان فارسی توضیح بده که این مطلب دقیقاً
درباره چیست و چه نکات مهمی دارد.

خروجی باید حدود 10 تا 15 خط باشد.

در تحلیل، تا جایی که متن اجازه می‌دهد، این موارد
را پوشش بده:

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
6. از bulletهای خیلی کوتاه استفاده نکن؛
   متن باید خوانا و تحلیلی باشد.
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


# ============================================================
# DEEP ANALYSIS WITH FALLBACK
# ============================================================

def deep_analyze(
    title,
    article_text,
    link,
    source
):

    prompt = build_analysis_prompt(
        title,
        article_text,
        link,
        source
    )

    for item in ANALYSIS_MODELS:

        provider = item["provider"]
        model = item["model"]

        key = (
            f"{provider}/{model}"
        )

        if should_skip_model(key):

            print(
                f"    [ANALYSIS] "
                f"skip cooldown: {key}"
            )

            continue

        try:

            print(
                f"    [ANALYSIS] "
                f"trying {key}"
            )

            result = call_model(
                provider,
                model,
                prompt,
                max_tokens=1200
            )

            if not result:

                raise RuntimeError(
                    "Empty analysis"
                )

            print(
                f"    [ANALYSIS] "
                f"success: {key}"
            )

            return result

        except Exception as e:

            print(
                f"    [ANALYSIS ERROR] "
                f"{key}: {e}"
            )

            mark_model_error(
                key,
                str(e)
            )

            continue

    return None


# ============================================================
# PROCESS ENTRY
# ============================================================

def process_entry(
    entry,
    index,
    total
):

    title = clean_html(
        entry.get(
            "title",
            ""
        )
    )

    rss_summary = clean_html(
        entry.get(
            "summary",
            entry.get(
                "description",
                ""
            )
        )
    )

    link = entry.get(
        "link",
        ""
    )

    print()
    print(
        "=" * 70
    )

    print(
        f"[{index}/{total}] "
        f"{title[:100]}"
    )

    print(
        f"URL: {link}"
    )

    # --------------------------------------------------------
    # Detect source
    # --------------------------------------------------------

    source = detect_source(
        entry
    )

    # --------------------------------------------------------
    # Fetch article page
    # --------------------------------------------------------

    article_text = None

    if link:

        print(
            "    [ARTICLE] "
            "Fetching full article..."
        )

        article_text = (
            extract_article_text(
                link
            )
        )

    # --------------------------------------------------------
    # Build content
    # --------------------------------------------------------

    if article_text:

        content_for_filter = (
            article_text[:6000]
        )

        print(
            f"    [ARTICLE] "
            f"Full text: "
            f"{len(article_text)} chars"
        )

    else:

        content_for_filter = (
            rss_summary[:5000]
        )

        print(
            "    [ARTICLE] "
            "Using RSS summary."
        )

    # --------------------------------------------------------
    # WeChat detection
    # --------------------------------------------------------

    if (
        "weixin" in str(link).lower()
        or "wechat" in str(link).lower()
        or "微信" in title
        or "微信公众号" in content_for_filter
    ):

        source = (
            source
            or "WeChat"
        )

        print(
            "    [SOURCE] "
            "WeChat content detected."
        )

    # --------------------------------------------------------
    # FILTER
    # --------------------------------------------------------

    decision = filter_article(
        title,
        content_for_filter,
        source
    )

    # AI completely unavailable
    if decision is None:

        print(
            "    [RESULT] "
            "FILTER FAILED"
        )

        return {
            "status": "retry",
        }

    # --------------------------------------------------------
    # Rejected
    # --------------------------------------------------------

    if decision is False:

        print(
            "    [RESULT] "
            "REJECT"
        )

        return {
            "status": "rejected",
        }

    # --------------------------------------------------------
    # Relevant
    # --------------------------------------------------------

    print(
        "    [RESULT] "
        "RELEVANT"
    )

    # --------------------------------------------------------
    # Deep analysis
    # --------------------------------------------------------

    if not article_text:

        article_text = (
            rss_summary
        )

    if not article_text:

        print(
            "    [RESULT] "
            "No article text available."
        )

        return {
            "status": "retry"
        }

    analysis = deep_analyze(
        title,
        article_text,
        link,
        source
    )

    if not analysis:

        print(
            "    [RESULT] "
            "DEEP ANALYSIS FAILED"
        )

        return {
            "status": "retry"
        }

    # --------------------------------------------------------
    # Telegram
    # --------------------------------------------------------

    success = send_telegram(
        title=title,
        analysis=analysis,
        link=link,
        category="اخبار منتخب",
        source=source
    )

    if not success:

        print(
            "    [RESULT] "
            "Telegram failed."
        )

        return {
            "status": "retry"
        }

    return {
        "status": "sent"
    }


# ============================================================
# MAIN
# ============================================================

def main():

    start = time.time()

    print()
    print(
        "=" * 70
    )

    print(
        "RSS SECURITY NEWS BOT"
    )

    print(
        "=" * 70
    )

    # --------------------------------------------------------
    # Configuration
    # --------------------------------------------------------

    print(
        f"BOT_TOKEN: "
        f"{'OK' if BOT_TOKEN else 'MISSING'}"
    )

    print(
        f"CHAT_ID: "
        f"{'OK' if CHAT_ID else 'MISSING'}"
    )

    print(
        f"GEMINI_API_KEY: "
        f"{'OK' if GEMINI_API_KEY else 'MISSING'}"
    )

    print(
        f"GROQ_API_KEY: "
        f"{'OK' if GROQ_API_KEY else 'MISSING'}"
    )

    # --------------------------------------------------------
    # OPML
    # --------------------------------------------------------

    if not os.path.exists(
        OPML_FILE
    ):

        print(
            "[-] feeds.opml not found."
        )

        send_status_message(
            "❌ feeds.opml پیدا نشد."
        )

        return

    try:

        with open(
            OPML_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            opml = f.read()

        parsed = listparser.parse(
            opml
        )

    except Exception as e:

        print(
            f"[-] OPML error: {e}"
        )

        return

    feeds = parsed.feeds

    print(
        f"[+] Feeds loaded: "
        f"{len(feeds)}"
    )

    # --------------------------------------------------------
    # State
    # --------------------------------------------------------

    seen_ids = load_seen_ids()

    print(
        f"[+] Previously seen: "
        f"{len(seen_ids)}"
    )

    # --------------------------------------------------------
    # Download RSS
    # --------------------------------------------------------

    all_entries = []

    successful_feeds = 0

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {

            executor.submit(
                fetch_single_feed,
                feed
            ): feed

            for feed in feeds
        }

        for future in as_completed(
            futures
        ):

            try:

                entries = future.result()

                if entries:
                    successful_feeds += 1

                all_entries.extend(
                    entries
                )

            except Exception as e:

                print(
                    f"[-] Feed worker error: "
                    f"{e}"
                )

    print(
        f"[+] Successful feeds: "
        f"{successful_feeds}/{len(feeds)}"
    )

    print(
        f"[+] Downloaded entries: "
        f"{len(all_entries)}"
    )

    # --------------------------------------------------------
    # Deduplicate
    # --------------------------------------------------------

    candidates = []

    current_ids = set()

    skipped_seen = 0
    skipped_old = 0
    skipped_duplicate = 0

    for entry in all_entries:

        entry_id = get_entry_id(
            entry
        )

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

            # Old items never need retry.
            seen_ids.add(
                entry_id
            )

            continue

        current_ids.add(
            entry_id
        )

        candidates.append(
            (
                entry_id,
                entry
            )
        )

    print(
        f"[+] Candidates: "
        f"{len(candidates)}"
    )

    print(
        f"[+] Seen: "
        f"{skipped_seen}"
    )

    print(
        f"[+] Old: "
        f"{skipped_old}"
    )

    print(
        f"[+] Duplicates: "
        f"{skipped_duplicate}"
    )

    send_status_message(
        f"📥 *RSS دریافت شد*\n\n"
        f"▫️ فیدهای موفق: "
        f"{successful_feeds}/{len(feeds)}\n"
        f"▫️ مطالب جدید: "
        f"{len(candidates)}\n"
        f"▫️ قدیمی: {skipped_old}\n"
        f"▫️ تکراری: "
        f"{skipped_seen + skipped_duplicate}"
    )

    # --------------------------------------------------------
    # Process sequentially
    #
    # IMPORTANT:
    # AI calls remain sequential to avoid rate limits.
    # --------------------------------------------------------

    sent = 0
    rejected = 0
    failed = 0

    successfully_processed = set()

    total = len(candidates)

    for index, (
        entry_id,
        entry
    ) in enumerate(
        candidates,
        start=1
    ):

        try:

            result = process_entry(
                entry,
                index,
                total
            )

            status = result.get(
                "status"
            )

            if status == "sent":

                sent += 1

                successfully_processed.add(
                    entry_id
                )

            elif status == "rejected":

                rejected += 1

                successfully_processed.add(
                    entry_id
                )

            else:

                failed += 1

        except Exception as e:

            print(
                f"[FATAL ENTRY ERROR] "
                f"{e}"
            )

            failed += 1

        # Small delay between requests.
        time.sleep(
            GEMINI_DELAY
        )

    # --------------------------------------------------------
    # Save state
    # --------------------------------------------------------

    seen_ids.update(
        successfully_processed
    )

    save_seen_ids(
        seen_ids
    )

    # --------------------------------------------------------
    # Cooldown status
    # --------------------------------------------------------

    cooling = [

        key

        for key in model_error_times

        if should_skip_model(key)
    ]

    elapsed = round(
        time.time() - start,
        1
    )

    # --------------------------------------------------------
    # Final report
    # --------------------------------------------------------

    print()
    print(
        "=" * 70
    )

    print(
        f"Finished in {elapsed}s"
    )

    print(
        f"Sent: {sent}"
    )

    print(
        f"Rejected: {rejected}"
    )

    print(
        f"Failed/retry: {failed}"
    )

    print(
        f"Cooldown models: "
        f"{len(cooling)}"
    )

    print(
        "=" * 70
    )

    send_status_message(
        f"✅ *اجرای ربات تمام شد*\n\n"
        f"▫️ زمان: {elapsed} ثانیه\n"
        f"▫️ بررسی‌شده: {total}\n"
        f"▫️ ارسال‌شده: {sent}\n"
        f"▫️ ردشده: {rejected}\n"
        f"▫️ ناموفق/برای retry: {failed}\n"
        f"▫️ مدل‌های cooldown: "
        f"{len(cooling)}"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print(
            "\n[!] Interrupted."
        )

    except Exception as e:

        print(
            f"\n[FATAL] {e}"
        )

        send_status_message(
            "❌ خطای Fatal در ربات:\n"
            + str(e)[:500]
        )

        raise
````
