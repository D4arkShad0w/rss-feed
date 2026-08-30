import os
import json
import time
import re
import requests
import feedparser
import listparser
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from google import genai
from google.genai import types

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    print("[-] Groq library not found, Groq will be skipped.")
    GROQ_AVAILABLE = False

BOT_TOKEN = os.environ.get("BOT_TOKEN")
CHAT_ID = os.environ.get("CHAT_ID")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GROQ_API_KEY = os.environ.get("GROQ_API")

OPML_FILE = "feeds.opml"
STATE_FILE = "seen_ids.json"

MAX_WORKERS = 30
POSTS_PER_FEED = 50
MAX_AGE_DAYS = 7
TIMEOUT = 10
GEMINI_DELAY = 0.3

# --- سیستم خنک‌کنندگی هوشمند ---
MODEL_COOLDOWN_SECONDS = 1800  # 30 دقیقه خنک‌کنندگی بعد از خطا
model_error_times = {}         # {model_key: timestamp_of_last_error}

def should_skip_model(model_key):
    """بررسی می‌کند که آیا مدل در حال حاضر در دوره خنک‌کنندگی است یا خیر"""
    if model_key not in model_error_times:
        return False
    last_error = model_error_times[model_key]
    return (time.time() - last_error) < MODEL_COOLDOWN_SECONDS

def mark_model_error(model_key):
    """علامت‌گذاری مدل به عنوان خراب برای دوره خنک‌کنندگی"""
    model_error_times[model_key] = time.time()
    print(f"    [!] {model_key} cooldown activated for {MODEL_COOLDOWN_SECONDS/60:.0f} minutes.")

# --- لیست مدل‌ها به ترتیب اولویت شما ---
MODELS_FALLBACK = [
    {"provider": "groq", "model": "llama-3.1-8b-instant"},
    {"provider": "groq", "model": "llama-3.3-70b-versatile"},
    {"provider": "groq", "model": "openai/gpt-oss-120b"},
    {"provider": "groq", "model": "openai/gpt-oss-20b"},
    {"provider": "gemini", "model": "gemini-2.5-flash-lite"},
    {"provider": "gemini", "model": "gemini-2.5-flash"},
    {"provider": "gemini", "model": "gemini-2.5-pro"},
]

INTEREST_CATEGORIES = {
    "LOW-LEVEL SECURITY": [
        "Exploit Development", "Memory Corruption", "Use-After-Free", "Heap Exploitation",
        "Kernel Exploitation", "Privilege Escalation", "Sandbox Escape", "Mitigation Bypass",
        "PatchGuard Bypass", "Windows Defender / EDR Bypass", "0-day/1-day با تحلیل فنی"
    ],
    "WINDOWS INTERNALS": [
        "Windows Internals", "Windows Kernel Security", "Driver Security", "Code Integrity",
        "PatchGuard", "PPL", "VBS", "Credential Guard", "ETW Security", "Security Mitigations"
    ],
    "EDR / ENDPOINT": [
        "EDR Evasion", "EDR Bypass", "Detection Engineering", "Telemetry Evasion",
        "AMSI Bypass", "Security Product Internals"
    ],
    "REVERSE ENGINEERING": [
        "Reverse Engineering", "Binary Analysis", "Malware Reverse Engineering",
        "Static/Dynamic Analysis", "Binary Instrumentation"
    ],
    "FUZZING": [
        "Fuzzing", "Kernel Fuzzing", "Coverage-Guided Fuzzing", "Hybrid Fuzzing",
        "Automated Vulnerability Discovery"
    ],
    "ROOTKIT / FIRMWARE": [
        "Rootkit", "Bootkit", "UEFI Security", "Firmware Security", "Secure Boot",
        "Hardware Root of Trust"
    ],
    "MALWARE / ATTACK TECHNIQUES": [
        "Advanced Malware Analysis", "Malware Techniques", "Persistence Techniques",
        "Defense Evasion", "Living-off-the-Land"
    ],
    "OS / LOW-LEVEL CS": [
        "Operating Systems Internals", "Computer Architecture", "Compiler Internals",
        "ELF/PE Internals", "Kernel Design"
    ],
    "NETWORK / PROTOCOL SECURITY": [
        "Protocol Security", "Network Exploitation", "DNS Security", "SMB Security",
        "Authentication Protocol Security"
    ],
    "ADVANCED CS": [
        "Computer Science Research", "Systems Research", "Programming Languages",
        "Computer Architecture", "Unusual CS Projects"
    ],
    "MATHEMATICS": [
        "Pure Mathematics", "Applied Mathematics", "Number Theory", "Algebra", "Analysis",
        "Topology", "Geometry", "Discrete Mathematics", "Combinatorics", "Mathematical Logic",
        "Category Theory", "Graph Theory", "Mathematical Physics", "Dynamical Systems",
        "Mathematical Proofs", "Famous Mathematical Problems", "New Mathematical Discoveries"
    ],
    "AI & MATHEMATICS": [
        "Mathematical Foundations of AI", "Mathematical Foundations of Machine Learning",
        "Learning Theory", "Optimization Theory", "Probability and Statistics for AI",
        "Information Theory", "Linear Algebra for AI", "Algebraic Geometry in ML",
        "Topological Data Analysis", "Geometric Deep Learning", "Mathematical AI Research",
        "Theoretical Computer Science and AI"
    ],
    "AI SKEPTICISM / REALISM": [
        "AI Limitations", "LLM Limitations", "AI Hype Criticism", "AI Reality Check",
        "Skepticism about AGI", "AI Bubble Analysis", "Critical AI Analysis",
        "AI Overclaiming", "AI Evaluation Challenges", "AI Benchmark Limitations",
        "Empirical AI Analysis", "AI Scaling Laws Debate", "Rational AI Discourse"
    ],
    "SECURITY CONFERENCES": [
        "Black Hat", "DEF CON", "USENIX Security", "NDSS", "IEEE S&P", "Pwn2Own",
        "Security Conference Research"
    ],
    "THREAT INTEL / APT": [
        "APT", "Cyber Espionage", "State-Sponsored Cyber Operations", "Cyber Warfare",
        "APT Campaign Analysis", "TTP Analysis"
    ],
    "IRAN": [
        "امنیت سایبری ایران", "حملات سایبری مرتبط با ایران", "گروه‌های تهدید ایرانی",
        "زیرساخت‌های حیاتی ایران", "تحریم‌های فناوری علیه ایران", "تحولات راهبردی ایران"
    ],
    "CHINA": [
        "China Cyber Operations", "Chinese APT Groups", "China Semiconductor",
        "US-China Tech Competition", "China AI Strategy"
    ],
    "MIDDLE EAST / ISRAEL": [
        "Middle East Cybersecurity", "Israel Cyber Operations", "Iran-Israel Cyber Conflict",
        "Regional Strategic Security"
    ],
    "US NATIONAL SECURITY": [
        "US Cybersecurity Policy", "CISA", "Technology Export Controls",
        "Semiconductor Sanctions", "AI Regulation"
    ],
    "STRATEGIC TECH": [
        "Semiconductor Industry", "Chip Design/Manufacturing", "AI Hardware",
        "GPU Architecture", "Geopolitical Technology Competition"
    ],
    "CYBERSECURITY INDUSTRY": [
        "Cybersecurity Startups", "EDR/XDR Products", "Security Research Companies",
        "Vulnerability Research Companies", "Security Funding"
    ],
    "DEEP TECHNICAL CONTENT": [
        "Technical Deep Dive", "Post-Mortem Attacks", "Root Cause Analysis",
        "Unusual Security Techniques", "Creative Systems Projects"
    ]
}

try:
    gemini_client = genai.Client(api_key=GEMINI_API_KEY)
except Exception as e:
    print(f"[-] Gemini init failed: {e}")
    gemini_client = None

try:
    groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_AVAILABLE and GROQ_API_KEY else None
except Exception as e:
    print(f"[-] Groq init failed: {e}")
    groq_client = None

def load_seen_ids():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except: return set()
    return set()

def save_seen_ids(seen_ids):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(list(seen_ids), f)

def send_status_message(text):
    if not BOT_TOKEN or not CHAT_ID: return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": text, "parse_mode": "Markdown", "disable_notification": True}
    try: requests.post(url, json=payload, timeout=5)
    except: pass

def send_telegram(title_fa, summary_fa, link, category):
    text = f"📌 **[{category}]**\n\n🔹 **{title_fa}**\n\n{summary_fa}\n\n🔗 [مطالعه خبر کامل]({link})"
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": text, "parse_mode": "Markdown", "disable_web_page_preview": False}
    try: requests.post(url, json=payload, timeout=5)
    except: pass

def clean_html(raw_html):
    if not raw_html: return ""
    cleanr = re.compile('<.*?>|&[a-zA-Z]+;')
    cleantext = re.sub(cleanr, ' ', raw_html)
    return ' '.join(cleantext.split()).strip()

def build_interests_prompt():
    prompt_parts = []
    for category, interests in INTEREST_CATEGORIES.items():
        prompt_parts.append(f"{category}: {', '.join(interests)}")
    return "\n".join(prompt_parts)

INTERESTS_PROMPT = build_interests_prompt()

def fetch_single_feed(feed):
    feed_url = feed.get('url')
    if not feed_url: return []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'}
    try:
        response = requests.get(feed_url, headers=headers, timeout=TIMEOUT)
        feed_data = feedparser.parse(response.content)
        return feed_data.entries[:POSTS_PER_FEED]
    except:
        return []

def is_recent(entry, max_age_days=MAX_AGE_DAYS):
    published_parsed = entry.get('published_parsed') or entry.get('updated_parsed')
    if not published_parsed:
        return True
    published_date = datetime(*published_parsed[:6])
    return datetime.utcnow() - published_date <= timedelta(days=max_age_days)

def parse_ai_response(ai_result):
    if not ai_result:
        return None
    
    if "REJECT" in ai_result.upper() and "CATEGORY" not in ai_result.upper():
        return None
    
    try:
        cat_match = re.search(r'CATEGORY\s*:\s*(.+)', ai_result, re.IGNORECASE)
        title_match = re.search(r'TITLE\s*:\s*(.+)', ai_result, re.IGNORECASE)
        summary_match = re.search(r'SUMMARY\s*:\s*(.+)', ai_result, re.IGNORECASE | re.DOTALL)
        
        if cat_match and title_match and summary_match:
            return {
                "category": cat_match.group(1).strip(),
                "title": title_match.group(1).strip(),
                "summary": summary_match.group(1).strip()
            }
    except Exception as e:
        print(f"    [-] Regex parse error: {e}")
    
    return None

def call_gemini(model_name, prompt):
    if not gemini_client:
        raise Exception("Gemini client not initialized")
    
    response = gemini_client.models.generate_content(
        model=model_name,
        contents=prompt,
        config=types.GenerateContentConfig(temperature=0.5),
    )
    return response.text.strip()

def call_groq(model_name, prompt):
    if not groq_client:
        raise Exception("Groq client not initialized")
    
    chat_completion = groq_client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": "تو یک تحلیلگر ارشد امنیت سایبری، پژوهشگر ریاضیات و ژئوپلیتیک فناوری هستی. وظیفه تو فیلتر کردن اخبار بر اساس علاقه‌مندی‌های کاربر است."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.5,
        max_tokens=1024,
    )
    return chat_completion.choices[0].message.content.strip()

def analyze_with_multi_provider(title, summary):
    clean_title = clean_html(title)
    clean_summary = clean_html(summary)
    if len(clean_summary) > 3000: clean_summary = clean_summary[:3000]

    prompt = f"""حوزه‌های مورد علاقه کاربر:
{INTERESTS_PROMPT}

خبر زیر را ارزیابی کن:
عنوان: {clean_title}
خلاصه: {clean_summary}

قوانین:
- اگر خبر به هر یک از حوزه‌های بالا مرتبط است، آن را تایید کن.
- اگر خبر کاملاً نامرتبط است، رد کن.
- اگر شک داری، خبر را تایید کن (ترجیحاً خبر مرتبط را از دست نده).

مثال خروجی تایید شده:
CATEGORY: THREAT INTEL / APT
TITLE: تحلیل فنی کمپین جدید جاسوسی سایبری علیه خاورمیانه
SUMMARY: این گزارش یک کمپین جدید جاسوسی سایبری را با استفاده از تکنیک‌های Living-off-the-Land تحلیل می‌کند.

مثال خروجی رد شده:
REJECT

خروجی تو باید دقیقاً یکی از دو فرمت بالا باشد. اگر خبر مرتبط است، فرمت کامل را برگردان:"""

    for provider_info in MODELS_FALLBACK:
        provider = provider_info["provider"]
        model_name = provider_info["model"]
        model_key = f"{provider}/{model_name}"
        
        # اگر مدل در حال حاضر در دوره خنک‌کنندگی است، رد شو
        if should_skip_model(model_key):
            continue
        
        try:
            if provider == "groq":
                result = call_groq(model_name, prompt)
            elif provider == "gemini":
                result = call_gemini(model_name, prompt)
            else:
                continue
            
            print(f"    [+] Success with {model_key}")
            return result
            
        except Exception as e:
            error_str = str(e).lower()
            error_code = getattr(e, 'code', None) or getattr(e, 'status_code', None)
            
            # اگر خطای مربوط به نرخ محدود یا مدل در دسترس نبود، مدل را خنک کن
            if any(x in error_str for x in ['429', 'rate limit', 'quota', '404', 'not found']):
                mark_model_error(model_key)
                continue
            
            # سایر خطاها هم مدل را خنک می‌کنند
            print(f"  [-] Error with {model_key}: {e}")
            mark_model_error(model_key)
            continue
    
    print(f"  [-] All providers/models failed or cooling down for this request")
    return "REJECT"

def main():
    start_time = time.time()
    send_status_message("🚀 **ربات شروع شد:** در حال دانلود موازی فیدها با سیستم خنک‌کنندگی هوشمند...")

    seen_ids = load_seen_ids()
    new_seen_ids = set(seen_ids)
    
    if not os.path.exists(OPML_FILE):
        send_status_message("❌ فایل OPML یافت نشد.")
        return

    with open(OPML_FILE, 'r', encoding='utf-8') as f:
        opml_content = f.read()

    parsed_opml = listparser.parse(opml_content)
    print(f"[+] {len(parsed_opml.feeds)} feeds loaded.")

    all_entries = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_single_feed, feed): feed for feed in parsed_opml.feeds}
        for future in as_completed(futures):
            entries = future.result()
            all_entries.extend(entries)

    unique_entries = []
    skipped_old = 0
    skipped_seen = 0
    
    for entry in all_entries:
        post_id = entry.get("id") or entry.get("link")
        if not post_id:
            continue
            
        if post_id in seen_ids or post_id in new_seen_ids:
            skipped_seen += 1
            continue
            
        if not is_recent(entry):
            skipped_old += 1
            new_seen_ids.add(post_id)
            continue
            
        unique_entries.append(entry)
        new_seen_ids.add(post_id)
    
    print(f"[*] Total entries downloaded: {len(all_entries)}")
    print(f"[*] Skipped (already seen): {skipped_seen}")
    print(f"[*] Skipped (too old): {skipped_old}")
    print(f"[*] New unique posts to analyze: {len(unique_entries)}")
    
    send_status_message(
        f"📥 **دانلود کامل شد.**\n"
        f"▫️ پست‌های جدید برای تحلیل: {len(unique_entries)}\n"
        f"▫️ رد شده به دلیل قدیمی بودن: {skipped_old}\n"
        f"▫️ رد شده به دلیل تکراری بودن: {skipped_seen}"
    )

    sent_count = 0
    rejected_count = 0
    parse_errors = 0

    for i, entry in enumerate(unique_entries):
        title = entry.get("title", "").strip()
        summary = entry.get("summary", entry.get("description", "")).strip()
        
        print(f"  [{i+1}/{len(unique_entries)}] {title[:50]}...")
        
        ai_result = analyze_with_multi_provider(title, summary)
        parsed = parse_ai_response(ai_result)
        
        if parsed:
            try:
                send_telegram(
                    parsed["title"],
                    parsed["summary"],
                    entry.get("link", ""),
                    parsed["category"]
                )
                sent_count += 1
                time.sleep(0.2)
            except Exception as e:
                print(f"    [-] Send error: {e}")
                parse_errors += 1
        else:
            if rejected_count < 50:
                print(f"  [DEBUG REJECT] Title: {title[:60]} | AI Output: {ai_result[:150]}")
            rejected_count += 1
        
        time.sleep(GEMINI_DELAY)

    save_seen_ids(new_seen_ids)
    
    # گزارش وضعیت خنک‌کنندگی
    cooling_models = [k for k in model_error_times if should_skip_model(k)]
    elapsed = round(time.time() - start_time, 1)
    status_summary = (
        f"✅ **پایان اجرا در {elapsed} ثانیه.**\n"
        f"▫️ پست‌های جدید بررسی‌شده: {len(unique_entries)}\n"
        f"▫️ تایید و ارسال‌شده: {sent_count}\n"
        f"▫️ رد شده: {rejected_count}\n"
        f"▫️ خطاهای پارس: {parse_errors}\n"
        f"▫️ مدل‌های در حال خنک‌کنندگی: {len(cooling_models)}"
    )
    send_status_message(status_summary)

if __name__ == "__main__":
    main()
