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

BOT_TOKEN = os.environ.get("BOT_TOKEN")
CHAT_ID = os.environ.get("CHAT_ID")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

OPML_FILE = "feeds.opml"
STATE_FILE = "seen_ids.json"

# --- تنظیمات عملکردی برای ۱۰۰ خبر در هر ۵ ساعت ---
MAX_WORKERS = 30       # تعداد فیدهایی که همزمان دانلود می‌شوند
POSTS_PER_FEED = 50    # حداکثر پست‌های دریافتی از هر فید
MAX_AGE_DAYS = 7       # فقط پست‌های ۷ روز اخیر پردازش می‌شوند (جلوگیری از پردازش تاریخچه)
TIMEOUT = 10           # Timeout برای درخواست‌های شبکه
GEMINI_DELAY = 0.3     # تأخیر بین درخواست‌های Gemini برای جلوگیری از Rate Limit

# --- لیست کامل علاقه‌مندی‌ها به صورت دسته‌بندی‌شده ---
INTEREST_CATEGORIES = {
    "LOW-LEVEL SECURITY & VULNERABILITY RESEARCH": [
        "Vulnerability Research با ارزش فنی بالا", "Exploit Development", "0-day و 1-dayهای مهم با تحلیل فنی",
        "Exploit Chain و Exploit Chaining", "تحقیقات جدید در Memory Corruption", "Use-After-Free", "Heap Exploitation",
        "Kernel Exploitation", "Privilege Escalation با تحلیل فنی", "Sandbox Escape", "Security Boundary Bypass",
        "Mitigation Bypass", "Control-Flow Integrity Bypass", "Code Integrity Bypass", "PatchGuard Bypass",
        "Windows Defender / EDR Bypass", "تحقیقات جدید در Windows Security Architecture",
        "CVE فقط در صورت وجود exploit واقعی، PoC مهم، تحلیل فنی عمیق، exploit chain، یا اثرگذاری گسترده"
    ],
    "WINDOWS INTERNALS & KERNEL": [
        "Windows Internals", "Windows Kernel", "Windows Kernel Security", "Windows Security Architecture",
        "Windows Kernel Exploitation", "Windows Driver Security", "Windows Driver Vulnerabilities",
        "Windows Code Integrity", "Driver Signature Enforcement", "Kernel Protection", "PatchGuard",
        "Protected Process / PPL", "Secure Kernel", "VBS و Virtualization-Based Security", "Credential Guard",
        "Windows Authentication Internals", "Windows Object Manager", "Windows Process / Thread Internals",
        "Windows Memory Manager", "Windows I/O Internals", "Windows ETW و امنیت ETW", "Windows Security Mitigations"
    ],
    "EDR / ENDPOINT / DETECTION": [
        "EDR Architecture", "EDR Internals", "EDR Evasion", "EDR Bypass Techniques", "Endpoint Security Architecture",
        "Detection Engineering با نوآوری فنی", "Detection Bypass", "Telemetry Evasion", "ETW Bypass", "AMSI Bypass",
        "Security Product Internals", "تحقیقات فنی درباره EDRهای مطرح", "مقایسه فنی قابلیت‌های EDR", "روش‌های جدید تشخیص رفتار مخرب"
    ],
    "REVERSE ENGINEERING & BINARY SECURITY": [
        "Reverse Engineering", "Advanced Reverse Engineering", "Binary Analysis", "Binary Security",
        "Static Analysis", "Dynamic Analysis", "Binary Instrumentation", "Software Internals",
        "Malware Reverse Engineering", "Reverse Engineering Techniques", "تحقیقات جدید در Binary Analysis", "تحلیل فنی بدافزارها با تکنیک‌های جدید"
    ],
    "FUZZING & AUTOMATED VULNERABILITY DISCOVERY": [
        "Fuzzing", "Advanced Fuzzing Techniques", "Kernel Fuzzing", "Coverage-Guided Fuzzing",
        "Structure-Aware Fuzzing", "Grammar-Based Fuzzing", "Hybrid Fuzzing", "Fuzzing برای کشف vulnerability",
        "Automated Vulnerability Discovery", "تحقیقات جدید در Fuzzing", "روش‌های جدید crash triage و root-cause analysis"
    ],
    "ROOTKIT / BOOTKIT / FIRMWARE": [
        "Rootkit", "Kernel Rootkit", "Bootkit", "UEFI Security", "BIOS Security", "Firmware Security",
        "Firmware Reverse Engineering", "Firmware Vulnerability Research", "UEFI Vulnerability Research",
        "Secure Boot", "Boot Chain Security", "Platform Security", "Hardware Root of Trust",
        "تحقیقات امنیتی در سطح firmware و boot chain"
    ],
    "MALWARE & ADVANCED ATTACK TECHNIQUES": [
        "Advanced Malware Analysis", "Malware Internals", "Malware Techniques با نوآوری فنی",
        "Advanced Persistence Techniques", "Stealth Techniques", "Defense Evasion", "Privilege Escalation Techniques",
        "Initial Access Techniques با نوآوری", "Post-Exploitation Techniques با نوآوری", "Living-off-the-Land Techniques",
        "تحقیقات جدید درباره تکنیک‌های پیچیده مهاجمان"
    ],
    "OPERATING SYSTEMS & LOW-LEVEL COMPUTER SCIENCE": [
        "Operating Systems Internals", "Low-Level Systems", "Systems Programming", "Computer Architecture",
        "CPU Architecture", "Memory Architecture", "Virtual Memory", "Processes and Threads", "Kernel Design",
        "Compiler Internals", "Programming Language Internals", "Runtime Internals", "Linkers و Loaders",
        "ELF Internals", "PE Internals", "Dynamic Linking", "Binary Formats", "Operating System Security Architecture"
    ],
    "NETWORKING / PROTOCOL SECURITY": [
        "Network Protocol Internals", "Protocol Security", "Network Security Research", "Protocol Vulnerability Research",
        "Network Exploitation با نوآوری", "DNS Security Research", "SMB Security", "Windows Network Protocols",
        "Authentication Protocol Security", "تحقیقات جدید در امنیت پروتکل‌ها"
    ],
    "ADVANCED COMPUTER SCIENCE": [
        "تحقیقات جدید و غیرمعمول Computer Science", "Computer Science Research با کاربرد عملی",
        "تحقیقات جدید در Systems", "تحقیقات جدید در Operating Systems", "تحقیقات جدید در Programming Languages",
        "تحقیقات جدید در Computer Architecture", "تحقیقات جدید در Compilers", "ایده‌های غیرمتعارف و جالب در Computer Science",
        "تکنیک‌های جدید و خلاقانه در سیستم‌های کامپیوتری"
    ],
    "SECURITY RESEARCH / CONFERENCES": [
        "تحقیقات منتشرشده در کنفرانس‌های امنیتی معتبر", "Black Hat", "DEF CON", "USENIX Security", "NDSS",
        "ACM CCS", "IEEE Symposium on Security and Privacy", "Black Hat Arsenal", "Pwn2Own",
        "تحقیقات فنی منتشرشده در Security Conferences", "PoCهای مهم و تحقیقات پشت آن‌ها", "تحقیقات جدید Vulnerability Research"
    ],
    "THREAT INTELLIGENCE / APT": [
        "APT", "Advanced Persistent Threats", "Cyber Espionage", "State-Sponsored Cyber Operations",
        "Government Cyber Operations", "Cyber Warfare", "Advanced Threat Campaigns", "تحلیل فنی کمپین‌های APT",
        "تحلیل TTPهای جدید مهاجمان", "تحلیل ابزارها و malwareهای مورد استفاده گروه‌های APT"
    ],
    "IRAN": [
        "امنیت سایبری ایران", "تحقیقات امنیتی مرتبط با ایران", "حملات سایبری مرتبط با ایران با تحلیل فنی",
        "گروه‌های تهدید ایرانی", "عملیات سایبری مرتبط با ایران", "زیرساخت‌های حیاتی ایران",
        "تحولات فناوری ایران با اهمیت راهبردی", "سیاست فناوری ایران با اثر امنیتی یا راهبردی",
        "تحریم‌های فناوری علیه ایران", "قوانین و مقررات فناوری ایران با اثر مهم",
        "تحولات سیاسی و راهبردی ایران با اثر مستقیم بر فناوری یا امنیت"
    ],
    "CHINA": [
        "China Cybersecurity", "China Cyber Operations", "Chinese APT Groups", "Chinese Cyber Espionage",
        "Chinese Security Research", "تحقیقات امنیتی منتشرشده از چین", "فناوری چین با اهمیت راهبردی",
        "صنعت فناوری چین", "شرکت‌های فناوری چینی با اهمیت راهبردی", "سیاست فناوری چین", "قوانین فناوری چین",
        "رقابت فناوری چین و آمریکا", "تحریم‌های فناوری علیه چین", "رقابت تراشه و Semiconductor بین چین و آمریکا",
        "تحولات AI چین با اهمیت راهبردی"
    ],
    "MIDDLE EAST / ISRAEL": [
        "تحولات راهبردی خاورمیانه", "امنیت سایبری خاورمیانه", "عملیات سایبری در خاورمیانه",
        "Israel Cybersecurity", "Israeli Cybersecurity Industry", "Israeli Cyber Operations",
        "Israeli Security Research", "روابط ایران و اسرائیل", "تحولات امنیتی منطقه با اهمیت راهبردی"
    ],
    "UNITED STATES / NATIONAL SECURITY": [
        "US National Security Technology", "US Cybersecurity Policy", "CISA", "US Cybersecurity Regulation",
        "US Technology Policy", "US National Security Policy", "Technology Export Controls",
        "Semiconductor Export Controls", "Technology Sanctions", "AI Regulation با اهمیت راهبردی", "Cybersecurity Regulation با اثر مهم"
    ],
    "STRATEGIC TECHNOLOGY": [
        "Technology Competition", "US-China Technology Competition", "Semiconductor Industry",
        "Advanced Semiconductor Technology", "Chip Design", "Chip Manufacturing", "AI Hardware",
        "GPU Architecture", "Accelerator Architecture", "Strategic Technology", "تحولات فناوری با اثر ژئوپلیتیکی",
        "رقابت فناوری بین قدرت‌های جهانی"
    ],
    "CYBERSECURITY INDUSTRY / PRODUCTS": [
        "Cybersecurity Startups با فناوری متمایز", "محصولات جدید Cybersecurity با نوآوری فنی",
        "EDR/XDR Products", "Endpoint Security Products", "Threat Intelligence Products",
        "Security Research Companies", "Exploit Development Companies", "Vulnerability Research Companies",
        "Malware Analysis Companies", "Security Product Acquisitions", "Cybersecurity Funding در شرکت‌های دارای فناوری قابل توجه",
        "فناوری‌های امنیتی جدید با قابلیت ایجاد محصول"
    ],
    "ANALYTICAL / DEEP TECHNICAL CONTENT": [
        "Technical Deep Dive", "تحلیل‌های فنی عمیق", "تحلیل فنی حملات سایبری", "Post-Mortem حملات سایبری",
        "Root Cause Analysis", "تحلیل معماری سیستم‌های امنیتی", "تحلیل تکنیک‌های غیرمعمول در امنیت",
        "تکنیک‌های خلاقانه و غیرمعمول در امنیت", "تحقیقات عجیب و جالب Computer Science",
        "پروژه‌های غیرمعمول و جالب در سیستم‌ها", "تحقیقات جدید که یک تکنیک یا ایده فنی جدید معرفی می‌کنند"
    ]
}

try:
    client = genai.Client(api_key=GEMINI_API_KEY)
except Exception as e:
    print(f"[-] Gemini init failed: {e}")
    client = None

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
    """ساخت پرامپت کامل از لیست علاقه‌مندی‌ها"""
    prompt_parts = ["حوزه‌های مورد علاقه کاربر (اگر خبر در یکی از این دسته‌ها قرار می‌گیرد، تایید کن):"]
    for category, interests in INTEREST_CATEGORIES.items():
        prompt_parts.append(f"\n{category}:")
        prompt_parts.append(", ".join(interests))
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
    except Exception as e:
        return []

def is_recent(entry, max_age_days=MAX_AGE_DAYS):
    """بررسی می‌کند که پست در بازه زمانی مجاز باشد"""
    published_parsed = entry.get('published_parsed') or entry.get('updated_parsed')
    if not published_parsed:
        return True  # اگر تاریخ وجود نداشت، پردازش شود
    published_date = datetime(*published_parsed[:6])
    return datetime.utcnow() - published_date <= timedelta(days=max_age_days)

def analyze_with_gemini(title, summary):
    if not client: return "REJECT"
    
    clean_title = clean_html(title)
    clean_summary = clean_html(summary)
    if len(clean_summary) > 3000: clean_summary = clean_summary[:3000]

    prompt = f"""تو یک تحلیلگر ارشد امنیت سایبری، پژوهشگر سیستم‌های سطح پایین و ژئوپلیتیک فناوری هستی.
وظیفه تو فیلتر کردن اخبار RSS بر اساس لیست دقیق علاقه‌مندی‌های کاربر است.

{INTERESTS_PROMPT}

قوانین تایید (ACCEPT):
- اخبار دارای تحلیل فنی عمیق (Deep Dive)، معرفی تکنیک‌های جدید، یا تحقیقات مرتبط با دسته‌های بالا.
- کشف آسیب‌پذیری‌های مهم، گزارش‌های Threat Intel، تحولات راهبردی فناوری، و مقالات کنفرانس‌ها.
- اخبار مرتبط با ایران، چین، اسرائیل، خاورمیانه، و رقابت‌های ژئوپلیتیک فناوری.

قوانین رد (REJECT):
- اخبار عمومی IT، بازاریابی محصولات، اعلامیه‌های CVE بدون تحلیل، اخبار بورس، و موارد نامرتبط با لیست بالا.

عنوان خبر: {clean_title}
خلاصه خبر: {clean_summary}

خروجی:
اگر خبر مرتبط است، دقیقاً این فرمت را برگردان:
CATEGORY: [نام دقیق‌ترین دسته مرتبط از لیست بالا]
TITLE: [ترجمه جذاب و حرفه‌ای عنوان به فارسی]
SUMMARY: [خلاصه فنی و مفید در ۲-۳ جمله به فارسی روان]

اگر خبر مرتبط نیست، فقط و فقط یک کلمه برگردان:
REJECT
"""

    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(temperature=0.3),
        )
        return response.text.strip()
    except Exception as e:
        print(f"  [-] Gemini error: {e}")
        return "REJECT"

def main():
    start_time = time.time()
    send_status_message("🚀 **ربات شروع شد:** در حال دانلود موازی فیدها...")

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

    # فیلتر کردن پست‌های تکراری و قدیمی قبل از پردازش با Gemini
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
            new_seen_ids.add(post_id)  # به عنوان دیده‌شده علامت‌گذاری می‌شود تا دیگر پردازش نشود
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

    for i, entry in enumerate(unique_entries):
        title = entry.get("title", "").strip()
        summary = entry.get("summary", entry.get("description", "")).strip()
        
        print(f"  [{i+1}/{len(unique_entries)}] {title[:50]}...")
        
        ai_result = analyze_with_gemini(title, summary)
        
        if "REJECT" not in ai_result and "CATEGORY:" in ai_result:
            try:
                lines = ai_result.split("\n")
                cat = next((l.split(":", 1)[1].strip() for l in lines if l.startswith("CATEGORY:")), "")
                title_fa = next((l.split(":", 1)[1].strip() for l in lines if l.startswith("TITLE:")), "")
                summary_fa = next((l.split(":", 1)[1].strip() for l in lines if l.startswith("SUMMARY:")), "")
                
                if cat and title_fa and summary_fa:
                    send_telegram(title_fa, summary_fa, entry.get("link", ""), cat)
                    sent_count += 1
                    time.sleep(0.2)  # تأخیر کوتاه برای تلگرام
            except Exception as e:
                print(f"    [-] Parse error: {e}")
        else:
            if rejected_count < 10:  # لاگ ۱۰ نمونه اول برای دیباگ
                print(f"  [DEBUG REJECT] Title: {title[:60]} | AI Output: {ai_result[:100]}")
            rejected_count += 1
        
        time.sleep(GEMINI_DELAY)  # تأخیر برای جلوگیری از Rate Limit Gemini

    save_seen_ids(new_seen_ids)
    
    elapsed = round(time.time() - start_time, 1)
    status_summary = (
        f"✅ **پایان اجرا در {elapsed} ثانیه.**\n"
        f"▫️ پست‌های جدید بررسی‌شده: {len(unique_entries)}\n"
        f"▫️ تایید و ارسال‌شده: {sent_count}\n"
        f"▫️ رد شده: {rejected_count}"
    )
    send_status_message(status_summary)

if __name__ == "__main__":
    main()
