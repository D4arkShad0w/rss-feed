import os
import json
import time
import requests
import feedparser
import listparser
from google import genai
from google.genai import types

BOT_TOKEN = os.environ.get("BOT_TOKEN")
CHAT_ID = os.environ.get("CHAT_ID")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

OPML_FILE = "feeds.opml"
STATE_FILE = "seen_ids.json"

USER_INTERESTS = [
    # 1. LOW-LEVEL SECURITY & VULNERABILITY RESEARCH
    "Vulnerability Research با ارزش فنی بالا", "Exploit Development", "0-day و 1-dayهای مهم با تحلیل فنی",
    "Exploit Chain و Exploit Chaining", "تحقیقات جدید در Memory Corruption", "Use-After-Free", "Heap Exploitation",
    "Kernel Exploitation", "Privilege Escalation با تحلیل فنی", "Sandbox Escape", "Security Boundary Bypass",
    "Mitigation Bypass", "Control-Flow Integrity Bypass", "Code Integrity Bypass", "PatchGuard Bypass",
    "Windows Defender / EDR Bypass", "تحقیقات جدید در Windows Security Architecture",
    "CVE فقط در صورت وجود exploit واقعی، PoC مهم، تحلیل فنی عمیق، exploit chain، یا اثرگذاری گسترده",

    # 2. WINDOWS INTERNALS & KERNEL
    "Windows Internals", "Windows Kernel", "Windows Kernel Security", "Windows Security Architecture",
    "Windows Kernel Exploitation", "Windows Driver Security", "Windows Driver Vulnerabilities",
    "Windows Code Integrity", "Driver Signature Enforcement", "Kernel Protection", "PatchGuard",
    "Protected Process / PPL", "Secure Kernel", "VBS و Virtualization-Based Security", "Credential Guard",
    "Windows Authentication Internals", "Windows Object Manager", "Windows Process / Thread Internals",
    "Windows Memory Manager", "Windows I/O Internals", "Windows ETW و امنیت ETW", "Windows Security Mitigations",

    # 3. EDR / ENDPOINT / DETECTION
    "EDR Architecture", "EDR Internals", "EDR Evasion", "EDR Bypass Techniques", "Endpoint Security Architecture",
    "Detection Engineering با نوآوری فنی", "Detection Bypass", "Telemetry Evasion", "ETW Bypass", "AMSI Bypass",
    "Security Product Internals", "تحقیقات فنی درباره EDRهای مطرح", "مقایسه فنی قابلیت‌های EDR", "روش‌های جدید تشخیص رفتار مخرب",

    # 4. REVERSE ENGINEERING & BINARY SECURITY
    "Reverse Engineering", "Advanced Reverse Engineering", "Binary Analysis", "Binary Security",
    "Static Analysis", "Dynamic Analysis", "Binary Instrumentation", "Software Internals",
    "Malware Reverse Engineering", "Reverse Engineering Techniques", "تحقیقات جدید در Binary Analysis", "تحلیل فنی بدافزارها با تکنیک‌های جدید",

    # 5. FUZZING & AUTOMATED VULNERABILITY DISCOVERY
    "Fuzzing", "Advanced Fuzzing Techniques", "Kernel Fuzzing", "Coverage-Guided Fuzzing",
    "Structure-Aware Fuzzing", "Grammar-Based Fuzzing", "Hybrid Fuzzing", "Fuzzing برای کشف vulnerability",
    "Automated Vulnerability Discovery", "تحقیقات جدید در Fuzzing", "روش‌های جدید crash triage و root-cause analysis",

    # 6. ROOTKIT / BOOTKIT / FIRMWARE
    "Rootkit", "Kernel Rootkit", "Bootkit", "UEFI Security", "BIOS Security", "Firmware Security",
    "Firmware Reverse Engineering", "Firmware Vulnerability Research", "UEFI Vulnerability Research",
    "Secure Boot", "Boot Chain Security", "Platform Security", "Hardware Root of Trust",
    "تحقیقات امنیتی در سطح firmware و boot chain",

    # 7. MALWARE & ADVANCED ATTACK TECHNIQUES
    "Advanced Malware Analysis", "Malware Internals", "Malware Techniques با نوآوری فنی",
    "Advanced Persistence Techniques", "Stealth Techniques", "Defense Evasion", "Privilege Escalation Techniques",
    "Initial Access Techniques با نوآوری", "Post-Exploitation Techniques با نوآوری", "Living-off-the-Land Techniques",
    "تحقیقات جدید درباره تکنیک‌های پیچیده مهاجمان",

    # 8. OPERATING SYSTEMS & LOW-LEVEL COMPUTER SCIENCE
    "Operating Systems Internals", "Low-Level Systems", "Systems Programming", "Computer Architecture",
    "CPU Architecture", "Memory Architecture", "Virtual Memory", "Processes and Threads", "Kernel Design",
    "Compiler Internals", "Programming Language Internals", "Runtime Internals", "Linkers و Loaders",
    "ELF Internals", "PE Internals", "Dynamic Linking", "Binary Formats", "Operating System Security Architecture",

    # 9. NETWORKING / PROTOCOL SECURITY
    "Network Protocol Internals", "Protocol Security", "Network Security Research", "Protocol Vulnerability Research",
    "Network Exploitation با نوآوری", "DNS Security Research", "SMB Security", "Windows Network Protocols",
    "Authentication Protocol Security", "تحقیقات جدید در امنیت پروتکل‌ها",

    # 10. ADVANCED COMPUTER SCIENCE
    "تحقیقات جدید و غیرمعمول Computer Science", "Computer Science Research با کاربرد عملی",
    "تحقیقات جدید در Systems", "تحقیقات جدید در Operating Systems", "تحقیقات جدید در Programming Languages",
    "تحقیقات جدید در Computer Architecture", "تحقیقات جدید در Compilers", "ایده‌های غیرمتعارف و جالب در Computer Science",
    "تکنیک‌های جدید و خلاقانه در سیستم‌های کامپیوتری",

    # 11. SECURITY RESEARCH / CONFERENCES
    "تحقیقات منتشرشده در کنفرانس‌های امنیتی معتبر", "Black Hat", "DEF CON", "USENIX Security", "NDSS",
    "ACM CCS", "IEEE Symposium on Security and Privacy", "Black Hat Arsenal", "Pwn2Own",
    "تحقیقات فنی منتشرشده در Security Conferences", "PoCهای مهم و تحقیقات پشت آن‌ها", "تحقیقات جدید Vulnerability Research",

    # 12. THREAT INTELLIGENCE / APT
    "APT", "Advanced Persistent Threats", "Cyber Espionage", "State-Sponsored Cyber Operations",
    "Government Cyber Operations", "Cyber Warfare", "Advanced Threat Campaigns", "تحلیل فنی کمپین‌های APT",
    "تحلیل TTPهای جدید مهاجمان", "تحلیل ابزارها و malwareهای مورد استفاده گروه‌های APT",

    # 13. IRAN
    "امنیت سایبری ایران", "تحقیقات امنیتی مرتبط با ایران", "حملات سایبری مرتبط با ایران با تحلیل فنی",
    "گروه‌های تهدید ایرانی", "عملیات سایبری مرتبط با ایران", "زیرساخت‌های حیاتی ایران",
    "تحولات فناوری ایران با اهمیت راهبردی", "سیاست فناوری ایران با اثر امنیتی یا راهبردی",
    "تحریم‌های فناوری علیه ایران", "قوانین و مقررات فناوری ایران با اثر مهم",
    "تحولات سیاسی و راهبردی ایران با اثر مستقیم بر فناوری یا امنیت",

    # 14. CHINA
    "China Cybersecurity", "China Cyber Operations", "Chinese APT Groups", "Chinese Cyber Espionage",
    "Chinese Security Research", "تحقیقات امنیتی منتشرشده از چین", "فناوری چین با اهمیت راهبردی",
    "صنعت فناوری چین", "شرکت‌های فناوری چینی با اهمیت راهبردی", "سیاست فناوری چین", "قوانین فناوری چین",
    "رقابت فناوری چین و آمریکا", "تحریم‌های فناوری علیه چین", "رقابت تراشه و Semiconductor بین چین و آمریکا",
    "تحولات AI چین با اهمیت راهبردی",

    # 15. MIDDLE EAST / ISRAEL
    "تحولات راهبردی خاورمیانه", "امنیت سایبری خاورمیانه", "عملیات سایبری در خاورمیانه",
    "Israel Cybersecurity", "Israeli Cybersecurity Industry", "Israeli Cyber Operations",
    "Israeli Security Research", "روابط ایران و اسرائیل", "تحولات امنیتی منطقه با اهمیت راهبردی",

    # 16. UNITED STATES / NATIONAL SECURITY
    "US National Security Technology", "US Cybersecurity Policy", "CISA", "US Cybersecurity Regulation",
    "US Technology Policy", "US National Security Policy", "Technology Export Controls",
    "Semiconductor Export Controls", "Technology Sanctions", "AI Regulation با اهمیت راهبردی", "Cybersecurity Regulation با اثر مهم",

    # 17. STRATEGIC TECHNOLOGY
    "Technology Competition", "US-China Technology Competition", "Semiconductor Industry",
    "Advanced Semiconductor Technology", "Chip Design", "Chip Manufacturing", "AI Hardware",
    "GPU Architecture", "Accelerator Architecture", "Strategic Technology", "تحولات فناوری با اثر ژئوپلیتیکی",
    "رقابت فناوری بین قدرت‌های جهانی",

    # 18. CYBERSECURITY INDUSTRY / PRODUCTS
    "Cybersecurity Startups با فناوری متمایز", "محصولات جدید Cybersecurity با نوآوری فنی",
    "EDR/XDR Products", "Endpoint Security Products", "Threat Intelligence Products",
    "Security Research Companies", "Exploit Development Companies", "Vulnerability Research Companies",
    "Malware Analysis Companies", "Security Product Acquisitions", "Cybersecurity Funding در شرکت‌های دارای فناوری قابل توجه",
    "فناوری‌های امنیتی جدید با قابلیت ایجاد محصول",

    # 19. ANALYTICAL / DEEP TECHNICAL CONTENT
    "Technical Deep Dive", "تحلیل‌های فنی عمیق", "تحلیل فنی حملات سایبری", "Post-Mortem حملات سایبری",
    "Root Cause Analysis", "تحلیل معماری سیستم‌های امنیتی", "تحلیل تکنیک‌های غیرمعمول در امنیت",
    "تکنیک‌های خلاقانه و غیرمعمول در امنیت", "تحقیقات عجیب و جالب Computer Science",
    "پروژه‌های غیرمعمول و جالب در سیستم‌ها", "تحقیقات جدید که یک تکنیک یا ایده فنی جدید معرفی می‌کنند"
]

client = genai.Client(api_key=GEMINI_API_KEY)

def load_seen_ids():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return set(json.load(f))
        except Exception as e:
            print(f"Error loading state file: {e}")
    return set()

def save_seen_ids(seen_ids):
    with open(STATE_FILE, "w") as f:
        json.dump(list(seen_ids), f)

def send_status_message(text):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": text,
        "disable_notification": True
    }
    try:
        requests.post(url, json=payload)
    except Exception as e:
        print(f"[-] Status message error: {e}")

def analyze_and_translate_with_gemini(title, summary):
    prompt = f"""
    تو یک تحلیلگر ارشد امنیت سایبری و پژوهشگر سیستم‌های سطح پایین (Low-Level Systems) هستی.
    
    علاقه‌مندی‌های کلیدی کاربر:
    - آسیب‌پذیری‌های با ارزش فنی بالا، اکسپلویت نویسی، رم مموری کوراپشن، کرنل و هپ اکسپلویت‌شن
    - معماری داخلی و امنیت کرنل ویندوز، درایورها، PPL، متیگیشن‌ها و بایپس‌های امنیتی (EDR/Defender/PatchGuard)
    - مهندسی معکوس پیشرفته، تحلیل بدافزارهای پیچیده و تکنیک‌های دفاع‌گریز (Defense Evasion)
    - فازینگ پیشرفته، تحقیقات سخت‌افزار، فریم‌ورک و UEFI
    - تحلیل فنی عملیات APT و اطلاعات تهدیدات سایبری (Cyber Threat Intelligence)
    - تحولات راهبردی فناوری و ژئوپلیتیک (ایران، چین، آمریکا، خاورمیانه و رقابت تراشه)
    
    عنوان خبر: {title}
    متن/خلاصه خبر: {summary}
    
    دستورالعمل سخت‌گیرانه فیلترینگ:
    - این خبر نباید صرفاً به خاطر داشتن یک کلمه کلیدی، نام شرکت یا کشور انتخاب شود.
    - **باید اولویت داده شود به:** تکنیک‌های فنی جدید، تحقیقات مهم آسیب‌پذیری، توسعه اکسپلویت، روش‌های نوآورانه بایپس EDR، تحقیقات کرنل/فریم‌ورک/ویندوز، تکنیک‌های پیشرفته بدافزار، عملیات مهم APT، تحولات راهبردی کلان، یا مقالات عمیق فنی (Deep Technical Dive).
    - **باید رد شود (REJECT):** اعلامیه‌های روتین CVE بدون اکسپلویت یا تحلیل فنی عمیق، اخبار عمومی و سطحی امنیت، بازاریابی شرکت‌ها، بیانیه‌های مطبوعاتی، آپدیت‌های روتین پچ، اخبار عمومی هوش مصنوعی یا کلود بدون کاربرد ساختاری، و اخبار بازار بورس.
    
    وظایف:
    ۱. بررسی کن آیا خبر مطابق معیارهای بالا ارزش تایید دارد یا خیر.
    ۲. اگر فاقد ارزش فنی یا راهبردی است، فقط و فقط بنویس: REJECT
    ۳. اگر واجد شرایط است، پاسخی دقیقاً به فرمت زیر به زبان فارسی روان بده:
    
    CATEGORY: [نام دقیق دسته‌بندی مرتبط از حوزه علاقه‌مندی‌ها]
    TITLE: [ترجمه جذاب، حرفه‌ای و دقیق عنوان به فارسی]
    SUMMARY: [خلاصه فنی و مفید خبر در ۲ الی ۴ جمله به زبان فارسی روان]
    """

    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.1,
            ),
        )
        return response.text.strip()
    except Exception as e:
        print(f"[-] Error calling Gemini API: {e}")
        return "REJECT"

def send_telegram(title_fa, summary_fa, link, category):
    text = f"📌 **[{category}]**\n\n🔹 **{title_fa}**\n\n{summary_fa}\n\n🔗 [مطالعه خبر کامل]({link})"
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": False
    }
    res = requests.post(url, json=payload)
    if res.status_code != 200:
        print(f"[-] Telegram API Error: {res.text}")
    else:
        print(f"[+] Message sent to Telegram: {title_fa}")

def main():
    send_status_message("🔄 **ربات روشن شد:** در حال بررسی دقیق فیدها با الگوریتم سخت‌گیرانه فنی...")

    seen_ids = load_seen_ids()
    new_seen_ids = set(seen_ids)
    
    if not os.path.exists(OPML_FILE):
        print("[-] OPML file not found!")
        send_status_message("❌ **خطا:** فایل feeds.opml یافت نشد.")
        return

    parsed_opml = listparser.parse(OPML_FILE)
    print(f"[+] Total feeds found in OPML: {len(parsed_opml.feeds)}")
    
    sent_count = 0
    processed_count = 0

    for feed in parsed_opml.feeds:
        feed_data = feedparser.parse(feed.url)
        
        for entry in feed_data.entries[:100]:
            post_id = entry.get("id", entry.link)
            if post_id in seen_ids:
                continue
                
            title = entry.get("title", "")
            summary = entry.get("summary", entry.get("description", ""))
            
            processed_count += 1
            print(f"[*] Checking post #{processed_count}: {title}")
            
            ai_result = analyze_and_translate_with_gemini(title, summary)
            
            if "REJECT" not in ai_result and "CATEGORY:" in ai_result:
                try:
                    lines = ai_result.split("\n")
                    cat = [l for l in lines if "CATEGORY:" in l][0].split("CATEGORY:")[1].strip()
                    title_fa = [l for l in lines if "TITLE:" in l][0].split("TITLE:")[1].strip()
                    summary_fa = [l for l in lines if "SUMMARY:" in l][0].split("SUMMARY:")[1].strip()
                    
                    send_telegram(title_fa, summary_fa, entry.link, cat)
                    sent_count += 1
                except Exception as e:
                    print(f"  [-] Error parsing AI response: {e}")
            
            new_seen_ids.add(post_id)
            time.sleep(0.2)

    save_seen_ids(new_seen_ids)
    
    status_summary = f"✅ **بررسی تمام شد.**\n▫️ اخبار جدید بررسی‌شده: {processed_count}\n▫️ اخبار مرتبط تاییدشده: {sent_count}"
    send_status_message(status_summary)

if __name__ == "__main__":
    main()
