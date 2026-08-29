import os
import json
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

# لیست علاقه‌مندی‌های شما (می‌توانید تغییر دهید)
USER_INTERESTS = [
    # ─────────────────────────────────────
    # Cybersecurity — Technical
    # ─────────────────────────────────────

    "امنیت سایبری",
    "EDR و Endpoint Security",
    "EDR Evasion و Bypass Techniques",
    "مهندسی معکوس و Reverse Engineering",
    "Binary Analysis و Binary Security",
    "Exploit Development",
    "Vulnerability Research",
    "Fuzzing و Fuzzing Techniques",
    "Rootkit",
    "Bootkit",
    "Firmware Security",
    "UEFI و BIOS Security",
    "Windows Internals",
    "Windows Kernel Security",
    "Windows Security Architecture",
    "Windows امنیتی و سیاست‌های امنیتی مایکروسافت",
    "Windows Code Integrity و Driver Security",
    "PatchGuard و Kernel Protection",
    "Malware Analysis",
    "Advanced Malware Techniques",
    "Threat Detection و Detection Engineering",
    "Threat Intelligence",
    "APT و Advanced Persistent Threats",
    "Cyber Espionage",
    "Cyber Warfare",

    # ─────────────────────────────────────
    # Computer Science
    # ─────────────────────────────────────

    "Computer Science",
    "سیستم‌عامل‌ها و Operating Systems",
    "سیستم‌های سطح پایین و Low-Level Systems",
    "Compiler و Compiler Internals",
    "Programming Languages",
    "Computer Architecture",
    "CPU و معماری پردازنده",
    "Networking و Network Protocols",
    "Distributed Systems",
    "Systems Programming",
    "Virtualization",
    "Cloud Infrastructure",
    "Database Internals",
    "پروژه‌های جالب و غیرمعمول Computer Science",
    "تحقیقات و ایده‌های جدید در علوم کامپیوتر",

    # ─────────────────────────────────────
    # Security Research & Conferences
    # ─────────────────────────────────────

    "کنفرانس‌های امنیت سایبری",
    "مقالات و تحقیقات منتشرشده در کنفرانس‌های امنیتی",
    "Black Hat",
    "DEF CON",
    "USENIX Security",
    "NDSS",
    "ACM CCS",
    "IEEE Symposium on Security and Privacy",
    "Black Hat Arsenal",
    "Pwn2Own",
    "CTF و تحقیقات امنیتی جالب",
    "تحقیقات جدید Vulnerability Research",

    # ─────────────────────────────────────
    # Security Companies & Products
    # ─────────────────────────────────────

    "استارتاپ‌های امنیت سایبری",
    "محصولات جدید Cybersecurity",
    "محصولات EDR و XDR",
    "محصولات Endpoint Security",
    "محصولات Threat Intelligence",
    "محصولات Detection و Security Operations",
    "شرکت‌های فعال در Vulnerability Research",
    "شرکت‌های فعال در Exploit Development",
    "شرکت‌های فعال در Malware Analysis",
    "سرمایه‌گذاری و Acquisition در Cybersecurity",
    "معرفی محصولات و فناوری‌های امنیتی جدید",

    # ─────────────────────────────────────
    # Geopolitics & Strategic
    # ─────────────────────────────────────

    "اخبار راهبردی و استراتژیک",
    "تحلیل‌های ژئوپلیتیک",
    "امنیت ملی و National Security",
    "جنگ سایبری و Cyber Warfare",
    "Cyber Espionage",
    "عملیات سایبری دولت‌ها",
    "تحولات امنیتی بین‌المللی",
    "رقابت فناوری بین قدرت‌های جهانی",
    "جنگ فناوری و Technology Competition",

    # ─────────────────────────────────────
    # Iran
    # ─────────────────────────────────────

    "ایران",
    "امنیت سایبری ایران",
    "تحولات فناوری ایران",
    "سیاست فناوری ایران",
    "زیرساخت‌های حیاتی ایران",
    "حملات سایبری مرتبط با ایران",
    "گروه‌های تهدید ایرانی",
    "تحولات سیاسی و راهبردی مرتبط با ایران",
    "تحریم‌های فناوری علیه ایران",
    "قوانین و مقررات فناوری ایران",

    # ─────────────────────────────────────
    # China
    # ─────────────────────────────────────

    "چین",
    "فناوری چین",
    "امنیت سایبری چین",
    "صنعت فناوری چین",
    "سیاست فناوری چین",
    "شرکت‌های فناوری چینی",
    "تحقیقات امنیتی چین",
    "Cyber Operations مرتبط با چین",
    "رقابت فناوری چین و آمریکا",
    "قوانین و مقررات فناوری چین",

    # ─────────────────────────────────────
    # Middle East & Israel
    # ─────────────────────────────────────

    "خاورمیانه",
    "امنیت سایبری خاورمیانه",
    "تحولات راهبردی خاورمیانه",
    "اسرائیل",
    "امنیت سایبری اسرائیل",
    "صنعت Cybersecurity اسرائیل",
    "استارتاپ‌های امنیتی اسرائیل",
    "عملیات سایبری اسرائیل",
    "روابط ایران و اسرائیل",
    "تحولات امنیتی منطقه",

    # ─────────────────────────────────────
    # United States & Regulation
    # ─────────────────────────────────────

    "آمریکا",
    "قوانین فناوری آمریکا",
    "قوانین امنیت سایبری آمریکا",
    "Cybersecurity Regulation آمریکا",
    "سیاست‌های فناوری آمریکا",
    "سیاست‌های امنیت ملی آمریکا",
    "CISA و سیاست‌های امنیت سایبری",
    "مقررات صادرات فناوری",
    "تحریم‌های فناوری و صادرات تراشه",
    "قوانین مرتبط با AI و Cybersecurity",

    # ─────────────────────────────────────
    # Analytical / Interesting Content
    # ─────────────────────────────────────

    "مقالات تحلیلی و عمیق",
    "تحلیل‌های فنی و Technical Deep Dive",
    "تحلیل‌های راهبردی",
    "تحلیل حملات سایبری",
    "Post-Mortem حملات سایبری",
    "مطالب Technical و Trick-Based",
    "تکنیک‌های غیرمعمول و خلاقانه در امنیت",
    "تحقیقات عجیب و جالب Computer Science",
    "ایده‌های غیرمتعارف در فناوری",
    "مقالات و پروژه‌های بسیار جالب",
    "تحقیقات جدید و غیرمعمول",
    "مطالبی که ایده یا تکنیک جدیدی معرفی می‌کنند",
]

client = genai.Client(api_key=GEMINI_API_KEY)

def load_seen_ids():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return set(json.load(f))
    return set()

def save_seen_ids(seen_ids):
    with open(STATE_FILE, "w") as f:
        json.dump(list(seen_ids), f)

def analyze_and_translate_with_gemini(title, summary):
    prompt = f"""
    تو یک دستیار هوشمند خبری هستی.
    
    علاقه‌مندی‌های کاربر: {', '.join(USER_INTERESTS)}
    
    عنوان خبر: {title}
    متن/خلاصه خبر: {summary}
    
    وظایف:
    ۱. بررسی کن آیا این خبر به یکی از علاقه‌مندی‌های کاربر مربوط است یا خیر.
    ۲. اگر مرتبط نیست، فقط بنویس: "REJECT"
    ۳. اگر مرتبط است، پاسخی دقیقاً به فرمت زیر به زبان فارسی بده (بدون اضافه کردن هیچ متن دیگری):
    
    CATEGORY: [نام دسته‌بندی مرتبط]
    TITLE: [ترجمه جذاب و دقیق عنوان به فارسی]
    SUMMARY: [خلاصه مفید خبر در ۲ الی ۴ جمله به فارسی روان]
    """

    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.2,
            ),
        )
        return response.text.strip()
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
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
    requests.post(url, json=payload)

def main():
    seen_ids = load_seen_ids()
    new_seen_ids = set(seen_ids)
    
    parsed_opml = listparser.parse(OPML_FILE)
    
    for feed in parsed_opml.feeds:
        feed_data = feedparser.parse(feed.url)
        
        for entry in feed_data.entries[:3]:
            post_id = entry.get("id", entry.link)
            if post_id in seen_ids:
                continue
                
            title = entry.get("title", "")
            summary = entry.get("summary", entry.get("description", ""))
            
            ai_result = analyze_and_translate_with_gemini(title, summary)
            
            if ai_result != "REJECT" and "CATEGORY:" in ai_result:
                try:
                    lines = ai_result.split("\n")
                    cat = [l for l in lines if l.startswith("CATEGORY:")][0].replace("CATEGORY:", "").strip()
                    title_fa = [l for l in lines if l.startswith("TITLE:")][0].replace("TITLE:", "").strip()
                    summary_fa = [l for l in lines if l.startswith("SUMMARY:")][0].replace("SUMMARY:", "").strip()
                    
                    send_telegram(title_fa, summary_fa, entry.link, cat)
                except Exception as e:
                    print(f"Error parsing Gemini response: {e}")

            new_seen_ids.add(post_id)

    save_seen_ids(new_seen_ids)

if __name__ == "__main__":
    main()
