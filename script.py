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
    "امنیتی و هک و اکسپلویت",
    "هوش مصنوعی و مدل‌های زبانی",
    "اخبار لینوکس و سیستم‌عامل",
    "برنامه‌نویسی و مهندسی معکوس"
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
