headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityBot/1.0'}
try:
    response = requests.get(feed.url, headers=headers, timeout=15)
    feed_data = feedparser.parse(response.content)
except Exception as e:
    print(f"Error fetching {feed.url}: {e}")
    continue
