#!/usr/bin/env python3
# File: modules/intel/threat_feed_watcher.py

import feedparser
import time
import json
from datetime import datetime

RSS_FEEDS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.xml",
    "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",
    "https://packetstormsecurity.com/rss/"
]

ALERT_FILE = "webgui/alerts.json"
MAX_ITEMS = 10

def parse_feeds():
    entries = []
    for url in RSS_FEEDS:
        feed = feedparser.parse(url)
        for entry in feed.entries[:MAX_ITEMS]:
            entries.append({
                "title": entry.title,
                "link": entry.link,
                "published": entry.get("published", datetime.utcnow().isoformat()),
                "source": url
            })
    return entries

def save_alerts(entries):
    print(f"[+] Writing {len(entries)} new threat alerts to {ALERT_FILE}")
    with open(ALERT_FILE, "w") as f:
        json.dump(entries, f, indent=2)

if __name__ == "__main__":
    print("[*] Fetching and parsing threat feeds...")
    alerts = parse_feeds()
    save_alerts(alerts)
