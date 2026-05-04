import os
import random
import re
import time
import feedparser
import tweepy
import requests
import traceback
import json
from datetime import datetime, timedelta, timezone
from calendar import timegm
from groq import Groq
from PIL import Image, ImageDraw, ImageFont
import textwrap

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
X_API_KEY             = os.environ.get("X_API_KEY")
X_API_SECRET          = os.environ.get("X_API_SECRET")
X_ACCESS_TOKEN        = os.environ.get("X_ACCESS_TOKEN")
X_ACCESS_TOKEN_SECRET = os.environ.get("X_ACCESS_TOKEN_SECRET")
GROQ_API_KEY          = os.environ.get("GROQ_API_KEY")
DISCORD_WEBHOOK_URL   = os.environ.get("DISCORD_WEBHOOK_URL")

DAILY_POST_CAP = 7          # Maximum tweets/threads per day
ARTICLE_MAX_AGE_HOURS = 6   # Skip articles older than this

RSS_FEEDS = [
    {"url": "https://feeds.feedburner.com/TheHackersNews",  "name": "The Hacker News"},
    {"url": "https://www.bleepingcomputer.com/feed/",       "name": "BleepingComputer"},
    {"url": "https://www.darkreading.com/rss.xml",          "name": "Dark Reading"},
    {"url": "https://cyberscoop.com/feed/",                 "name": "CyberScoop"},
    {"url": "https://krebsonsecurity.com/feed/",            "name": "Krebs on Security"},
]

HISTORY_FILE = "posted_urls.txt"
DB_FILE      = "database.json"

COLOR_MAP = {
    "🔴": "#ff4757",
    "🟠": "#ffa502",
    "🟡": "#eccc68",
    "🟢": "#2ed573",
}

# ─────────────────────────────────────────────
# DAILY CAP HELPERS
# ─────────────────────────────────────────────
def get_todays_post_count() -> int:
    """Count how many entries were added to database.json today (Strict UTC)."""
    if not os.path.exists(DB_FILE) or os.path.getsize(DB_FILE) == 0:
        return 0
    try:
        with open(DB_FILE, "r") as f:
            db_data = json.load(f)
    except json.JSONDecodeError:
        return 0

    # TWEAK: Strict UTC time to prevent server timezone desync
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return sum(1 for item in db_data if item.get("date", "").startswith(today_str))

# ─────────────────────────────────────────────
# URL HISTORY & DATABASE
# ─────────────────────────────────────────────
def get_posted_urls() -> list:
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE, "r") as f:
        return f.read().splitlines()

def save_posted_url(url: str):
    with open(HISTORY_FILE, "a") as f:
        f.write(url + "\n")

def load_db() -> list:
    if not os.path.exists(DB_FILE) or os.path.getsize(DB_FILE) == 0:
        return []
    try:
        with open(DB_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []

def save_db(db_data: list):
    with open(DB_FILE, "w") as f:
        json.dump(db_data, f, indent=4)

# ─────────────────────────────────────────────
# THREAT CARD IMAGE
# ─────────────────────────────────────────────
def generate_threat_card(severity_icon, technical_title, bluf_summary,
                         cve, threat_actor, simply_put_summary, source_site) -> str:
    """Generates a premium dark-mode PNG threat card."""
    card_width  = 1024
    card_height = 512

    bg_color     = "#0d1117"
    footer_color = "#161b22"
    accent_color = COLOR_MAP.get(severity_icon, "#ff4757")
    text_primary   = "#ffffff"
    text_secondary = "#8b949e"

    image = Image.new("RGB", (card_width, card_height), color=bg_color)
    draw  = ImageDraw.Draw(image)

    # TWEAK: Fallback size limits for missing fonts
    try:
        font_alert       = ImageFont.truetype("Roboto-Bold.ttf",   22)
        font_title       = ImageFont.truetype("Roboto-Bold.ttf",   38)
        font_body        = ImageFont.truetype("Roboto-Medium.ttf", 26)
        font_meta_label  = ImageFont.truetype("Roboto-Bold.ttf",   24)
        font_meta_data   = ImageFont.truetype("Roboto-Medium.ttf", 26)
        font_footer_head = ImageFont.truetype("Roboto-Bold.ttf",   20)
        font_footer_body = ImageFont.truetype("Roboto-Medium.ttf", 24)
    except OSError:
        # NOTE: Ensure the Roboto .ttf files are uploaded to your repo to avoid this!
        print("WARNING: Custom fonts not found. Falling back to default.")
        font_alert = font_title = font_body = font_meta_label = \
        font_meta_data = font_footer_head = font_footer_body = ImageFont.load_default()

    margin_x  = 45
    current_y = 40

    draw.rectangle([(0, 0), (card_width, 12)], fill=accent_color)

    def draw_wrapped_text(text, font, width_chars, x, y, fill_color, padding=8):
        wrapper = textwrap.TextWrapper(width=width_chars)
        lines   = wrapper.wrap(text)
        for line in lines:
            draw.text((x, y), line, font=font, fill=fill_color)
            bbox = font.getbbox(line)
            y += (bbox[3] - bbox[1]) + padding
        return y + padding

    draw.text((margin_x, current_y), "THREAT INTELLIGENCE ALERT", font=font_alert, fill=accent_color)
    current_y += 35

    current_y = draw_wrapped_text(technical_title, font_title, 48, margin_x, current_y, text_primary, padding=12)
    current_y += 10

    current_y = draw_wrapped_text(f"Summary: {bluf_summary}", font_body, 75, margin_x, current_y, "#c9d1d9")
    if source_site:
        current_y = draw_wrapped_text(f"Source: {source_site}", font_body, 75, margin_x, current_y, text_secondary, padding=5)
    current_y += 20

    draw.line([(margin_x, current_y), (card_width - margin_x, current_y)], fill="#30363d", width=2)
    current_y += 25

    meta_x_col2 = margin_x + 140

    if cve:
        draw.text((margin_x, current_y), "THREAT:", font=font_meta_label, fill=text_secondary)
        current_y = draw_wrapped_text(cve, font_meta_data, 55, meta_x_col2, current_y, accent_color)

    if threat_actor:
        current_y += 10
        draw.text((margin_x, current_y), "TARGET:", font=font_meta_label, fill=text_secondary)
        current_y = draw_wrapped_text(threat_actor, font_meta_data, 55, meta_x_col2, current_y, text_primary)

    footer_height = 110
    footer_top    = card_height - footer_height
    draw.rectangle([(0, footer_top), (card_width, card_height)], fill=footer_color)
    draw.line([(0, footer_top), (card_width, footer_top)], fill="#30363d", width=2)
    draw.text((margin_x, footer_top + 15), "SIMPLY PUT:", font=font_footer_head, fill=text_secondary)
    draw_wrapped_text(simply_put_summary, font_footer_body, 82, margin_x, footer_top + 45, text_primary, padding=5)

    output_filename = "threat_card.png"
    image.save(output_filename, "PNG")
    return output_filename

# ─────────────────────────────────────────────
# NVD CVSS LOOKUP
# ─────────────────────────────────────────────
def get_nvd_cvss(cve_id: str):
    # TWEAK: Adding a 1-second sleep to respect NVD API rate limits
    time.sleep(1) 
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data  = response.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                metrics = vulns[0].get("cve", {}).get("metrics", {})
                if "cvssMetricV31" in metrics:
                    return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV3" in metrics:
                    return metrics["cvssMetricV3"][0]["cvssData"]["baseScore"]
                return "Score Pending"
    except Exception as e:
        print(f"NVD API Error: {e}")
    return "N/A"

# ─────────────────────────────────────────────
# GROQ — STRICT JSON MODE
# ─────────────────────────────────────────────
def generate_thread_content(title: str, summary: str, source_name: str) -> dict | None:
    client = Groq(api_key=GROQ_API_KEY)

    prompt = f"""You are an elite cyber threat intelligence analyst. Read the cybersecurity article below and produce a structured Twitter thread in JSON format.

STRICT RULES:
1. CONTENT FILTER: If the article is a contest, giveaway, advertisement, webinar, opinion piece, or sponsored content, output exactly: {{"skip": true}}
2. THREAT LEVEL: Choose ONE severity emoji using these strict criteria:
   - 🔴 CRITICAL: Confirmed data breaches, ransomware deployments, active zero-day exploits, state-sponsored APT activity.
   - 🟠 HIGH: High severity vulnerabilities (CVSS 7.0-8.9), new malware variants, large-scale phishing campaigns.
   - 🟡 MEDIUM: Discovered vulnerabilities with no active exploitation, general security research.
   - 🟢 LOW: Policy updates, industry news, minor bugs.
3. OUTPUT FORMAT: Return ONLY valid JSON, no markdown, no backticks, no preamble. Schema:
{{
  "skip": false,
  "severity_icon": "<single emoji>",
  "cve": "<CVE-XXXX-XXXXX or empty string>",
  "threat_actor": "<name or empty string>",
  "target": "<affected software/org or empty string>",
  "hook": "<Tweet 1: 1-2 punchy sentences that stop the scroll. Lead with the severity emoji. State WHAT happened and to WHOM. Max 240 chars.>",
  "technical": "<Tweet 2: Factual technical breakdown. Include CVE, threat actor, target if available. Max 240 chars.>",
  "impact": "<Tweet 3: Real-world blast radius. Who is at risk, how many users/systems affected, what data or access is at stake. Strictly factual, no speculation. Max 240 chars.>",
  "closer": "<Tweet 4: Professional close. 'Reported by {source_name}. Follow for daily threat intelligence.' Then 2-3 relevant hashtags. Max 240 chars.>",
  "simply_put": "<1 sentence, zero-jargon explanation for the threat card image. Max 120 chars.>"
}}
4. MISSING DATA: If CVE, threat actor, or target is not in the article, use an empty string. Do NOT invent details.
5. FACTUAL ONLY: Do not include mitigation advice, recommendations, or speculation.

ARTICLE:
Title: {title}
Summary: {summary}"""

    # TWEAK: Enforcing strict JSON object output natively in the API call
    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"}
    )

    raw = response.choices[0].message.content.strip()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print(f"Failed to parse Groq JSON:\n{raw}")
        return None

    if data.get("skip"):
        return None

    return data

# ─────────────────────────────────────────────
# TWITTER POSTING
# ─────────────────────────────────────────────
def get_twitter_clients():
    client_v2 = tweepy.Client(
        consumer_key=X_API_KEY,
        consumer_secret=X_API_SECRET,
        access_token=X_ACCESS_TOKEN,
        access_token_secret=X_ACCESS_TOKEN_SECRET,
    )
    auth     = tweepy.OAuth1UserHandler(X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET)
    api_v1   = tweepy.API(auth)
    return client_v2, api_v1

def upload_media(api_v1, media_path: str):
    if media_path and os.path.exists(media_path):
        media = api_v1.media_upload(filename=media_path)
        return media.media_id
    return None

def post_thread(tweets: list[str], media_path: str = None):
    client_v2, api_v1 = get_twitter_clients()
    reply_to_id = None

    for i, text in enumerate(tweets):
        media_ids = None
        if i == 1 and media_path:
            media_id = upload_media(api_v1, media_path)
            if media_id:
                media_ids = [media_id]

        kwargs = {"text": text}
        if reply_to_id:
            kwargs["in_reply_to_tweet_id"] = reply_to_id
        if media_ids:
            kwargs["media_ids"] = media_ids

        response    = client_v2.create_tweet(**kwargs)
        reply_to_id = response.data["id"]
        print(f"  Tweet {i+1} posted. ID: {reply_to_id}")

    return reply_to_id

def post_single_tweet(text: str, media_path: str = None):
    client_v2, api_v1 = get_twitter_clients()
    media_ids = None
    if media_path:
        media_id = upload_media(api_v1, media_path)
        if media_id:
            media_ids = [media_id]

    kwargs = {"text": text}
    if media_ids:
        kwargs["media_ids"] = media_ids

    response = client_v2.create_tweet(**kwargs)
    print(f"  Single tweet posted. ID: {response.data['id']}")

# ─────────────────────────────────────────────
# DISCORD ERROR ALERTS
# ─────────────────────────────────────────────
def send_discord_alert(error_message: str):
    if not DISCORD_WEBHOOK_URL:
        print("No Discord Webhook URL configured. Skipping alert.")
        return
    data = {
        "content": (
            f"🚨 **CyberNewsBot Crash Report** 🚨\n"
            f"An error occurred during the latest run:\n```python\n{error_message}\n```"
        )
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=data)
    except Exception as e:
        print(f"Failed to send Discord alert: {e}")

# ─────────────────────────────────────────────
# MAIN AGENT
# ─────────────────────────────────────────────
def run_agent():
    print("Agent waking up. Checking for new cybersecurity news...")

    todays_count = get_todays_post_count()
    if todays_count >= DAILY_POST_CAP:
        print(f"Daily cap of {DAILY_POST_CAP} posts reached. Exiting.")
        return

    random.shuffle(RSS_FEEDS)
    posted_urls = get_posted_urls()

    for feed_info in RSS_FEEDS:
        print(f"Checking feed: {feed_info['name']}")
        feed = feedparser.parse(feed_info["url"])

        for entry in feed.entries:
            if entry.link in posted_urls:
                continue

            print(f"New article found: {entry.title}")

            # TWEAK: Bulletproof UTC time conversion
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                article_time = datetime.fromtimestamp(timegm(entry.published_parsed), timezone.utc)
                if datetime.now(timezone.utc) - article_time > timedelta(hours=ARTICLE_MAX_AGE_HOURS):
                    print("Skipping old article.")
                    continue

            try:
                print("Asking Groq to generate thread content...")
                thread_data = generate_thread_content(
                    entry.title,
                    entry.description,
                    feed_info["name"],
                )

                if thread_data is None:
                    save_posted_url(entry.link)
                    print("Skipped (promotional/non-threat content).")
                    continue

                severity_icon  = thread_data.get("severity_icon", "🟡")
                cve_id         = thread_data.get("cve", "")
                threat_actor   = thread_data.get("threat_actor", "")
                target         = thread_data.get("target", "")
                simply_put     = thread_data.get("simply_put", "")
                hook_tweet     = thread_data.get("hook", "")
                technical_tweet = thread_data.get("technical", "")
                impact_tweet   = thread_data.get("impact", "")
                closer_tweet   = thread_data.get("closer", "")

                if cve_id:
                    print(f"Fetching CVSS score for {cve_id}...")
                    cvss_score = get_nvd_cvss(cve_id)

                    try:
                        score_float = float(cvss_score)
                        if score_float >= 9.0:
                            severity_icon = "🔴"
                        elif score_float >= 7.0:
                            severity_icon = "🟠"
                        elif score_float >= 4.0:
                            severity_icon = "🟡"
                        else:
                            severity_icon = "🟢"
                    except ValueError:
                        pass

                    score_str = f"{cve_id} (CVSS: {cvss_score}/10)" if cvss_score not in ["N/A", "Score Pending"] \
                                else f"{cve_id} (CVSS: {cvss_score})"

                    technical_tweet = technical_tweet.replace(cve_id, score_str)
                    hook_tweet      = hook_tweet.replace(cve_id, score_str)

                print(f"\nSeverity: {severity_icon}")
                print(f"Hook:      {hook_tweet}")
                print(f"Technical: {technical_tweet}")
                print(f"Impact:    {impact_tweet}")
                print(f"Closer:    {closer_tweet}\n")

                try:
                    card_filename = generate_threat_card(
                        severity_icon,
                        entry.title,
                        hook_tweet.lstrip(severity_icon).strip(),
                        cve_id,
                        target or threat_actor,
                        simply_put,
                        feed_info["name"],
                    )
                except Exception as img_e:
                    print(f"Threat card generation failed: {img_e}")
                    card_filename = None

                is_high_priority = severity_icon in ("🔴", "🟠")

                print("Posting to X...")

                if is_high_priority:
                    tweets = [
                        hook_tweet,
                        technical_tweet,
                        impact_tweet,
                        closer_tweet,
                    ]
                    tweets = [t[:277] + "..." if len(t) > 280 else t for t in tweets]
                    post_thread(tweets, media_path=card_filename)
                else:
                    single = f"{hook_tweet}\n\n{closer_tweet}"
                    if len(single) > 280:
                        single = single[:277] + "..."
                    post_single_tweet(single, media_path=card_filename)

                save_posted_url(entry.link)

                db_data = load_db()
                db_data.append({
                    "date":    datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                    "content": "\n".join([hook_tweet, technical_tweet, impact_tweet, closer_tweet]),
                    "url":     entry.link,
                })
                save_db(db_data)

                print("Agent finished successfully. Exiting.")
                return 

            except Exception as e:
                print(f"An error occurred processing article: {e}")
                traceback.print_exc()
                return

    print("No new articles found. Exiting.")

# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    try:
        run_agent()
    except Exception as e:
        error_details = traceback.format_exc()
        print(f"CRITICAL ERROR: {e}")
        send_discord_alert(error_details)
        raise e