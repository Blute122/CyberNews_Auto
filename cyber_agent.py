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

DAILY_POST_CAP        = 7    # Max tweets per day (UTC)
ARTICLE_MAX_AGE_HOURS = 6    # Skip articles older than this

RSS_FEEDS = [
    {"url": "https://feeds.feedburner.com/TheHackersNews", "name": "The Hacker News"},
    {"url": "https://www.bleepingcomputer.com/feed/",      "name": "BleepingComputer"},
    {"url": "https://www.darkreading.com/rss.xml",         "name": "Dark Reading"},
    {"url": "https://cyberscoop.com/feed/",                "name": "CyberScoop"},
    {"url": "https://krebsonsecurity.com/feed/",           "name": "Krebs on Security"},
]

HISTORY_FILE = "posted_urls.txt"
DB_FILE      = "database.json"

COLOR_MAP = {
    "🔴": "#ff4757",
    "🟠": "#ffa502",
    "🟡": "#eccc68",
    "🟢": "#2ed573",
}

# Strict CVE pattern — rejects any placeholder like CVE-XXXX-XXXXX
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}$", re.IGNORECASE)


# ─────────────────────────────────────────────
# DAILY CAP
# ─────────────────────────────────────────────
def get_todays_post_count() -> int:
    if not os.path.exists(DB_FILE) or os.path.getsize(DB_FILE) == 0:
        return 0
    try:
        with open(DB_FILE, "r") as f:
            db_data = json.load(f)
    except json.JSONDecodeError:
        return 0
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
# NVD CVSS LOOKUP
# ─────────────────────────────────────────────
def get_nvd_cvss(cve_id: str):
    time.sleep(1)  # Respect NVD rate limits
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
# GROQ — SINGLE CALL, 3 FIELDS ONLY
# ─────────────────────────────────────────────
def generate_content(title: str, summary: str, source_name: str) -> dict | None:
    """
    One Groq call. Returns a dict with:
        severity_icon, cve, threat_actor, target, tweet, card_summary, simply_put
    Returns None if the article should be skipped.
    """
    client = Groq(api_key=GROQ_API_KEY)

    prompt = f"""You are a cyber threat intelligence analyst. Analyze the article and return a JSON object.

CONTENT FILTER: If the article is a contest, giveaway, advertisement, webinar, opinion piece, or sponsored content — return exactly: {{"skip": true}}

SEVERITY RULES (pick ONE emoji):
🔴 CRITICAL — confirmed data breach, ransomware deployed, active zero-day, state-sponsored APT
🟠 HIGH     — CVSS 7.0-8.9, new malware variant, large phishing campaign
🟡 MEDIUM   — vulnerability with no active exploitation, security research
🟢 LOW      — policy update, industry news, minor bug

OUTPUT: Return ONLY a valid JSON object. No markdown, no backticks, no extra text.

{{
  "skip": false,
  "severity_icon": "<one emoji>",
  "cve": "<exact CVE-YYYY-NNNNN if explicitly stated in the article, else empty string>",
  "threat_actor": "<attacker or group name if present, else empty string>",
  "target": "<affected software or organization if present, else empty string>",
  "tweet": "<A single punchy tweet. Lead with the severity emoji. State WHAT happened and WHO is affected. End with 'via {source_name}' and 1-2 relevant hashtags. STRICT MAX: 210 CHARACTERS. Count carefully.>",
  "card_summary": "<1-2 sentence factual summary for the threat card image. Max 130 chars.>",
  "simply_put": "<1 sentence plain-English explanation for a non-technical reader. Max 100 chars.>"
}}

STRICT RULES:
- cve field: only write a real CVE ID (e.g. CVE-2024-12345). If none is in the article, write empty string "". Never invent or guess.
- tweet must be 210 characters or fewer BEFORE any CVSS injection happens in post-processing.
- No mitigation advice, recommendations, or speculation anywhere.
- All fields must be factual and sourced only from the article provided.

ARTICLE:
Title: {title}
Summary: {summary}"""

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
    )

    raw = response.choices[0].message.content.strip()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print(f"Failed to parse Groq JSON:\n{raw}")
        return None

    if data.get("skip"):
        return None

    # Validate CVE strictly — reject placeholders, partial matches, invented IDs
    cve = data.get("cve", "").strip()
    if cve and not CVE_PATTERN.fullmatch(cve):
        print(f"Rejected invalid CVE: '{cve}'")
        data["cve"] = ""

    return data


# ─────────────────────────────────────────────
# THREAT CARD — FIXED ZONE LAYOUT
# ─────────────────────────────────────────────
def generate_threat_card(severity_icon: str, title: str, card_summary: str,
                         cve: str, target: str, simply_put: str, source_site: str) -> str:
    """
    Three fixed vertical zones so THREAT and TARGET always render
    regardless of title or summary length.

    Zone 1 (top)    — Alert label + title + summary + source
    Zone 2 (middle) — THREAT row + TARGET row
    Zone 3 (bottom) — SIMPLY PUT footer
    """
    W, H      = 1024, 512
    FOOTER_H  = 95   # Zone 3 height
    META_H    = 85   # Zone 2 height
    HEADER_H  = H - FOOTER_H - META_H  # Zone 1 height (~332px)

    bg_color     = "#0d1117"
    footer_color = "#161b22"
    accent_color = COLOR_MAP.get(severity_icon, "#ff4757")
    text_primary   = "#ffffff"
    text_secondary = "#8b949e"

    image = Image.new("RGB", (W, H), color=bg_color)
    draw  = ImageDraw.Draw(image)

    try:
        f_label  = ImageFont.truetype("Roboto-Bold.ttf",   18)
        f_title  = ImageFont.truetype("Roboto-Bold.ttf",   30)
        f_body   = ImageFont.truetype("Roboto-Medium.ttf", 20)
        f_meta_l = ImageFont.truetype("Roboto-Bold.ttf",   19)
        f_meta_v = ImageFont.truetype("Roboto-Medium.ttf", 20)
        f_foot_l = ImageFont.truetype("Roboto-Bold.ttf",   16)
        f_foot_v = ImageFont.truetype("Roboto-Medium.ttf", 20)
    except OSError:
        f_label = f_title = f_body = f_meta_l = f_meta_v = \
        f_foot_l = f_foot_v = ImageFont.load_default()

    MX = 45  # Horizontal margin

    # ── Top accent bar ──────────────────────────────────
    draw.rectangle([(0, 0), (W, 10)], fill=accent_color)

    def line_height(font) -> int:
        bbox = font.getbbox("Ag")
        return bbox[3] - bbox[1]

    def draw_lines_clipped(text: str, font, x: int, y: int, fill, max_y: int,
                           width_chars: int = 80, padding: int = 5) -> int:
        """Wraps and draws text lines, stopping before max_y. Returns final y."""
        for line in textwrap.TextWrapper(width=width_chars).wrap(text):
            lh = line_height(font)
            if y + lh > max_y:
                break
            draw.text((x, y), line, font=font, fill=fill)
            y += lh + padding
        return y

    # ── ZONE 1: Header ──────────────────────────────────
    zone1_top    = 14
    zone1_bottom = HEADER_H   # ~332

    y = zone1_top + 8
    draw.text((MX, y), "THREAT INTELLIGENCE ALERT", font=f_label, fill=accent_color)
    y += 26

    # Title — hard cap at 2 lines
    for line in textwrap.TextWrapper(width=52).wrap(title)[:2]:
        lh = line_height(f_title)
        if y + lh > zone1_bottom - 65:
            break
        draw.text((MX, y), line, font=f_title, fill=text_primary)
        y += lh + 6
    y += 4

    # Summary
    draw_lines_clipped(card_summary, f_body, MX, y, "#c9d1d9", zone1_bottom - 28,
                       width_chars=85, padding=4)

    # Source — pinned to bottom of zone 1
    if source_site:
        src_h = line_height(f_body)
        draw.text((MX, zone1_bottom - src_h - 2),
                  f"Source: {source_site}", font=f_body, fill=text_secondary)

    # ── Divider ─────────────────────────────────────────
    div_y = zone1_bottom
    draw.line([(MX, div_y), (W - MX, div_y)], fill="#30363d", width=2)

    # ── ZONE 2: Meta (THREAT + TARGET always render here) ─
    zone2_top   = div_y + 12
    meta_col2_x = MX + 120
    row_y       = zone2_top

    if cve:
        lh = line_height(f_meta_l)
        draw.text((MX, row_y), "THREAT:", font=f_meta_l, fill=text_secondary)
        cve_text = cve if len(cve) <= 58 else cve[:55] + "…"
        draw.text((meta_col2_x, row_y), cve_text, font=f_meta_v, fill=accent_color)
        row_y += lh + 10

    if target:
        draw.text((MX, row_y), "TARGET:", font=f_meta_l, fill=text_secondary)
        target_text = target if len(target) <= 58 else target[:55] + "…"
        draw.text((meta_col2_x, row_y), target_text, font=f_meta_v, fill=text_primary)

    # ── ZONE 3: Footer (SIMPLY PUT) ─────────────────────
    footer_top = H - FOOTER_H
    draw.rectangle([(0, footer_top), (W, H)], fill=footer_color)
    draw.line([(0, footer_top), (W, footer_top)], fill="#30363d", width=2)

    draw.text((MX, footer_top + 10), "SIMPLY PUT:", font=f_foot_l, fill=text_secondary)
    draw_lines_clipped(simply_put, f_foot_v, MX, footer_top + 32,
                       text_primary, H - 6, width_chars=90, padding=4)

    output_filename = "threat_card.png"
    image.save(output_filename, "PNG")
    return output_filename


# ─────────────────────────────────────────────
# TWITTER — SINGLE TWEET ONLY ($0.01 per run)
# ─────────────────────────────────────────────
def post_tweet(text: str, media_path: str = None):
    client_v2 = tweepy.Client(
        consumer_key=X_API_KEY,
        consumer_secret=X_API_SECRET,
        access_token=X_ACCESS_TOKEN,
        access_token_secret=X_ACCESS_TOKEN_SECRET,
    )

    media_id = None
    if media_path and os.path.exists(media_path):
        auth   = tweepy.OAuth1UserHandler(
            X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET
        )
        api_v1 = tweepy.API(auth)
        media  = api_v1.media_upload(filename=media_path)
        media_id = media.media_id

    kwargs = {"text": text}
    if media_id:
        kwargs["media_ids"] = [media_id]

    response = client_v2.create_tweet(**kwargs)
    print(f"Tweet posted. ID: {response.data['id']}")


# ─────────────────────────────────────────────
# SAFE TWEET TRIMMER
# ─────────────────────────────────────────────
def safe_trim(text: str, limit: int = 278) -> str:
    """
    Trims to limit chars, breaking at the last whole word.
    Appends '…' only if trimmed. Never cuts mid-word.
    Note: Twitter t.co shortens URLs to ~23 chars regardless of
    original length, so 278 chars of text is safe.
    """
    if len(text) <= limit:
        return text
    trimmed = text[:limit].rsplit(" ", 1)[0]
    return trimmed.rstrip(".,;:—-") + "…"


# ─────────────────────────────────────────────
# DISCORD ERROR ALERTS
# ─────────────────────────────────────────────
def send_discord_alert(error_message: str):
    if not DISCORD_WEBHOOK_URL:
        return
    data = {
        "content": (
            f"🚨 **CyberNewsBot Crash Report** 🚨\n"
            f"```python\n{error_message}\n```"
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

    # Daily cap check
    todays_count = get_todays_post_count()
    if todays_count >= DAILY_POST_CAP:
        print(f"Daily cap of {DAILY_POST_CAP} reached ({todays_count} posts today). Exiting.")
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

            # Age filter (strict UTC)
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                article_time = datetime.fromtimestamp(timegm(entry.published_parsed), timezone.utc)
                if datetime.now(timezone.utc) - article_time > timedelta(hours=ARTICLE_MAX_AGE_HOURS):
                    print("Skipping old article.")
                    continue

            try:
                # ── Single Groq call ──────────────────────────
                print("Calling Groq...")
                data = generate_content(entry.title, entry.description, feed_info["name"])

                if data is None:
                    save_posted_url(entry.link)
                    print("Skipped (non-threat content).")
                    continue

                severity_icon = data.get("severity_icon", "🟡")
                cve           = data.get("cve", "").strip()
                threat_actor  = data.get("threat_actor", "").strip()
                target        = data.get("target", "").strip()
                tweet_text    = data.get("tweet", "").strip()
                card_summary  = data.get("card_summary", "").strip()
                simply_put    = data.get("simply_put", "").strip()

                # ── NVD CVSS enrichment ───────────────────────
                if cve:
                    print(f"Fetching CVSS for {cve}...")
                    cvss_score = get_nvd_cvss(cve)

                    # Override severity emoji from official score
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

                    # Inject CVSS into tweet text
                    if cvss_score not in ["N/A", "Score Pending"]:
                        score_str = f"{cve} (CVSS: {cvss_score}/10)"
                    else:
                        score_str = f"{cve} (CVSS: {cvss_score})"

                    tweet_text = tweet_text.replace(cve, score_str)

                # ── Safe trim AFTER CVSS injection ────────────
                tweet_text = safe_trim(tweet_text, limit=278)

                print(f"\nSeverity : {severity_icon}")
                print(f"CVE      : {cve or 'N/A'}")
                print(f"Target   : {target or 'N/A'}")
                print(f"Tweet    : {tweet_text}")
                print(f"Length   : {len(tweet_text)} chars\n")

                # ── Generate threat card ──────────────────────
                card_filename = None
                try:
                    card_filename = generate_threat_card(
                        severity_icon,
                        entry.title,
                        card_summary,
                        cve,
                        target or threat_actor,
                        simply_put,
                        feed_info["name"],
                    )
                    print(f"Threat card generated: {card_filename}")
                except Exception as img_e:
                    print(f"Threat card failed: {img_e}")

                # ── Post single tweet ($0.01) ─────────────────
                print("Posting to X...")
                post_tweet(tweet_text, media_path=card_filename)

                # ── Persist ───────────────────────────────────
                save_posted_url(entry.link)

                db_data = load_db()
                db_data.append({
                    "date":    datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                    "content": tweet_text,
                    "url":     entry.link,
                })
                save_db(db_data)

                print("Agent finished successfully. Exiting.")
                return  # One tweet per GitHub Actions run

            except Exception as e:
                print(f"Error processing article: {e}")
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