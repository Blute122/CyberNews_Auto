import os
import random
import re
import feedparser
import tweepy
import requests
import traceback
import json
from datetime import datetime, timedelta, timezone
from time import mktime
from groq import Groq
from PIL import Image, ImageDraw, ImageFont
import textwrap

# Fetch environment variables for GitHub Actions
X_API_KEY = os.environ.get("X_API_KEY")
X_API_SECRET = os.environ.get("X_API_SECRET")
X_ACCESS_TOKEN = os.environ.get("X_ACCESS_TOKEN")
X_ACCESS_TOKEN_SECRET = os.environ.get("X_ACCESS_TOKEN_SECRET")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL")

RSS_FEEDS = [
    {"url": "https://feeds.feedburner.com/TheHackersNews", "name": "The Hacker News"},
    {"url": "https://www.bleepingcomputer.com/feed/", "name": "BleepingComputer"},
    {"url": "https://www.darkreading.com/rss.xml", "name": "Dark Reading"},
    {"url": "https://cyberscoop.com/feed/", "name": "CyberScoop"},
    {"url": "https://krebsonsecurity.com/feed/", "name": "Krebs on Security"}
]

HISTORY_FILE = "posted_urls.txt"

# Severity Color Map
COLOR_MAP = {
    '🔴': '#e74c3c', # Critical Red
    '🟠': '#e67e22', # High Orange
    '🟡': '#f1c40f', # Medium Yellow
    '🟢': '#2ecc71'  # Low Green
}

def generate_threat_card(severity_icon, technical_title, bluf_summary, cve, threat_actor, simply_put_summary):
    """Dynamically generates a highly structured 1024x512 Threat Card image."""
    card_width = 1024
    card_height = 512
    bg_color = COLOR_MAP.get(severity_icon, '#34495e') 
    
    image = Image.new('RGB', (card_width, card_height), color=bg_color)
    draw = ImageDraw.Draw(image)
    
    # Fonts
    try:
        font_alert = ImageFont.truetype("Roboto-Bold.ttf", 24)
        font_title = ImageFont.truetype("Roboto-Bold.ttf", 42)
        font_body = ImageFont.truetype("Roboto-Bold.ttf", 28)
        font_meta_label = ImageFont.truetype("Roboto-Bold.ttf", 28)
        font_meta_data = ImageFont.truetype("Roboto-Bold.ttf", 28)
        font_footer_head = ImageFont.truetype("Roboto-Bold.ttf", 20)
        font_footer_body = ImageFont.truetype("Roboto-Bold.ttf", 24)
    except OSError:
        font_alert = font_title = font_body = font_meta_label = font_meta_data = font_footer_head = font_footer_body = ImageFont.load_default()

    text_color = "black" if bg_color in ['#f1c40f', '#2ecc71'] else "white" # High contrast text
    margin_x = 40
    current_y = 30 

    # Helper function for dynamic text wrapping and drawing
    def draw_wrapped_text(text, font, max_chars, x, y, fill_color):
        wrapper = textwrap.TextWrapper(width=max_chars)
        lines = wrapper.wrap(text)
        for line in lines:
            draw.text((x, y), line, font=font, fill=fill_color)
            # Use font.getbbox to calculate height of the line plus some padding
            bbox = font.getbbox(line)
            line_height = bbox[3] - bbox[1]
            y += line_height + 8 
        return y

    # 1. Header
    draw.text((margin_x, current_y), "THREAT INTELLIGENCE ALERT", font=font_alert, fill=text_color)
    current_y += 40

    # 2. Technical Title
    current_y = draw_wrapped_text(technical_title, font_title, 45, margin_x, current_y, text_color)
    current_y += 15

    # 3. BLUF Summary
    current_y = draw_wrapped_text(f"Summary: {bluf_summary}", font_body, 70, margin_x, current_y, text_color)
    current_y += 20

    # 4. Metadata Section (Two-column layout)
    draw.text((margin_x, current_y), "METADATA", font=font_alert, fill=text_color)
    current_y += 35
    
    meta_x_col2 = margin_x + 160
    
    if cve:
        draw.text((margin_x, current_y), "🚨 THREAT:", font=font_meta_label, fill=text_color)
        draw.text((meta_x_col2, current_y), cve, font=font_meta_data, fill=text_color)
        current_y += 40
        
    if threat_actor:
        draw.text((margin_x, current_y), "🎯 TARGET:", font=font_meta_label, fill=text_color)
        draw_wrapped_text(threat_actor, font_meta_data, 50, meta_x_col2, current_y, text_color)
        current_y += 40

    # 5. Simply Put Footer (Dark Box at the bottom)
    footer_height = 110
    footer_top = card_height - footer_height
    draw.rectangle([(0, footer_top), (card_width, card_height)], fill="#2c3e50")
    
    draw.text((margin_x, footer_top + 15), "SIMPLY PUT:", font=font_footer_head, fill="#95a5a6")
    draw_wrapped_text(simply_put_summary, font_footer_body, 80, margin_x, footer_top + 40, "white")

    output_filename = "threat_card.jpg"
    image.save(output_filename, "JPEG", quality=95)
    return output_filename

def get_posted_urls():
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE, "r") as file:
        return file.read().splitlines()

def save_posted_url(url):
    with open(HISTORY_FILE, "a") as file:
        file.write(url + "\n")

def generate_tweet(title, summary, source_name):
    client = Groq(api_key=GROQ_API_KEY)
    
    prompt = f"""You are an elite cyber threat intelligence analyst. Your job is to read cybersecurity articles, extract actionable intelligence, and summarize the threat into a highly structured format.

STRICT RULES:
1. CONTENT FILTER: If the article is a contest, giveaway, advertisement, webinar, opinion piece, or sponsored marketing, output exactly the word "SKIP" and nothing else.
2. THREAT LEVEL SCORING: You must categorize the threat strictly using these emoji guidelines. Start your response with the chosen emoji:
   - 🔴 CRITICAL: ALL data breaches (confirmed or claimed), ransomware deployments, active zero-day exploits, or state-sponsored APT activity.
   - 🟠 HIGH: High severity vulnerabilities (CVSS 7.0-8.9), new malware variants, or large-scale phishing campaigns.
   - 🟡 MEDIUM: Discovered vulnerabilities with no active exploitation, or general security research.
   - 🟢 LOW: Policy updates, industry news, or minor bugs.
3. FORMATTING: You must follow this EXACT structure. Do not deviate or add conversational text.
   
   [Emoji from Rule 2] [A 1-2 sentence high-level summary of the incident, breach, or discovery (BLUF format).]
   
   🚨 Threat: [Technical name, Threat Actor, and/or CVE]
   🎯 Target: [The affected software, hardware, or organization]
   ⚠️ Simply Put: [A 1-sentence, zero-jargon explanation of the risk so a beginner can easily understand]
   
   According to {source_name}. #[Tag1] #[Tag2]

4. MISSING DATA: If the Threat or Target is not explicitly mentioned in the article, omit that specific bullet point entirely. 
5. LENGTH: The entire output MUST be as concise as possible to fit Twitter character limits.

EXAMPLE OUTPUT:
🔴 ShinyHunters claims a successful data breach against Instructure, allegedly stealing massive amounts of user data and offering it for sale on dark web forums.

🚨 Threat: ShinyHunters
🎯 Target: Instructure
⚠️ Simply Put: Hackers broke into an education technology company's database and stole private user information.

According to BleepingComputer. #DataBreach #ShinyHunters

ACTUAL INPUT:
Title: {title}
Summary: {summary}"""

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[
            {"role": "user", "content": prompt}
        ]
    )
    
    # Strip any stray quotes the AI might have included
    tweet_text = response.choices[0].message.content.strip(' "\'')
    return tweet_text

def post_to_x(tweet_text, media_path=None):
    client_v2 = tweepy.Client(
        consumer_key=X_API_KEY,
        consumer_secret=X_API_SECRET,
        access_token=X_ACCESS_TOKEN,
        access_token_secret=X_ACCESS_TOKEN_SECRET
    )
    
    try:
        if media_path and os.path.exists(media_path):
            auth = tweepy.OAuth1UserHandler(
                X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET
            )
            api_v1 = tweepy.API(auth)
            # 1. Upload the image using v1.1
            media = api_v1.media_upload(filename=media_path)
            media_id = media.media_id
            
            # 2. Post the tweet using v2, attaching the media_id
            response = client_v2.create_tweet(text=tweet_text, media_ids=[media_id])
        else:
            response = client_v2.create_tweet(text=tweet_text)
        print(f"Success! Tweet ID: {response.data['id']}")
    except Exception as e:
        print(f"Error posting tweet: {e}")
        if media_path:
            print("Falling back to text-only tweet...")
            response = client_v2.create_tweet(text=tweet_text)
            print(f"Success! Tweet ID: {response.data['id']}")
        else:
            raise e

def send_discord_alert(error_message):
    if not DISCORD_WEBHOOK_URL:
        print("No Discord Webhook URL configured. Skipping alert.")
        return

    data = {
        "content": f"🚨 **CyberNewsBot Crash Report** 🚨\nAn error occurred during the latest run:\n```python\n{error_message}\n```"
    }
    
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=data)
    except Exception as e:
        print(f"Failed to send Discord alert: {e}")

def get_nvd_cvss(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        # NIST API can be slow, adding a 10-second timeout
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                metrics = vulns[0].get("cve", {}).get("metrics", {})
                # Try v3.1 first, then v3.0
                if "cvssMetricV31" in metrics:
                    return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV3" in metrics:
                    return metrics["cvssMetricV3"][0]["cvssData"]["baseScore"]
                else:
                    return "Score Pending"
    except Exception as e:
        print(f"NVD API Error: {e}")
    return "N/A"

def run_agent():
    print("Agent waking up. Checking for new cybersecurity news...")
    random.shuffle(RSS_FEEDS)
    posted_urls = get_posted_urls()
    
    for feed_info in RSS_FEEDS:
        print(f"Checking feed: {feed_info['name']}")
        feed = feedparser.parse(feed_info["url"])
        
        for entry in feed.entries:
            if entry.link not in posted_urls:
                print(f"New article found: {entry.title}")
                if hasattr(entry, 'published_parsed'):
                    article_time = datetime.fromtimestamp(mktime(entry.published_parsed))
                    if datetime.now() - article_time > timedelta(hours=6):
                        print(f"Skipping old article: {entry.title}")
                        continue
                try:
                    print("Asking Groq to write the tweet...")
                    tweet = generate_tweet(entry.title, entry.description, feed_info["name"])
                    
                    if "SKIP" in tweet:
                        save_posted_url(entry.link)
                        print("Skipped promotional content.")
                        continue
                    
                    # Check if Groq included a CVE in the generated tweet
                    cve_match = re.search(r'(CVE-\d{4}-\d+)', tweet)
                    
                    if cve_match:
                        cve_id = cve_match.group(1)
                        print(f"Extracted {cve_id}. Fetching official CVSS score from NIST...")
                        cvss_score = get_nvd_cvss(cve_id)
                        
                        # Dynamically set the threat color based on the CVSS v3.1 scale
                        try:
                            score_float = float(cvss_score)
                            if score_float >= 9.0:
                                threat_color = "🔴" # Critical
                            elif score_float >= 7.0:
                                threat_color = "🟠" # High
                            elif score_float >= 4.0:
                                threat_color = "🟡" # Medium
                            else:
                                threat_color = "🟢" # Low
                                
                            # Replace the default yellow emoji with the calculated severity color
                            tweet = tweet.replace("🟡", threat_color)
                        except ValueError:
                            # If the score is "Score Pending" or "N/A", leave the emoji as is
                            pass
                        
                        # Inject the score into the tweet text
                        if cvss_score not in ["N/A", "Score Pending"]:
                            tweet = tweet.replace(cve_id, f"{cve_id} (CVSS: {cvss_score}/10)")
                        else:
                            tweet = tweet.replace(cve_id, f"{cve_id} (CVSS: {cvss_score})")
                    
                    print(f"Drafted Tweet:\n{tweet}\n")
                    
                    # --- PARSE GROQ OUTPUT ---
                    parts = tweet.strip().split('\n')
                    
                    severity_icon = parts[0][:1] 
                    
                    # Extract the BLUF summary from the first line (removing the emoji)
                    bluf_summary = parts[0][1:].strip()
                    
                    cve_id_to_pass = ""
                    threat_actor = ""
                    simply_put_summary = ""
                    hashtags = ""
                    
                    for line in parts:
                        if line.startswith("🚨 Threat:"): cve_id_to_pass = line.replace("🚨 Threat:", "").strip()
                        if line.startswith("🎯 Target:"): threat_actor = line.replace("🎯 Target:", "").strip()
                        if line.startswith("⚠️ Simply Put:"): simply_put_summary = line.replace("⚠️ Simply Put:", "").strip()
                        if "According to" in line: 
                            try:
                                hashtags = line.split("According to")[1].split(".")[1].strip()
                            except IndexError:
                                hashtags = "#CyberSecurity #InfoSec" # Fallback if parsing fails

                    # Re-extract CVE since it might have been modified with CVSS score
                    cve_match2 = re.search(r'(CVE-\d{4}-\d+)', tweet)
                    if cve_match2:
                        cve_id_to_pass = cve_match2.group(1)

                    technical_title = entry.title 

                    # --- GENERATE THE IMAGE ---
                    try:
                        card_filename = generate_threat_card(
                            severity_icon, technical_title, bluf_summary, cve_id_to_pass, threat_actor, simply_put_summary
                        )
                    except Exception as img_e:
                        print(f"Failed to generate threat card image: {img_e}")
                        card_filename = None

                    # --- COMPILE THE SHORT TWEET ---
                    # The text payload is dramatically shortened to prevent 403 Spam filtering
                    short_tweet = f"{severity_icon} {bluf_summary[:100]}...\n\nFull details in the threat card below 👇\n\n{hashtags}"
                    
                    # Failsafe limit
                    if len(short_tweet) > 270:
                        short_tweet = short_tweet[:267] + "..."

                    print("Posting to X...")
                    post_to_x(short_tweet, media_path=card_filename)
                    save_posted_url(entry.link)
                    
                    # Update database.json
                    db_file = "database.json"
                    if os.path.exists(db_file) and os.path.getsize(db_file) > 0:
                        try:
                            with open(db_file, "r") as f:
                                db_data = json.load(f)
                        except json.JSONDecodeError:
                            db_data = []
                    else:
                        db_data = []
                        
                    db_data.append({
                        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                        "content": tweet,
                        "url": entry.link
                    })
                    
                    with open(db_file, "w") as f:
                        json.dump(db_data, f, indent=4)

                    
                    print("Agent finished successfully. Exiting.")
                    return # Instantly exit execution flow after one tweet
                except Exception as e:
                    print(f"An error occurred: {e}")
                    return # Exit on error
                    
    print("No new articles found. Exiting.")

if __name__ == "__main__":
    try:
        run_agent()
    except Exception as e:
        # If anything crashes, grab the detailed error trace and send it to Discord
        error_details = traceback.format_exc()
        print(f"CRITICAL ERROR: {e}")
        send_discord_alert(error_details)
        raise e  # Re-raise the error so GitHub Actions correctly logs it as a "Failed" run
