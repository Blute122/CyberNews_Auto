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

def post_to_x(tweet_text):
    client = tweepy.Client(
        consumer_key=X_API_KEY,
        consumer_secret=X_API_SECRET,
        access_token=X_ACCESS_TOKEN,
        access_token_secret=X_ACCESS_TOKEN_SECRET
    )
    response = client.create_tweet(text=tweet_text)
    print(f"Success! Tweet ID: {response.data['id']}")

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
                    print("Posting to X...")
                    post_to_x(tweet)
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