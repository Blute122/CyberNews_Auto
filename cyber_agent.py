import os
import random
import feedparser
import tweepy
from groq import Groq

# Fetch environment variables for GitHub Actions
X_API_KEY = os.environ.get("X_API_KEY")
X_API_SECRET = os.environ.get("X_API_SECRET")
X_ACCESS_TOKEN = os.environ.get("X_ACCESS_TOKEN")
X_ACCESS_TOKEN_SECRET = os.environ.get("X_ACCESS_TOKEN_SECRET")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")

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
    
    prompt = f"""You are an elite cybersecurity news bot. Your job is to filter, analyze the threat level, and summarize technical articles into a single, punchy tweet.

STRICT RULES:
1. CONTENT FILTER: If the article is a contest, giveaway, advertisement, webinar, or sponsored marketing, output exactly the word "SKIP" and nothing else.
2. THREAT LEVEL SCORING: If it is legitimate news, you must start the tweet with one of these three emojis based on severity:
   - 🔴 CRITICAL: Massive data breaches, active zero-days, widespread ransomware, or state-sponsored attacks.
   - 🟡 WARNING: Discovered vulnerabilities, new malware variants, or targeted attacks.
   - 🟢 INFO: General security research, policy changes, or minor news.
3. DYNAMIC HASHTAGS: Do NOT use generic hashtags. Generate exactly two highly specific hashtags based on the technology or attack vector (e.g., #Ransomware, #ActiveDirectory, #Phishing). Place them at the very end.
4. Output ONLY the tweet text. Do not add conversational filler.
5. Do NOT include URLs or links anywhere in the output.
6. End the tweet text with the exact phrase: "According to {source_name}." before the hashtags.
7. Keep the total length under 240 characters.

EXAMPLE OUTPUT (CRITICAL):
🔴 Microsoft has discovered a massive zero-day exploit targeting unpatched Exchange servers globally. Admins are urged to apply patches immediately to prevent remote code execution. According to Dark Reading. #ZeroDay #ExchangeServer

EXAMPLE OUTPUT (WARNING):
🟡 A new phishing campaign is targeting remote workers using fake Zoom update installers to deploy the Qakbot banking trojan. According to BleepingComputer. #Phishing #Qakbot

EXAMPLE OUTPUT (INFO):
🟢 The US government has published new guidelines for federal agencies regarding the secure deployment of internal AI models. According to CyberScoop. #AIPolicy #GovTech

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
                try:
                    print("Asking Groq to write the tweet...")
                    tweet = generate_tweet(entry.title, entry.description, feed_info["name"])
                    
                    if "SKIP" in tweet:
                        save_posted_url(entry.link)
                        print("Skipped promotional content.")
                        continue
                    
                    print(f"Drafted Tweet:\n{tweet}\n")
                    print("Posting to X...")
                    post_to_x(tweet)
                    save_posted_url(entry.link)
                    
                    print("Agent finished successfully. Exiting.")
                    return # Instantly exit execution flow after one tweet
                except Exception as e:
                    print(f"An error occurred: {e}")
                    return # Exit on error
                    
    print("No new articles found. Exiting.")

if __name__ == "__main__":
    run_agent()