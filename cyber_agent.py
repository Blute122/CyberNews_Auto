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
    
    prompt = f"""You are an elite cybersecurity news bot. Your job is to summarize technical articles into a single, punchy tweet.

STRICT RULES:
1. Output ONLY the tweet text. Do not write "Here is your tweet" or add any conversational filler.
2. Do NOT use any emojis.
3. Do NOT include any URLs, links, or web addresses anywhere in the output (this is critical to avoid Twitter API premium fees).
4. End the tweet with the exact phrase: "According to {source_name}."
5. Include exactly two relevant hashtags at the very end.
6. Keep the total length under 240 characters.

EXAMPLE INPUT:
Title: Microsoft Details Cookie-Controlled PHP Web Shells Persisting via Cron on Linux Servers
Summary: Hackers are using persistent PHP web shells to maintain access to Linux servers.

EXAMPLE OUTPUT:
Microsoft has detailed a new attack vector where hackers utilize cookie-controlled PHP web shells to maintain persistent access on Linux servers via Cron jobs. A highly sophisticated evasion tactic. According to The Hacker News. #CyberSecurity #Linux

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