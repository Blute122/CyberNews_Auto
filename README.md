# CyberNews Auto

CyberNews Auto is an automated cyber threat intelligence bot. It watches trusted cybersecurity RSS feeds, uses an LLM to summarize and classify new stories, enriches CVE-based stories with NVD CVSS data, creates a threat-card image, posts the result to X, and stores each posted item in a JSON database for dashboard views.

The project is designed to run on a schedule through GitHub Actions, while also supporting local runs for development and debugging.

## Features

- Pulls cybersecurity articles from RSS feeds such as The Hacker News, BleepingComputer, Dark Reading, CyberScoop, and Krebs on Security.
- Filters out old articles and previously posted URLs.
- Uses Groq LLaMA to extract severity, CVE, affected target, threat actor, tweet text, card summary, and a plain-English explanation.
- Validates CVE IDs before enrichment to avoid posting placeholder or invented CVEs.
- Looks up CVSS scores from the NVD API when a real CVE is present.
- Generates a shareable threat-card PNG with severity color, title, summary, target, and simplified explanation.
- Posts one item per run to X.
- Stores posted URLs in `posted_urls.txt`.
- Stores dashboard data in `database.json`.
- Provides both a Streamlit dashboard and a static HTML dashboard.
- Sends optional crash alerts to Discord.

## Project Structure

```text
.
|-- .github/workflows/twitter_bot.yml  # Scheduled GitHub Actions workflow
|-- cyber_agent.py                     # Main RSS, LLM, enrichment, image, and posting agent
|-- dashboard.py                       # Streamlit dashboard for local analytics
|-- index.html                         # Static browser dashboard powered by database.json
|-- database.json                      # Posted threat feed used by dashboards
|-- posted_urls.txt                    # URL history used to avoid duplicate posts
|-- requirements.txt                   # Python dependencies
|-- Roboto-Bold.ttf                    # Font used for threat-card image generation
`-- Roboto-Medium.ttf                  # Font used for threat-card image generation
```

## Requirements

- Python 3.10 or newer
- A Groq API key
- X API credentials with permission to create posts and upload media
- Optional Discord webhook URL for crash alerts
- Optional GitHub repository secrets if running through GitHub Actions

Install Python dependencies:

```bash
pip install -r requirements.txt
```

## Environment Variables

The bot reads credentials from environment variables:

```text
GROQ_API_KEY
X_API_KEY
X_API_SECRET
X_ACCESS_TOKEN
X_ACCESS_TOKEN_SECRET
DISCORD_WEBHOOK_URL
```

`DISCORD_WEBHOOK_URL` is optional. The other values are required for a successful automated post.

Do not hardcode real API credentials in source files. Use local environment variables for development and GitHub Actions secrets for deployment.

## Local Setup

1. Clone or open the project folder.

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Set the required environment variables.

   PowerShell example:

   ```powershell
   $env:GROQ_API_KEY="your_groq_key"
   $env:X_API_KEY="your_x_api_key"
   $env:X_API_SECRET="your_x_api_secret"
   $env:X_ACCESS_TOKEN="your_x_access_token"
   $env:X_ACCESS_TOKEN_SECRET="your_x_access_token_secret"
   $env:DISCORD_WEBHOOK_URL="your_discord_webhook_url"
   ```

4. Run the agent:

   ```bash
   python cyber_agent.py
   ```

The agent posts at most one tweet per run. It exits after successfully processing and posting one eligible article.

## Running the Dashboards

### Static Dashboard

The static dashboard is `index.html`. It fetches `database.json` from the same directory and refreshes every five minutes.

For best results, serve the folder with a local HTTP server:

```bash
python -m http.server 8000
```

Then open:

```text
http://localhost:8000/index.html
```

### Streamlit Dashboard

Run:

```bash
streamlit run dashboard.py
```

The Streamlit dashboard reads `database.json`, shows threat counts, severity distribution, and a searchable threat feed.

## GitHub Actions Deployment

The workflow in `.github/workflows/twitter_bot.yml` runs every hour at minute 14:

```yaml
cron: '14 * * * *'
```

It:

1. Checks out the repository.
2. Installs Python 3.10 and dependencies.
3. Runs `python cyber_agent.py`.
4. Commits updates to `posted_urls.txt` and `database.json`.

Add these repository secrets before enabling the workflow:

```text
GROQ_API_KEY
X_API_KEY
X_API_SECRET
X_ACCESS_TOKEN
X_ACCESS_TOKEN_SECRET
DISCORD_WEBHOOK_URL
```

`DISCORD_WEBHOOK_URL` can be omitted if you do not want Discord crash notifications.

## How the Agent Works

1. Checks the daily post count in `database.json`.
2. Stops if the daily cap has already been reached.
3. Shuffles the RSS feed list.
4. Skips articles already present in `posted_urls.txt`.
5. Skips articles older than the configured maximum age.
6. Sends the article title and summary to Groq for structured JSON extraction.
7. Rejects invalid CVE placeholders.
8. Looks up CVSS from NVD when a valid CVE is found.
9. Generates a threat-card image.
10. Posts the tweet and image to X.
11. Saves the article URL and dashboard record.
12. Exits after one successful post.

## Configuration

Important constants live near the top of `cyber_agent.py`:

```python
DAILY_POST_CAP = 7
ARTICLE_MAX_AGE_HOURS = 12
RSS_FEEDS = [...]
HISTORY_FILE = "posted_urls.txt"
DB_FILE = "database.json"
```

Change these values to adjust post volume, article freshness, RSS sources, or storage file names.

## Data Files

### `posted_urls.txt`

Stores one article URL per line. This prevents duplicate posts across scheduled runs.

### `database.json`

Stores dashboard records. Current records use this shape:

```json
{
  "date": "2026-05-05 06:51 UTC",
  "content": "Tweet or threat text",
  "url": "https://example.com/article"
}
```

For future improvements, consider storing richer fields such as `title`, `source`, `severity`, `cve`, `cvss`, `target`, `threat_actor`, and `summary`.

## Security Notes

- Rotate any API keys that were ever committed to the repository.
- Do not commit real credentials.
- Keep local secrets in environment variables or an untracked `.env` file.
- Store production secrets in GitHub Actions repository secrets.
- Review generated LLM content before increasing automation scope or posting frequency.

## Troubleshooting

### The bot finds no articles

- Check that the RSS feeds are reachable.
- Confirm articles are newer than `ARTICLE_MAX_AGE_HOURS`.
- Check `posted_urls.txt`; the article may already have been posted.

### Groq fails

- Confirm `GROQ_API_KEY` is set.
- Check account quota and model availability.
- Inspect the workflow logs or terminal output for JSON parsing errors.

### X posting fails

- Confirm all X credentials are set.
- Confirm the app has write permissions.
- Check whether the generated tweet exceeds platform limits after CVSS injection.

### Dashboard shows no data

- Confirm `database.json` exists and contains a JSON array.
- If using `index.html`, serve the folder over HTTP instead of opening the file directly.
- If using Streamlit, run from the project root so `database.json` resolves correctly.

