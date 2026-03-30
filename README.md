# 🛡️ CyberWatch — Personal Threat Intelligence Dashboard

A free, fully automated cybersecurity threat intelligence dashboard that
aggregates CVEs, advisories, incidents, and news from multiple sources
into a single clean interface. Updates itself every day via GitHub Actions.
No server, no cost, no manual intervention required.

---

## 🔴 Live Dashboard

Once deployed → `https://<your-username>.github.io/<repo-name>/`

---

## 📡 Data Sources

| Source | Type | API Key? |
|---|---|---|
| NVD (NIST) | Latest CVEs | No |
| CISA Alerts | US Gov Advisories | No |
| The Hacker News | Cybersecurity News | No |
| Bleeping Computer | Incidents & Breaches | No |
| Krebs on Security | Investigative News | No |
| SANS ISC | Threat Diaries | No |
| Reddit r/netsec | Community Intel | No |
| AlienVault OTX | Threat Pulses | Optional |

---

## 🚀 Setup (One-Time, 10 Minutes)

### 1. Fork / Clone this repo

```bash
git clone https://github.com/<your-username>/cyberwatch-dashboard.git
cd cyberwatch-dashboard
```

### 2. Enable GitHub Pages

1. Go to your repo on GitHub
2. Click **Settings** → **Pages**
3. Under **Source**, select `Deploy from a branch`
4. Choose `main` branch and `/ (root)` folder
5. Click **Save**

Your dashboard will be live at `https://<your-username>.github.io/<repo-name>/`

### 3. Enable GitHub Actions

1. Go to your repo → **Actions** tab
2. If prompted, click **"I understand my workflows, go ahead and enable them"**
3. That's it — it will run daily at 06:00 UTC automatically

### 4. (Optional) Add API Keys for More Sources

To enable AlienVault OTX:
1. Create a free account at https://otx.alienvault.com
2. Go to your OTX profile → **API Key**
3. In your GitHub repo: **Settings** → **Secrets and variables** → **Actions**
4. Click **New repository secret**
5. Name: `OTX_API_KEY`, Value: your key
6. Save

### 5. Test it Right Now

Trigger a manual run:
1. Go to **Actions** tab in your repo
2. Click **"Daily Intel Update"** in the left sidebar
3. Click **"Run workflow"** → **"Run workflow"**
4. Watch it fetch and update!

---

## 📁 Project Structure

```
.
├── .github/
│   └── workflows/
│       └── update.yml        # GitHub Actions: runs daily at 06:00 UTC
├── scripts/
│   └── fetch_intel.py        # Python script: fetches all sources → intel.json
├── data/
│   └── intel.json            # Auto-generated daily data file
├── index.html                # Dashboard HTML
├── style.css                 # Dark cyber theme
├── app.js                    # JavaScript: renders intel.json into the dashboard
└── README.md
```

---

## 🛠️ Running Locally

```bash
# Install Python dependencies
pip install requests feedparser

# Fetch live data
python scripts/fetch_intel.py

# Serve locally (Python built-in server)
python -m http.server 8080

# Open in browser
# http://localhost:8080
```

---

## 🔧 Customization

**Add a new RSS source:** Edit `RSS_SOURCES` in `scripts/fetch_intel.py`

```python
{
    "name":     "Dark Reading",
    "url":      "https://www.darkreading.com/rss.xml",
    "category": "news",
    "severity": "medium",
},
```

**Change update schedule:** Edit the cron in `.github/workflows/update.yml`

```yaml
- cron: '0 6 * * *'   # 06:00 UTC daily
- cron: '0 */6 * * *' # every 6 hours
- cron: '0 6 * * 1'   # every Monday
```

---

## 💡 Tips

- The dashboard works even if some sources fail — it uses whatever data was fetched
- The `data/intel.json` file is committed to the repo so GitHub Pages can serve it
- API keys are stored as GitHub Secrets — they are never visible in the repo
- All sources used are completely free with no rate limit issues at this scale

---

## 📚 Learning Resources

- [GitHub Actions Docs](https://docs.github.com/en/actions)
- [GitHub Pages Docs](https://docs.github.com/en/pages)
- [NVD API Docs](https://nvd.nist.gov/developers/vulnerabilities)
- [feedparser Docs](https://feedparser.readthedocs.io/)

---

*Built for personal learning and staying updated with the cybersecurity landscape.*
