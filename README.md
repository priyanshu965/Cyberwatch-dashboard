# CyberWatch

A free, cybersecurity threat intelligence dashboard that aggregates CVEs, 
advisories, incidents, and news from multiple sources into a single clean
interface. Updates itself every day via GitHub Actions.

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
| AlienVault OTX | Threat Pulses | Yes |

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
