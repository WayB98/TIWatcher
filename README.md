# TIWatcher Web (Sword & Shield)

A minimal Flask web UI for monitoring Windows network connections against a local IOC list.
When the agent posts a connection that matches an IOC (IP or domain), an alert is created and pushed live via SSE.

## Features
- IOC CRUD + CSV bulk upload
- Alerts list with open/close
- Dashboard metrics + recent alerts
- Agent `/api/ingest` endpoint with Bearer token
- Live toasts via Server-Sent Events

## Quick Start (Local)

```bash
cd TIWatcherWeb
python -m venv .venv && . .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env  # set SECRET_KEY and AGENT_TOKEN
flask --app app.py init-db
python app.py
# open http://127.0.0.1:5000
```

### Run Agent on a Windows host
```powershell
pip install psutil requests
setx TIW_SERVER "http://<your-server>:5000"
setx TIW_TOKEN  "supersecrettoken"   # must match AGENT_TOKEN
python agent\agent.py
```

### Docker
```bash
docker build -t tiwatcher-web .
docker run -p 5000:5000 --env SECRET_KEY=change --env AGENT_TOKEN=supersecrettoken tiwatcher-web
```

## CSV Bulk Upload
Upload a CSV at **IOCs → Bulk Upload** where each line is `value[,type]` e.g.
```
1.2.3.4,ip
bad.example.com,domain
```

## Notes / TODO
- Add authentication (Flask-Login) and roles.
- Add pagination and search to Alerts.
- Enrich with WHOIS/GeoIP on alerts.
- Export to CSV/JSON and webhook to Teams/Slack.
