\
import os
import csv
import json
import time
import queue
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, request, render_template, redirect, url_for, flash, Response, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///tiwatcher.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "supersecrettoken")

db = SQLAlchemy(app)

# --- Models ---
class IOC(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(255), nullable=False, unique=True)
    ioc_type = db.Column(db.String(20), nullable=False, default="ip")  # ip|domain
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Connection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(128), nullable=False)
    pid = db.Column(db.Integer)
    exe = db.Column(db.String(255))
    laddr = db.Column(db.String(255))
    raddr = db.Column(db.String(255))
    rport = db.Column(db.Integer)
    ts = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ioc_id = db.Column(db.Integer, db.ForeignKey('ioc.id'), nullable=False)  # <- was 'IOC.id'
    connection_id = db.Column(db.Integer, db.ForeignKey('connection.id'), nullable=False)
    status = db.Column(db.String(20), default="open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    ioc = db.relationship('IOC')
    connection = db.relationship('Connection')


# SSE subscribers
subscribers = []  # list[queue.Queue]

def publish_event(payload: dict):
    """Publish an event to all SSE subscribers."""
    data = json.dumps(payload)
    for q in list(subscribers):
        try:
            q.put_nowait(data)
        except Exception:
            pass

def sse_stream():
    q = queue.Queue(maxsize=100)
    subscribers.append(q)
    try:
        while True:
            data = q.get()
            yield f"data: {data}\n\n"
    except GeneratorExit:
        pass
    finally:
        if q in subscribers:
            subscribers.remove(q)

# --- Routes (UI) ---
@app.route("/")
def index():
    total_iocs = db.session.scalar(db.select(func.count()).select_from(IOC))
    total_alerts = db.session.scalar(db.select(func.count()).select_from(Alert))
    open_alerts = db.session.scalar(db.select(func.count()).select_from(Alert).where(Alert.status=="open"))
    total_connections = db.session.scalar(db.select(func.count()).select_from(Connection))
    recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(10).all()
    return render_template("index.html",
                           total_iocs=total_iocs or 0,
                           total_alerts=total_alerts or 0,
                           open_alerts=open_alerts or 0,
                           total_connections=total_connections or 0,
                           recent_alerts=recent_alerts)

@app.route("/iocs", methods=["GET", "POST"])
def iocs():
    if request.method == "POST":
        value = request.form.get("value","").strip()
        ioc_type = request.form.get("ioc_type","ip").strip()
        if not value:
            flash("IOC value is required","error")
        else:
            if IOC.query.filter_by(value=value).first():
                flash("IOC already exists","warning")
            else:
                db.session.add(IOC(value=value, ioc_type=ioc_type))
                db.session.commit()
                flash("IOC added","success")
        return redirect(url_for("iocs"))
    items = IOC.query.order_by(IOC.created_at.desc()).all()
    return render_template("iocs.html", items=items)

@app.route("/iocs/<int:ioc_id>/toggle", methods=["POST"])
def toggle_ioc(ioc_id):
    item = IOC.query.get_or_404(ioc_id)
    item.enabled = not item.enabled
    db.session.commit()
    flash("IOC updated","success")
    return redirect(url_for("iocs"))

@app.route("/iocs/<int:ioc_id>/delete", methods=["POST"])
def delete_ioc(ioc_id):
    item = IOC.query.get_or_404(ioc_id)
    db.session.delete(item)
    db.session.commit()
    flash("IOC deleted","success")
    return redirect(url_for("iocs"))

@app.route("/iocs/upload", methods=["POST"])
def upload_iocs():
    file = request.files.get("file")
    if not file:
        flash("No file provided","error")
        return redirect(url_for("iocs"))
    added = 0
    reader = csv.reader((line.decode("utf-8") for line in file.stream))
    for row in reader:
        if not row: 
            continue
        raw = row[0].strip()
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split(",")
        value = parts[0].strip()
        ioc_type = (parts[1].strip().lower() if len(parts)>1 else "ip")
        if not IOC.query.filter_by(value=value).first():
            db.session.add(IOC(value=value, ioc_type=ioc_type))
            added += 1
    db.session.commit()
    flash(f"Uploaded {added} new IOCs","success")
    return redirect(url_for("iocs"))

@app.route("/alerts")
def alerts():
    qstatus = request.args.get("status")
    query = Alert.query.order_by(Alert.created_at.desc())
    if qstatus in {"open","closed"}:
        query = query.filter_by(status=qstatus)
    items = query.limit(500).all()
    return render_template("alerts.html", items=items, qstatus=qstatus)

@app.route("/alerts/<int:alert_id>/close", methods=["POST"])
def close_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.status = "closed"
    db.session.commit()
    flash("Alert closed","success")
    return redirect(url_for("alerts", status="open"))

@app.route("/events/stream")
def events_stream():
    return Response(sse_stream(), mimetype="text/event-stream")

# --- APIs (agent ingest) ---
@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    token = request.headers.get("Authorization","").replace("Bearer ","")
    if token != AGENT_TOKEN:
        return {"error":"unauthorized"}, 401
    payload = request.get_json(silent=True) or {}
    host = payload.get("host") or request.remote_addr or "unknown"
    conns = payload.get("connections", [])
    created_alerts = 0

    # Preload enabled IOCs for matching
    enabled_iocs = IOC.query.filter_by(enabled=True).all()
    ips = {ioc.value for ioc in enabled_iocs if ioc.ioc_type == "ip"}
    domains = {ioc.value.lower() for ioc in enabled_iocs if ioc.ioc_type == "domain"}

    for c in conns:
        conn = Connection(
            host=host,
            pid=c.get("pid"),
            exe=c.get("exe"),
            laddr=c.get("laddr"),
            raddr=c.get("raddr"),
            rport=c.get("rport"),
            ts=datetime.utcfromtimestamp(c.get("ts", time.time()))
        )
        db.session.add(conn)
        db.session.flush()  # get conn.id

        # Match logic
        raddr = (c.get("raddr") or "").strip()
        hit_ioc = None
        if raddr in ips:
            hit_ioc = IOC.query.filter_by(value=raddr, ioc_type="ip").first()
        else:
            # try domain match on hostname
            try:
                hostname = urlparse(f"//{raddr}").hostname or raddr
                hostname = hostname.lower()
            except Exception:
                hostname = raddr.lower()
            if hostname and hostname in domains:
                hit_ioc = IOC.query.filter_by(value=hostname, ioc_type="domain").first()

        if hit_ioc:
            alert = Alert(ioc_id=hit_ioc.id, connection_id=conn.id, status="open")
            db.session.add(alert)
            created_alerts += 1

            publish_event({
                "type": "alert",
                "message": f"IOC match on {raddr} (host {host})",
                "alert_id": None,  # filled after commit
                "raddr": raddr,
                "host": host,
                "ts": datetime.utcnow().isoformat() + "Z"
            })

    db.session.commit()
    # Update last event with id not trivial; future: include IDs via join in publish.
    return {"status":"ok","alerts_created":created_alerts}

@app.cli.command("init-db")
def init_db():
    """flask init-db"""
    db.create_all()
    print("Database initialized.")

# --- Helpers ---
@app.template_filter("dt")
def fmt_dt(v):
    if not v: return ""
    return v.strftime("%Y-%m-%d %H:%M:%S")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
