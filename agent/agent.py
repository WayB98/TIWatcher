\
"""
TIWatcher Agent (Windows)
- Collects established TCP connections and posts to the server.
Usage:
  setx TIW_SERVER "http://<server>:5000"
  setx TIW_TOKEN  "supersecrettoken"
  python agent.py
"""
import os
import time
import socket
import json
import requests
import psutil
from datetime import datetime

SERVER = os.getenv("TIW_SERVER", "http://127.0.0.1:5000")
TOKEN = os.getenv("TIW_TOKEN", "supersecrettoken")
HOSTNAME = socket.gethostname()

def snapshot_connections():
    out = []
    for c in psutil.net_connections(kind="tcp"):
        if c.status != psutil.CONN_ESTABLISHED:
            continue
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
        exe = None
        try:
            if c.pid:
                p = psutil.Process(c.pid)
                exe = p.name()
        except Exception:
            pass
        out.append({
            "pid": c.pid,
            "exe": exe,
            "laddr": laddr,
            "raddr": c.raddr.ip if c.raddr else "",
            "rport": c.raddr.port if c.raddr else None,
            "ts": time.time()
        })
    return out

def main():
    while True:
        payload = {
            "host": HOSTNAME,
            "connections": snapshot_connections()
        }
        try:
            r = requests.post(f"{SERVER}/api/ingest",
                              json=payload,
                              headers={"Authorization": f"Bearer {TOKEN}"},
                              timeout=10)
            print(datetime.now(), "sent", len(payload["connections"]), "conn ->", r.status_code, r.text[:120])
        except Exception as e:
            print("Error posting:", e)
        time.sleep(10)

if __name__ == "__main__":
    main()
