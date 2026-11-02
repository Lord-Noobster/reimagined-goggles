import sqlite3
import requests
from urllib.parse import urljoin
import time
import os
from dotenv import load_dotenv

load_dotenv()  # this loads the .env file with our sensitive constants

API_BASE = os.getenv("API_BASE")

EMAIL = os.getenv("EMAIL")

_last_call = 0.0  # since last call

MIN_INTERVAL = 1.5  # minimum time in seconds between each call


def init_db(path="incidents.db"):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.commit()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incidentId TEXT PRIMARY KEY,
            incidentName TEXT,
            severity TEXT,
            status TEXT,
            timestamp DEFAULT CURRENT_TIMESTAMP
                 )
    """)
    conn.commit()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alertId TEXT PRIMARY KEY,
            incidentId TEXT,
            category TEXT,
            machineId TEXT,
            firstSeen TEXT,
            detectionSource TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (incidentId) REFERENCES incidents(incidentId)
                )
    """)
    conn.commit()

    return conn


def insert_into_db(conn, rows_incidents, rows_alerts):
    cur = conn.cursor()
    cur.executemany(
        "INSERT OR IGNORE INTO incidents (incidentId, incidentName, severity, status ) "
        "VALUES (:IncidentId, :IncidentName, :Severity, :Status)",
        (rows_incidents),
    )
    conn.commit()
    cur.executemany(
        "INSERT OR IGNORE INTO alerts (alertId, incidentId, category, machineId, firstSeen, detectionSource) "
        "VALUES (:alertId, :incidentId, :category, :machineId, :firstSeen, :detectionSource)",
        (rows_alerts),
    )
    conn.commit()


def throttle():
    global _last_call
    wait = MIN_INTERVAL - (time.monotonic() - _last_call)
    if wait > 0:
        time.sleep(wait)
    _last_call = time.monotonic()


def get_token():
    r = requests.post(f"{API_BASE}/api/auth/token", json={"email": EMAIL})
    return r.json()["token"]


def get_incidents(token):
    header = {"Authorization": f"Bearer {token}"}
    results = []
    url = f"{API_BASE}/api/incidents?$top=100"

    while url:
        throttle()
        r = requests.get(url, headers=header)
        print(r.text)
        print(r.headers)
        r.raise_for_status()
        page = r.json()

        results.extend(page["value"])

        next_link = page.get("@odata.nextLink")
        url = urljoin(API_BASE, next_link) if next_link else None
    # print(len(results))
    return results


def data_manipulation(results):
    rows_incidents = []

    rows_alerts = []

    for incident in results:
        rows_incidents.append(
            {
                "IncidentId": incident["incidentId"],
                "IncidentName": incident["incidentName"],
                "Severity": incident["severity"],
                "Status": incident["status"],
            }
        )
        for alert in incident["alerts"]:
            rows_alerts.append(
                {
                    "alertId": alert["alertId"],
                    "incidentId": incident["incidentId"],
                    "category": alert["category"],
                    "machineId": alert["machineId"],
                    "firstSeen": alert["firstSeen"],
                    "detectionSource": alert["detectionSource"],
                }
            )
    return rows_incidents, rows_alerts


def program():
    conn = init_db()

    token = get_token()

    results = get_incidents(token)

    rows_incidents, rows_alerts = data_manipulation(results)

    insert_into_db(conn, rows_incidents, rows_alerts)


program()
# print(API_BASE)
# print(EMAIL)
