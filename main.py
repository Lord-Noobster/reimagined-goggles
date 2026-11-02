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

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_entities (
            alertId TEXT,
            entityType TEXT,
            value TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (alertId, entityType, value),
            FOREIGN KEY (alertId) REFERENCES alerts(alertId)
        )
    """)
    conn.commit()

    return conn


def insert_into_db(conn, the_dict):
    TABLES = {
        "incidents": ["incidentId", "incidentName", "severity", "status"],
        "alerts": [
            "alertId",
            "incidentId",
            "category",
            "machineId",
            "firstSeen",
            "detectionSource",
        ],
        "alert_entities": ["alertId", "entityType", "value"],
    }
    cur = conn.cursor()

    with conn:
        for name in TABLES:
            cols = ", ".join(TABLES[name])
            placeholder = ", ".join(f":{item}" for item in TABLES[name])

            sql = f"INSERT OR IGNORE INTO {name} ({cols}) VALUES ({placeholder})"
            conn.executemany(sql, the_dict[name])
    # cur.executemany(
    #   "INSERT OR IGNORE INTO incidents (incidentId, incidentName, severity, status ) "
    #  "VALUES (:IncidentId, :IncidentName, :Severity, :Status)",
    # (the_dict["incidents"]),
    # )
    # conn.commit()
    # cur.executemany(
    #   "INSERT OR IGNORE INTO alerts (alertId, incidentId, category, machineId, firstSeen, detectionSource) "
    #  "VALUES (:alertId, :incidentId, :category, :machineId, :firstSeen, :detectionSource)",
    # (the_dict["alerts"]),
    # )
    # conn.commit()

    # cur.executemany(
    #   "INSERT OR IGNORE INTO alert_entities (alertId, entityType, value) "
    #  "VALUES (:alertId, :entityType, :value)",
    # (the_dict["alert_entities"]),
    # )
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
        # print(r.text)
        # print(r.headers)
        r.raise_for_status()
        page = r.json()

        results.extend(page["value"])
        print("Ok")
        print(len(results))
        next_link = page.get("@odata.nextLink")
        url = urljoin(API_BASE, next_link) if next_link else None
    # print(len(results))
    return results


def data_manipulation(results):
    ENTITY_TYPES = ["domains", "emails", "fileHashes", "ips", "processes", "urls"]
    the_dict = {"incidents": [], "alerts": [], "alert_entities": []}

    for incident in results:
        the_dict["incidents"].append(
            {
                "incidentId": incident["incidentId"],
                "incidentName": incident["incidentName"],
                "severity": incident["severity"],
                "status": incident["status"],
            }
        )
        for alert in incident["alerts"]:
            the_dict["alerts"].append(
                {
                    "alertId": alert["alertId"],
                    "incidentId": incident["incidentId"],
                    "category": alert["category"],
                    "machineId": alert["machineId"],
                    "firstSeen": alert["firstSeen"],
                    "detectionSource": alert["detectionSource"],
                }
            )

            for entity_type in ENTITY_TYPES:
                for value in alert["entities"].get(entity_type, []):
                    the_dict["alert_entities"].append(
                        {
                            "alertId": alert["alertId"],
                            "entityType": entity_type,
                            "value": value,
                        }
                    )
    return the_dict


def program():
    conn = init_db()

    token = get_token()

    results = get_incidents(token)

    the_dict = data_manipulation(results)

    insert_into_db(conn, the_dict)


program()
# print(API_BASE)
# print(EMAIL)
