import sqlite3
import requests
from urllib.parse import urljoin
import time
import os
from pathlib import Path
from dotenv import load_dotenv, set_key, get_key


load_dotenv()  # this loads the .env file with our sensitive constants
ENV_PATH = ".env"
API_BASE = os.getenv("API_BASE")

EMAIL = os.getenv("EMAIL")

_last_call = 0.0  # since last call

MIN_INTERVAL = 1.5  # minimum time in seconds between each call

TOKEN_EXPIRATION = (
    169200  # 47 hours a buffer of one hour to avoid token expiring during a call
)


def init_db(path="incidents.db"):
    try:
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

    except sqlite3.DatabaseError:
        print("Database error")
        conn.close()
    except sqlite3.Error as e:
        print(f"Error {e}")
        conn.close()


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
    # cur = conn.cursor()
    try:
        with conn:
            for name in TABLES:
                cols = ", ".join(TABLES[name])
                placeholder = ", ".join(f":{item}" for item in TABLES[name])

                sql = f"INSERT OR IGNORE INTO {name} ({cols}) VALUES ({placeholder})"
                conn.executemany(sql, the_dict[name])
        conn.commit()

    except sqlite3.IntegrityError as e:
        print(f"Integrity error {e}")
        conn.close()
    except sqlite3.ProgrammingError as e:
        print(f"programming error {e}")
        conn.close()
    except sqlite3.Error as e:
        print("error {e}")
        conn.close()
    except Exception as e:
        print(f"{e}")


def throttle():
    global _last_call
    wait = MIN_INTERVAL - (time.monotonic() - _last_call)
    if wait > 0:
        time.sleep(wait)
    _last_call = time.monotonic()


def verify_token():
    env_path = Path(".env")
    token = get_key(dotenv_path=env_path, key_to_get="TOKEN")
    token_timestamp_str = get_key(dotenv_path=env_path, key_to_get="TOKEN_TIMESTAMP")

    try:
        timestamp_age = int(time.time() - int(token_timestamp_str))
    except (TypeError, ValueError):
        timestamp_age = None

    if token and timestamp_age is not None and 0 <= timestamp_age <= TOKEN_EXPIRATION:
        return token
    return update_token(env_path)


def update_token(env_path):
    new_token = get_token()
    new_token_timestamp = int(time.time())
    check_token = set_key(
        dotenv_path=env_path, key_to_set="TOKEN", value_to_set=f"{new_token}"
    )
    check_timestamp = set_key(
        dotenv_path=env_path,
        key_to_set="TOKEN_TIMESTAMP",
        value_to_set=f"{new_token_timestamp}",
    )
    print(check_token, check_timestamp)
    return new_token


def get_token():
    print("get_token runs")
    try:
        throttle()
        r = requests.post(
            f"{API_BASE}/api/auth/token", json={"email": EMAIL}, timeout=0.5
        )
        r.raise_for_status()
        return r.json()["token"]
    except requests.exceptions.Timeout:
        print("timeout")
    except requests.exceptions.TooManyRedirects:
        print("too many redirects")
    except requests.exceptions.RequestException as e:
        print("error {e}")
    except Exception as e:
        print("{e}")
    except requests.HTTPError as e:
        raise SystemExit(e)


def get_incidents(token):
    header = {"Authorization": f"Bearer {token}"}
    results = []
    url = f"{API_BASE}/api/incidents?$top=100"
    try:
        while url:
            throttle()
            r = requests.get(url, headers=header, timeout=0.5)
            # print(r.text)
            # print(r.headers)
            r.raise_for_status()
            page = r.json()

            results.extend(page["value"])
            print("Ok")
            print(len(results))
            next_link = page.get("@odata.nextLink")
            url = urljoin(API_BASE, next_link) if next_link else None
    except requests.exceptions.Timeout:
        print("timeout")
    except requests.exceptions.TooManyRedirects:
        print("too many redirects")
    except requests.exceptions.RequestException as e:
        print(f"error {e}")
    except Exception as e:
        print(f"{e}")
    except requests.exceptions.HTTPError as e:
        raise SystemExit(e)

    return results


def data_manipulation(results):

    ENTITY_TYPES = ["domains", "emails", "fileHashes", "ips", "processes", "urls"]
    the_dict = {"incidents": [], "alerts": [], "alert_entities": []}
    try:
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
    except Exception as e:
        print(f"{e}")


def program():
    conn = init_db()

    token = verify_token()

    # token = get_token()

    results = get_incidents(token)

    the_dict = data_manipulation(results)

    insert_into_db(conn, the_dict)


program()
# print(API_BASE)
# print(EMAIL)
