def get_incidents(token):
    max_attempts = [0, 1, 2]
    header = {"Authorization": f"Bearer {token}"}
    results = []
    url = f"{API_BASE}/api/incidents?$top=100"
    refreshed = False
    while url:
        for attempt in range(1, max_attempts +1 ):
            throttle()
            try:
                r = requests.get(url, headers=header, timeout=0.5)
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                print(f"attempt {attempt}: {e}")
                time.sleep(2 ** attempt)
                continue

            http_code = r.status_code
            if http_code == 401 and not refreshed:
                token = update_token(".env")
                header = {"Authorization": f"Bearer {token}"}
                refreshed = True
                continue
            if http_code in (418, 429) or 500 <= http_code < 600:
                print(f"attempt {attempt}: status {http_code}, retrying")
                time.sleep(2 ** attempt)
                continue
            break
        else:
            raise RuntimeError(f"gave up on {url} after {max_attempts} attempts")
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
