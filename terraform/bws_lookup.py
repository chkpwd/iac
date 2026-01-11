#!/usr/bin/env python3
import json
import sys
import logging
import os
import urllib.request
import urllib.error
import time

class InvalidToken(Exception):
    pass

if os.environ.get("TF_LOG") == "DEBUG":
    logging.basicConfig(
        filename='bws-lookup.log',
        encoding='utf-8',
        level=logging.DEBUG
    )

access_token = os.environ.get("BWS_ACCESS_TOKEN")
if not access_token:
    raise InvalidToken("Token is not set")

key_name = json.load(sys.stdin)["key"].split(",")
logging.info(key_name)

results = []

def fetch_with_retry(url, headers, max_retries=5, backoff_factor=1, timeout=30):
    """Fetch URL with retry logic for specific status codes."""
    retry_status_codes = {502, 503, 504}

    for attempt in range(max_retries):
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            if e.code in retry_status_codes and attempt < max_retries - 1:
                sleep_time = backoff_factor * (2 ** attempt)
                logging.warning(f"HTTP {e.code} error, retrying in {sleep_time}s...")
                time.sleep(sleep_time)
            else:
                raise
        except urllib.error.URLError as e:
            if attempt < max_retries - 1:
                sleep_time = backoff_factor * (2 ** attempt)
                logging.warning(f"URL error: {e.reason}, retrying in {sleep_time}s...")
                time.sleep(sleep_time)
            else:
                raise

for key in key_name:
    headers = {"Authorization": f"Bearer {access_token}"}
    bws_response = fetch_with_retry(
        f"http://10.0.10.4:5000/key/{key}",
        headers=headers,
        timeout=30
    )
    logging.debug(bws_response)
    try:
        results.append(bws_response['value'])
    except KeyError as exc:
        raise InvalidToken(
            "Token is invalid or does not have permissions to read value"
        ) from exc

flat = {}
for name, value in zip(key_name, results):
    flat.update({f"{name}_{dict_key}": dict_value for dict_key,
                dict_value in value.items()})

logging.debug(flat)
print(json.dumps(flat))
