#!/usr/bin/env python3

import json
import sys
import logging
import os
import requests

from requests.adapters import HTTPAdapter, Retry

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

s = requests.Session()
retries = Retry(total=5, backoff_factor=1, status_forcelist=[ 502, 503, 504 ])
s.mount('http://', HTTPAdapter(max_retries=retries))

for key in key_name:
    bws_response = s.get(
        f"http://10.0.10.4:5000/key/{key}",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30,
    ).json()

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
