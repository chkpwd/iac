import json
import sys
import logging
import os
import requests

class InvalidToken(Exception):
    pass

logging.basicConfig(filename='tf.log', encoding='utf-8', level=logging.DEBUG)

access_token = os.environ.get("BWS_ACCESS_TOKEN")
if not access_token:
    raise InvalidToken("Token is not set")

key_name = json.load(sys.stdin)["key"].split(",")

logging.info(key_name)
results = []

for key in key_name:
    bws_response = requests.get(
        f"http://172.16.16.4:5000/key/{key}",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    ).json()

    logging.debug(bws_response)

    try:
        results.append(bws_response['value'])
    except KeyError:
        raise InvalidToken("Token is invalid or does not have permissions to read value")

flat = {}

for name, value in zip(key_name, results):
    flat.update({f"{name}_{dict_key}":dict_value for dict_key, dict_value in value.items()})

print(json.dumps(flat))
