import json
import sys
import os
import requests

access_token = os.environ.get("BWS_ACCESS_TOKEN")
key_name = json.load(sys.stdin)["key"].split(",")
results = []

for key in key_name:
    bws_response = requests.get(
        f"http://172.16.16.4:5000/key/{key}",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    ).json()

    results.append(bws_response['value'])

flat = {}

for name, value in zip(key_name, results):
    flat.update({f"{name}_{dict_key}":dict_value for dict_key, dict_value in value.items()})
