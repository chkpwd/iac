import json
import sys
import os
import requests

def flatten_json(y):
    out = {}

    def flatten(x, name=''):
        if isinstance(x, dict):
            for a in x:
                flatten(x[a], name + a)
        elif isinstance(x, list):
            for a in x:
                flatten(a, name)
        else:
            out[name] = x

    flatten(y)
    return out

access_token = os.environ.get("BWS_ACCESS_TOKEN")
key_name = json.load(sys.stdin)["key"].split(",")

results = []

for key in key_name:
    bws_response = requests.get(
        f"http://mgmt-srv-01:5000/key/{key}",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    ).json()

    results.append(bws_response['value'])

flat = flatten_json(results)
print(json.dumps(flat))
