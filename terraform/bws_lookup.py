import json
import sys
import os
import requests

access_token = os.environ.get("BWS_ACCESS_TOKEN")
key_name = json.load(sys.stdin)["key"]

bws_response = requests.get(
    f"http://mgmt-srv-01:5000/key/{key_name}",
    headers={"Authorization": f"Bearer {access_token}"},
    timeout=10,
).json()

# Ensure valid json response
print(json.dumps(bws_response['value']))
