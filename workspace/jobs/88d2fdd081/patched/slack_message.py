from __future__ import print_function
import os
import json
import urllib.request

# Slack webhook URL loaded from environment variable
webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
slack_data = {"text": "Hi Sarath Kaul"}

if webhook_url:
    response = urllib.request.Request(
        webhook_url,
        data=json.dumps(slack_data),
        headers={"Content-Type": "application/json"},
    )
    print(response)
else:
    print("SLACK_WEBHOOK_URL environment variable is not set.")
