import os
import requests

# 1. Load Groq key from environment
API_KEY = os.environ.get("GROQ_API_KEY", "")

url = "https://api.groq.com/openai/v1/models"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
    models = response.json().get("data", [])
    print("--- Available Groq Models ---")
    
    # Sort and print the model IDs
    free_models = sorted([model["id"] for model in models])
    for model_id in free_models:
        print(f"- {model_id}")
else:
    print(f"Failed to fetch models. Status code: {response.status_code}")
    print(response.text)
