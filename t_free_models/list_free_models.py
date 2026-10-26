import requests

print("Fetching live models from OpenRouter...")
response = requests.get("https://openrouter.ai/api/v1/models")

if response.status_code == 200:
    models = response.json().get("data", [])
    free_models = []
    
    for model in models:
        # Check if the pricing is exactly 0 for both prompt and completion
        pricing = model.get("pricing", {})
        if pricing.get("prompt") == "0" and pricing.get("completion") == "0":
            free_models.append(model["id"])
            
    print(f"\n--- Found {len(free_models)} Free Models ---")
    for model_id in sorted(free_models):
        print(model_id)
        
    print("\nTip: Copy any of the model IDs above and paste it as your MODEL_ID in your test script.")
else:
    print(f"Failed to fetch models. Status code: {response.status_code}")