import os
import requests

API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
MODEL_ID = "openrouter/free"  # Change to poolside/laguna-s-2.1:free whenever needed

messages = [
    {
        "role": "system",
        "content": "You are an expert software engineer and code assistant. Provide clean, well-documented, production-ready code.",
    }
]

print(f"--- Chat session started with {MODEL_ID} ---")
print("Type 'exit' or 'quit' to end the session.\n")

while True:
    user_input = input("You: ").strip()
    if not user_input:
        continue
    if user_input.lower() in ["exit", "quit"]:
        print("Exiting chat...")
        break

    messages.append({"role": "user", "content": user_input})

    try:
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json",
            },
            json={"model": MODEL_ID, "messages": messages},
            timeout=60,
        )

        if response.status_code == 200:
            reply = response.json()["choices"][0]["message"]["content"]
            print(f"\nAI:\n{reply}\n" + "-" * 50)
            messages.append({"role": "assistant", "content": reply})
        else:
            print(f"\n[Error {response.status_code}]: {response.text}\n")
    except Exception as e:
        print(f"\n[Request failed]: {e}\n")
