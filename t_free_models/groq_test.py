import os
import requests

API_KEY = os.environ.get("GROQ_API_KEY", "")
MODEL_ID = "openai/gpt-oss-120b" 

# This list will store the conversation history
messages = [
    {
        "role": "system",
        "content": "You are a helpful and expert coding assistant. Provide clean and concise answers."
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

    # Add the user's message to the history
    messages.append({"role": "user", "content": user_input})

    try:
        response = requests.post(
            url="https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": MODEL_ID,
                "messages": messages,
                "temperature": 0.6  # Recommended range for Groq is 0.5 - 0.7
            },
            timeout=60,
        )

        if response.status_code == 200:
            # Extract the AI's reply
            reply = response.json()["choices"][0]["message"]["content"]
            print(f"\nAI:\n{reply}\n" + "-" * 50)
            
            # Add the AI's reply to the history so it remembers context
            messages.append({"role": "assistant", "content": reply})
        else:
            print(f"\n[Error {response.status_code}]: {response.text}\n")
            # If the request fails, remove the user's message so it isn't stuck in history
            messages.pop()
            
    except Exception as e:
        print(f"\n[Request failed]: {e}\n")
        messages.pop()
