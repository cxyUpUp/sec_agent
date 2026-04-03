import os
from openai import OpenAI

import json


def handle_llm_output(raw_output):
    try:
        data = json.loads(raw_output)
        return data["params"]["response"]
    except:
        return raw_output

os.environ["HTTP_PROXY"] = "http://127.0.0.1:7980"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7980"



# api_key = os.environ.get("OPENAI_API_KEY")
# client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
client = OpenAI(
    api_key=os.environ.get("DEEPSEEK_API_KEY"),
    base_url="https://api.deepseek.com/v1"
)



SYSTEM_PROMPT = """
You are a secure AI agent.

Output policy:
- If a tool is needed, respond with ONLY one JSON object:
  {
    "action": "...",
    "params": {}
  }
- If no tool is needed, respond in normal natural language (plain text), not JSON and not Markdown code block.

Available actions:
- get_time
- echo
- pwned_check

If a user asks for the current time, use the get_time tool.

Security note:
- If user asks to check a password against Pwned Passwords, prefer telling them to use the local command:
  pwned <password>
"""


def call_llm(user_input: str):
    resp = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_input}
        ],
        temperature=0.7

    )
    return resp.choices[0].message.content