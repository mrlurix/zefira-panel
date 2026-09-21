import sys, json, urllib.request
sys.path.insert(0, ".")
from database import Database, Setting
from config import BASE_DIR
from security import decrypt_text
from sqlalchemy import select

db = Database(BASE_DIR / "instance" / "zefira.db")
with db.s() as s:
    enc = s.scalar(select(Setting.value).where(Setting.key == "ai_api_key_enc"))
key = decrypt_text(enc or "")
assert key and len(key) > 10, "no AI key stored"

req = urllib.request.Request(
    "https://api.groq.com/openai/v1/models",
    headers={"Authorization": "Bearer " + key, "User-Agent": "zefira-panel"},
    method="GET",
)
with urllib.request.urlopen(req, timeout=20) as resp:
    data = json.loads(resp.read().decode())
ids = sorted(m["id"] for m in data.get("data", []) if isinstance(m.get("id"), str))
print("MODELS:", len(ids))
for mid in ids:
    print(" -", mid)
