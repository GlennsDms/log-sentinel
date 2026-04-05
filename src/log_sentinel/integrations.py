import requests
import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

def check_ip(ip: str) -> dict:
    headers = {"Key": os.getenv("ABUSEIPDB_API_KEY"), "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    r = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=5)
    r.raise_for_status()
    return r.json().get("data", {})