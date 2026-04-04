import pandas as pd
import re
from pathlib import Path

AUTH_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<status>Accepted|Failed password for(?: invalid user)?|Invalid user|Disconnected from)\s+"
    r"(?:(?:password|publickey)\s+for\s+)?(?:invalid\s+user\s+)?"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"port\s+(?P<port>\d+)"
)

def parser_auth_log(path: Path) -> pd.DataFrame:
    records = []
    with open(path, "r") as f:
        for line in f:
            match = AUTH_PATTERN.search(line)
            if match:
                d = match.groupdict()
                records.append({
                    "timestamp": f"{d['month']} {d['day']} {d['time']}",
                    "host": d["host"],
                    "user": d["user"],
                    "ip": d["ip"],
                    "port": int(d["port"]),
                    "status": "accepted" if "Accepted" in d["status"] else
                              "failed" if "Failed" in d["status"] else
                              "invalid_user" if "Invalid" in d["status"] else
                              "disconnected"
                })
    return pd.DataFrame(records)

if __name__ == "__main__":
    df = parser_auth_log(Path("logs/auth.log.sample"))
    print(df.to_string())