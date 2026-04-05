import pandas as pd
import re
from pathlib import Path

# Parte 1 - Parser
AUTH_PATTERN = re.compile(
    r'(\w+\s+\d+\s[\d:]+)\s(\S+)\s(\S+)\[(\d+)\]:\s(.+)'
)

def parse_auth_log(path: Path) -> pd.DataFrame:
    records = []
    with open(path) as f:
        for line in f:
            m = AUTH_PATTERN.match(line.strip())
            if m:
                records.append({
                    'timestamp': m.group(1),
                    'host': m.group(2),
                    'process': m.group(3),
                    'pid': m.group(4),
                    'message': m.group(5),
                })
    return pd.DataFrame(records)

# Parte 2 - Normalizer
EVENT_PATTERNS = {
    'failed_login': re.compile(r'Failed password for'),
    'successful_login': re.compile(r'Accepted (?:password|publickey) for'),
    'invalid_user': re.compile(r'Invalid user'),
    'disconnected': re.compile(r'Disconnected from'),
}

IP_PATTERN = re.compile(r'from\s([\d.]+)')

def normalize(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%b %d %H:%M:%S', errors='coerce')
    df['source_ip'] = df['message'].str.extract(IP_PATTERN.pattern)
    df['event_type'] = 'other'
    for event, pattern in EVENT_PATTERNS.items():
        mask = df['message'].str.contains(pattern.pattern, regex=True, na=False)
        df.loc[mask, 'event_type'] = event
    return df

if __name__ == "__main__":
    df = parse_auth_log(Path("logs/auth.log.sample"))
    df = normalize(df)
    print(df.to_string())