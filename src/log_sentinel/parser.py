import pandas as pd
import re
from pathlib import Path

AUTH_PATTERN = re.compile(r"")  # ¿Qué es esto? (regex - regular expression)

def parser_auth_log(path: Path) -> pd.DataFrame:
    records = []
    ... # Implementa acá.
    return pd.DataFrame(records)