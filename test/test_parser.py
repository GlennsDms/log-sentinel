import pandas as pd
from pathlib import Path
from log_sentinel.parser import parse_auth_log, normalize
from log_sentinel.analyzer import detect_anomalies

SAMPLE = Path("logs/auth.log.sample")


def test_pipeline_output_has_required_columns():
    df = parse_auth_log(SAMPLE)
    df = normalize(df)
    result = detect_anomalies(df)
    assert "anomaly_score" in result.columns
    assert "is_anomaly" in result.columns


def test_anomaly_score_is_normalized():
    df = parse_auth_log(SAMPLE)
    df = normalize(df)
    result = detect_anomalies(df)
    scores = result["anomaly_score"].dropna()
    assert scores.between(0, 1).all()


def test_is_anomaly_is_boolean():
    df = parse_auth_log(SAMPLE)
    df = normalize(df)
    result = detect_anomalies(df)
    assert result["is_anomaly"].dropna().dtype == bool


def test_brute_force_ip_is_flagged():
    # 185.220.101.47 aparece 15+ veces en el sample, debe salir como anomalía
    df = parse_auth_log(SAMPLE)
    df = normalize(df)
    result = detect_anomalies(df)
    flagged_ips = result[result["is_anomaly"] == True]["source_ip"].unique()
    assert "185.220.101.47" in flagged_ips
