import os
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler
import ollama

FEATURES = [
    "failed_count",
    "success_count",
    "invalid_user_count",
    "unique_users_tried",
    "attempt_rate",
    "failed_ratio",
]


class _Autoencoder(nn.Module):
    def __init__(self, dim: int):
        super().__init__()
        self.encoder = nn.Sequential(nn.Linear(dim, 16), nn.ReLU(), nn.Linear(16, 8))
        self.decoder = nn.Sequential(nn.Linear(8, 16), nn.ReLU(), nn.Linear(16, dim))

    def forward(self, x):
        return self.decoder(self.encoder(x))


def _build_ip_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    username_pattern = r"for (?:invalid user )?(\S+) from"

    def agg(g):
        failed = (g["event_type"] == "failed_login").sum()
        success = (g["event_type"] == "successful_login").sum()
        invalid = (g["event_type"] == "invalid_user").sum()
        total = max(failed + success + invalid, 1)
        duration = (g["timestamp"].max() - g["timestamp"].min()).total_seconds() / 60
        return pd.Series({
            "failed_count": failed,
            "success_count": success,
            "invalid_user_count": invalid,
            "unique_users_tried": g["message"].str.extract(username_pattern)[0].nunique(),
            "attempt_rate": len(g) / max(duration, 1),
            "failed_ratio": failed / total,
        })

    return df.groupby("source_ip").apply(agg).reset_index()


def _train(X: np.ndarray, epochs: int = 60) -> tuple:
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X_t = torch.FloatTensor(X_scaled)

    model = _Autoencoder(X.shape[1])
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.MSELoss()

    model.train()
    for _ in range(epochs):
        optimizer.zero_grad()
        loss = loss_fn(model(X_t), X_t)
        loss.backward()
        optimizer.step()

    model.eval()
    with torch.no_grad():
        errors = ((model(X_t) - X_t) ** 2).mean(dim=1).numpy()

    threshold = errors.mean() + 2 * errors.std()
    return model, scaler, threshold


def detect_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    clean = df.dropna(subset=["source_ip"])
    feat_df = _build_ip_features(clean)
    X = feat_df[FEATURES].values

    model, scaler, threshold = _train(X)

    X_scaled = scaler.transform(X)
    X_t = torch.FloatTensor(X_scaled)
    model.eval()
    with torch.no_grad():
        errors = ((model(X_t) - X_t) ** 2).mean(dim=1).numpy()

    feat_df["anomaly_score"] = (errors / errors.max()).round(4)
    feat_df["is_anomaly"] = errors > threshold

    return df.merge(
        feat_df[["source_ip", "anomaly_score", "is_anomaly"]],
        on="source_ip",
        how="left",
    )


def summarize_incidents(df: pd.DataFrame) -> str:
    summary = (
        df.groupby("source_ip")
        .agg(
            failed=("event_type", lambda x: (x == "failed_login").sum()),
            invalid=("event_type", lambda x: (x == "invalid_user").sum()),
            successful=("event_type", lambda x: (x == "successful_login").sum()),
            score=("anomaly_score", "max"),
        )
        .reset_index()
        .sort_values("score", ascending=False)
        .to_string(index=False)
    )

    model = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
    prompt = (
        "You are a SOC analyst reviewing flagged SSH log entries. "
        "Summarize the following anomalous activity in 3-5 sentences. "
        "Identify likely attack patterns, the most suspicious IPs, "
        "and assign an overall risk level (Low / Medium / High / Critical).\n\n"
        f"{summary}"
    )

    response = ollama.chat(
        model=model,
        messages=[{"role": "user", "content": prompt}],
    )
    return response["message"]["content"]