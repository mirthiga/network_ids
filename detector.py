"""Hybrid IDS: (1) explainable rule layer, (2) IsolationForest anomaly layer trained on benign traffic only."""
import numpy as np, pandas as pd, joblib
from sklearn.ensemble import IsolationForest
from features import FEATURES

# Rule thresholds per 5 s window (chosen from benign baseline: benign sources max ~6 SYN/window, <=3 ports)
RULES = {
    "port_scan":      dict(feat="uniq_dst_ports", thr=15),
    "dos_syn_flood":  dict(feat="syn_cnt", thr=300, extra=("half_open_ratio", 0.8)),
    "ssh_bruteforce": dict(feat="max_syn_same_port", thr=12, extra=("top_port", {22, 23, 21, 3389})),
}


def tf(X):
    return np.log1p(X[FEATURES].astype(float).clip(lower=0))


def train(train_df, path="model.joblib", contamination_q=0.005):
    X = tf(train_df)
    iso = IsolationForest(n_estimators=200, random_state=0).fit(X)
    sc = iso.score_samples(X)
    thr = np.quantile(sc, contamination_q)                 # tolerate ~0.5% benign FP by construction
    med = X.median()
    mad = (X - med).abs().median().clip(lower=0.25)   # floor: avoids dividing by ~0
    joblib.dump(dict(iso=iso, thr=thr, med=med, mad=mad, lo=sc.min(), hi=sc.max()), path)
    return path


def apply_rules(r):
    hits = []
    for name, d in RULES.items():
        v = r[d["feat"]]
        ok = v >= d["thr"]
        if ok and "extra" in d:
            k, c = d["extra"]
            ok = (r[k] in c) if isinstance(c, set) else (r[k] >= c)
        if ok:
            ratio = v / d["thr"]
            hits.append((name, f"{d['feat']}={v:g} >= {d['thr']}" +
                         (f" and {d['extra'][0]} matches" if "extra" in d else ""), ratio))
    return hits


def detect(feat_df, model_path="model.joblib"):
    m = joblib.load(model_path)
    X = tf(feat_df)
    sc = m["iso"].score_samples(X)
    z = (X - m["med"]) / m["mad"]
    events = []
    for i, (_, r) in enumerate(feat_df.iterrows()):
        hits = apply_rules(r)
        anomalous = sc[i] < m["thr"]
        if not hits and not anomalous:
            continue
        top = z.iloc[i].sort_values(ascending=False).head(3)
        ml_why = "; ".join(f"{k}={r[k]:.3g} ({v:+.1f} MAD above benign)" for k, v in top.items())
        if hits:
            name, why, ratio = max(hits, key=lambda h: h[2])
            conf = "high" if anomalous else "medium"           # rule+ML agree -> higher confidence
            sev = "CRITICAL" if ratio >= 3 else "HIGH" if ratio >= 1.5 else "MEDIUM"
            src_layer = "rule+ML" if anomalous else "rule"
        else:
            name, why, conf, sev, src_layer = "unclassified_anomaly", "no rule matched", "low", "LOW", "ML"
        events.append(dict(t_start=r.t_start, src=r.src, dst=r.top_dst, flagged_as=name, severity=sev,
                           confidence=conf, layer=src_layer, rule_match=why, ml_top_features=ml_why,
                           anomaly_score=round(float(-sc[i]), 3), win=r.win))
    return pd.DataFrame(events)
