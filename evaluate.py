"""Scores detections against generator ground truth at (window, source) granularity."""
import json, pandas as pd, numpy as np
from features import extract
from detector import detect


def label(feat, truth):
    y = np.zeros(len(feat), dtype=int)
    for i, r in enumerate(feat.itertuples()):
        for a in truth:
            if r.src == a["src"] and r.t_start < a["end"] and r.t_end > a["start"]:
                y[i] = 1
    return y


def run_all(meta_path="data/labels.json", model="model.joblib"):
    meta = json.load(open(meta_path))
    rows, details = [], {}
    for name, m in meta.items():
        if name == "train":
            continue
        f = extract(m["pcap"])
        ev = detect(f, model)
        y = label(f, m["labels"])
        flagged = set(ev.win.astype(str) + ev.src) if len(ev) else set()
        yhat = np.array([int((str(r.win) + r.src) in flagged) for r in f.itertuples()])
        tp, fp = int(((y == 1) & (yhat == 1)).sum()), int(((y == 0) & (yhat == 1)).sum())
        fn, tn = int(((y == 1) & (yhat == 0)).sum()), int(((y == 0) & (yhat == 0)).sum())
        rows.append(dict(scenario=name, windows=len(f), TP=tp, FP=fp, FN=fn, TN=tn))
        details[name] = (f, ev, y, yhat)
    res = pd.DataFrame(rows)
    T = res[["TP", "FP", "FN", "TN"]].sum()
    tot = dict(scenario="ALL", windows=int(res.windows.sum()), **{k: int(v) for k, v in T.items()})
    res = pd.concat([res, pd.DataFrame([tot])], ignore_index=True)
    res["precision"] = (res.TP / (res.TP + res.FP).replace(0, np.nan)).round(3)
    res["recall"] = (res.TP / (res.TP + res.FN).replace(0, np.nan)).round(3)
    res["accuracy"] = ((res.TP + res.TN) / res.windows).round(3)
    return res, details


def dos_impact(pcap="data/s3_dos.pcap", victim="10.0.1.10", w=5.0):
    """Packets/s and half-open SYN rate arriving at the victim, per window (Scenario 3 performance impact)."""
    from features import read_packets
    d = read_packets(pcap); d = d[d.dst == victim]
    d["win"] = ((d.t - d.t.min()) // w).astype(int)
    g = d.groupby("win").agg(pps=("t", lambda x: len(x) / w), syn_per_s=("tflags", lambda x: (x == 2).sum() / w))
    return g.round(1)
