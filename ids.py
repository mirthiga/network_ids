#!/usr/bin/env python3
"""CLI:  python ids.py generate | train | detect <pcap> | evaluate"""
import argparse, json, sys, pandas as pd
pd.set_option("display.width", 250); pd.set_option("display.max_colwidth", 90)


def main():
    ap = argparse.ArgumentParser(description="Hybrid rule + Isolation Forest network IDS")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate", help="create synthetic PCAPs + ground truth in ./data")
    tr = sub.add_parser("train", help="fit anomaly model on benign training PCAP"); tr.add_argument("--pcap"); tr.add_argument("--model", default="model.joblib")
    d = sub.add_parser("detect", help="run detection on a PCAP"); d.add_argument("pcap"); d.add_argument("--csv")
    ev_ = sub.add_parser("evaluate", help="score scenarios against ground truth"); ev_.add_argument("--meta", default="data/labels.json"); ev_.add_argument("--model", default="model.joblib"); ev_.add_argument("--tag", default="")
    a = ap.parse_args()

    if a.cmd == "generate":
        import generate_traffic; generate_traffic.main()
    elif a.cmd == "train":
        from features import extract; from detector import train
        pcap = a.pcap or json.load(open("data/labels.json"))["train"]["pcap"]
        f = extract(pcap); train(f, a.model); print(f"trained on {len(f)} benign windows from {pcap} -> {a.model}")
    elif a.cmd == "detect":
        from features import extract; from detector import detect
        f = extract(a.pcap); ev = detect(f)
        print(f"{len(f)} windows analysed, {len(ev)} flagged")
        for _, e in ev.iterrows():
            print(f"\n[{e.severity}] {e.flagged_as}  src={e.src} -> {e.dst}  t+{e.win*5}s  conf={e.confidence} ({e.layer})"
                  f"\n   rule : {e.rule_match}\n   ML   : {e.ml_top_features}  (anomaly score {e.anomaly_score})")
        if a.csv: ev.to_csv(a.csv, index=False)
    elif a.cmd == "evaluate":
        from evaluate import run_all
        res, det = run_all(a.meta, a.model); print(res.to_string(index=False))
        res.to_csv(f"results_metrics{a.tag}.csv", index=False)
        if a.meta == "data/labels.json":
            from evaluate import dos_impact
            print("\nScenario 3 - load on victim 10.0.1.10 (per 5 s window):"); print(dos_impact().T.to_string())
        for n, (f, ev, y, yhat) in det.items():
            miss = f[(y == 1) & (yhat == 0)]; fp = f[(y == 0) & (yhat == 1)]
            if len(miss): print(f"\n[{n}] MISSED: {miss.src.unique().tolist()} in {len(miss)} windows")
            if len(fp):   print(f"[{n}] FALSE POSITIVE: {fp.src.unique().tolist()} in {len(fp)} windows")


if __name__ == "__main__":
    main()
