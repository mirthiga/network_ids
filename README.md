# Hybrid Network IDS (rules + Isolation Forest)

Prototype for the Megaminds *AI-Driven Network Traffic Analysis and Intrusion Detection* assessment.

## Setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt        # scapy, pandas, numpy, scikit-learn, joblib
```
No root, Mininet or live capture needed: traffic is synthesised with Scapy into PCAPs (seeded -> reproducible).

## Reproduce results
```bash
python ids.py generate                 # PCAPs + data/labels.json (ground truth)
python ids.py train                    # fit anomaly model on benign-only train_benign.pcap
python ids.py evaluate                 # all 5 scenarios, metrics, DoS load table
python ids.py detect data/s2_portscan.pcap          # analyst view for one PCAP
python ids.py detect <your.pcap> --csv out.csv      # works on real captures (tcpdump/Wireshark)
```

## Pipeline
PCAP -> 5 s window x source-IP features (`features.py`) -> rule layer + IsolationForest (`detector.py`) -> explained events -> metrics (`evaluate.py`).

| Feature | Why |
|---|---|
| syn_cnt | connection-attempt rate (flood, brute force) |
| uniq_dst_ports / uniq_dst_ips | horizontal/vertical scan breadth |
| max_syn_same_port | repeated attempts on one service (brute force) |
| half_open_ratio | SYNs never completed by an ACK (flood/scan vs. real sessions) |
| pps, bytes, mean_pkt_size | volume / shape of traffic |

Rules: port_scan (>=15 ports/window), dos_syn_flood (>=300 SYN & >=80% half-open), ssh_bruteforce (>=12 SYN to one auth port).
ML layer: IsolationForest trained on benign windows only; catches rule-less anomalies, flagged as `unclassified_anomaly` (LOW).
Each event reports: what, why (rule + top-3 deviating features in MADs above benign), severity (threshold ratio), confidence (rule+ML agree = high).

## Scenarios (data/)
S1 benign | S2 SYN port scan | S3 SYN flood | S4 SSH brute force | S5 slow scan (missed by rules) + benign health-checker (false positive)

## Known limitations
Synthetic traffic (not CICIDS2017); single-source attacks (spoofed/distributed floods defeat per-source features); fixed window enables low-and-slow evasion; thresholds tuned on the same generator; offline analysis only, no latency/throughput benchmarking.
