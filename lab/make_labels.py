"""Build a ground-truth labels file for your own capture.
usage: python lab/make_labels.py events.log my_attack.pcap data/real_labels.json [benign_test.pcap]"""
import sys, json
log, pcap, out = sys.argv[1:4]
labels = []
for line in open(log):
    typ, src, t0, t1 = line.split()
    labels.append({"src": src, "type": typ, "start": float(t0), "end": float(t1)})
meta = {"real_attack_capture": {"pcap": pcap, "labels": labels}}
if len(sys.argv) > 4:
    meta["real_benign_capture"] = {"pcap": sys.argv[4], "labels": []}
json.dump(meta, open(out, "w"), indent=2); print("wrote", out, "-", len(labels), "attacks")
