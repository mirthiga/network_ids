"""Flow/window feature extraction: one row per (5-second window, source IP) for sources that initiated TCP connections."""
import numpy as np, pandas as pd
from scapy.all import PcapReader, IP, TCP, UDP

WINDOW = 5.0
FEATURES = ["syn_cnt", "uniq_dst_ports", "uniq_dst_ips", "max_syn_same_port",
            "half_open_ratio", "pps", "bytes", "mean_pkt_size"]


def read_packets(pcap):
    rows = []
    with PcapReader(pcap) as r:
        for p in r:
            if IP not in p:
                continue
            ip = p[IP]
            if TCP in p:
                f, dport, proto = int(p[TCP].flags), p[TCP].dport, "tcp"
            elif UDP in p:
                f, dport, proto = 0, p[UDP].dport, "udp"
            else:
                f, dport, proto = 0, 0, "other"
            rows.append((float(p.time), ip.src, ip.dst, dport, f, len(p), proto))
    return pd.DataFrame(rows, columns=["t", "src", "dst", "dport", "tflags", "len", "proto"])


def extract(pcap):
    df = read_packets(pcap)
    if df.empty:
        return pd.DataFrame()
    t0 = df.t.min()
    df["win"] = ((df.t - t0) // WINDOW).astype(int)
    df["is_syn"] = (df.tflags == 0x02)                       # pure SYN (connection attempt)
    df["is_ack"] = (df.tflags == 0x10)                       # pure ACK (handshake completion)
    out = []
    for (w, src), g in df.groupby(["win", "src"]):
        syn = g[g.is_syn]
        if syn.empty:                                      # only score connection initiators
            continue
        n_syn = len(syn)
        out.append(dict(
            win=w, src=src, t_start=t0 + w * WINDOW, t_end=t0 + (w + 1) * WINDOW,
            syn_cnt=n_syn,
            uniq_dst_ports=syn.dport.nunique(),
            uniq_dst_ips=syn.dst.nunique(),
            max_syn_same_port=syn.groupby("dport").size().max(),
            half_open_ratio=max(0, n_syn - g.is_ack.sum()) / n_syn,
            pps=len(g) / WINDOW, bytes=g.len.sum(), mean_pkt_size=g.len.mean(),
            top_dst=syn.dst.mode().iat[0], top_port=int(syn.dport.mode().iat[0])))
    return pd.DataFrame(out)
