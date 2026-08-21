#!/usr/bin/env python3
"""
label_flows.py

Turns unlabeled flow records into a labeled training set by matching each
flow's start time (+ involved IP) against a log of when you were running
known attacks in your test lab.

Requires your flow CSV to have been upgraded with `start_ts`, `srcIp`,
`dstIp` columns first (see the C++ changes discussed in chat) -- this
can't label flows that don't carry a timestamp and an IP.

Usage:
    python label_flows.py flows.csv attack_windows.csv labeled_flows.csv

flows.csv expected columns (at minimum):
    start_ts, srcIp, dstIp, ...(all your existing flow features)

attack_windows.csv expected columns:
    attack_type, start_ts, end_ts, attacker_ip
    (one row per attack run -- e.g. logged with the bash snippet from chat
    while you run nmap/hping3/slowloris/hydra against a lab target)
"""
import sys
import pandas as pd


def label_flows(flows_path: str, windows_path: str, out_path: str) -> None:
    flows = pd.read_csv(flows_path)
    windows = pd.read_csv(windows_path)

    for col in ("start_ts", "srcIp", "dstIp"):
        if col not in flows.columns:
            raise SystemExit(
                f"flows file is missing '{col}' -- add timestamp/IP capture "
                f"to your collector before labeling (see chat)."
            )

    flows["label"] = "benign"
    overlap_count = 0

    for _, w in windows.iterrows():
        in_window = flows["start_ts"].between(w["start_ts"], w["end_ts"])
        involves_attacker = (flows["srcIp"] == w["attacker_ip"]) | (flows["dstIp"] == w["attacker_ip"])
        mask = in_window & involves_attacker

        already_labeled = mask & (flows["label"] != "benign")
        if already_labeled.any():
            overlap_count += int(already_labeled.sum())

        flows.loc[mask, "label"] = w["attack_type"]

    flows.to_csv(out_path, index=False)

    print(f"Labeled {len(flows)} flows -> {out_path}")
    print(flows["label"].value_counts().to_string())
    if overlap_count:
        print(
            f"\nNote: {overlap_count} flow(s) fell inside more than one attack "
            f"window (last match won). Check attack_windows.csv for overlaps."
        )


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("Usage: python label_flows.py flows.csv attack_windows.csv labeled_flows.csv")
    label_flows(*sys.argv[1:4])
