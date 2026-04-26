"""
analyze.py — Synthesize and visualize tshark capture CSVs.

Reads one or more capture CSV files produced by capture.py and generates:
    • Per-condition summary statistics (packets/min, bytes/min, avg size, …)
    • Packet size distribution histograms
    • Packets-per-second time series for each condition
    • Cross-condition comparison charts
    • A plain-text report saved to reports/

Usage:
    # Analyze a single file
    python analyze.py data/idle/capture_20240101_120000.csv

    # Analyze all three conditions and compare
    python analyze.py --compare \
        data/idle/capture_20240101_120000.csv \
        data/live/capture_20240101_130000.csv \
        data/research/capture_20240101_140000.csv

    # Auto-discover latest capture per condition
    python analyze.py --auto
"""

import argparse
import os
import glob
import json
import datetime
import sys

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")           # headless — no display needed
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import matplotlib.gridspec as gridspec
import seaborn as sns

# ── style ──────────────────────────────────────────────────────────────────
sns.set_theme(style="darkgrid", palette="muted")
CONDITION_COLORS = {
    "idle":     "#4C9BE8",   # calm blue
    "live":     "#E8704C",   # warm orange — high energy
    "research": "#4CE87A",   # green — controlled
}
CONDITION_LABELS = {
    "idle":     "Idle (Baseline)",
    "live":     "Live Show",
    "research": "Research (Controlled)",
}

# Audio protocol port map for annotating traffic
AUDIO_PORTS = {
    319:  "PTP Event",
    320:  "PTP General",
    4440: "Dante",
    5004: "RTP",
    5005: "RTCP",
    6000: "CobraNet",
}

# Size bins (bytes) that matter for audio networks
# Dante: typically 1000–1400 bytes  |  RTP: 172–1472  |  PTP: 44 bytes
SIZE_BINS = [0, 64, 128, 256, 512, 1024, 1280, 1500, 9000]
SIZE_LABELS = [
    "≤64",
    "65–128",
    "129–256",
    "257–512",
    "513–1024",
    "1025–1280",
    "1281–1500",
    ">1500",
]


# ── Loading ────────────────────────────────────────────────────────────────

def load_csv(csv_path: str) -> tuple[pd.DataFrame, dict]:
    """Load a capture CSV and its sidecar metadata JSON."""
    df = pd.read_csv(csv_path, low_memory=False)

    # Normalise column names (strip whitespace)
    df.columns = [c.strip() for c in df.columns]

    # Parse timestamps
    if "frame.time_epoch" in df.columns:
        df["time"] = pd.to_datetime(
            df["frame.time_epoch"].astype(float), unit="s", utc=True
        )
        df.sort_values("time", inplace=True)
        df.reset_index(drop=True, inplace=True)

    # Numeric coercion for packet length
    if "frame.len" in df.columns:
        df["frame.len"] = pd.to_numeric(df["frame.len"], errors="coerce")

    # Load sidecar metadata if present
    meta_path = csv_path.replace(".csv", "_meta.json")
    meta = {}
    if os.path.exists(meta_path):
        with open(meta_path) as mf:
            meta = json.load(mf)
    else:
        # Infer condition from directory name
        meta["condition"] = os.path.basename(os.path.dirname(csv_path))

    return df, meta


# ── Statistics ────────────────────────────────────────────────────────────

def compute_statistics(df: pd.DataFrame, meta: dict) -> dict:
    """Compute summary statistics for a single capture session."""
    condition = meta.get("condition", "unknown")
    total_packets = len(df)
    sizes = df["frame.len"].dropna()

    # Duration: from metadata or inferred from timestamps
    duration_s = meta.get("duration_s", None)
    if duration_s is None and "time" in df.columns and len(df) > 1:
        duration_s = (df["time"].iloc[-1] - df["time"].iloc[0]).total_seconds()
    duration_s = max(duration_s or 1, 1)   # avoid division by zero

    packets_per_min = total_packets / duration_s * 60
    bytes_total = sizes.sum()
    mbytes_per_min = bytes_total / duration_s * 60 / 1_000_000

    stats = {
        "condition": condition,
        "total_packets": int(total_packets),
        "duration_s": round(duration_s, 2),
        "packets_per_min": round(packets_per_min, 1),
        "bytes_total": int(bytes_total),
        "MB_per_min": round(mbytes_per_min, 3),
        "avg_packet_size_bytes": round(float(sizes.mean()), 1) if len(sizes) else 0,
        "median_packet_size_bytes": round(float(sizes.median()), 1) if len(sizes) else 0,
        "min_packet_size_bytes": int(sizes.min()) if len(sizes) else 0,
        "max_packet_size_bytes": int(sizes.max()) if len(sizes) else 0,
        "std_packet_size_bytes": round(float(sizes.std()), 1) if len(sizes) else 0,
    }

    # Packet size bin counts
    if len(sizes):
        bin_counts = pd.cut(
            sizes, bins=SIZE_BINS, labels=SIZE_LABELS, right=True
        ).value_counts().sort_index()
        for label, count in bin_counts.items():
            stats[f"size_bin_{label}"] = int(count)

    # Protocol breakdown (UDP vs TCP vs other)
    if "ip.proto" in df.columns:
        proto_counts = df["ip.proto"].value_counts()
        stats["udp_packets"] = int(proto_counts.get(17, 0))
        stats["tcp_packets"] = int(proto_counts.get(6, 0))
        stats["other_packets"] = int(total_packets - stats["udp_packets"] - stats["tcp_packets"])

    # Latency proxy: inter-packet gap (IPG) distribution
    if "time" in df.columns and len(df) > 1:
        ipg_ms = df["time"].diff().dt.total_seconds().dropna() * 1000
        stats["ipg_mean_ms"] = round(float(ipg_ms.mean()), 3)
        stats["ipg_median_ms"] = round(float(ipg_ms.median()), 3)
        stats["ipg_p95_ms"] = round(float(ipg_ms.quantile(0.95)), 3)
        stats["ipg_p99_ms"] = round(float(ipg_ms.quantile(0.99)), 3)
        stats["ipg_min_ms"] = round(float(ipg_ms.min()), 4)
        stats["ipg_max_ms"] = round(float(ipg_ms.max()), 3)
        # Jitter estimate (std dev of IPG — a common proxy)
        stats["jitter_estimate_ms"] = round(float(ipg_ms.std()), 3)

    return stats


# ── Per-second time series ────────────────────────────────────────────────

def packets_per_second(df: pd.DataFrame) -> pd.Series:
    """Resample to 1-second bins and count packets."""
    if "time" not in df.columns:
        return pd.Series(dtype=int)
    df2 = df.set_index("time")
    return df2.resample("1s")["frame.len"].count().rename("packets")


def bytes_per_second(df: pd.DataFrame) -> pd.Series:
    """Resample to 1-second bins and sum bytes."""
    if "time" not in df.columns:
        return pd.Series(dtype=float)
    df2 = df.set_index("time")
    return df2.resample("1s")["frame.len"].sum().rename("bytes")


# ── Plotting ──────────────────────────────────────────────────────────────

def plot_size_distribution(dfs: dict[str, pd.DataFrame], output_dir: str):
    """Histogram of packet sizes, one series per condition."""
    fig, axes = plt.subplots(1, len(dfs), figsize=(6 * len(dfs), 5), sharey=False)
    if len(dfs) == 1:
        axes = [axes]

    for ax, (condition, df) in zip(axes, dfs.items()):
        sizes = df["frame.len"].dropna()
        color = CONDITION_COLORS.get(condition, "#888888")
        ax.hist(
            sizes,
            bins=80,
            color=color,
            edgecolor="white",
            linewidth=0.3,
            alpha=0.85,
        )
        ax.set_title(CONDITION_LABELS.get(condition, condition), fontsize=11, fontweight="bold")
        ax.set_xlabel("Packet Size (bytes)", fontsize=9)
        ax.set_ylabel("Count", fontsize=9)
        ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{int(x):,}"))

        # Annotate mean
        mean_val = sizes.mean()
        ax.axvline(mean_val, color="red", linestyle="--", linewidth=1.2, label=f"Mean: {mean_val:.0f}B")
        ax.legend(fontsize=8)

    fig.suptitle("Packet Size Distribution by Condition", fontsize=13, fontweight="bold", y=1.02)
    plt.tight_layout()
    path = os.path.join(output_dir, "packet_size_distribution.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [✓] {path}")
    return path


def plot_size_bins_comparison(stats_list: list[dict], output_dir: str):
    """Grouped bar chart of packet size bins across all conditions."""
    rows = []
    for s in stats_list:
        cond = s["condition"]
        for label in SIZE_LABELS:
            key = f"size_bin_{label}"
            rows.append({
                "Condition": CONDITION_LABELS.get(cond, cond),
                "Size Range": label,
                "Count": s.get(key, 0),
            })
    df_plot = pd.DataFrame(rows)

    fig, ax = plt.subplots(figsize=(13, 5))
    conditions = df_plot["Condition"].unique()
    x = np.arange(len(SIZE_LABELS))
    width = 0.8 / len(conditions)

    for i, cond in enumerate(conditions):
        subset = df_plot[df_plot["Condition"] == cond]
        counts = [subset[subset["Size Range"] == l]["Count"].values[0]
                  if len(subset[subset["Size Range"] == l]) else 0
                  for l in SIZE_LABELS]
        raw_cond = [k for k, v in CONDITION_LABELS.items() if v == cond]
        color = CONDITION_COLORS.get(raw_cond[0] if raw_cond else "", "#888")
        ax.bar(x + i * width, counts, width, label=cond, color=color, alpha=0.85)

    ax.set_xlabel("Packet Size Range (bytes)", fontsize=10)
    ax.set_ylabel("Packet Count", fontsize=10)
    ax.set_title("Packet Size Bins Across Conditions", fontsize=12, fontweight="bold")
    ax.set_xticks(x + width * (len(conditions) - 1) / 2)
    ax.set_xticklabels(SIZE_LABELS, rotation=30, ha="right", fontsize=8)
    ax.legend(fontsize=9)
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda y, _: f"{int(y):,}"))
    plt.tight_layout()
    path = os.path.join(output_dir, "size_bins_comparison.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [✓] {path}")
    return path


def plot_time_series(dfs: dict[str, pd.DataFrame], output_dir: str):
    """Packets-per-second time series for each condition (subplots)."""
    n = len(dfs)
    fig, axes = plt.subplots(n, 1, figsize=(12, 3.5 * n), sharex=False)
    if n == 1:
        axes = [axes]

    for ax, (condition, df) in zip(axes, dfs.items()):
        pps = packets_per_second(df)
        color = CONDITION_COLORS.get(condition, "#888888")
        if len(pps):
            t_rel = (pps.index - pps.index[0]).total_seconds()
            ax.fill_between(t_rel, pps.values, alpha=0.35, color=color)
            ax.plot(t_rel, pps.values, color=color, linewidth=1.2)
            ax.set_title(
                f"{CONDITION_LABELS.get(condition, condition)} — Packets/s",
                fontsize=11, fontweight="bold"
            )
            ax.set_xlabel("Time (seconds)", fontsize=9)
            ax.set_ylabel("Packets / second", fontsize=9)

            # Reference lines at common audio network thresholds
            mean_pps = pps.mean()
            ax.axhline(mean_pps, color="red", linestyle="--", linewidth=1,
                       label=f"Mean: {mean_pps:.1f} pkt/s")
            ax.legend(fontsize=8)
        else:
            ax.text(0.5, 0.5, "No timestamp data", ha="center", va="center",
                    transform=ax.transAxes)

    fig.suptitle("Packet Rate Over Time by Condition", fontsize=13, fontweight="bold")
    plt.tight_layout()
    path = os.path.join(output_dir, "packets_per_second_timeseries.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [✓] {path}")
    return path


def plot_ipg_distribution(dfs: dict[str, pd.DataFrame], output_dir: str):
    """
    Inter-Packet Gap (IPG) distribution — a latency proxy.
    We focus on the 0–50 ms window where audio network performance matters.
    """
    fig, ax = plt.subplots(figsize=(10, 5))

    for condition, df in dfs.items():
        if "time" not in df.columns or len(df) < 2:
            continue
        ipg_ms = df["time"].diff().dt.total_seconds().dropna() * 1000
        # Clip to sensible audio range
        ipg_ms = ipg_ms[ipg_ms <= 50]
        color = CONDITION_COLORS.get(condition, "#888")
        ax.hist(
            ipg_ms,
            bins=100,
            color=color,
            alpha=0.55,
            label=CONDITION_LABELS.get(condition, condition),
            density=True,
        )

    ax.axvline(10, color="red", linestyle="--", linewidth=1.5, label="10 ms threshold (Wessel & Wright, 2002)")
    ax.axvline(3, color="orange", linestyle=":", linewidth=1.5, label="3 ms (Mitchell et al. ideal)")
    ax.set_xlabel("Inter-Packet Gap (ms)", fontsize=10)
    ax.set_ylabel("Density", fontsize=10)
    ax.set_title("Inter-Packet Gap Distribution (Latency Proxy)", fontsize=12, fontweight="bold")
    ax.legend(fontsize=8)
    ax.set_xlim(0, 50)
    plt.tight_layout()
    path = os.path.join(output_dir, "ipg_distribution.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [✓] {path}")
    return path


def plot_protocol_breakdown(stats_list: list[dict], output_dir: str):
    """Stacked bar showing UDP/TCP/Other breakdown per condition."""
    fig, ax = plt.subplots(figsize=(8, 5))
    conditions = [CONDITION_LABELS.get(s["condition"], s["condition"]) for s in stats_list]
    udp = [s.get("udp_packets", 0) for s in stats_list]
    tcp = [s.get("tcp_packets", 0) for s in stats_list]
    other = [s.get("other_packets", 0) for s in stats_list]

    x = np.arange(len(conditions))
    ax.bar(x, udp, label="UDP (audio/RTP/Dante)", color="#4C9BE8")
    ax.bar(x, tcp, bottom=udp, label="TCP (control/management)", color="#E8704C")
    bottom2 = [u + t for u, t in zip(udp, tcp)]
    ax.bar(x, other, bottom=bottom2, label="Other / non-IP", color="#888888")

    ax.set_xticks(x)
    ax.set_xticklabels(conditions, fontsize=9)
    ax.set_ylabel("Packet Count", fontsize=10)
    ax.set_title("Protocol Breakdown by Condition", fontsize=12, fontweight="bold")
    ax.legend(fontsize=9)
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda y, _: f"{int(y):,}"))
    plt.tight_layout()
    path = os.path.join(output_dir, "protocol_breakdown.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [✓] {path}")
    return path


def plot_throughput_comparison(stats_list: list[dict], output_dir: str):
    """Bar chart: MB/min and packets/min side-by-side for each condition."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))
    conditions = [CONDITION_LABELS.get(s["condition"], s["condition"]) for s in stats_list]
    colors = [CONDITION_COLORS.get(s["condition"], "#888") for s in stats_list]

    # Packets per minute
    ppm = [s["packets_per_min"] for s in stats_list]
    ax1.bar(conditions, ppm, color=colors, alpha=0.85, edgecolor="white")
    ax1.set_title("Packets per Minute", fontsize=11, fontweight="bold")
    ax1.set_ylabel("Packets / min", fontsize=9)
    ax1.yaxis.set_major_formatter(ticker.FuncFormatter(lambda y, _: f"{int(y):,}"))
    for i, v in enumerate(ppm):
        ax1.text(i, v * 1.01, f"{v:,.0f}", ha="center", fontsize=8)

    # MB per minute
    mbpm = [s["MB_per_min"] for s in stats_list]
    ax2.bar(conditions, mbpm, color=colors, alpha=0.85, edgecolor="white")
    ax2.set_title("Data Throughput per Minute", fontsize=11, fontweight="bold")
    ax2.set_ylabel("MB / min", fontsize=9)
    for i, v in enumerate(mbpm):
        ax2.text(i, v * 1.01, f"{v:.2f}", ha="center", fontsize=8)

    fig.suptitle("Network Load Comparison Across Conditions", fontsize=13, fontweight="bold")
    plt.tight_layout()
    path = os.path.join(output_dir, "throughput_comparison.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [✓] {path}")
    return path


# ── Text report ───────────────────────────────────────────────────────────

def generate_text_report(stats_list: list[dict], output_dir: str) -> str:
    """Write a human-readable plain-text summary report."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    lines.append("=" * 70)
    lines.append("  LIVE SOUND NETWORK — PACKET MEASUREMENT REPORT")
    lines.append(f"  Generated: {timestamp}")
    lines.append("=" * 70)
    lines.append("")

    for s in stats_list:
        cond = CONDITION_LABELS.get(s["condition"], s["condition"])
        lines.append(f"─── {cond} ───────────────────────────────────────────")
        lines.append(f"  Duration              : {s['duration_s']:.1f} s")
        lines.append(f"  Total Packets         : {s['total_packets']:,}")
        lines.append(f"  Packets / Minute      : {s['packets_per_min']:,.1f}")
        lines.append(f"  Total Data            : {s['bytes_total'] / 1_000_000:.3f} MB")
        lines.append(f"  Data / Minute         : {s['MB_per_min']:.3f} MB/min")
        lines.append("")
        lines.append("  Packet Size (bytes)")
        lines.append(f"    Mean   : {s['avg_packet_size_bytes']:.1f}")
        lines.append(f"    Median : {s['median_packet_size_bytes']:.1f}")
        lines.append(f"    Min    : {s['min_packet_size_bytes']}")
        lines.append(f"    Max    : {s['max_packet_size_bytes']}")
        lines.append(f"    StdDev : {s['std_packet_size_bytes']:.1f}")
        lines.append("")

        # Size bins
        lines.append("  Packet Size Bins")
        for label in SIZE_LABELS:
            key = f"size_bin_{label}"
            count = s.get(key, 0)
            bar = "█" * min(int(count / max(s["total_packets"], 1) * 50), 50)
            pct = count / max(s["total_packets"], 1) * 100
            lines.append(f"    {label:>12} bytes : {count:6,}  ({pct:5.1f}%)  {bar}")
        lines.append("")

        # Protocol breakdown
        if "udp_packets" in s:
            tot = s["total_packets"]
            lines.append("  Protocol Breakdown")
            lines.append(f"    UDP   : {s['udp_packets']:,} ({s['udp_packets']/max(tot,1)*100:.1f}%)")
            lines.append(f"    TCP   : {s['tcp_packets']:,} ({s['tcp_packets']/max(tot,1)*100:.1f}%)")
            lines.append(f"    Other : {s['other_packets']:,} ({s['other_packets']/max(tot,1)*100:.1f}%)")
            lines.append("")

        # IPG / latency proxy
        if "ipg_mean_ms" in s:
            lines.append("  Inter-Packet Gap (latency proxy, ms)")
            lines.append(f"    Mean   : {s['ipg_mean_ms']:.3f}")
            lines.append(f"    Median : {s['ipg_median_ms']:.3f}")
            lines.append(f"    P95    : {s['ipg_p95_ms']:.3f}")
            lines.append(f"    P99    : {s['ipg_p99_ms']:.3f}")
            lines.append(f"    Min    : {s['ipg_min_ms']:.4f}")
            lines.append(f"    Max    : {s['ipg_max_ms']:.3f}")
            lines.append(f"    Jitter : {s['jitter_estimate_ms']:.3f}")
            lines.append("")

    lines.append("─" * 70)
    lines.append("  NOTES")
    lines.append("  • Latency figures are inter-packet gap proxies, not round-trip latency.")
    lines.append("  • For true RTT, configure tshark to capture both outbound and inbound")
    lines.append("    streams and match packet IDs.")
    lines.append("  • Audio synchronisation threshold: <10 ms (Wessel & Wright, 2002)")
    lines.append("  • Dante/RTP ideal target: <3 ms (Mitchell et al., 2014)")
    lines.append("  • Jitter should be <1 ms for professional audio (McPherson et al., 2016)")
    lines.append("=" * 70)

    report_text = "\n".join(lines)
    path = os.path.join(output_dir, "measurement_report.txt")
    with open(path, "w") as f:
        f.write(report_text)
    print(f"  [✓] {path}")
    return path


# ── CSV stats export ──────────────────────────────────────────────────────

def export_stats_csv(stats_list: list[dict], output_dir: str) -> str:
    df = pd.DataFrame(stats_list)
    path = os.path.join(output_dir, "summary_statistics.csv")
    df.to_csv(path, index=False)
    print(f"  [✓] {path}")
    return path


# ── Auto-discovery ────────────────────────────────────────────────────────

def find_latest_captures(data_root: str = "data") -> dict[str, str]:
    """Find the most recent CSV in each condition subdirectory."""
    found = {}
    for condition in ["idle", "live", "research"]:
        pattern = os.path.join(data_root, condition, "capture_*.csv")
        files = sorted(glob.glob(pattern))
        if files:
            found[condition] = files[-1]
    return found


# ── Main entry point ──────────────────────────────────────────────────────

def run_analysis(csv_paths: list[str], report_dir: str = "reports"):
    """
    Load CSV files, compute statistics, and generate all plots + reports.
    """
    os.makedirs(report_dir, exist_ok=True)
    dfs: dict[str, pd.DataFrame] = {}
    stats_list: list[dict] = []

    print("\n[*] Loading capture files …")
    for path in csv_paths:
        if not os.path.exists(path):
            print(f"  [!] File not found: {path}")
            continue
        df, meta = load_csv(path)
        condition = meta.get("condition", "unknown")
        print(f"  [+] {condition}: {len(df):,} packets from {path}")
        dfs[condition] = df
        stats = compute_statistics(df, meta)
        stats_list.append(stats)

    if not dfs:
        print("[!] No valid data loaded.")
        return

    print("\n[*] Generating plots …")
    plot_size_distribution(dfs, report_dir)
    plot_time_series(dfs, report_dir)
    plot_ipg_distribution(dfs, report_dir)

    if len(stats_list) > 1:
        plot_size_bins_comparison(stats_list, report_dir)
        plot_protocol_breakdown(stats_list, report_dir)
        plot_throughput_comparison(stats_list, report_dir)

    print("\n[*] Generating reports …")
    generate_text_report(stats_list, report_dir)
    export_stats_csv(stats_list, report_dir)

    # Print a quick console summary
    print("\n" + "=" * 60)
    print("  QUICK SUMMARY")
    print("=" * 60)
    header = f"  {'Condition':<20} {'Pkts/min':>10} {'MB/min':>8} {'Avg Size':>10} {'Jitter ms':>10}"
    print(header)
    print("  " + "-" * 58)
    for s in stats_list:
        jitter = s.get("jitter_estimate_ms", "—")
        jitter_str = f"{jitter:.3f}" if isinstance(jitter, float) else "—"
        print(
            f"  {CONDITION_LABELS.get(s['condition'], s['condition']):<20}"
            f" {s['packets_per_min']:>10,.1f}"
            f" {s['MB_per_min']:>8.3f}"
            f" {s['avg_packet_size_bytes']:>9.1f}B"
            f" {jitter_str:>10}"
        )
    print("=" * 60)
    print(f"\n[✓] All outputs saved to: {report_dir}/\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze tshark capture CSVs from the sound network study",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single idle capture
  python analyze.py data/idle/capture_20240101_120000.csv

  # Compare all three conditions
  python analyze.py --compare \\
      data/idle/capture_20240101_120000.csv \\
      data/live/capture_20240101_130000.csv \\
      data/research/capture_20240101_140000.csv

  # Auto-discover most recent capture per condition
  python analyze.py --auto
        """,
    )
    parser.add_argument("files", nargs="*", help="CSV capture file(s) to analyze")
    parser.add_argument("--compare", action="store_true",
                        help="Alias for analyzing multiple files together")
    parser.add_argument("--auto", action="store_true",
                        help="Auto-discover latest capture per condition")
    parser.add_argument("--data-dir", default="data",
                        help="Root data directory for --auto (default: data/)")
    parser.add_argument("--report-dir", default="reports",
                        help="Directory for output reports (default: reports/)")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.auto:
        captures = find_latest_captures(args.data_dir)
        if not captures:
            print(f"[!] No captures found in {args.data_dir}/")
            sys.exit(1)
        csv_paths = list(captures.values())
    else:
        csv_paths = args.files

    if not csv_paths:
        print("Error: provide CSV file paths or use --auto. See --help.")
        sys.exit(1)

    run_analysis(csv_paths, report_dir=args.report_dir)


if __name__ == "__main__":
    main()


## CODE GENERATED WITH CLAUDE