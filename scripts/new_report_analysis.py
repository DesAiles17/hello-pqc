#!/usr/bin/env python3
"""
Enhanced benchmark analysis with normalized visualizations.
Focuses on relative comparisons (ratios, percentages) for non-technical understanding.
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence
import matplotlib.pyplot as plt
import numpy as np
from matplotlib import cm
from matplotlib.patches import Patch

try:
    import matplotlib
    matplotlib.use("Agg")
except ImportError:
    print("Error: matplotlib required. Install: pip install matplotlib", file=sys.stderr)
    sys.exit(1)


ConditionKey = tuple[str, str, str, str, str]
RunRecord = Mapping[str, Any]

HYBRID_PROFILES = {"hmac_sha256_ml_dsa", "hmac_sha256_fn_dsa", "eddsa_ml_dsa", "eddsa_fn_dsa"}
CLASSICAL_PROFILES = {"rsa_pss", "eddsa", "ecdsa", "hmac_sha256"}
PQC_PROFILES = {"ml_dsa", "slh_dsa", "fn_dsa"}
HASH_ORDER = ["sha256", "blake3", "keccak256"]
SCENARIO_ORDER = [
    "workflow",
    "sign_only",
    "verify_manifest",
    "verify_stored",
    "verify_uploaded",
    "verify_full",
]


def coerce_float(value: Any) -> float | None:
    """Safe float coercion."""
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def profile_group(profile: str) -> str:
    """Classify profile type."""
    if profile in HYBRID_PROFILES:
        return "Hybrid"
    elif profile in CLASSICAL_PROFILES:
        return "Classical"
    elif profile in PQC_PROFILES:
        return "PQC"
    return "Unknown"


def profile_color(profile: str) -> str:
    """Color by profile type."""
    group = profile_group(profile)
    if group == "Hybrid":
        return "#8B4513"  # Saddle brown
    elif group == "Classical":
        return "#1f77b4"  # Blue
    elif group == "PQC":
        return "#d62728"  # Red
    return "#7f7f7f"  # Gray


def load_evidence_metrics(csv_path: Path) -> list[dict]:
    """Load evidence metrics CSV."""
    rows = []
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def aggregate_by_profile_hash(rows: list[dict]) -> dict:
    """Group metrics by profile and hash, computing medians."""
    agg = defaultdict(lambda: defaultdict(list))

    for row in rows:
        if row.get("metric_applicability") != "applicable":
            continue
        if row.get("metric_scope") not in ["client", "server"]:
            continue

        profile = row.get("signature_profile", "")
        hash_algo = row.get("hash_algorithm", "")
        metric_name = row.get("metric_name", "")
        median = coerce_float(row.get("median"))

        if median is None or not profile or not hash_algo:
            continue

        key = (profile, hash_algo)
        agg[key][metric_name].append(median)

    # Compute medians
    result = {}
    for key, metrics in agg.items():
        result[key] = {metric: np.median(vals) for metric, vals in metrics.items()}

    return result


def plot_profile_performance_comparison(plt_module: Any, agg_data: dict, output_dir: Path) -> None:
    """
    100% normalized bar chart: time component breakdown by profile.
    Shows relative composition of hash, sign, verify within total.
    """
    fig, axes = plt_module.subplots(2, 1, figsize=(14, 10))

    # Extract unique profiles and hashes
    profiles = sorted(set(key[0] for key in agg_data.keys()))
    hashes = ["sha256", "blake3"]

    for idx, hash_algo in enumerate(hashes):
        ax = axes[idx]
        profile_times = {}

        for profile in profiles:
            key = (profile, hash_algo)
            if key not in agg_data:
                continue

            metrics = agg_data[key]
            hash_ms = metrics.get("server_hash_ms", 0)
            sign_ms = 0
            verify_ms = 0

            # Sum signing metrics
            for field in metrics:
                if "sign_ms" in field:
                    sign_ms += metrics[field]

            # Sum verify metrics
            for field in metrics:
                if "verify_ms" in field:
                    verify_ms += metrics[field]

            total = hash_ms + sign_ms + verify_ms
            if total > 0:
                profile_times[profile] = {
                    "hash": (hash_ms / total) * 100,
                    "sign": (sign_ms / total) * 100,
                    "verify": (verify_ms / total) * 100,
                }

        if not profile_times:
            ax.text(0.5, 0.5, f"No data for {hash_algo}", ha="center", va="center")
            continue

        # Stacked bar
        profiles_list = list(profile_times.keys())
        hash_pcts = [profile_times[p].get("hash", 0) for p in profiles_list]
        sign_pcts = [profile_times[p].get("sign", 0) for p in profiles_list]
        verify_pcts = [profile_times[p].get("verify", 0) for p in profiles_list]

        x = np.arange(len(profiles_list))

        ax.bar(x, hash_pcts, label="Hashing", color="#2ecc71", alpha=0.8)
        ax.bar(x, sign_pcts, bottom=hash_pcts, label="Signing", color="#3498db", alpha=0.8)
        ax.bar(x, verify_pcts, bottom=np.array(hash_pcts) + np.array(sign_pcts),
               label="Verification", color="#e74c3c", alpha=0.8)

        ax.set_ylim([0, 100])
        ax.set_ylabel("Relative Time Contribution (%)")
        ax.set_title(f"Time Component Breakdown ({hash_algo.upper()}): Relative Contribution")
        x_ticks = np.arange(len(profiles_list))
        ax.set_xticks(x_ticks)
        ax.set_xticklabels(profiles_list, rotation=45, ha="right")
        ax.legend(loc="upper right")
        ax.grid(axis="y", alpha=0.3)

    fig.tight_layout()
    fig.savefig(output_dir / "01_profile_composition.png", dpi=150, bbox_inches="tight")
    print(f"✓ Profile composition chart: 01_profile_composition.png")


def plot_hash_efficiency(plt_module: Any, agg_data: dict, output_dir: Path) -> None:
    """Hash algorithm efficiency: hash time per MB (normalized)."""
    fig, ax = plt_module.subplots(figsize=(10, 6))

    hash_metrics = defaultdict(list)

    for (profile, hash_algo), metrics in agg_data.items():
        hash_ms = metrics.get("server_hash_ms", 0)
        if hash_ms > 0:
            hash_metrics[hash_algo].append(hash_ms)

    hashes_list = sorted(hash_metrics.keys())
    hash_times = [np.median(hash_metrics[h]) for h in hashes_list]

    # Normalize to baseline (fastest = 100%)
    baseline = min(hash_times)
    efficiency = [100 * baseline / t for t in hash_times]

    colors = ["#27ae60" if e >= 95 else "#f39c12" if e >= 85 else "#e74c3c" for e in efficiency]
    bars = ax.barh(hashes_list, efficiency, color=colors, alpha=0.8)

    # Add value labels
    for bar, eff in zip(bars, efficiency):
        width = bar.get_width()
        ax.text(width + 1, bar.get_y() + bar.get_height()/2, f"{eff:.1f}%",
                va="center", fontsize=11, fontweight="bold")

    ax.set_xlabel("Relative Speed (% of Fastest Hash)")
    ax.set_title("Hash Algorithm Efficiency Comparison (Higher % = Faster)")
    ax.set_xlim([0, 110])
    ax.grid(axis="x", alpha=0.3)

    fig.tight_layout()
    fig.savefig(output_dir / "02_hash_efficiency.png", dpi=150, bbox_inches="tight")
    print(f"✓ Hash efficiency chart: 02_hash_efficiency.png")


def plot_signature_cost_ratio(plt_module: Any, agg_data: dict, output_dir: Path) -> None:
    """Signature cost as % of total operation time."""
    fig, ax = plt_module.subplots(figsize=(12, 6))

    profile_costs = {}

    for (profile, hash_algo), metrics in agg_data.items():
        if hash_algo != "sha256":  # Use single hash for comparison
            continue

        sign_ms = 0
        for field in metrics:
            if "sign_ms" in field:
                sign_ms += metrics[field]

        total = metrics.get("server_total_ms", 1)
        if total > 0:
            cost_pct = (sign_ms / total) * 100
            if profile not in profile_costs:
                profile_costs[profile] = []
            profile_costs[profile].append(cost_pct)

    profiles_list = sorted(profile_costs.keys())
    costs = [np.median(profile_costs[p]) for p in profiles_list]
    groups = [profile_group(p) for p in profiles_list]

    colors = [{"Hybrid": "#8B4513", "Classical": "#1f77b4", "PQC": "#d62728"}.get(g, "#7f7f7f")
              for g in groups]

    bars = ax.bar(profiles_list, costs, color=colors, alpha=0.8, edgecolor="black", linewidth=1.5)

    # Add value labels
    for bar, cost in zip(bars, costs):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, height + 1, f"{cost:.1f}%",
                ha="center", va="bottom", fontsize=10, fontweight="bold")

    ax.set_ylabel("Relative Cost (% of Total Operation Time)")
    ax.set_title("Signature Generation Cost Ratio (SHA256)")
    ax.set_ylim([0, max(costs) * 1.15])
    x_ticks = np.arange(len(profiles_list))
    ax.set_xticks(x_ticks)
    ax.set_xticklabels(profiles_list, rotation=45, ha="right")
    ax.grid(axis="y", alpha=0.3)

    # Legend
    legend_elements = [
        Patch(facecolor="#1f77b4", alpha=0.8, label="Classical"),
        Patch(facecolor="#d62728", alpha=0.8, label="PQC"),
        Patch(facecolor="#8B4513", alpha=0.8, label="Hybrid"),
    ]
    ax.legend(handles=legend_elements, loc="upper right")

    fig.tight_layout()
    fig.savefig(output_dir / "03_signature_cost_ratio.png", dpi=150, bbox_inches="tight")
    print(f"✓ Signature cost chart: 03_signature_cost_ratio.png")


def plot_classical_vs_pqc_performance(plt_module: Any, agg_data: dict, output_dir: Path) -> None:
    """Relative performance: Classical vs PQC (hybrid as reference)."""
    fig, ax = plt_module.subplots(figsize=(12, 7))

    # Collect hybrid baseline
    hybrid_times = []
    for (profile, hash_algo), metrics in agg_data.items():
        if profile in HYBRID_PROFILES and hash_algo == "sha256":
            total = metrics.get("server_total_ms", 0)
            if total > 0:
                hybrid_times.append(total)

    if not hybrid_times:
        ax.text(0.5, 0.5, "No hybrid data available for baseline comparison", ha="center", va="center")
        fig.savefig(output_dir / "04_classical_vs_pqc.png", dpi=150, bbox_inches="tight")
        return

    hybrid_baseline = np.median(hybrid_times)

    # Collect classical and PQC
    profile_groups = {"Classical": {}, "PQC": {}}

    for (profile, hash_algo), metrics in agg_data.items():
        if hash_algo != "sha256":
            continue

        group = profile_group(profile)
        if group in profile_groups:
            total = metrics.get("server_total_ms", 0)
            if total > 0:
                ratio = (total / hybrid_baseline) * 100
                profile_groups[group][profile] = ratio

    # Plot
    all_profiles = []
    all_ratios = []
    all_colors = []

    for group_name in ["Classical", "PQC"]:
        for profile, ratio in sorted(profile_groups[group_name].items()):
            all_profiles.append(profile)
            all_ratios.append(ratio)
            color = "#1f77b4" if group_name == "Classical" else "#d62728"
            all_colors.append(color)

    x = np.arange(len(all_profiles))
    bars = ax.bar(x, all_ratios, color=all_colors, alpha=0.8, edgecolor="black", linewidth=1.5)

    # Reference line at 100% (hybrid)
    ax.axhline(100, color="black", linestyle="--", linewidth=2, label="Hybrid Baseline (100%)")

    # Value labels
    for bar, ratio in zip(bars, all_ratios):
        height = bar.get_height()
        label_y = height + 2 if height >= 100 else height - 5
        ax.text(bar.get_x() + bar.get_width()/2, label_y, f"{ratio:.1f}%",
                ha="center", va="bottom" if height >= 100 else "top", fontsize=10, fontweight="bold")

    ax.set_ylabel("Time Relative to Hybrid (%)")
    ax.set_title("Performance Comparison: Classical vs PQC (Hybrid = 100%)")
    ax.set_ylim([0, max(all_ratios) * 1.15])
    ax.set_xticks(x)
    ax.set_xticklabels(all_profiles, rotation=45, ha="right")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)

    fig.tight_layout()
    fig.savefig(output_dir / "04_classical_vs_pqc.png", dpi=150, bbox_inches="tight")
    if all_profiles:
        print(f"✓ Classical vs PQC chart: 04_classical_vs_pqc.png")
    else:
        print(f"✓ Classical vs PQC chart: 04_classical_vs_pqc.png (no hybrid baseline)")


def plot_signature_size_comparison(plt_module: Any, agg_data: dict, output_dir: Path) -> None:
    """Signature byte overhead normalized to 100%."""
    fig, ax = plt_module.subplots(figsize=(12, 6))

    profile_sizes = {}

    for (profile, hash_algo), metrics in agg_data.items():
        if hash_algo != "sha256":
            continue

        size = metrics.get("total_signature_bytes", 0)
        if size > 0:
            if profile not in profile_sizes:
                profile_sizes[profile] = []
            profile_sizes[profile].append(size)

    if not profile_sizes:
        ax.text(0.5, 0.5, "No signature size data available", ha="center", va="center")
        fig.savefig(output_dir / "05_signature_size.png", dpi=150, bbox_inches="tight")
        print(f"✓ Signature size chart: 05_signature_size.png (no data)")
        return

    profiles_list = sorted(profile_sizes.keys())
    sizes = [np.median(profile_sizes[p]) for p in profiles_list]
    max_size = max(sizes)
    normalized = [100 * s / max_size for s in sizes]
    groups = [profile_group(p) for p in profiles_list]

    colors = [{"Hybrid": "#8B4513", "Classical": "#1f77b4", "PQC": "#d62728"}.get(g, "#7f7f7f")
              for g in groups]

    x = np.arange(len(profiles_list))
    bars = ax.bar(x, normalized, color=colors, alpha=0.8, edgecolor="black", linewidth=1.5)

    # Value labels (actual bytes)
    for bar, size, norm in zip(bars, sizes, normalized):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, height + 2, f"{int(size)}B",
                ha="center", va="bottom", fontsize=9, fontweight="bold")

    ax.set_ylabel("Relative Size (% of Largest Profile)")
    ax.set_title("Signature Size Overhead (Normalized)")
    ax.set_ylim([0, 110])
    ax.set_xticks(x)
    ax.set_xticklabels(profiles_list, rotation=45, ha="right")
    ax.grid(axis="y", alpha=0.3)

    fig.tight_layout()
    fig.savefig(output_dir / "05_signature_size.png", dpi=150, bbox_inches="tight")
    print(f"✓ Signature size chart: 05_signature_size.png")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enhanced benchmark analysis with ratio-based visualizations"
    )
    parser.add_argument("csv", type=Path, help="Evidence metrics CSV")
    parser.add_argument("--output-dir", type=Path, default=None, help="Output directory for charts")

    args = parser.parse_args()

    if not args.csv.exists():
        print(f"Error: CSV not found: {args.csv}", file=sys.stderr)
        return 1

    # Determine output dir
    output_dir = args.output_dir or args.csv.parent / "analysis"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"📊 Loading metrics from {args.csv.name}...")
    rows = load_evidence_metrics(args.csv)
    print(f"   Loaded {len(rows)} rows")

    print(f"📈 Aggregating by profile and hash...")
    agg_data = aggregate_by_profile_hash(rows)
    print(f"   Aggregated {len(agg_data)} profile-hash combinations")

    print(f"🎨 Generating charts...")
    plot_profile_performance_comparison(plt, agg_data, output_dir)
    plot_hash_efficiency(plt, agg_data, output_dir)
    plot_signature_cost_ratio(plt, agg_data, output_dir)
    plot_classical_vs_pqc_performance(plt, agg_data, output_dir)
    plot_signature_size_comparison(plt, agg_data, output_dir)

    print(f"\n✅ Analysis complete: {output_dir}")
    return 0
