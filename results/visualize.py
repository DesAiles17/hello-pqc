#!/usr/bin/env python3
"""
Benchmark visualisation: 10 insight-driven charts for hybrid PQC performance analysis.

Usage:
    python3 scripts/visualise_benchmark.py \\
        --stage-metrics <path/to/stage_metrics_long.csv> \\
        --output-dir <output_dir>

Reads stage_metrics_long.csv produced by analyze_benchmark_report.py.
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Any

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
except ImportError:
    print("Error: matplotlib and numpy required. Run: pip install matplotlib numpy", file=sys.stderr)
    sys.exit(1)

# ── Profile constants ─────────────────────────────────────────────────────────

PROFILES = ["eddsa_fn_dsa", "eddsa_ml_dsa", "ecdsa_fn_dsa", "ecdsa_ml_dsa"]

PROFILE_LABELS = {
    "eddsa_fn_dsa": "EdDSA + FN-DSA",
    "eddsa_ml_dsa": "EdDSA + ML-DSA",
    "ecdsa_fn_dsa": "ECDSA + FN-DSA",
    "ecdsa_ml_dsa": "ECDSA + ML-DSA",
}

# Semantic colour scheme:
#   Green family  = FN-DSA component (small & fast PQC)
#   Orange family = ML-DSA component (standard NIST PQC)
#   Lighter shade = EdDSA classical; darker shade = ECDSA classical
PROFILE_COLORS = {
    "eddsa_fn_dsa": "#43A047",   # medium green
    "ecdsa_fn_dsa": "#1B5E20",   # dark green
    "eddsa_ml_dsa": "#FB8C00",   # orange
    "ecdsa_ml_dsa": "#BF360C",   # dark orange-red
}

BUCKETS = ["10KB", "1MB", "50MB"]
BUCKET_BYTES = {"10KB": 10_240, "1MB": 1_048_576, "50MB": 52_428_800}

HASH_ALGOS = ["sha256", "blake3"]

SCENARIOS = [
    "workflow", "sign_only",
    "verify_manifest", "verify_stored", "verify_uploaded", "verify_full",
]
SCENARIO_LABELS = {
    "workflow":         "Full Workflow",
    "sign_only":        "Sign Only",
    "verify_manifest":  "Verify Manifest",
    "verify_stored":    "Verify Stored",
    "verify_uploaded":  "Verify Uploaded",
    "verify_full":      "Verify Full",
}

# ── Data helpers ──────────────────────────────────────────────────────────────

def load_stage_metrics(csv_paths: list[Path]) -> list[dict]:
    rows: list[dict] = []
    for csv_path in csv_paths:
        with open(csv_path, newline="") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or []
            
            # Detect format: 'metric_name' exists if it's long format
            is_long = "metric_name" in fieldnames
            
            for row in reader:
                if is_long:
                    rows.append(row)
                else:
                    # Convert wide format to long format
                    base_cols = {
                        "signature_profile": row.get("signature_profile"),
                        "hash_algorithm": row.get("hash_algorithm"),
                        "bucket": row.get("bucket"),
                        "benchmark_scenario": row.get("benchmark_scenario"),
                        "storage_state_label": row.get("storage_state_label"),
                        "metric_applicability": "applicable"  # Assume applicable for converted rows
                    }
                    
                    # Extract unique metric names (strip _median, _iqr, etc.)
                    metrics = set()
                    for k in row.keys():
                        if k.endswith("_median"):
                            metrics.add(k[:-7])
                            
                    for m in metrics:
                        # Remap 'total_ms' to 'client_total_ms' to match what charts expect
                        mapped_m = "client_total_ms" if m == "total_ms" else m
                        
                        long_row = dict(base_cols)
                        long_row["metric_name"] = mapped_m
                        long_row["median"] = row.get(f"{m}_median")
                        long_row["iqr"] = row.get(f"{m}_iqr")
                        long_row["p95"] = row.get(f"{m}_p95")
                        long_row["ci95_low"] = row.get(f"{m}_ci95_low")
                        long_row["ci95_high"] = row.get(f"{m}_ci95_high")
                        rows.append(long_row)
    return rows


def _f(val: Any) -> float | None:
    if val is None or str(val).strip() == "":
        return None
    try:
        return float(val)
    except (ValueError, TypeError):
        return None


def get_row(
    rows: list[dict],
    metric_name: str,
    *,
    profile: str,
    scenario: str = "workflow",
    bucket: str = "10KB",
    hash_algo: str = "sha256",
    storage_state: str = "warm",
) -> dict | None:
    """Return the first applicable matching row, or None."""
    for r in rows:
        if (
            r["metric_name"] == metric_name
            and r["signature_profile"] == profile
            and r["benchmark_scenario"] == scenario
            and r["bucket"] == bucket
            and r["hash_algorithm"] == hash_algo
            and r["storage_state_label"] == storage_state
            and r["metric_applicability"] == "applicable"
        ):
            return r
    return None


def med(rows: list[dict], metric_name: str, *, profile: str, **kw) -> float | None:
    r = get_row(rows, metric_name, profile=profile, **kw)
    return _f(r["median"]) if r else None


def ci95(rows: list[dict], metric_name: str, *, profile: str, **kw) -> tuple[float, float] | None:
    r = get_row(rows, metric_name, profile=profile, **kw)
    if r is None:
        return None
    lo, hi = _f(r["ci95_low"]), _f(r["ci95_high"])
    return (lo, hi) if lo is not None and hi is not None else None


def iqr_val(rows: list[dict], metric_name: str, *, profile: str, **kw) -> float | None:
    r = get_row(rows, metric_name, profile=profile, **kw)
    return _f(r["iqr"]) if r else None


def p95_val(rows: list[dict], metric_name: str, *, profile: str, **kw) -> float | None:
    r = get_row(rows, metric_name, profile=profile, **kw)
    return _f(r["p95"]) if r else None


# ── Style helpers ─────────────────────────────────────────────────────────────

def clean_axes(ax: plt.Axes, axis: str = "y") -> None:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color("#9e9e9e")
    if axis in ("y", "both"):
        ax.grid(axis="y", color="#eeeeee", linewidth=0.8, zorder=0)
    if axis in ("x", "both"):
        ax.grid(axis="x", color="#eeeeee", linewidth=0.8, zorder=0)


def save(fig: plt.Figure, output_dir: Path, name: str) -> None:
    fig.savefig(output_dir / name, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  ✓  {name}")


def profile_legend(ax: plt.Axes, **legend_kw) -> None:
    handles = [mpatches.Patch(color=PROFILE_COLORS[p], label=PROFILE_LABELS[p]) for p in PROFILES]
    ax.legend(handles=handles, **legend_kw)


# ─────────────────────────────────────────────────────────────────────────────
# CHART 1 — Relative latency overhead vs fastest profile, grouped by file size
# ─────────────────────────────────────────────────────────────────────────────

def plot_01_overhead_vs_fastest(rows: list[dict], output_dir: Path) -> None:
    """
    For each file-size bucket: how much slower is each profile compared to
    the fastest one within that bucket?  Y-axis reads '% slower', not ms.
    """
    fig, ax = plt.subplots(figsize=(13, 6))

    bar_w = 0.18
    group_gap = 0.55
    n = len(PROFILES)

    x_ticks, x_tick_labels = [], []

    for g, bucket in enumerate(BUCKETS):
        base = g * (n * bar_w + group_gap)
        center = base + (n - 1) * bar_w / 2
        x_ticks.append(center)
        x_tick_labels.append(bucket)

        medians = {p: med(rows, "client_total_ms", profile=p, bucket=bucket) for p in PROFILES}
        medians = {p: v for p, v in medians.items() if v is not None}
        if not medians:
            continue

        fastest = min(medians.values())

        for i, profile in enumerate(PROFILES):
            if profile not in medians:
                continue
            m = medians[profile]
            overhead = (m - fastest) / fastest * 100
            x = base + i * bar_w

            if overhead == 0:
                # Add a tiny bar and star for the fastest performer
                ax.bar(x, 0.5, width=bar_w - 0.02, color=PROFILE_COLORS[profile], alpha=0.9, zorder=3)
                ax.text(x, 1.0, "Fastest", ha="center", va="bottom", fontsize=8, color="#000000", fontweight="bold", rotation=90)
            else:
                ax.bar(x, overhead, width=bar_w - 0.02,
                       color=PROFILE_COLORS[profile], alpha=0.88, zorder=3)

            # CI error bars
            c = ci95(rows, "client_total_ms", profile=profile, bucket=bucket)
            if c and fastest > 0:
                lo, hi = c
                err_lo = max(0.0, overhead - (lo - fastest) / fastest * 100)
                err_hi = max(0.0, (hi - fastest) / fastest * 100 - overhead)
                ax.errorbar(x, overhead,
                            yerr=[[err_lo], [err_hi]],
                            fmt="none", color="#333", capsize=3, linewidth=1, zorder=4)

            if overhead > 0.08:
                ax.text(x, overhead + err_hi + 0.04,
                        f"{overhead:.1f}%", ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x_ticks)
    ax.set_xticklabels(x_tick_labels, fontsize=12, fontweight="bold")
    ax.set_ylabel("% slower than fastest option", fontsize=11)
    ax.set_title(
        "How Much Slower Is Each Algorithm Configuration?\n"
        "(0% = fastest for that file size; error bars = 95% CI)",
        fontsize=12,
    )
    ax.set_ylim(bottom=0)
    profile_legend(ax, loc="upper left", fontsize=9)
    clean_axes(ax)

    fig.tight_layout()
    save(fig, output_dir, "01_overhead_vs_fastest.png")


# ─────────────────────────────────────────────────────────────────────────────
# CHART 2 — 100% stacked bar: where does server time actually go?
# ─────────────────────────────────────────────────────────────────────────────

def plot_02_server_time_breakdown(rows: list[dict], output_dir: Path) -> None:
    """
    100% horizontal stacked bar for 10 KB workflow (SHA-256).
    Segments: DB persist | Classical sign | PQC sign |
              Classical verify | PQC verify | Hash | Other
    """
    CLASSICAL_SIGN = {
        "eddsa_fn_dsa": "server_eddsa_sign_ms",
        "eddsa_ml_dsa": "server_eddsa_sign_ms",
        "ecdsa_fn_dsa": "server_ecdsa_sign_ms",
        "ecdsa_ml_dsa": "server_ecdsa_sign_ms",
    }
    PQC_SIGN = {
        "eddsa_fn_dsa": "server_fn_dsa_sign_ms",
        "eddsa_ml_dsa": "server_ml_dsa_sign_ms",
        "ecdsa_fn_dsa": "server_fn_dsa_sign_ms",
        "ecdsa_ml_dsa": "server_ml_dsa_sign_ms",
    }
    CLASSICAL_VERIFY = {
        "eddsa_fn_dsa": "server_eddsa_verify_ms",
        "eddsa_ml_dsa": "server_eddsa_verify_ms",
        "ecdsa_fn_dsa": "server_ecdsa_verify_ms",
        "ecdsa_ml_dsa": "server_ecdsa_verify_ms",
    }
    PQC_VERIFY = {
        "eddsa_fn_dsa": "server_fn_dsa_verify_ms",
        "eddsa_ml_dsa": "server_ml_dsa_verify_ms",
        "ecdsa_fn_dsa": "server_fn_dsa_verify_ms",
        "ecdsa_ml_dsa": "server_ml_dsa_verify_ms",
    }

    seg_labels = [
        "Process API & Storage", "Hashing", "Classical sign", "PQC sign",
        "Verify API & Storage", "Classical verify", "PQC verify",
    ]
    seg_colors = [
        "#9E9E9E",   # grey — process (DB/HTTP overhead)
        "#AB47BC",   # purple — hash
        "#1565C0",   # dark blue — classical sign
        "#43A047",   # green — PQC sign
        "#E0E0E0",   # light grey — verify (DB/HTTP overhead)
        "#42A5F5",   # light blue — classical verify
        "#66BB6A",   # light green — PQC verify
    ]

    data = {label: [] for label in seg_labels}

    for profile in PROFILES:
        kw = dict(profile=profile, bucket="10KB")
        sg_gw_ = med(rows, "server_process_gateway_ms", **kw) or 0.0
        v_gw_  = med(rows, "server_verify_gateway_ms",  **kw) or 0.0
        
        cs   = med(rows, CLASSICAL_SIGN[profile],     **kw) or 0.0
        ps   = med(rows, PQC_SIGN[profile],           **kw) or 0.0
        cv_  = med(rows, CLASSICAL_VERIFY[profile],   **kw) or 0.0
        pv   = med(rows, PQC_VERIFY[profile],         **kw) or 0.0
        hsh  = med(rows, "server_hash_ms",            **kw) or 0.0
        
        # Calculate non-crypto overhead from the gateway boundary
        sign_overhead = max(0.0, sg_gw_ - cs - ps - hsh)
        verify_overhead = max(0.0, v_gw_ - cv_ - pv)

        parts = [sign_overhead, hsh, cs, ps, verify_overhead, cv_, pv]
        total = sum(parts) or 1.0
        pcts  = [p / total * 100 for p in parts]

        for label, pct in zip(seg_labels, pcts):
            data[label].append(pct)

    fig, ax = plt.subplots(figsize=(14, 5))
    y = np.arange(len(PROFILES))
    bar_h = 0.55
    lefts = np.zeros(len(PROFILES))

    for label, color in zip(seg_labels, seg_colors):
        vals = np.array(data[label])
        bars = ax.barh(y, vals, left=lefts, height=bar_h, color=color, label=label, zorder=3)
        for bar, v, l in zip(bars, vals, lefts):
            if v > 4:
                # Use dark text for light grey background
                text_color = "#333333" if label == "Verify API & Storage" else "white"
                ax.text(l + v / 2, bar.get_y() + bar.get_height() / 2,
                        f"{v:.0f}%", ha="center", va="center", fontsize=8,
                        fontweight="bold", color=text_color)
        lefts += vals

    ax.set_yticks(y)
    ax.set_yticklabels([PROFILE_LABELS[p] for p in PROFILES], fontsize=11)
    ax.set_xlabel("Share of total server processing time (%)", fontsize=11)
    ax.set_title(
        "Where Does Server Time Go? (10 KB file, full workflow)\n"
        "100% = total server processing time",
        fontsize=12,
    )
    ax.set_xlim(0, 100)
    ax.legend(loc="center left", bbox_to_anchor=(1.0, 0.5), fontsize=9, ncol=1)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="x", color="#eeeeee", linewidth=0.8, zorder=0)

    fig.tight_layout()
    save(fig, output_dir, "02_server_time_breakdown.png")


# ─────────────────────────────────────────────────────────────────────────────
# CHART 3 — Diverging bars: sign time ←→ verify time per algorithm component
# ─────────────────────────────────────────────────────────────────────────────

def plot_03_sign_verify_asymmetry(rows: list[dict], output_dir: Path) -> None:
    """
    Diverging horizontal bar: signing time extends LEFT, verification RIGHT.
    One row per algorithm component (EdDSA, ECDSA, FN-DSA, ML-DSA).
    Highlights FN-DSA's 2x verification advantage.
    """
    def component_ms(sign_metric: str, verify_metric: str, source_profile: str):
        s    = med(rows, sign_metric,   profile=source_profile, bucket="10KB") or 0.0
        v    = med(rows, verify_metric, profile=source_profile, bucket="10KB") or 0.0
        s_iq = iqr_val(rows, sign_metric,   profile=source_profile, bucket="10KB") or 0.0
        v_iq = iqr_val(rows, verify_metric, profile=source_profile, bucket="10KB") or 0.0
        return s, v, s_iq, v_iq

    components = [
        ("EdDSA",  *component_ms("server_eddsa_sign_ms",  "server_eddsa_verify_ms",  "eddsa_fn_dsa")),
        ("ECDSA",  *component_ms("server_ecdsa_sign_ms",  "server_ecdsa_verify_ms",  "ecdsa_fn_dsa")),
        ("FN-DSA", *component_ms("server_fn_dsa_sign_ms", "server_fn_dsa_verify_ms", "eddsa_fn_dsa")),
        ("ML-DSA", *component_ms("server_ml_dsa_sign_ms", "server_ml_dsa_verify_ms", "eddsa_ml_dsa")),
    ]

    algo_colors = {
        "EdDSA":  "#1565C0",
        "ECDSA":  "#0288D1",
        "FN-DSA": "#43A047",
        "ML-DSA": "#FB8C00",
    }

    fig, ax = plt.subplots(figsize=(12, 5))
    y = np.arange(len(components))
    bar_h = 0.38

    max_val = 0.0
    for name, sv, vv, se, ve in components:
        max_val = max(max_val, sv, vv)

    for i, (name, sv, vv, se, ve) in enumerate(components):
        color = algo_colors[name]
        # Sign bar (left, negative direction)
        ax.barh(y[i] + bar_h / 2, -sv, height=bar_h, color=color, alpha=0.9, zorder=3)
        ax.errorbar(-sv, y[i] + bar_h / 2, xerr=se / 2,
                    fmt="none", color="#333", capsize=3, linewidth=1, zorder=4)
        ax.text(-sv - se / 2 - 0.015, y[i] + bar_h / 2,
                f"{sv:.3f} ms", ha="right", va="center", fontsize=9, fontweight="bold")

        # Verify bar (right, positive direction)
        ax.barh(y[i] - bar_h / 2, vv, height=bar_h, color=color, alpha=0.5, zorder=3)
        ax.errorbar(vv, y[i] - bar_h / 2, xerr=ve / 2,
                    fmt="none", color="#333", capsize=3, linewidth=1, zorder=4)
        ax.text(vv + ve / 2 + 0.015, y[i] - bar_h / 2,
                f"{vv:.3f} ms", ha="left", va="center", fontsize=9, fontweight="bold")

    ax.axvline(0, color="#333", linewidth=1.2)
    ax.set_yticks(y)
    ax.set_yticklabels([c[0] for c in components], fontsize=12, fontweight="bold")
    ax.set_xlabel("← Signing time (ms)          Verification time (ms) →", fontsize=11)
    ax.set_title(
        "Signing vs Verification Speed per Algorithm Component\n"
        "(solid = sign; transparent = verify; error bars = IQR/2; 10 KB, SHA-256)",
        fontsize=12,
    )
    clean_axes(ax, axis="x")

    fn_idx = 2  # FN-DSA row index
    fn_sv  = components[fn_idx][1]
    fn_vv  = components[fn_idx][2]
    ax.annotate(
        f"FN-DSA verifies {fn_sv/fn_vv:.1f}x faster than it signs",
        xy=(fn_vv, y[fn_idx] - bar_h / 2),
        xytext=(fn_vv + 0.05, y[fn_idx] - bar_h / 2 - 0.6),
        arrowprops=dict(arrowstyle="->", color="#2E7D32"),
        fontsize=9, color="#2E7D32", fontweight="bold",
    )

    ax.set_xlim(-max_val * 1.5, max_val * 1.8)
    fig.tight_layout()
    save(fig, output_dir, "03_sign_verify_asymmetry.png")


# ─────────────────────────────────────────────────────────────────────────────
# CHART 4 — Signature size as % of file, with classical/PQC component split
# ─────────────────────────────────────────────────────────────────────────────
def plot_04_signature_size_as_file_pct(rows: list[dict], output_dir: Path) -> None:
    """
    Horizontal stacked bar: for each hybrid profile, show what % of a 10 KB file
    is consumed by the security stamp, split into classical vs PQC bytes.
    Percentages displayed in a vertical column to the right: classical, PQC, total.
    """
    CLASSICAL_SIG = {
        "eddsa_fn_dsa": "eddsa_signature_bytes",
        "eddsa_ml_dsa": "eddsa_signature_bytes",
        "ecdsa_fn_dsa": "ecdsa_signature_bytes",
        "ecdsa_ml_dsa": "ecdsa_signature_bytes",
    }
    PQC_SIG = {
        "eddsa_fn_dsa": "fn_dsa_signature_bytes",
        "eddsa_ml_dsa": "ml_dsa_signature_bytes",
        "ecdsa_fn_dsa": "fn_dsa_signature_bytes",
        "ecdsa_ml_dsa": "ml_dsa_signature_bytes",
    }

    file_bytes = BUCKET_BYTES["10KB"]
    classical_pcts, pqc_pcts, total_sizes = [], [], []

    for profile in PROFILES:
        kw = dict(profile=profile, bucket="10KB")
        c_b = med(rows, CLASSICAL_SIG[profile], **kw) or 0.0
        p_b = med(rows, PQC_SIG[profile],       **kw) or 0.0
        classical_pcts.append(c_b / file_bytes * 100)
        pqc_pcts.append(p_b / file_bytes * 100)
        total_sizes.append(int(c_b + p_b))

    fig, ax = plt.subplots(figsize=(14, 4.5))
    y = np.arange(len(PROFILES))
    bar_h = 0.5

    classical_arr = np.array(classical_pcts)
    pqc_arr       = np.array(pqc_pcts)

    ax.barh(y, classical_arr, height=bar_h,
            color="#1565C0", alpha=0.9, label="Classical signature bytes", zorder=3)
    ax.barh(y, pqc_arr, left=classical_arr, height=bar_h,
            color="#43A047", alpha=0.85, label="Post-quantum signature bytes", zorder=3)

    for i, (cp, pp, tb) in enumerate(zip(classical_pcts, pqc_pcts, total_sizes)):
        total_pct = cp + pp
        
        # Place percentages in vertical column to the right
        col_x = total_pct + 1.5
        line_spacing = 0.22
        
        # Classical percentage
        ax.text(col_x, y[i] + line_spacing, f"{cp:.1f}%",
                va="center", ha="left", fontsize=8, color="#1565C0", fontweight="bold")
        
        # PQC percentage
        ax.text(col_x, y[i], f"{pp:.1f}%",
                va="center", ha="left", fontsize=8, color="#43A047", fontweight="bold")
        
        # Total percentage
        ax.text(col_x, y[i] - line_spacing, f"{total_pct:.1f}%",
                va="center", ha="left", fontsize=8.5, color="#333333", fontweight="bold",
                bbox=dict(boxstyle="round,pad=0.3", facecolor="#FFFDE7", 
                         edgecolor="#F57F17", linewidth=0.8))

    ax.axvline(100, color="#c62828", linewidth=1.5, linestyle="--", label="File size = 100%")
    ax.set_yticks(y)
    ax.set_yticklabels([PROFILE_LABELS[p] for p in PROFILES], fontsize=11)
    ax.set_xlabel("Security stamp size as % of the protected file (10 KB)", fontsize=11)
    ax.set_title(
        "How Much Storage Does Each Security Stamp Consume?\n"
        "(relative to the 10 KB file being protected)",
        fontsize=12,
    )
    ax.legend(loc="lower right", fontsize=9)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="x", color="#eeeeee", linewidth=0.8, zorder=0)
    max_pct = max(cp + pp for cp, pp in zip(classical_pcts, pqc_pcts))
    ax.set_xlim(0, max_pct * 1.8)

    fig.tight_layout()
    save(fig, output_dir, "04_signature_size_as_file_pct.png")

# ─────────────────────────────────────────────────────────────────────────────
# CHART 5 — Latency scaling with file size + crypto overhead fraction
# ─────────────────────────────────────────────────────────────────────────────

def plot_05_latency_scaling(rows: list[dict], output_dir: Path) -> None:
    """
    Left axis (log): absolute client latency for each profile across 3 file sizes.
    Right axis: crypto operations as % of total client time — converges to ~0% at 50 MB.
    SHA-256 only; CI bands shown as shaded areas.
    """
    SIGN_METRICS = {
        "eddsa_fn_dsa": ["server_eddsa_sign_ms", "server_fn_dsa_sign_ms"],
        "eddsa_ml_dsa": ["server_eddsa_sign_ms", "server_ml_dsa_sign_ms"],
        "ecdsa_fn_dsa": ["server_ecdsa_sign_ms", "server_fn_dsa_sign_ms"],
        "ecdsa_ml_dsa": ["server_ecdsa_sign_ms", "server_ml_dsa_sign_ms"],
    }
    VERIFY_METRICS = {
        "eddsa_fn_dsa": ["server_eddsa_verify_ms", "server_fn_dsa_verify_ms"],
        "eddsa_ml_dsa": ["server_eddsa_verify_ms", "server_ml_dsa_verify_ms"],
        "ecdsa_fn_dsa": ["server_ecdsa_verify_ms", "server_fn_dsa_verify_ms"],
        "ecdsa_ml_dsa": ["server_ecdsa_verify_ms", "server_ml_dsa_verify_ms"],
    }

    x_vals  = np.array([10_240, 1_048_576, 52_428_800], dtype=float)
    x_labels = ["10 KB", "1 MB", "50 MB"]

    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax2 = ax1.twinx()

    for p_idx, profile in enumerate(PROFILES):
        color = PROFILE_COLORS[profile]
        lat_ms, lo_arr, hi_arr, crypto_pcts = [], [], [], []
        
        # Add a tiny horizontal jitter so lines don't completely overlap 
        # (multiplying by 1.05 per profile to slightly shift on log scale)
        jitter_factor = 1.0 + (p_idx - len(PROFILES)/2 + 0.5) * 0.05
        jittered_x = x_vals * jitter_factor

        for bucket in BUCKETS:
            kw = dict(profile=profile, bucket=bucket)
            lt = med(rows, "client_total_ms", **kw)
            c  = ci95(rows, "client_total_ms", **kw)

            if lt is None:
                lat_ms.append(np.nan); lo_arr.append(np.nan)
                hi_arr.append(np.nan); crypto_pcts.append(np.nan)
                continue

            lat_ms.append(lt)
            lo_arr.append(c[0] if c else lt)
            hi_arr.append(c[1] if c else lt)

            crypto_ms = (
                sum(med(rows, m, **kw) or 0.0 for m in SIGN_METRICS[profile])
                + sum(med(rows, m, **kw) or 0.0 for m in VERIFY_METRICS[profile])
                + (med(rows, "server_hash_ms", **kw) or 0.0)
            )
            crypto_pcts.append(crypto_ms / lt * 100)

        lat  = np.array(lat_ms,    dtype=float)
        lo   = np.array(lo_arr,    dtype=float)
        hi   = np.array(hi_arr,    dtype=float)
        cpct = np.array(crypto_pcts, dtype=float)

        ax1.plot(jittered_x, lat, color=color, linewidth=2.2, marker="o",
                 markersize=7, label=PROFILE_LABELS[profile], zorder=4)
        ax1.fill_between(jittered_x, lo, hi, color=color, alpha=0.15, zorder=3)
        ax2.plot(jittered_x, cpct, color=color, linewidth=1.5,
                 linestyle=":", alpha=0.9, marker="x", zorder=3)

    ax1.set_xscale("log")
    ax1.set_yscale("log")
    ax1.set_xticks(x_vals)
    ax1.set_xticklabels(x_labels, fontsize=11)
    ax1.set_xlabel("File size", fontsize=11)
    ax1.set_ylabel("Total client latency (ms) — log scale", fontsize=11)
    ax1.legend(loc="upper left", fontsize=9)
    ax1.spines["top"].set_visible(False)
    ax1.grid(axis="y", color="#eeeeee", linewidth=0.8, zorder=0)

    ax2.set_ylabel("Crypto as % of total time (dashed lines)", fontsize=10, color="#666")
    ax2.tick_params(axis="y", labelcolor="#666")
    ax2.set_ylim(bottom=0)
    ax2.spines["top"].set_visible(False)

    ax1.set_title(
        "How Does Latency Scale with File Size? (SHA-256)\n"
        "Solid + shaded = total latency with 95% CI;  dashed = crypto fraction",
        fontsize=12,
    )

    fig.tight_layout()
    save(fig, output_dir, "05_latency_scaling.png")


# ─────────────────────────────────────────────────────────────────────────────
# CHART 6 — Consistency: nested whisker chart (median, IQR, p95, CI95)
# ─────────────────────────────────────────────────────────────────────────────

def plot_06_latency_consistency(rows: list[dict], output_dir: Path) -> None:
    """
    For each profile x hash-algo at 10 KB workflow: render 4 nested layers:
      CI95 (thin line), IQR (thick bar), median dot, p95 tick.
    """
    combos = [(p, h) for p in PROFILES for h in HASH_ALGOS]
    combo_labels = [
        f"{PROFILE_LABELS[p]}  ({h.upper()})" for p, h in combos
    ]

    fig, ax = plt.subplots(figsize=(14, 7))
    y = np.arange(len(combos))

    for i, (profile, hash_algo) in enumerate(combos):
        kw = dict(profile=profile, bucket="10KB", hash_algo=hash_algo)
        m     = med(rows,    "client_total_ms", **kw)
        c     = ci95(rows,   "client_total_ms", **kw)
        iq    = iqr_val(rows,"client_total_ms", **kw)
        p95_m = p95_val(rows,"client_total_ms", **kw)

        if m is None:
            continue

        color = PROFILE_COLORS[profile]
        alpha = 0.9 if hash_algo == "sha256" else 0.5

        # CI band (thin outer line)
        if c:
            ax.plot([c[0], c[1]], [y[i], y[i]], color=color,
                    linewidth=1.2, alpha=0.4, solid_capstyle="round", zorder=2)

        # IQR (thick bar)
        if iq:
            ax.plot([m - iq / 2, m + iq / 2], [y[i], y[i]], color=color,
                    linewidth=9, alpha=alpha * 0.65, solid_capstyle="round", zorder=3)

        # Median dot
        ax.scatter([m], [y[i]], color=color, s=65, zorder=5, alpha=alpha)

        # p95 tick
        if p95_m:
            ax.plot([p95_m, p95_m], [y[i] - 0.12, y[i] + 0.12],
                    color=color, linewidth=2, zorder=4, alpha=alpha)
            ax.text(p95_m + 0.04, y[i] + 0.16, f"{p95_m:.1f}",
                    fontsize=6.5, ha="left", va="bottom", color="#666")

        ax.text(m, y[i] - 0.25, f"{m:.1f}", ha="center", va="top",
                fontsize=7.5, fontweight="bold", color=color)

    ax.set_yticks(y)
    ax.set_yticklabels(combo_labels, fontsize=9)
    ax.set_xlabel("Client total latency (ms)", fontsize=11)
    ax.set_title(
        "Latency Predictability per Configuration  (10 KB, full workflow)\n"
        "●  median   ▬  IQR (middle 50%)   ─  95% CI   |  p95",
        fontsize=12,
    )
    clean_axes(ax, axis="x")

    # Move legend outside plot area to the right
    legend_text = "Solid = SHA-256 | Transparent = BLAKE-3"
    ax.text(1.02, 0.5, legend_text, transform=ax.transAxes, 
            ha="left", va="center", fontsize=9,
            bbox=dict(boxstyle="round,pad=0.5", facecolor="white", 
                     edgecolor="#bdbdbd", alpha=0.95))

    fig.tight_layout()
    save(fig, output_dir, "06_latency_consistency.png")


# ─────────────────────────────────────────────────────────────────────────────
# CHART 7 — Scenario heatmap
# ─────────────────────────────────────────────────────────────────────────────

def plot_07_scenario_heatmap(rows: list[dict], output_dir: Path) -> None:
    """
    Heatmap: profiles (rows) x scenarios (cols), 10 KB SHA-256.
    Each column normalised independently so fastest = 0%, slowest = 100%.
    Cell text shows absolute median ms.
    """
    abs_data = np.full((len(PROFILES), len(SCENARIOS)), np.nan)

    for j, scenario in enumerate(SCENARIOS):
        for i, profile in enumerate(PROFILES):
            v = med(rows, "client_total_ms",
                    profile=profile, scenario=scenario, bucket="10KB")
            if v is not None:
                abs_data[i, j] = v

    norm_data = np.full_like(abs_data, np.nan)
    for j in range(len(SCENARIOS)):
        col = abs_data[:, j]
        col_min = np.nanmin(col)
        col_max = np.nanmax(col)
        col_range = col_max - col_min if col_max != col_min else 1.0
        for i in range(len(PROFILES)):
            if not np.isnan(col[i]):
                norm_data[i, j] = (col[i] - col_min) / col_range * 100

    fig, ax = plt.subplots(figsize=(13, 5))
    im = ax.imshow(norm_data, cmap="RdYlGn_r", aspect="auto", vmin=0, vmax=100)

    ax.set_xticks(range(len(SCENARIOS)))
    ax.set_xticklabels(
        [SCENARIO_LABELS[s] for s in SCENARIOS],
        fontsize=10, rotation=20, ha="right",
    )
    ax.set_yticks(range(len(PROFILES)))
    ax.set_yticklabels([PROFILE_LABELS[p] for p in PROFILES], fontsize=10)

    for i in range(len(PROFILES)):
        for j in range(len(SCENARIOS)):
            v = abs_data[i, j]
            d = norm_data[i, j]
            if not np.isnan(v):
                text_color = "white" if d > 65 or d < 20 else "black"
                ax.text(j, i, f"{v:.1f} ms",
                        ha="center", va="center", fontsize=9,
                        fontweight="bold", color=text_color)

    plt.colorbar(im, ax=ax,
                 label="Relative latency within scenario (0% = fastest, 100% = slowest)")
    ax.set_title(
        "Which Operation Type Is Most Expensive for Each Configuration?  (10 KB, SHA-256)\n"
        "Colour = relative speed within each column;  numbers = actual median ms",
        fontsize=12,
    )
    fig.tight_layout()
    save(fig, output_dir, "07_scenario_heatmap.png")


# ─────────────────────────────────────────────────────────────────────────────
# CHART 8 — Classical vs PQC-only vs Hybrid: total crypto cost
# ─────────────────────────────────────────────────────────────────────────────

def plot_08_crypto_cost_by_mode(rows: list[dict], output_dir: Path) -> None:
    """
    Grouped bars in 3 sections: Classical | PQC-Only | Hybrid.
    Each bar = sign (solid) + verify (hatched overlay).
    Component values extracted from hybrid profile measurements.
    """
    kw10 = dict(bucket="10KB", scenario="workflow")

    eddsa_s = med(rows, "server_eddsa_sign_ms",    profile="eddsa_fn_dsa", **kw10) or 0.0
    eddsa_v = med(rows, "server_eddsa_verify_ms",  profile="eddsa_fn_dsa", **kw10) or 0.0
    ecdsa_s = med(rows, "server_ecdsa_sign_ms",    profile="ecdsa_fn_dsa", **kw10) or 0.0
    ecdsa_v = med(rows, "server_ecdsa_verify_ms",  profile="ecdsa_fn_dsa", **kw10) or 0.0
    fndsa_s = med(rows, "server_fn_dsa_sign_ms",   profile="eddsa_fn_dsa", **kw10) or 0.0
    fndsa_v = med(rows, "server_fn_dsa_verify_ms", profile="eddsa_fn_dsa", **kw10) or 0.0
    mldsa_s = med(rows, "server_ml_dsa_sign_ms",   profile="eddsa_ml_dsa", **kw10) or 0.0
    mldsa_v = med(rows, "server_ml_dsa_verify_ms", profile="eddsa_ml_dsa", **kw10) or 0.0

    # (short_label, sign_ms, verify_ms, color, group)
    configs = [
        ("EdDSA",        eddsa_s,            eddsa_v,            "#1565C0", "Classical"),
        ("ECDSA",        ecdsa_s,            ecdsa_v,            "#0288D1", "Classical"),
        ("FN-DSA",       fndsa_s,            fndsa_v,            "#43A047", "PQC-Only"),
        ("ML-DSA",       mldsa_s,            mldsa_v,            "#FB8C00", "PQC-Only"),
        ("EdDSA+\nFN-DSA",eddsa_s + fndsa_s, eddsa_v + fndsa_v, "#4CAF50", "Hybrid"),
        ("EdDSA+\nML-DSA",eddsa_s + mldsa_s, eddsa_v + mldsa_v, "#FF9800", "Hybrid"),
        ("ECDSA+\nFN-DSA",ecdsa_s + fndsa_s, ecdsa_v + fndsa_v, "#1B5E20", "Hybrid"),
        ("ECDSA+\nML-DSA",ecdsa_s + mldsa_s, ecdsa_v + mldsa_v, "#BF360C", "Hybrid"),
    ]

    bar_w   = 0.5
    gap     = 0.9   # gap between mode groups
    group_counts = {"Classical": 0, "PQC-Only": 0, "Hybrid": 0}
    group_starts: dict[str, float] = {}
    offset = 0.0
    for group in ["Classical", "PQC-Only", "Hybrid"]:
        group_starts[group] = offset
        count = sum(1 for c in configs if c[4] == group)
        group_counts[group] = count
        offset += count * (bar_w + 0.1) + gap

    fig, ax = plt.subplots(figsize=(14, 6))

    group_idx: dict[str, int] = {"Classical": 0, "PQC-Only": 0, "Hybrid": 0}
    bar_x_per_group: dict[str, list[float]] = {"Classical": [], "PQC-Only": [], "Hybrid": []}

    for short_label, sign_ms, verify_ms, color, group in configs:
        idx = group_idx[group]
        x   = group_starts[group] + idx * (bar_w + 0.1)
        group_idx[group] += 1
        bar_x_per_group[group].append(x)

        # Sign bar (solid)
        ax.bar(x, sign_ms, width=bar_w, color=color, alpha=0.9, zorder=3)
        # Verify bar (stacked, lighter + hatch)
        ax.bar(x, verify_ms, bottom=sign_ms, width=bar_w,
               color=color, alpha=0.4, hatch="//", edgecolor=color, zorder=3)

        total = sign_ms + verify_ms
        ax.text(x, total + 0.008,
                f"{total:.2f}", ha="center", va="bottom", fontsize=8.5, fontweight="bold")
        ax.text(x, -0.03, short_label,
                ha="center", va="top", fontsize=8, rotation=0)

    # Group centre labels
    for group, xs in bar_x_per_group.items():
        if xs:
            cx = (xs[0] + xs[-1]) / 2
            ax.text(cx, -0.09, group, ha="center", va="top",
                    fontsize=11, fontweight="bold",
                    transform=ax.get_xaxis_transform())
            # Vertical separator
            if group != "Classical":
                sep_x = xs[0] - (gap + 0.1) / 2
                ax.axvline(sep_x, color="#ccc", linewidth=1.2, linestyle="--")

    ax.set_ylabel("Total cryptographic time (ms)", fontsize=11)
    ax.set_title(
        "Cryptographic Cost: Classical vs Post-Quantum-Only vs Hybrid\n"
        "(solid = signing; hatched = verification;  10 KB file, SHA-256)",
        fontsize=12,
    )
    ax.set_ylim(bottom=0)
    ax.set_xlim(left=-0.3)
    ax.set_xticks([])

    legend_handles = [
        mpatches.Patch(facecolor="#aaa", label="Signing time (solid)"),
        mpatches.Patch(facecolor="#aaa", hatch="//", label="Verification time (hatched)"),
    ]
    ax.legend(handles=legend_handles, loc="upper left", fontsize=9)
    clean_axes(ax)

    fig.tight_layout()
    save(fig, output_dir, "08_crypto_cost_by_mode.png")


# ─────────────────────────────────────────────────────────────────────────────
# CHART 9 — Security-storage-performance tradeoff bubble chart
# ─────────────────────────────────────────────────────────────────────────────

def plot_09_security_storage_tradeoff(rows: list[dict], output_dir: Path) -> None:
    """
    Bubble scatter:
      X = total signature size (bytes) — proxy for security envelope size
      Y = total crypto latency (sign + verify, ms)
      Bubble size = storage amplification factor
    8 configurations: 2 classical-only + 2 PQC-only + 4 hybrids.
    """
    kw10 = dict(bucket="10KB", scenario="workflow")

    eddsa_s = med(rows, "server_eddsa_sign_ms",    profile="eddsa_fn_dsa", **kw10) or 0.0
    eddsa_v = med(rows, "server_eddsa_verify_ms",  profile="eddsa_fn_dsa", **kw10) or 0.0
    ecdsa_s = med(rows, "server_ecdsa_sign_ms",    profile="ecdsa_fn_dsa", **kw10) or 0.0
    ecdsa_v = med(rows, "server_ecdsa_verify_ms",  profile="ecdsa_fn_dsa", **kw10) or 0.0
    fndsa_s = med(rows, "server_fn_dsa_sign_ms",   profile="eddsa_fn_dsa", **kw10) or 0.0
    fndsa_v = med(rows, "server_fn_dsa_verify_ms", profile="eddsa_fn_dsa", **kw10) or 0.0
    mldsa_s = med(rows, "server_ml_dsa_sign_ms",   profile="eddsa_ml_dsa", **kw10) or 0.0
    mldsa_v = med(rows, "server_ml_dsa_verify_ms", profile="eddsa_ml_dsa", **kw10) or 0.0

    eb = med(rows, "eddsa_signature_bytes",  profile="eddsa_fn_dsa", **kw10) or 64.0
    cb = med(rows, "ecdsa_signature_bytes",  profile="ecdsa_fn_dsa", **kw10) or 71.0
    fb = med(rows, "fn_dsa_signature_bytes", profile="eddsa_fn_dsa", **kw10) or 654.0
    mb = med(rows, "ml_dsa_signature_bytes", profile="eddsa_ml_dsa", **kw10) or 3309.0

    def amp(profile: str) -> float:
        v = med(rows, "storage_amplification", profile=profile, **kw10)
        return v if v else 1.0

    # Approximate classical-only and PQC-only storage amplifications
    # (they don't appear in data directly, so estimate from signature+manifest overhead)
    classical_overhead_bytes = 500  # typical manifest overhead without PQC
    fn_amp_est = 1.0 + fb / BUCKET_BYTES["10KB"]
    ml_amp_est = 1.0 + mb / BUCKET_BYTES["10KB"]

    # (label, sig_bytes, crypto_ms, storage_amp, color, marker, group)
    points = [
        ("EdDSA\nonly",     eb,      eddsa_s + eddsa_v,               1.006, "#1565C0", "o", "Classical"),
        ("ECDSA\nonly",     cb,      ecdsa_s + ecdsa_v,               1.007, "#0288D1", "o", "Classical"),
        ("FN-DSA\nonly",    fb,      fndsa_s + fndsa_v,               fn_amp_est, "#43A047", "s", "PQC-Only"),
        ("ML-DSA\nonly",    mb,      mldsa_s + mldsa_v,               ml_amp_est, "#FB8C00", "s", "PQC-Only"),
        ("EdDSA+\nFN-DSA",  eb + fb, eddsa_s + fndsa_s + eddsa_v + fndsa_v, amp("eddsa_fn_dsa"), "#4CAF50",  "D", "Hybrid"),
        ("EdDSA+\nML-DSA",  eb + mb, eddsa_s + mldsa_s + eddsa_v + mldsa_v, amp("eddsa_ml_dsa"), "#FF9800",  "D", "Hybrid"),
        ("ECDSA+\nFN-DSA",  cb + fb, ecdsa_s + fndsa_s + ecdsa_v + fndsa_v, amp("ecdsa_fn_dsa"), "#1B5E20",  "D", "Hybrid"),
        ("ECDSA+\nML-DSA",  cb + mb, ecdsa_s + mldsa_s + ecdsa_v + mldsa_v, amp("ecdsa_ml_dsa"), "#BF360C",  "D", "Hybrid"),
    ]

    fig, ax = plt.subplots(figsize=(12, 7))

    for label, sig_b, crypto_ms, storage_amp, color, marker, group in points:
        bubble_size = max(60, (storage_amp - 1.0) * 4500 + 80)
        ax.scatter(sig_b, crypto_ms, s=bubble_size, color=color, marker=marker,
                   alpha=0.82, edgecolors="white", linewidths=1.5, zorder=4)
        ax.annotate(label, (sig_b, crypto_ms),
                    xytext=(sig_b + sig_b * 0.08 + 20, crypto_ms + 0.02),
                    fontsize=8.5, ha="left",
                    arrowprops=dict(arrowstyle="-", color="#bbb", lw=0.8))

    ax.set_xlabel("Total signature size (bytes) — larger = more security material", fontsize=11)
    ax.set_ylabel("Total cryptographic time: sign + verify (ms)", fontsize=11)
    ax.set_title(
        "Security Envelope vs Performance vs Storage Tradeoff\n"
        "Bubble area ∝ storage amplification factor  |  lower-left = more efficient\n"
        "Note: all PQC options meet the same NIST security level",
        fontsize=11,
    )
    clean_axes(ax, axis="both")
    
    # Add a bit more headroom above the top, top value is clipped
    ymin, ymax = ax.get_ylim()
    ax.set_ylim(top=ymax * 1.15)

    group_legend = [
        mpatches.Patch(color="#1565C0", label="Classical only"),
        mpatches.Patch(color="#43A047", label="PQC-only"),
        mpatches.Patch(color="#4CAF50", label="Hybrid (FN-DSA)"),
        mpatches.Patch(color="#FB8C00", label="Hybrid (ML-DSA)"),
    ]
    ax.legend(handles=group_legend, loc="upper left", fontsize=9)

    # Pareto callout for eddsa_fn_dsa hybrid
    ef_sig  = eb + fb
    ef_crpt = eddsa_s + fndsa_s + eddsa_v + fndsa_v
    ax.annotate(
        "EdDSA + FN-DSA:\nsmallest & fastest hybrid",
        xy=(ef_sig, ef_crpt),
        xytext=(ef_sig + 300, ef_crpt + 0.18),
        arrowprops=dict(arrowstyle="->", color="#2E7D32"),
        fontsize=9, color="#2E7D32", fontweight="bold",
        bbox=dict(boxstyle="round,pad=0.25", facecolor="#E8F5E9",
                  edgecolor="#2E7D32", alpha=0.9),
    )

    fig.tight_layout()
    save(fig, output_dir, "09_security_storage_tradeoff.png")


# ─────────────────────────────────────────────────────────────────────────────
# CHART 10 — What fraction of each hybrid's crypto work is quantum-safe?
# ─────────────────────────────────────────────────────────────────────────────

def plot_10_pqc_contribution(rows: list[dict], output_dir: Path) -> None:
    """
    Two 100% stacked horizontal bar panels side-by-side:
      left panel  = signing time split
      right panel = verification time split
    Shows what % of each hybrid's cryptographic work is post-quantum.
    """
    CLASSICAL_SIGN = {
        "eddsa_fn_dsa": "server_eddsa_sign_ms",
        "eddsa_ml_dsa": "server_eddsa_sign_ms",
        "ecdsa_fn_dsa": "server_ecdsa_sign_ms",
        "ecdsa_ml_dsa": "server_ecdsa_sign_ms",
    }
    PQC_SIGN = {
        "eddsa_fn_dsa": "server_fn_dsa_sign_ms",
        "eddsa_ml_dsa": "server_ml_dsa_sign_ms",
        "ecdsa_fn_dsa": "server_fn_dsa_sign_ms",
        "ecdsa_ml_dsa": "server_ml_dsa_sign_ms",
    }
    CLASSICAL_VERIFY = {
        "eddsa_fn_dsa": "server_eddsa_verify_ms",
        "eddsa_ml_dsa": "server_eddsa_verify_ms",
        "ecdsa_fn_dsa": "server_ecdsa_verify_ms",
        "ecdsa_ml_dsa": "server_ecdsa_verify_ms",
    }
    PQC_VERIFY = {
        "eddsa_fn_dsa": "server_fn_dsa_verify_ms",
        "eddsa_ml_dsa": "server_ml_dsa_verify_ms",
        "ecdsa_fn_dsa": "server_fn_dsa_verify_ms",
        "ecdsa_ml_dsa": "server_ml_dsa_verify_ms",
    }

    fig, (ax_s, ax_v) = plt.subplots(1, 2, figsize=(15, 4.5))
    kw10 = dict(bucket="10KB", scenario="workflow")

    for ax, panel, c_map, p_map in [
        (ax_s, "Signing",      CLASSICAL_SIGN,   PQC_SIGN),
        (ax_v, "Verification", CLASSICAL_VERIFY, PQC_VERIFY),
    ]:
        y = np.arange(len(PROFILES))
        c_pcts, p_pcts, c_vals, p_vals = [], [], [], []

        for profile in PROFILES:
            c_ms = med(rows, c_map[profile], profile=profile, **kw10) or 0.0
            p_ms = med(rows, p_map[profile], profile=profile, **kw10) or 0.0
            total = c_ms + p_ms or 1.0
            c_pcts.append(c_ms / total * 100)
            p_pcts.append(p_ms / total * 100)
            c_vals.append(c_ms)
            p_vals.append(p_ms)

        ax.barh(y, c_pcts, height=0.55,
                color="#1565C0", alpha=0.85, zorder=3)
        ax.barh(y, p_pcts, left=c_pcts, height=0.55,
                color="#43A047", alpha=0.85, zorder=3)

        for i, (cp, pp, cms, pms) in enumerate(zip(c_pcts, p_pcts, c_vals, p_vals)):
            if cp > 7:
                ax.text(cp / 2, y[i],
                        f"{cp:.0f}%\n({cms:.3f} ms)",
                        ha="center", va="center", fontsize=8,
                        color="white", fontweight="bold")
            if pp > 7:
                ax.text(cp + pp / 2, y[i],
                        f"{pp:.0f}%\n({pms:.3f} ms)",
                        ha="center", va="center", fontsize=8,
                        color="white", fontweight="bold")

        ax.set_yticks(y)
        ax.set_yticklabels([PROFILE_LABELS[p] for p in PROFILES], fontsize=10)
        ax.set_xlim(0, 100)
        ax.set_xlabel("Share of operation time (%)", fontsize=10)
        ax.set_title(f"{panel} Time Breakdown\n(blue = classical, green = post-quantum)", fontsize=11)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.grid(axis="x", color="#eeeeee", linewidth=0.8, zorder=0)

    # Place legend outside the chart area at the bottom center
    handles = [
        mpatches.Patch(color="#1565C0", label="Classical"),
        mpatches.Patch(color="#43A047", label="Post-quantum"),
    ]
    fig.legend(handles=handles, loc="lower center", fontsize=9, ncol=2, 
               bbox_to_anchor=(0.5, -0.08))

    fig.suptitle(
        "What Fraction of Each Hybrid's Cryptographic Work Is Quantum-Safe?\n"
        "(10 KB file, SHA-256, full workflow)",
        fontsize=12, y=1.00,
    )
    fig.tight_layout()
    save(fig, output_dir, "10_pqc_contribution.png")


# ─────────────────────────────────────────────────────────────────────────────
# CHART 11 — The True Cost of Upgrading to Hybrid
# ─────────────────────────────────────────────────────────────────────────────

def plot_11_cost_of_hybrid_upgrade(rows: list[dict], output_dir: Path) -> None:
    """
    Waterfall / step highlight: what is the explicit penalty (in both latency and storage)
    when taking a classical baseline and bolting on a PQC algorithm?
    Shows: Baseline -> + FN-DSA -> + ML-DSA.
    """
    kw10 = dict(bucket="10KB", scenario="workflow")

    # Baselines
    eddsa_ms = (med(rows, "server_eddsa_sign_ms", profile="eddsa_fn_dsa", **kw10) or 0.0) + \
               (med(rows, "server_eddsa_verify_ms", profile="eddsa_fn_dsa", **kw10) or 0.0)
    ecdsa_ms = (med(rows, "server_ecdsa_sign_ms", profile="ecdsa_fn_dsa", **kw10) or 0.0) + \
               (med(rows, "server_ecdsa_verify_ms", profile="ecdsa_fn_dsa", **kw10) or 0.0)

    eddsa_b = med(rows, "eddsa_signature_bytes", profile="eddsa_fn_dsa", **kw10) or 64.0
    ecdsa_b = med(rows, "ecdsa_signature_bytes", profile="ecdsa_fn_dsa", **kw10) or 71.0

    # Additions
    fn_ms = (med(rows, "server_fn_dsa_sign_ms", profile="eddsa_fn_dsa", **kw10) or 0.0) + \
            (med(rows, "server_fn_dsa_verify_ms", profile="eddsa_fn_dsa", **kw10) or 0.0)
    ml_ms = (med(rows, "server_ml_dsa_sign_ms", profile="eddsa_ml_dsa", **kw10) or 0.0) + \
            (med(rows, "server_ml_dsa_verify_ms", profile="eddsa_ml_dsa", **kw10) or 0.0)
            
    fn_b = med(rows, "fn_dsa_signature_bytes", profile="eddsa_fn_dsa", **kw10) or 654.0
    ml_b = med(rows, "ml_dsa_signature_bytes", profile="eddsa_ml_dsa", **kw10) or 3309.0

    fig, ax = plt.subplots(figsize=(12, 6))

    scenarios = [
        ("EdDSA\nBaseline", eddsa_ms, eddsa_ms, eddsa_b, 0.0, "#1565C0", "#1565C0"),
        ("+ FN-DSA\n(Fast/Small)", eddsa_ms + fn_ms, eddsa_ms, eddsa_b + fn_b, fn_ms, "#1565C0", "#43A047"),
        ("+ ML-DSA\n(Standard/Large)", eddsa_ms + ml_ms, eddsa_ms, eddsa_b + ml_b, ml_ms, "#1565C0", "#FB8C00"),
        ("ECDSA\nBaseline", ecdsa_ms, ecdsa_ms, ecdsa_b, 0.0, "#0288D1", "#0288D1"),
        ("+ FN-DSA\n(Fast/Small)", ecdsa_ms + fn_ms, ecdsa_ms, ecdsa_b + fn_b, fn_ms, "#0288D1", "#1B5E20"),
        ("+ ML-DSA\n(Standard/Large)", ecdsa_ms + ml_ms, ecdsa_ms, ecdsa_b + ml_b, ml_ms, "#0288D1", "#BF360C"),
    ]

    x_pos = [0, 1, 2, 4, 5, 6]  # Space between EdDSA family and ECDSA family
    bar_w = 0.6

    for i, (label, total_ms, baseline_ms, total_bytes, penalty_ms, baseline_c, uplift_c) in enumerate(scenarios):
        x = x_pos[i]

        if penalty_ms == 0:
            ax.bar(x, total_ms, color=baseline_c, alpha=0.85, width=bar_w, zorder=3)
            ax.text(
                x, total_ms / 2, f"{total_ms:.2f} ms",
                ha="center", va="center", color="white",
                fontweight="bold", fontsize=10,
            )
            bytes_y = total_ms + 0.08
        else:
            # Hybrid bars are stacked so the added PQC cost is represented directly.
            ax.bar(
                x, baseline_ms, color=baseline_c, alpha=0.28, width=bar_w,
                edgecolor=baseline_c, linewidth=1.2, zorder=2,
            )
            ax.bar(
                x, penalty_ms, bottom=baseline_ms, color=uplift_c,
                alpha=0.92, width=bar_w, zorder=3,
            )
            ax.hlines(
                baseline_ms, x - bar_w / 2, x + bar_w / 2,
                colors="white", linewidth=1.2, zorder=4,
            )
            ax.text(
                x, baseline_ms + penalty_ms / 2, f"+{penalty_ms:.2f} ms",
                ha="center", va="center", color="white",
                fontweight="bold", fontsize=10, zorder=5,
            )
            ax.text(
                x, total_ms + 0.04, f"{total_ms:.2f} ms total",
                ha="center", va="bottom", color="#37474F",
                fontsize=9, fontweight="bold",
            )
            bytes_y = total_ms + 0.14

        # Label total storage cost above the bar.
        ax.text(
            x, bytes_y, f"{int(total_bytes)} bytes",
            ha="center", va="bottom", color="#424242",
            fontsize=9, fontweight="bold",
        )

    ax.set_xticks(x_pos)
    ax.set_xticklabels([s[0] for s in scenarios], fontsize=10)
    ax.set_ylabel("Total crypto latency: Sign + Verify (ms)", fontsize=11)
    ax.set_title(
        "The Penalty of Upgrading: Navigating the Jump from Classical to Hybrid\n"
        "(Hybrid bars are stacked: muted base = classical cost, bright cap = added PQC latency)",
        fontsize=12,
    )
    clean_axes(ax, axis="y")
    ymin, ymax = ax.get_ylim()
    ax.set_ylim(top=ymax * 1.28)
    
    fig.tight_layout()
    save(fig, output_dir, "11_cost_of_hybrid_upgrade.png")


# ─────────────────────────────────────────────────────────────────────────────
# CHART 12 — Cloud Compute Tax (Throughput Extrapolation)
# ─────────────────────────────────────────────────────────────────────────────

def plot_12_throughput_extrapolation(rows: list[dict], output_dir: Path) -> None:
    """
    Extrapolates the pure cryptographic signing cost into Theoretical Signatures
    Per Second (TPS) per CPU core, showing how tiny ms differences slash capacity.
    """
    kw10 = dict(bucket="10KB", scenario="workflow")

    scenarios = []
    
    # Baselines
    eddsa_s = med(rows, "server_eddsa_sign_ms", profile="eddsa_fn_dsa", **kw10) or 0.1
    ecdsa_s = med(rows, "server_ecdsa_sign_ms", profile="ecdsa_fn_dsa", **kw10) or 0.1
    
    scenarios.append(("EdDSA\nOnly", eddsa_s, "#1565C0"))
    scenarios.append(("ECDSA\nOnly", ecdsa_s, "#0288D1"))

    # Hybrids
    fndsa_s = med(rows, "server_fn_dsa_sign_ms", profile="eddsa_fn_dsa", **kw10) or 0.1
    mldsa_s = med(rows, "server_ml_dsa_sign_ms", profile="eddsa_ml_dsa", **kw10) or 0.1
    
    scenarios.append(("EdDSA +\nFN-DSA", eddsa_s + fndsa_s, "#4CAF50"))
    scenarios.append(("EdDSA +\nML-DSA", eddsa_s + mldsa_s, "#FF9800"))
    scenarios.append(("ECDSA +\nFN-DSA", ecdsa_s + fndsa_s, "#1B5E20"))
    scenarios.append(("ECDSA +\nML-DSA", ecdsa_s + mldsa_s, "#BF360C"))

    # Calculate TPS (1000 ms / signing ms)
    tps_data = [(label, 1000.0 / ms, color) for label, ms, color in scenarios]

    fig, ax = plt.subplots(figsize=(12, 6))
    x_pos = np.arange(len(tps_data))
    
    bars = ax.bar(x_pos, [t[1] for t in tps_data], color=[t[2] for t in tps_data], width=0.6, alpha=0.9)
    
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + (max([t[1] for t in tps_data]) * 0.02),
                f"{int(height):,} TPS",
                ha='center', va='bottom', fontweight='bold', fontsize=10)

    ax.set_xticks(x_pos)
    ax.set_xticklabels([t[0] for t in tps_data], fontsize=11)
    ax.set_ylabel("Theoretical Peak Signatures Per Second (per core)", fontsize=11)
    ax.set_title(
        "The Compute Tax: How Fractions of a Millisecond Destroy Throughput\n"
        "(Extrapolated from pure cryptographic signing latency)",
        fontsize=12,
    )
    clean_axes(ax, axis="y")
    ymin, ymax = ax.get_ylim()
    ax.set_ylim(bottom=0, top=ymax * 1.15)
    
    fig.tight_layout()
    save(fig, output_dir, "12_throughput_extrapolation.png")


# ─────────────────────────────────────────────────────────────────────────────
# CHART 13 — Bandwidth Cost (Data Transit Extrapolation)
# ─────────────────────────────────────────────────────────────────────────────

def plot_13_bandwidth_extrapolation(rows: list[dict], output_dir: Path) -> None:
    """
    Extrapolates the storage footprint into total gigabytes transferred 
    over 1 Million requests for a 10 KB payload setting.
    """
    kw10 = dict(bucket="10KB", scenario="workflow")
    
    eddsa_b = med(rows, "eddsa_signature_bytes", profile="eddsa_fn_dsa", **kw10) or 64.0
    ecdsa_b = med(rows, "ecdsa_signature_bytes", profile="ecdsa_fn_dsa", **kw10) or 71.0
    fndsa_b = med(rows, "fn_dsa_signature_bytes", profile="eddsa_fn_dsa", **kw10) or 654.0
    mldsa_b = med(rows, "ml_dsa_signature_bytes", profile="eddsa_ml_dsa", **kw10) or 3309.0

    payload_bytes = 10_240
    requests = 1_000_000

    scenarios = [
        ("EdDSA", eddsa_b, "#1565C0"),
        ("ECDSA", ecdsa_b, "#0288D1"),
        ("EdDSA + FN-DSA", eddsa_b + fndsa_b, "#4CAF50"),
        ("ECDSA + FN-DSA", ecdsa_b + fndsa_b, "#1B5E20"),
        ("EdDSA + ML-DSA", eddsa_b + mldsa_b, "#FF9800"),
        ("ECDSA + ML-DSA", ecdsa_b + mldsa_b, "#BF360C"),
    ]
    
    # Sort by size to show the exponential curve
    scenarios.sort(key=lambda x: x[1])

    labels = [s[0] for s in scenarios]
    total_gbs = [(payload_bytes + s[1]) * requests / (1024**3) for s in scenarios]
    colors = [s[2] for s in scenarios]

    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Draw area to emphasize accumulation
    x_pos = np.arange(len(scenarios))
    ax.plot(x_pos, total_gbs, color="#D32F2F", marker="o", markersize=8, linewidth=2.5, zorder=4)
    ax.fill_between(x_pos, total_gbs, color="#FFCDD2", alpha=0.3, zorder=3)

    for i, gb in enumerate(total_gbs):
        ax.text(i, gb + 0.1, f"{gb:.2f} GB", ha="center", va="bottom", 
                fontweight="bold", fontsize=10, color="#B71C1C")

    # Add a dashed baseline for just the 10KB files alone
    base_gb = (payload_bytes * requests) / (1024**3)
    ax.axhline(base_gb, color="#757575", linestyle="--", linewidth=1.5, zorder=2)
    ax.text(0.1, base_gb - 0.15, f"Base 10KB Files (No Sigs): {base_gb:.2f} GB", 
            color="#757575", va="top", fontsize=9, fontweight="bold")

    ax.set_xticks(x_pos)
    ax.set_xticklabels(labels, fontsize=11, rotation=15)
    ax.set_ylabel("Total Gigabytes transferred", fontsize=11)
    ax.set_title(
        "The Bandwidth Tax: Total Data Transferred Over 1 Million Requests\n"
        "(10 KB Payloads - Revealing the hidden cost of massive PQC signatures)",
        fontsize=12,
    )
    clean_axes(ax, axis="y")
    ymin, ymax = ax.get_ylim()
    ax.set_ylim(bottom=base_gb - 0.5, top=ymax * 1.1)

    fig.tight_layout()
    save(fig, output_dir, "13_bandwidth_extrapolation.png")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate 10 insight-driven PQC benchmark charts from stage_metrics_long.csv"
    )
    parser.add_argument(
        "--stage-metrics", type=Path, required=True, nargs="+",
        help="Path(s) to stage_metrics_long.csv or wide format results csv (e.g. classical-pqc.csv hybrid.csv)",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=None,
        help="Output directory for PNG files (default: same directory as --stage-metrics)",
    )
    args = parser.parse_args()

    for path in args.stage_metrics:
        if not path.exists():
            print(f"Error: file not found: {path}", file=sys.stderr)
            return 1

    output_dir = args.output_dir or args.stage_metrics[0].parent
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading files: {[p.name for p in args.stage_metrics]} ...")
    rows = load_stage_metrics(args.stage_metrics)
    print(f"  {len(rows):,} rows loaded")
    print(f"Generating charts → {output_dir}/\n")

    charts = [
        ("Chart  1: Overhead vs fastest (per file size)",         plot_01_overhead_vs_fastest),
        ("Chart  2: Server time breakdown — where time goes",     plot_02_server_time_breakdown),
        ("Chart  3: Sign vs verify asymmetry (diverging bars)",   plot_03_sign_verify_asymmetry),
        ("Chart  4: Signature size",                   plot_04_signature_size_as_file_pct),
        ("Chart  5: Latency scaling with file size",              plot_05_latency_scaling),
        ("Chart  6: Latency consistency (nested whiskers)",       plot_06_latency_consistency),
        ("Chart  8: Crypto cost — Classical vs PQC vs Hybrid",    plot_08_crypto_cost_by_mode),
        ("Chart  9: Security-storage-performance tradeoff",       plot_09_security_storage_tradeoff),
        ("Chart 10: PQC contribution within each hybrid",         plot_10_pqc_contribution),
        ("Chart 11: True cost of upgrading to hybrid",            plot_11_cost_of_hybrid_upgrade),
        ("Chart 12: Cloud compute tax (Throughput)",              plot_12_throughput_extrapolation),
        ("Chart 13: Bandwidth cost extrapolation",                plot_13_bandwidth_extrapolation),
    ]

    failures = 0
    for desc, fn in charts:
        print(desc)
        try:
            fn(rows, output_dir)
        except Exception as exc:
            import traceback
            print(f"  ✗  FAILED: {exc}", file=sys.stderr)
            traceback.print_exc()
            failures += 1

    total = len(charts) - failures
    print(f"\nDone. {total}/{len(charts)} charts written to {output_dir}/")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
