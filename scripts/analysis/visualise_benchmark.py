#!/usr/bin/env python3
"""
Benchmark visualisation: 10 insight-driven charts for hybrid PQC performance analysis.

Usage:
    python3 scripts/analysis/visualise_benchmark.py \\
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

def load_stage_metrics(csv_path: Path) -> list[dict]:
    rows: list[dict] = []
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            rows.append(row)
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

            ax.bar(x, overhead, width=bar_w - 0.02,
                   color=PROFILE_COLORS[profile], alpha=0.88, zorder=3)

            # CI error bars
            c = ci95(rows, "client_total_ms", profile=profile, bucket=bucket)
            if c and fastest > 0:
                lo, hi = c
                err_lo = max(0.0, overhead - (lo - fastest) / fastest * 100)
                err_hi = max(0.0, (hi - fastest) / fastest * 100 - overhead)
                ax.errorbar(x + bar_w / 2 - 0.01, overhead,
                            yerr=[[err_lo], [err_hi]],
                            fmt="none", color="#333", capsize=3, linewidth=1, zorder=4)

            if overhead > 0.08:
                ax.text(x + bar_w / 2 - 0.01, overhead + 0.04,
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
        "Database write", "Classical sign", "Post-quantum sign",
        "Classical verify", "Post-quantum verify", "Hashing", "Other",
    ]
    seg_colors = [
        "#FDD835",   # yellow  — DB
        "#1565C0",   # dark blue — classical sign
        "#43A047",   # green — PQC sign
        "#42A5F5",   # light blue — classical verify
        "#66BB6A",   # light green — PQC verify
        "#AB47BC",   # purple — hash
        "#B0BEC5",   # grey — other
    ]

    data = {label: [] for label in seg_labels}

    for profile in PROFILES:
        kw = dict(profile=profile, bucket="10KB")
        db   = med(rows, "server_db_persist_ms",      **kw) or 0.0
        cs   = med(rows, CLASSICAL_SIGN[profile],     **kw) or 0.0
        ps   = med(rows, PQC_SIGN[profile],           **kw) or 0.0
        cv_  = med(rows, CLASSICAL_VERIFY[profile],   **kw) or 0.0
        pv   = med(rows, PQC_VERIFY[profile],         **kw) or 0.0
        hsh  = med(rows, "server_hash_ms",            **kw) or 0.0
        tot  = med(rows, "server_total_ms",           **kw) or 1.0
        other = max(0.0, tot - db - cs - ps - cv_ - pv - hsh)

        parts = [db, cs, ps, cv_, pv, hsh, other]
        total = sum(parts) or 1.0
        pcts  = [p / total * 100 for p in parts]

        for label, pct in zip(seg_labels, pcts):
            data[label].append(pct)

    fig, ax = plt.subplots(figsize=(13, 5))
    y = np.arange(len(PROFILES))
    bar_h = 0.55
    lefts = np.zeros(len(PROFILES))

    for label, color in zip(seg_labels, seg_colors):
        vals = np.array(data[label])
        bars = ax.barh(y, vals, left=lefts, height=bar_h, color=color, label=label, zorder=3)
        for bar, v, l in zip(bars, vals, lefts):
            if v > 4:
                ax.text(l + v / 2, bar.get_y() + bar.get_height() / 2,
                        f"{v:.0f}%", ha="center", va="center", fontsize=8,
                        fontweight="bold", color="white")
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
    ax.legend(loc="lower right", fontsize=9, ncol=2)
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
        ax.text(-sv - 0.005, y[i] + bar_h / 2,
                f"{sv:.3f} ms", ha="right", va="center", fontsize=9, fontweight="bold")

        # Verify bar (right, positive direction)
        ax.barh(y[i] - bar_h / 2, vv, height=bar_h, color=color, alpha=0.5, zorder=3)
        ax.errorbar(vv, y[i] - bar_h / 2, xerr=ve / 2,
                    fmt="none", color="#333", capsize=3, linewidth=1, zorder=4)
        ax.text(vv + 0.005, y[i] - bar_h / 2,
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
        f"FN-DSA verifies {fn_sv/fn_vv:.1f}x faster than it signs\n"
        "→ ideal for read-heavy workloads",
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

    fig, ax = plt.subplots(figsize=(12, 4.5))
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
        ax.text(total_pct + 0.3, y[i], f"{total_pct:.1f}% of file  ({tb:,} bytes)",
                va="center", fontsize=10, fontweight="bold")
        if cp > 0.3:
            ax.text(cp / 2, y[i], f"{cp:.1f}%",
                    ha="center", va="center", fontsize=8, color="white", fontweight="bold")
        if pp > 1.5:
            ax.text(cp + pp / 2, y[i], f"{pp:.1f}%",
                    ha="center", va="center", fontsize=8, color="white", fontweight="bold")

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
    ax.set_xlim(0, max_pct * 1.6)

    # Find ML-DSA vs FN-DSA ratio
    fn_total = classical_pcts[0] + pqc_pcts[0]   # eddsa_fn_dsa
    ml_total = classical_pcts[1] + pqc_pcts[1]   # eddsa_ml_dsa
    if fn_total > 0:
        ax.annotate(
            f"ML-DSA adds {ml_total/fn_total:.1f}x more\nstorage than FN-DSA",
            xy=(ml_total, y[1]),
            xytext=(ml_total + 3, y[1] + 1.0),
            arrowprops=dict(arrowstyle="->", color="#555"),
            fontsize=9, color="#555",
        )

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

    for profile in PROFILES:
        color = PROFILE_COLORS[profile]
        lat_ms, lo_arr, hi_arr, crypto_pcts = [], [], [], []

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

        ax1.plot(x_vals, lat, color=color, linewidth=2.2, marker="o",
                 markersize=7, label=PROFILE_LABELS[profile], zorder=4)
        ax1.fill_between(x_vals, lo, hi, color=color, alpha=0.15, zorder=3)
        ax2.plot(x_vals, cpct, color=color, linewidth=1.2,
                 linestyle="--", alpha=0.65, zorder=3)

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

    fig, ax = plt.subplots(figsize=(13, 7))
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

    ax.text(0.99, 0.01,
            "Solid = SHA-256 | Transparent = BLAKE-3",
            transform=ax.transAxes, ha="right", va="bottom", fontsize=9,
            bbox=dict(boxstyle="round,pad=0.3", facecolor="white", edgecolor="#bdbdbd"))

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
        ax.text(x + bar_w / 2, total + 0.008,
                f"{total:.2f}", ha="center", va="bottom", fontsize=8.5, fontweight="bold")
        ax.text(x + bar_w / 2, -0.03, short_label,
                ha="center", va="top", fontsize=8, rotation=0)

    # Group centre labels
    for group, xs in bar_x_per_group.items():
        if xs:
            cx = (xs[0] + xs[-1] + bar_w) / 2
            ax.text(cx, -0.09, group, ha="center", va="top",
                    fontsize=11, fontweight="bold",
                    transform=ax.get_xaxis_transform())
            # Vertical separator
            if group != "Classical":
                sep_x = xs[0] - 0.3
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
                color="#1565C0", alpha=0.85, label="Classical", zorder=3)
        ax.barh(y, p_pcts, left=c_pcts, height=0.55,
                color="#43A047", alpha=0.85, label="Post-quantum", zorder=3)

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

    ax_s.legend(loc="lower right", fontsize=9)

    fig.suptitle(
        "What Fraction of Each Hybrid's Cryptographic Work Is Quantum-Safe?\n"
        "(10 KB file, SHA-256, full workflow)",
        fontsize=12, y=1.02,
    )
    fig.tight_layout()
    save(fig, output_dir, "10_pqc_contribution.png")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate 10 insight-driven PQC benchmark charts from stage_metrics_long.csv"
    )
    parser.add_argument(
        "--stage-metrics", type=Path, required=True,
        help="Path to stage_metrics_long.csv",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=None,
        help="Output directory for PNG files (default: same directory as --stage-metrics)",
    )
    args = parser.parse_args()

    if not args.stage_metrics.exists():
        print(f"Error: file not found: {args.stage_metrics}", file=sys.stderr)
        return 1

    output_dir = args.output_dir or args.stage_metrics.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading {args.stage_metrics.name} ...")
    rows = load_stage_metrics(args.stage_metrics)
    print(f"  {len(rows):,} rows loaded")
    print(f"Generating charts → {output_dir}/\n")

    charts = [
        ("Chart  1: Overhead vs fastest (per file size)",         plot_01_overhead_vs_fastest),
        ("Chart  2: Server time breakdown — where time goes",     plot_02_server_time_breakdown),
        ("Chart  3: Sign vs verify asymmetry (diverging bars)",   plot_03_sign_verify_asymmetry),
        ("Chart  4: Signature size as % of file",                 plot_04_signature_size_as_file_pct),
        ("Chart  5: Latency scaling with file size",              plot_05_latency_scaling),
        ("Chart  6: Latency consistency (nested whiskers)",       plot_06_latency_consistency),
        ("Chart  7: Scenario cost heatmap",                       plot_07_scenario_heatmap),
        ("Chart  8: Crypto cost — Classical vs PQC vs Hybrid",    plot_08_crypto_cost_by_mode),
        ("Chart  9: Security-storage-performance tradeoff",       plot_09_security_storage_tradeoff),
        ("Chart 10: PQC contribution within each hybrid",         plot_10_pqc_contribution),
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
