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
import numpy as np

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    print("Error: matplotlib required. Install: pip install matplotlib", file=sys.stderr)
    import sys
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Load evidence metrics CSV and aggregate by profile/hash.\n"
            "Chart generation has moved to scripts/analysis/visualise_benchmark.py\n"
            "which reads stage_metrics_long.csv and produces 10 insight-driven charts."
        )
    )
    parser.add_argument("csv", type=Path, help="Evidence metrics CSV")
    parser.add_argument("--output-dir", type=Path, default=None, help="(unused) Output directory")

    args = parser.parse_args()

    if not args.csv.exists():
        print(f"Error: CSV not found: {args.csv}", file=sys.stderr)
        return 1

    print(f"Loading metrics from {args.csv.name}...")
    rows = load_evidence_metrics(args.csv)
    print(f"   Loaded {len(rows)} rows")

    agg_data = aggregate_by_profile_hash(rows)
    print(f"   Aggregated {len(agg_data)} profile-hash combinations")

    print(
        "\nChart generation has moved to scripts/analysis/visualise_benchmark.py\n"
        "Run: python3 scripts/analysis/visualise_benchmark.py --stage-metrics <stage_metrics_long.csv>"
    )
    return 0
