#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence


ConditionKey = tuple[str, str, str, str, str]
RunRecord = Mapping[str, Any]

PROFILE_ORDER = [
    "rsa_pss",
    "eddsa",
    "ecdsa",
    "hmac_sha256",
    "ml_dsa",
    "ml_dsa",
    "slh_dsa",
    "fn_dsa",
    "rsa_pss_ml_dsa",
]
CLASSICAL_PROFILES = {"rsa_pss", "eddsa", "ecdsa", "hmac_sha256"}
PQC_PROFILES = {"ml_dsa", "ml_dsa", "slh_dsa", "fn_dsa"}
HYBRID_PROFILES = {"rsa_pss_ml_dsa"}
HASH_ORDER = ["sha256", "blake3", "keccak256"]
SCENARIO_ORDER = [
    "workflow",
    "sign_only",
    "verify_manifest",
    "verify_stored",
    "verify_uploaded",
    "verify_full",
]
STORAGE_STATE_ORDER = ["cold", "warm"]
SUMMARY_FIELD_BY_RAW_METRIC = {
    "setup_upload_ms": "setup_upload_ms",
    "setup_process_ms": "setup_process_ms",
    "client_upload_ms": "upload_ms",
    "client_process_ms": "process_ms",
    "client_verify_ms": "verify_ms",
    "client_total_ms": "total_ms",
    "client_upload_mib_s": "client_upload_mib_s",
    "client_process_mib_s": "client_process_mib_s",
    "client_verify_mib_s": "client_verify_mib_s",
    "client_total_mib_s": "client_total_mib_s",
    "server_process_gateway_ms": "server_process_gateway_ms",
    "server_verify_gateway_ms": "server_verify_gateway_ms",
    "server_hash_ms": "server_hash_ms",
    "server_object_exists_check_ms": "server_object_exists_check_ms",
    "server_object_store_ms": "server_object_store_ms",
    "server_manifest_canonicalize_ms": "server_manifest_canonicalize_ms",
    "server_db_persist_ms": "server_db_persist_ms",
    "server_rsa_sign_ms": "server_rsa_sign_ms",
    "server_ml_dsa_sign_ms": "server_ml_dsa_sign_ms",
    "server_eddsa_sign_ms": "server_eddsa_sign_ms",
    "server_ecdsa_sign_ms": "server_ecdsa_sign_ms",
    "server_hmac_sign_ms": "server_hmac_sign_ms",
    "server_ml_dsa_sign_ms": "server_ml_dsa_sign_ms",
    "server_slh_dsa_sign_ms": "server_slh_dsa_sign_ms",
    "server_fn_dsa_sign_ms": "server_fn_dsa_sign_ms",
    "server_eddsa_verify_ms": "server_eddsa_verify_ms",
    "server_ecdsa_verify_ms": "server_ecdsa_verify_ms",
    "server_hmac_verify_ms": "server_hmac_verify_ms",
    "server_ml_dsa_verify_ms": "server_ml_dsa_verify_ms",
    "server_slh_dsa_verify_ms": "server_slh_dsa_verify_ms",
    "server_fn_dsa_verify_ms": "server_fn_dsa_verify_ms",
    "server_manifest_fetch_db_lookup_ms": "server_manifest_fetch_db_lookup_ms",
    "server_verify_hash_ms": "server_verify_hash_ms",
    "server_verify_canonicalize_ms": "server_verify_canonicalize_ms",
    "server_signature_verify_ms": "server_signature_verify_ms",
    "server_stored_object_verify_ms": "server_stored_object_verify_ms",
    "server_uploaded_content_verify_ms": "server_uploaded_content_verify_ms",
    "server_verify_ms": "server_verify_ms",
    "server_total_ms": "server_total_ms",
    "server_hash_mib_s": "server_hash_mib_s",
    "server_verify_mib_s": "server_verify_mib_s",
    "server_total_mib_s": "server_total_mib_s",
    "manifest_size_bytes": "manifest_size_bytes",
    "manifest_core_bytes": "manifest_core_bytes",
    "manifest_core_cbor_bytes": "manifest_core_cbor_bytes",
    "manifest_envelope_bytes": "manifest_envelope_bytes",
    "rsa_signature_bytes": "rsa_signature_bytes",
    "ml_dsa_signature_bytes": "ml_dsa_signature_bytes",
    "eddsa_signature_bytes": "eddsa_signature_bytes",
    "ecdsa_signature_bytes": "ecdsa_signature_bytes",
    "hmac_signature_bytes": "hmac_signature_bytes",
    "ml_dsa_signature_bytes": "ml_dsa_signature_bytes",
    "slh_dsa_signature_bytes": "slh_dsa_signature_bytes",
    "fn_dsa_signature_bytes": "fn_dsa_signature_bytes",
    "total_signature_bytes": "total_signature_bytes",
    "manifest_overhead_pct": "manifest_overhead_pct",
    "signature_overhead_pct": "signature_overhead_pct",
    "storage_amplification": "storage_amplification",
    "storage_bytes_written": "storage_bytes_written",
    "storage_bytes_read": "storage_bytes_read",
}
THROUGHPUT_MS_FIELD = {
    "client_upload_mib_s": "client_upload_ms",
    "client_process_mib_s": "client_process_ms",
    "client_verify_mib_s": "client_verify_ms",
    "client_total_mib_s": "client_total_ms",
    "server_hash_mib_s": "server_hash_ms",
    "server_verify_mib_s": "server_verify_ms",
    "server_total_mib_s": "server_total_ms",
}
KNOWN_SERVER_ATOMIC_FIELDS = [
    "server_hash_ms",
    "server_object_exists_check_ms",
    "server_object_store_ms",
    "server_manifest_canonicalize_ms",
    "server_db_persist_ms",
    "server_rsa_sign_ms",
    "server_ml_dsa_sign_ms",
    "server_eddsa_sign_ms",
    "server_ecdsa_sign_ms",
    "server_hmac_sign_ms",
    "server_ml_dsa_sign_ms",
    "server_slh_dsa_sign_ms",
    "server_fn_dsa_sign_ms",
    "server_manifest_fetch_db_lookup_ms",
    "server_verify_hash_ms",
    "server_verify_canonicalize_ms",
    "server_signature_verify_ms",
    "server_stored_object_verify_ms",
    "server_uploaded_content_verify_ms",
]
PROFILE_SIGN_FIELDS = {
    "rsa_pss": ["server_rsa_sign_ms"],
    "ml_dsa": ["server_ml_dsa_sign_ms"],
    "rsa_pss_ml_dsa": ["server_rsa_sign_ms", "server_ml_dsa_sign_ms"],
    "eddsa": ["server_eddsa_sign_ms"],
    "ecdsa": ["server_ecdsa_sign_ms"],
    "hmac_sha256": ["server_hmac_sign_ms"],
    "ml_dsa": ["server_ml_dsa_sign_ms"],
    "slh_dsa": ["server_slh_dsa_sign_ms"],
    "fn_dsa": ["server_fn_dsa_sign_ms"],
}
PROFILE_VERIFY_FIELDS = {
    "eddsa": ["server_eddsa_verify_ms"],
    "ecdsa": ["server_ecdsa_verify_ms"],
    "hmac_sha256": ["server_hmac_verify_ms"],
    "ml_dsa": ["server_ml_dsa_verify_ms"],
    "slh_dsa": ["server_slh_dsa_verify_ms"],
    "fn_dsa": ["server_fn_dsa_verify_ms"],
}
LATENCY_SUMMARY_METRICS = [
    "client_total_ms",
    "server_total_ms",
    "client_upload_ms",
    "client_process_ms",
    "client_verify_ms",
    "server_process_gateway_ms",
    "server_verify_gateway_ms",
]
ARTIFACT_SUMMARY_METRICS = [
    "manifest_size_bytes",
    "manifest_core_bytes",
    "manifest_core_cbor_bytes",
    "manifest_envelope_bytes",
    "rsa_signature_bytes",
    "ml_dsa_signature_bytes",
    "eddsa_signature_bytes",
    "ecdsa_signature_bytes",
    "hmac_signature_bytes",
    "ml_dsa_signature_bytes",
    "slh_dsa_signature_bytes",
    "fn_dsa_signature_bytes",
    "total_signature_bytes",
    "manifest_overhead_pct",
    "signature_overhead_pct",
    "storage_amplification",
    "storage_bytes_written",
    "storage_bytes_read",
    "cbor_compression_ratio",
    "signature_size_pct_of_file",
]
STAGE_METRIC_SPECS = [
    {"name": "setup_upload_ms", "scope": "setup", "group": "setup", "unit": "ms"},
    {"name": "setup_process_ms", "scope": "setup", "group": "setup", "unit": "ms"},
    {"name": "client_upload_ms", "scope": "client", "group": "upload", "unit": "ms"},
    {"name": "client_process_ms", "scope": "client", "group": "process", "unit": "ms"},
    {"name": "client_verify_ms", "scope": "client", "group": "verify", "unit": "ms"},
    {"name": "client_total_ms", "scope": "client", "group": "total", "unit": "ms"},
    {"name": "client_total_mib_s", "scope": "client", "group": "throughput", "unit": "MiB/s"},
    {"name": "server_process_gateway_ms", "scope": "server", "group": "gateway", "unit": "ms"},
    {"name": "server_verify_gateway_ms", "scope": "server", "group": "gateway", "unit": "ms"},
    {"name": "server_hash_ms", "scope": "server", "group": "hash", "unit": "ms"},
    {"name": "server_object_exists_check_ms", "scope": "server", "group": "storage", "unit": "ms"},
    {"name": "server_object_store_ms", "scope": "server", "group": "storage", "unit": "ms"},
    {"name": "server_manifest_canonicalize_ms", "scope": "server", "group": "sign", "unit": "ms"},
    {"name": "server_db_persist_ms", "scope": "server", "group": "sign", "unit": "ms"},
    {"name": "server_rsa_sign_ms", "scope": "server", "group": "sign", "unit": "ms"},
    {"name": "server_ml_dsa_sign_ms", "scope": "server", "group": "sign", "unit": "ms"},
    {"name": "server_eddsa_sign_ms", "scope": "server", "group": "sign", "unit": "ms"},
    {"name": "server_ecdsa_sign_ms", "scope": "server", "group": "sign", "unit": "ms"},
    {"name": "server_hmac_sign_ms", "scope": "server", "group": "sign", "unit": "ms"},
    {"name": "server_ml_dsa_sign_ms", "scope": "server", "group": "sign", "unit": "ms"},
    {"name": "server_slh_dsa_sign_ms", "scope": "server", "group": "sign", "unit": "ms"},
    {"name": "server_fn_dsa_sign_ms", "scope": "server", "group": "sign", "unit": "ms"},
    {"name": "server_manifest_fetch_db_lookup_ms", "scope": "server", "group": "verify", "unit": "ms"},
    {"name": "server_verify_hash_ms", "scope": "server", "group": "verify", "unit": "ms"},
    {"name": "server_verify_canonicalize_ms", "scope": "server", "group": "verify", "unit": "ms"},
    {"name": "server_signature_verify_ms", "scope": "server", "group": "verify", "unit": "ms"},
    {"name": "server_eddsa_verify_ms", "scope": "server", "group": "verify", "unit": "ms"},
    {"name": "server_ecdsa_verify_ms", "scope": "server", "group": "verify", "unit": "ms"},
    {"name": "server_hmac_verify_ms", "scope": "server", "group": "verify", "unit": "ms"},
    {"name": "server_ml_dsa_verify_ms", "scope": "server", "group": "verify", "unit": "ms"},
    {"name": "server_slh_dsa_verify_ms", "scope": "server", "group": "verify", "unit": "ms"},
    {"name": "server_fn_dsa_verify_ms", "scope": "server", "group": "verify", "unit": "ms"},
    {"name": "server_stored_object_verify_ms", "scope": "server", "group": "verify", "unit": "ms"},
    {"name": "server_uploaded_content_verify_ms", "scope": "server", "group": "verify", "unit": "ms"},
    {"name": "server_verify_ms", "scope": "server", "group": "verify", "unit": "ms"},
    {"name": "server_hash_mib_s", "scope": "server", "group": "throughput", "unit": "MiB/s"},
    {"name": "server_verify_mib_s", "scope": "server", "group": "throughput", "unit": "MiB/s"},
    {"name": "server_total_ms", "scope": "server", "group": "total", "unit": "ms"},
    {"name": "server_total_mib_s", "scope": "server", "group": "throughput", "unit": "MiB/s"},
    {"name": "manifest_size_bytes", "scope": "artifact", "group": "manifest", "unit": "bytes"},
    {"name": "manifest_core_bytes", "scope": "artifact", "group": "manifest", "unit": "bytes"},
    {"name": "manifest_core_cbor_bytes", "scope": "artifact", "group": "manifest", "unit": "bytes"},
    {"name": "manifest_envelope_bytes", "scope": "artifact", "group": "manifest", "unit": "bytes"},
    {"name": "rsa_signature_bytes", "scope": "artifact", "group": "signature", "unit": "bytes"},
    {"name": "ml_dsa_signature_bytes", "scope": "artifact", "group": "signature", "unit": "bytes"},
    {"name": "eddsa_signature_bytes", "scope": "artifact", "group": "signature", "unit": "bytes"},
    {"name": "ecdsa_signature_bytes", "scope": "artifact", "group": "signature", "unit": "bytes"},
    {"name": "hmac_signature_bytes", "scope": "artifact", "group": "signature", "unit": "bytes"},
    {"name": "ml_dsa_signature_bytes", "scope": "artifact", "group": "signature", "unit": "bytes"},
    {"name": "slh_dsa_signature_bytes", "scope": "artifact", "group": "signature", "unit": "bytes"},
    {"name": "fn_dsa_signature_bytes", "scope": "artifact", "group": "signature", "unit": "bytes"},
    {"name": "total_signature_bytes", "scope": "artifact", "group": "signature", "unit": "bytes"},
    {"name": "manifest_overhead_pct", "scope": "artifact", "group": "overhead", "unit": "%"},
    {"name": "signature_overhead_pct", "scope": "artifact", "group": "overhead", "unit": "%"},
    {"name": "storage_amplification", "scope": "artifact", "group": "overhead", "unit": "ratio"},
    {"name": "storage_bytes_written", "scope": "artifact", "group": "io", "unit": "bytes"},
    {"name": "storage_bytes_read", "scope": "artifact", "group": "io", "unit": "bytes"},
    {"name": "sign_overhead_pct", "scope": "server", "group": "sign", "unit": "%"},
    {"name": "cbor_compression_ratio", "scope": "artifact", "group": "manifest", "unit": "ratio"},
    {"name": "signature_size_pct_of_file", "scope": "artifact", "group": "overhead", "unit": "%"},
]
COMPARISON_METRICS = [
    {"name": "server_total_ms", "scope": "server", "unit": "ms"},
    {"name": "client_total_ms", "scope": "client", "unit": "ms"},
    {"name": "manifest_size_bytes", "scope": "artifact", "unit": "bytes"},
    {"name": "total_signature_bytes", "scope": "artifact", "unit": "bytes"},
]
PROFILE_DISPLAY = {
    "rsa_pss": "RSA-PSS",
    "ml_dsa": "ml_dsa",
    "rsa_pss_ml_dsa": "RSA-PSS + ml_dsa",
    "eddsa": "EdDSA",
    "ecdsa": "ECDSA",
    "hmac_sha256": "HMAC-SHA256",
    "ml_dsa": "ML-DSA",
    "slh_dsa": "SLH-DSA",
    "fn_dsa": "fn_dsa",
}
PROFILE_COLORS = {
    "rsa_pss": "#315c7c",
    "eddsa": "#4f7f52",
    "ecdsa": "#739e3f",
    "hmac_sha256": "#9b8f2b",
    "ml_dsa": "#c26a2d",
    "ml_dsa": "#d47c3c",
    "slh_dsa": "#db9659",
    "fn_dsa": "#e6b985",
    "rsa_pss_ml_dsa": "#8f3b2f",
}


def percentile(sorted_values: Sequence[float], p: float) -> float:
    if not sorted_values:
        raise ValueError("percentile() requires at least one value")
    if p <= 0.0:
        return float(sorted_values[0])
    if p >= 1.0:
        return float(sorted_values[-1])

    rank = (len(sorted_values) - 1) * p
    lower_index = int(math.floor(rank))
    upper_index = int(math.ceil(rank))
    lower_value = float(sorted_values[lower_index])
    upper_value = float(sorted_values[upper_index])
    if lower_index == upper_index:
        return lower_value
    fraction = rank - lower_index
    return lower_value + (upper_value - lower_value) * fraction


def coefficient_of_variation(values: Sequence[float]) -> float | None:
    numeric = [float(value) for value in values]
    if len(numeric) < 2:
        return None
    mean = statistics.mean(numeric)
    if math.isclose(mean, 0.0, abs_tol=1e-12):
        return None
    return statistics.stdev(numeric) / mean


def bootstrap_ratio(
    baseline: Sequence[float],
    comparison: Sequence[float],
    samples: int,
    seed: int,
) -> tuple[float | None, float | None, float | None]:
    baseline_values = sorted(float(value) for value in baseline)
    comparison_values = sorted(float(value) for value in comparison)
    if not baseline_values or not comparison_values:
        return None, None, None

    baseline_median = percentile(baseline_values, 0.5)
    comparison_median = percentile(comparison_values, 0.5)
    if baseline_median <= 0.0:
        return None, None, None
    ratio = comparison_median / baseline_median

    if samples <= 0 or len(baseline_values) < 2 or len(comparison_values) < 2:
        return ratio, None, None

    rng = random.Random(seed)
    baseline_count = len(baseline_values)
    comparison_count = len(comparison_values)
    bootstrap_ratios: list[float] = []
    for _ in range(samples):
        baseline_sample = sorted(
            baseline_values[rng.randrange(baseline_count)] for _ in range(baseline_count)
        )
        comparison_sample = sorted(
            comparison_values[rng.randrange(comparison_count)] for _ in range(comparison_count)
        )
        sampled_baseline = percentile(baseline_sample, 0.5)
        if sampled_baseline <= 0.0:
            continue
        sampled_comparison = percentile(comparison_sample, 0.5)
        bootstrap_ratios.append(sampled_comparison / sampled_baseline)

    if not bootstrap_ratios:
        return ratio, None, None

    bootstrap_ratios.sort()
    return ratio, percentile(bootstrap_ratios, 0.025), percentile(bootstrap_ratios, 0.975)


def known_server_stage_ms(run: RunRecord) -> float:
    total = 0.0
    for field_name in KNOWN_SERVER_ATOMIC_FIELDS:
        value = coerce_float(run.get(field_name))
        if value is not None:
            total += value
    return total


def measured_runs(report: Mapping[str, Any]) -> list[RunRecord]:
    return [
        run
        for run in report.get("raw_runs", [])
        if is_measured_phase(run) and is_scenario_success(run)
    ]


def group_by_condition(runs: Iterable[RunRecord]) -> dict[ConditionKey, list[RunRecord]]:
    grouped: dict[ConditionKey, list[RunRecord]] = defaultdict(list)
    for run in runs:
        grouped[condition_key_from_run(run)].append(run)
    return dict(grouped)


def extract_values(runs: Iterable[RunRecord], field: str) -> list[float]:
    values: list[float] = []
    for run in runs:
        value = get_metric_value(run, field)
        if value is not None:
            values.append(float(value))
    values.sort()
    return values


def compute_summary_stats(
    values: Sequence[float],
    bootstrap_samples: int,
    seed: int,
) -> dict[str, Any]:
    numeric = sorted(float(value) for value in values)
    if not numeric:
        return {
            "n": 0,
            "mean": None,
            "median": None,
            "iqr": None,
            "p95": None,
            "p99": None,
            "min": None,
            "max": None,
            "ci95_low": None,
            "ci95_high": None,
            "cv": None,
            "p99_p50_ratio": None,
        }

    p25 = percentile(numeric, 0.25)
    p50 = percentile(numeric, 0.50)
    p75 = percentile(numeric, 0.75)
    p95 = percentile(numeric, 0.95)
    p99 = percentile(numeric, 0.99)
    mean_val = statistics.mean(numeric)
    p99_p50_ratio = p99 / p50 if p50 > 0 else None
    ci95_low, ci95_high = bootstrap_median_ci(numeric, bootstrap_samples, seed)
    return {
        "n": len(numeric),
        "mean": mean_val,
        "median": p50,
        "iqr": p75 - p25,
        "p95": p95,
        "p99": p99,
        "min": numeric[0],
        "max": numeric[-1],
        "ci95_low": ci95_low,
        "ci95_high": ci95_high,
        "cv": coefficient_of_variation(numeric),
        "p99_p50_ratio": p99_p50_ratio,
    }


def parse_bucket_to_bytes(label: str) -> int:
    text = str(label).strip().upper().replace(" ", "")
    if not text:
        raise ValueError("bucket label is empty")

    units = {
        "B": 1,
        "KB": 1024,
        "KIB": 1024,
        "MB": 1024**2,
        "MIB": 1024**2,
        "GB": 1024**3,
        "GIB": 1024**3,
    }
    for suffix, multiplier in sorted(units.items(), key=lambda item: len(item[0]), reverse=True):
        if text.endswith(suffix):
            number = text[: -len(suffix)]
            return int(float(number) * multiplier)
    return int(float(text))


class AnalysisContext:
    def __init__(
        self,
        *,
        report: Mapping[str, Any],
        bootstrap_samples: int,
        seed: int,
        raw_runs: list[RunRecord],
        all_measured_runs: list[RunRecord],
        success_runs: list[RunRecord],
        all_by_condition: dict[ConditionKey, list[RunRecord]],
        success_by_condition: dict[ConditionKey, list[RunRecord]],
        summary_lookup: dict[ConditionKey, Mapping[str, Any]],
        condition_keys: list[ConditionKey],
    ) -> None:
        self.report = report
        self.bootstrap_samples = bootstrap_samples
        self.seed = seed
        self.raw_runs = raw_runs
        self.all_measured_runs = all_measured_runs
        self.success_runs = success_runs
        self.all_by_condition = all_by_condition
        self.success_by_condition = success_by_condition
        self.summary_lookup = summary_lookup
        self.condition_keys = condition_keys
        self.metric_values_cache: dict[tuple[ConditionKey, str], list[float]] = {}
        self.metric_stats_cache: dict[tuple[ConditionKey, str], dict[str, Any]] = {}

    def metric_values(self, key: ConditionKey, metric_name: str) -> list[float]:
        cache_key = (key, metric_name)
        if cache_key not in self.metric_values_cache:
            self.metric_values_cache[cache_key] = extract_values(
                self.success_by_condition.get(key, []),
                metric_name,
            )
        return self.metric_values_cache[cache_key]

    def metric_stats(self, key: ConditionKey, metric_name: str) -> dict[str, Any]:
        cache_key = (key, metric_name)
        if cache_key in self.metric_stats_cache:
            return self.metric_stats_cache[cache_key]

        values = self.metric_values(key, metric_name)
        summary_metric_name = SUMMARY_FIELD_BY_RAW_METRIC.get(metric_name, metric_name)
        summary = self.summary_lookup.get(key)
        summary_stats = summary.get(summary_metric_name) if summary else None

        stats: dict[str, Any]
        if isinstance(summary_stats, Mapping) and summary_stats.get("median") is not None:
            p99 = coerce_float(summary_stats.get("p99"))
            p50 = coerce_float(summary_stats.get("median"))
            stats = {
                "n": int(summary_stats.get("n", len(values) or 0)),
                "mean": coerce_float(summary_stats.get("mean")),
                "median": p50,
                "iqr": coerce_float(summary_stats.get("iqr")),
                "p95": coerce_float(summary_stats.get("p95")),
                "p99": p99,
                "min": coerce_float(summary_stats.get("min")),
                "max": coerce_float(summary_stats.get("max")),
                "ci95_low": coerce_float(summary_stats.get("ci95_low")),
                "ci95_high": coerce_float(summary_stats.get("ci95_high")),
                "cv": coefficient_of_variation(values),
                "p99_p50_ratio": (p99 / p50 if p99 is not None and p50 is not None and p50 > 0 else None),
            }
        else:
            stats = compute_summary_stats(
                values,
                self.bootstrap_samples,
                stable_seed(self.seed, *key, metric_name),
            )

        self.metric_stats_cache[cache_key] = stats
        return stats

    def condition_summary(self, key: ConditionKey) -> Mapping[str, Any] | None:
        return self.summary_lookup.get(key)


def enrich_runs_with_derived_fields(runs: list[Any]) -> None:
    """Compute per-run derived metrics and inject them as new fields into each run dict."""
    for run in runs:
        if not isinstance(run, dict):
            continue
        # sign_overhead_pct: signing time as % of total server processing time
        sign_ms = sign_stage_ms_for_run(run)
        server_total = coerce_float(run.get("server_total_ms"))
        run["sign_overhead_pct"] = (
            sign_ms / server_total * 100
            if sign_ms is not None and server_total is not None and server_total > 0
            else None
        )
        # cbor_compression_ratio: uncompressed manifest core vs CBOR-encoded size
        core_bytes = coerce_float(run.get("manifest_core_bytes"))
        core_cbor = coerce_float(run.get("manifest_core_cbor_bytes"))
        run["cbor_compression_ratio"] = (
            core_bytes / core_cbor
            if core_bytes is not None and core_cbor is not None and core_cbor > 0
            else None
        )
        # signature_size_pct_of_file: signature bytes as % of payload file size
        sig_bytes = coerce_float(run.get("total_signature_bytes"))
        file_bytes = coerce_float(run.get("file_size_bytes"))
        run["signature_size_pct_of_file"] = (
            sig_bytes / file_bytes * 100
            if sig_bytes is not None and file_bytes is not None and file_bytes > 0
            else None
        )


def build_analysis_context(
    report: Mapping[str, Any],
    bootstrap_samples: int,
    seed: int,
) -> AnalysisContext:
    raw_runs = list(report.get("raw_runs", []) or [])
    enrich_runs_with_derived_fields(raw_runs)
    all_measured = [run for run in raw_runs if is_measured_phase(run)]
    successes = [run for run in all_measured if is_scenario_success(run)]
    summary_lookup: dict[ConditionKey, Mapping[str, Any]] = {}
    for summary in report.get("summaries", []) or []:
        if isinstance(summary, Mapping):
            key = condition_key_from_summary(summary)
            summary_lookup[key] = summary

    condition_keys = sorted(
        set(group_by_condition(all_measured)) | set(summary_lookup),
        key=condition_sort_key,
    )

    return AnalysisContext(
        report=report,
        bootstrap_samples=bootstrap_samples,
        seed=seed,
        raw_runs=raw_runs,
        all_measured_runs=all_measured,
        success_runs=successes,
        all_by_condition=group_by_condition(all_measured),
        success_by_condition=group_by_condition(successes),
        summary_lookup=summary_lookup,
        condition_keys=condition_keys,
    )


def build_condition_quality_rows(
    report: Mapping[str, Any],
    *,
    min_condition_success_rate: float,
    min_server_coverage: float,
    max_relative_iqr: float,
    max_server_relative_iqr: float,
    min_samples: int,
    bootstrap_samples: int,
    report_seed: int,
) -> list[dict[str, Any]]:
    context = build_analysis_context(report, bootstrap_samples, report_seed)
    return build_condition_quality_rows_from_context(
        context,
        min_condition_success_rate=min_condition_success_rate,
        min_server_coverage=min_server_coverage,
        max_relative_iqr=max_relative_iqr,
        max_server_relative_iqr=max_server_relative_iqr,
        min_samples=min_samples,
    )


def build_condition_quality_rows_from_context(
    context: AnalysisContext,
    *,
    min_condition_success_rate: float,
    min_server_coverage: float,
    max_relative_iqr: float,
    max_server_relative_iqr: float,
    min_samples: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for key in context.condition_keys:
        runs = context.all_by_condition.get(key, [])
        success_runs = context.success_by_condition.get(key, [])
        summary = context.condition_summary(key)

        scenario_success_total = len(success_runs)
        measured_runs_total = len(runs)
        if measured_runs_total == 0 and summary:
            measured_runs_total = int(summary.get("measured_runs_total", 0) or 0)
            scenario_success_total = int(summary.get("measured_runs_success", 0) or 0)

        measured_runs_failed = max(measured_runs_total - scenario_success_total, 0)
        scenario_success_rate = (
            scenario_success_total / measured_runs_total if measured_runs_total else 0.0
        )

        verify_applicable_runs = sum(1 for run in runs if verify_is_applicable(run))
        verify_ok_runs = sum(1 for run in runs if verify_is_ok(run))
        if verify_applicable_runs == 0 and summary:
            verify_applicable_runs = int(summary.get("verify_applicable_runs", 0) or 0)
            verify_ok_runs = int(summary.get("verify_ok_runs", 0) or 0)
        verify_applicable_success_rate = (
            verify_ok_runs / verify_applicable_runs if verify_applicable_runs else None
        )
        verify_success_rate = (
            sum(1 for run in runs if bool(run.get("verify_overall_ok"))) / measured_runs_total
            if measured_runs_total
            else 0.0
        )

        server_available_runs = sum(1 for run in success_runs if has_available_server_telemetry(run))
        server_telemetry_configured = any(
            has_server_telemetry_configured(run) for run in runs or success_runs
        )
        if not server_telemetry_configured and summary:
            server_telemetry_configured = bool(summary.get("server_telemetry_configured"))
        server_total_coverage = (
            server_available_runs / scenario_success_total if scenario_success_total else 0.0
        )
        if math.isclose(server_total_coverage, 0.0, abs_tol=1e-12) and summary:
            server_total_coverage = coerce_float(summary.get("server_telemetry_coverage")) or 0.0

        client_stats = context.metric_stats(key, "client_total_ms")
        server_stats = context.metric_stats(key, "server_total_ms")
        client_relative_iqr = relative_iqr(client_stats)
        server_relative_iqr = relative_iqr(server_stats)

        client_invalid_reasons: list[str] = []
        server_invalid_reasons: list[str] = []

        if scenario_success_rate < min_condition_success_rate:
            client_invalid_reasons.append("condition_success_rate")
            server_invalid_reasons.append("condition_success_rate")
        if client_stats["n"] < min_samples:
            client_invalid_reasons.append("insufficient_client_samples")
        if client_relative_iqr is None or client_relative_iqr > max_relative_iqr:
            client_invalid_reasons.append("client_dispersion")
        if server_stats["n"] < min_samples:
            server_invalid_reasons.append("insufficient_server_samples")
        if server_total_coverage < min_server_coverage:
            server_invalid_reasons.append("server_coverage")
        if server_relative_iqr is None or server_relative_iqr > max_server_relative_iqr:
            server_invalid_reasons.append("server_dispersion")
        if not server_telemetry_configured:
            server_invalid_reasons.append("server_not_configured")

        storage_hit_values = [
            coerce_float(run.get("server_object_store_hit"))
            for run in success_runs
            if run.get("server_object_store_hit") is not None
        ]
        storage_hit_rate = (
            sum(storage_hit_values) / len(storage_hit_values) if storage_hit_values else None
        )

        row = {
            **condition_base_dict(key),
            "measured_runs_total": measured_runs_total,
            "measured_runs_success": scenario_success_total,
            "measured_runs_failed": measured_runs_failed,
            "scenario_success_rate": scenario_success_rate,
            "verify_applicable_runs": verify_applicable_runs,
            "verify_ok_runs": verify_ok_runs,
            "verify_applicable_success_rate": verify_applicable_success_rate,
            "verify_success_rate": verify_success_rate,
            "storage_hit_rate": storage_hit_rate,
            "server_telemetry_configured": server_telemetry_configured,
            "server_total_coverage": server_total_coverage,
            "server_telemetry_coverage": server_total_coverage,
            "client_total_n": client_stats["n"],
            "client_total_median": client_stats["median"],
            "client_total_iqr": client_stats["iqr"],
            "client_total_p95": client_stats["p95"],
            "client_total_ci95_low": client_stats["ci95_low"],
            "client_total_ci95_high": client_stats["ci95_high"],
            "client_total_cv": client_stats["cv"],
            "client_relative_iqr": client_relative_iqr,
            "server_total_n": server_stats["n"],
            "server_total_median": server_stats["median"],
            "server_total_iqr": server_stats["iqr"],
            "server_total_p95": server_stats["p95"],
            "server_total_ci95_low": server_stats["ci95_low"],
            "server_total_ci95_high": server_stats["ci95_high"],
            "server_total_cv": server_stats["cv"],
            "server_relative_iqr": server_relative_iqr,
            "valid_for_client_comparison": not client_invalid_reasons,
            "valid_for_server_comparison": not server_invalid_reasons,
            "client_invalid_reasons": ";".join(client_invalid_reasons),
            "server_invalid_reasons": ";".join(server_invalid_reasons),
        }
        rows.append(row)

    rows.sort(key=condition_row_sort_key)
    return rows


def build_latency_summary_rows(
    report: Mapping[str, Any],
    bootstrap_samples: int,
    seed: int,
) -> list[dict[str, Any]]:
    context = build_analysis_context(report, bootstrap_samples, seed)
    quality_rows = build_condition_quality_rows_from_context(
        context,
        min_condition_success_rate=0.0,
        min_server_coverage=0.0,
        max_relative_iqr=float("inf"),
        max_server_relative_iqr=float("inf"),
        min_samples=0,
    )
    quality_by_key = {row_to_condition_key(row): row for row in quality_rows}
    return build_wide_summary_rows(
        context,
        quality_by_key,
        LATENCY_SUMMARY_METRICS,
    )


def build_artifact_summary_rows(
    report: Mapping[str, Any],
    bootstrap_samples: int,
    seed: int,
) -> list[dict[str, Any]]:
    context = build_analysis_context(report, bootstrap_samples, seed)
    quality_rows = build_condition_quality_rows_from_context(
        context,
        min_condition_success_rate=0.0,
        min_server_coverage=0.0,
        max_relative_iqr=float("inf"),
        max_server_relative_iqr=float("inf"),
        min_samples=0,
    )
    quality_by_key = {row_to_condition_key(row): row for row in quality_rows}
    return build_wide_summary_rows(
        context,
        quality_by_key,
        ARTIFACT_SUMMARY_METRICS,
    )


def build_stage_metrics_long_rows(
    report: Mapping[str, Any],
    bootstrap_samples: int,
    seed: int,
) -> list[dict[str, Any]]:
    context = build_analysis_context(report, bootstrap_samples, seed)
    quality_rows = build_condition_quality_rows_from_context(
        context,
        min_condition_success_rate=0.0,
        min_server_coverage=0.0,
        max_relative_iqr=float("inf"),
        max_server_relative_iqr=float("inf"),
        min_samples=0,
    )
    quality_by_key = {row_to_condition_key(row): row for row in quality_rows}

    rows: list[dict[str, Any]] = []
    for key in context.condition_keys:
        quality_row = quality_by_key.get(key, {})
        measured_success = int(quality_row.get("measured_runs_success", 0) or 0)
        server_telemetry_configured = bool(quality_row.get("server_telemetry_configured", False))
        for spec in STAGE_METRIC_SPECS:
            stats = context.metric_stats(key, spec["name"])
            coverage = (
                stats["n"] / measured_success if measured_success and stats["n"] is not None else 0.0
            )
            if spec["scope"] == "server" and not server_telemetry_configured:
                applicability = "not_configured"
            elif stats["n"] == 0:
                applicability = "not_applicable"
            else:
                applicability = "applicable"

            rows.append(
                {
                    **condition_base_dict(key),
                    "metric_name": spec["name"],
                    "metric_scope": spec["scope"],
                    "metric_group": spec["group"],
                    "metric_unit": spec["unit"],
                    "metric_applicability": applicability,
                    "n": stats["n"],
                    "coverage": coverage if stats["n"] else None,
                    "mean": stats.get("mean"),
                    "median": stats["median"],
                    "iqr": stats["iqr"],
                    "p95": stats["p95"],
                    "p99": stats.get("p99"),
                    "min": stats.get("min"),
                    "max": stats.get("max"),
                    "ci95_low": stats["ci95_low"],
                    "ci95_high": stats["ci95_high"],
                    "cv": stats["cv"],
                    "p99_p50_ratio": stats.get("p99_p50_ratio"),
                    "valid_for_client_comparison": quality_row.get("valid_for_client_comparison"),
                    "valid_for_server_comparison": quality_row.get("valid_for_server_comparison"),
                }
            )

    rows.sort(
        key=lambda row: (
            condition_row_sort_key(row),
            row.get("metric_scope", ""),
            row.get("metric_group", ""),
            row.get("metric_name", ""),
        )
    )
    return rows


def build_comparison_metrics_rows(
    report: Mapping[str, Any],
    quality_rows: Sequence[Mapping[str, Any]],
    bootstrap_samples: int,
    seed: int,
) -> list[dict[str, Any]]:
    context = build_analysis_context(report, bootstrap_samples, seed)
    quality_by_key = {row_to_condition_key(row): row for row in quality_rows}
    rows: list[dict[str, Any]] = []

    grouped_by_baseline_dims: dict[tuple[str, str, str, str], list[ConditionKey]] = defaultdict(list)
    for key in context.condition_keys:
        scenario, state, profile, hash_algorithm, bucket = key
        grouped_by_baseline_dims[(scenario, state, hash_algorithm, bucket)].append(key)

    for baseline_dims, keys in grouped_by_baseline_dims.items():
        scenario, state, hash_algorithm, bucket = baseline_dims
        baseline_key = (scenario, state, "rsa_pss", hash_algorithm, bucket)
        if baseline_key not in context.condition_keys:
            continue

        baseline_quality = quality_by_key.get(baseline_key, {})
        for metric in COMPARISON_METRICS:
            baseline_values = context.metric_values(baseline_key, metric["name"])
            baseline_stats = context.metric_stats(baseline_key, metric["name"])
            if not baseline_values or baseline_stats["median"] is None:
                continue

            for key in sorted(keys, key=condition_sort_key):
                profile = key[2]
                comparison_values = context.metric_values(key, metric["name"])
                comparison_stats = context.metric_stats(key, metric["name"])
                if not comparison_values or comparison_stats["median"] is None:
                    continue

                if profile == "rsa_pss":
                    ratio, ci95_low, ci95_high = 1.0, 1.0, 1.0
                else:
                    ratio, ci95_low, ci95_high = bootstrap_ratio(
                        baseline_values,
                        comparison_values,
                        bootstrap_samples,
                        stable_seed(seed, *key, metric["name"], "comparison"),
                    )

                quality_row = quality_by_key.get(key, {})
                if metric["scope"] == "server":
                    valid_for_comparison = bool(
                        baseline_quality.get("valid_for_server_comparison")
                        and quality_row.get("valid_for_server_comparison")
                    )
                elif metric["scope"] == "client":
                    valid_for_comparison = bool(
                        baseline_quality.get("valid_for_client_comparison")
                        and quality_row.get("valid_for_client_comparison")
                    )
                else:
                    valid_for_comparison = bool(
                        baseline_quality.get("scenario_success_rate", 0.0) > 0.0
                        and quality_row.get("scenario_success_rate", 0.0) > 0.0
                    )

                baseline_median = baseline_stats["median"]
                comparison_median = comparison_stats["median"]
                absolute_delta = (
                    comparison_median - baseline_median
                    if baseline_median is not None and comparison_median is not None
                    else None
                )
                percent_delta = (
                    ((comparison_median - baseline_median) / baseline_median) * 100.0
                    if baseline_median not in (None, 0.0) and comparison_median is not None
                    else None
                )

                rows.append(
                    {
                        **condition_base_dict(key),
                        "baseline_signature_profile": "rsa_pss",
                        "baseline_profile_family": profile_family("rsa_pss"),
                        "metric_name": metric["name"],
                        "metric_scope": metric["scope"],
                        "metric_unit": metric["unit"],
                        "baseline_median": baseline_median,
                        "comparison_median": comparison_median,
                        "absolute_delta": absolute_delta,
                        "percent_delta": percent_delta,
                        "ratio": ratio,
                        "ci95_low": ci95_low,
                        "ci95_high": ci95_high,
                        "baseline_n": baseline_stats["n"],
                        "comparison_n": comparison_stats["n"],
                        "valid_for_comparison": valid_for_comparison,
                        "baseline_valid_for_client_comparison": baseline_quality.get(
                            "valid_for_client_comparison"
                        ),
                        "baseline_valid_for_server_comparison": baseline_quality.get(
                            "valid_for_server_comparison"
                        ),
                        "comparison_valid_for_client_comparison": quality_row.get(
                            "valid_for_client_comparison"
                        ),
                        "comparison_valid_for_server_comparison": quality_row.get(
                            "valid_for_server_comparison"
                        ),
                        "client_note": (
                            "sign_only client_total_ms includes upload/setup overhead"
                            if metric["name"].startswith("client_") and key[0] == "sign_only"
                            else None
                        ),
                    }
                )

    rows.sort(
        key=lambda row: (
            row.get("metric_name", ""),
            condition_row_sort_key(row),
        )
    )
    return rows


def build_run_diagnostics_rows(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for run in sorted(report.get("raw_runs", []) or [], key=lambda item: int(item.get("run_index", 0) or 0)):
        client_total_ms = get_metric_value(run, "client_total_ms")
        server_total_ms = get_metric_value(run, "server_total_ms")
        known_stage_sum_ms = known_server_stage_ms(run)
        rows.append(
            {
                "run_index": run.get("run_index"),
                "phase": run.get("phase"),
                "benchmark_scenario": condition_scenario(run),
                "storage_state_label": condition_storage_state(run),
                "signature_profile": condition_profile(run),
                "hash_algorithm": condition_hash(run),
                "bucket": condition_bucket(run),
                "bucket_bytes": parse_bucket_to_bytes(condition_bucket(run)),
                "file_size_bytes": run.get("file_size_bytes"),
                "request_id": run.get("request_id"),
                "scenario_success": is_scenario_success(run),
                "server_telemetry_status": run.get("server_telemetry_status"),
                "client_total_ms": client_total_ms,
                "server_total_ms": server_total_ms,
                "known_server_stage_ms": known_stage_sum_ms,
                "server_unaccounted_ms": (
                    server_total_ms - known_stage_sum_ms if server_total_ms is not None else None
                ),
                "client_server_gap_ms": (
                    client_total_ms - server_total_ms
                    if client_total_ms is not None and server_total_ms is not None
                    else None
                ),
                "client_known_stage_gap_ms": (
                    client_total_ms - known_stage_sum_ms if client_total_ms is not None else None
                ),
                "known_stage_fraction_of_server_total": (
                    known_stage_sum_ms / server_total_ms
                    if server_total_ms not in (None, 0.0)
                    else None
                ),
                "error_stage": run.get("error_stage"),
                "error": run.get("error"),
            }
        )
    return rows


def build_quality_checks(
    report: Mapping[str, Any],
    quality_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    measured_total = len([run for run in report.get("raw_runs", []) or [] if is_measured_phase(run)])
    measured_success = len(measured_runs(report))
    client_valid = sum(1 for row in quality_rows if row.get("valid_for_client_comparison"))
    server_valid = sum(1 for row in quality_rows if row.get("valid_for_server_comparison"))
    client_failures = Counter()
    server_failures = Counter()
    for row in quality_rows:
        for reason in str(row.get("client_invalid_reasons") or "").split(";"):
            if reason:
                client_failures[reason] += 1
        for reason in str(row.get("server_invalid_reasons") or "").split(";"):
            if reason:
                server_failures[reason] += 1

    success_rates = sorted(
        float(row.get("scenario_success_rate") or 0.0)
        for row in quality_rows
    )
    server_coverages = sorted(
        float(row.get("server_total_coverage") or 0.0)
        for row in quality_rows
    )
    return {
        "analysis_generated_at": utc_now_iso(),
        "report_generated_at": report.get("generated_at"),
        "raw_runs_total": len(report.get("raw_runs", []) or []),
        "measured_runs_total": measured_total,
        "measured_runs_success": measured_success,
        "measured_success_rate": (
            measured_success / measured_total if measured_total else None
        ),
        "conditions_total": len(quality_rows),
        "conditions_valid_for_client_comparison": client_valid,
        "conditions_valid_for_server_comparison": server_valid,
        "condition_success_rate_median": (
            percentile(success_rates, 0.50) if success_rates else None
        ),
        "condition_success_rate_min": success_rates[0] if success_rates else None,
        "server_total_coverage_median": (
            percentile(server_coverages, 0.50) if server_coverages else None
        ),
        "server_total_coverage_min": server_coverages[0] if server_coverages else None,
        "client_failure_reason_counts": dict(client_failures),
        "server_failure_reason_counts": dict(server_failures),
    }


def write_csv(
    path: Path,
    rows: Sequence[Mapping[str, Any]],
    fieldnames: Sequence[str] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        fieldnames = ordered_fieldnames(rows)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
        writer.writeheader()
        for row in rows:
            writer.writerow({name: csv_value(row.get(name)) for name in fieldnames})


def write_json_file(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")


def build_analysis_manifest(
    report: Mapping[str, Any],
    output_dir: Path,
    *,
    input_report_path: Path,
    bootstrap_samples: int,
    plot_formats: Sequence[str],
    skip_plots: bool,
    written_files: Sequence[str],
    figure_files: Sequence[str],
    quality_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "analysis_version": "1.0",
        "analysis_generated_at": utc_now_iso(),
        "input_report_path": str(input_report_path),
        "output_dir": str(output_dir),
        "report_generated_at": report.get("generated_at"),
        "report_seed": resolve_report_seed(report),
        "bootstrap_samples": bootstrap_samples,
        "skip_plots": skip_plots,
        "plot_formats": list(plot_formats),
        "files_written": list(written_files),
        "figure_files": list(figure_files),
        "raw_runs_total": len(report.get("raw_runs", []) or []),
        "conditions_total": len(quality_rows),
        "cli_config": report.get("cli_config"),
        "environment": report.get("environment"),
    }


def write_all_artifacts(
    report: Mapping[str, Any],
    output_dir: Path,
    *,
    input_report_path: Path,
    bootstrap_samples: int,
    plot_formats: Sequence[str],
    skip_plots: bool,
    min_condition_success_rate: float,
    min_server_coverage: float,
    max_relative_iqr: float,
    max_server_relative_iqr: float,
    min_samples: int,
    report_seed: int,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)

    context = build_analysis_context(report, bootstrap_samples, report_seed)
    quality_rows = build_condition_quality_rows_from_context(
        context,
        min_condition_success_rate=min_condition_success_rate,
        min_server_coverage=min_server_coverage,
        max_relative_iqr=max_relative_iqr,
        max_server_relative_iqr=max_server_relative_iqr,
        min_samples=min_samples,
    )
    quality_by_key = {row_to_condition_key(row): row for row in quality_rows}
    latency_rows = build_wide_summary_rows(context, quality_by_key, LATENCY_SUMMARY_METRICS)
    artifact_rows = build_wide_summary_rows(context, quality_by_key, ARTIFACT_SUMMARY_METRICS)
    stage_rows = build_stage_metrics_long_rows_from_context(context, quality_by_key)
    comparison_rows = build_comparison_metrics_rows(report, quality_rows, bootstrap_samples, report_seed)
    diagnostics_rows = build_run_diagnostics_rows(report)
    quality_checks = build_quality_checks(report, quality_rows)

    written_files = []

    condition_quality_path = output_dir / "condition_quality.csv"
    write_csv(condition_quality_path, quality_rows)
    written_files.append(condition_quality_path.name)

    latency_summary_path = output_dir / "latency_summary.csv"
    write_csv(latency_summary_path, latency_rows)
    written_files.append(latency_summary_path.name)

    artifact_summary_path = output_dir / "artifact_summary.csv"
    write_csv(artifact_summary_path, artifact_rows)
    written_files.append(artifact_summary_path.name)

    stage_metrics_path = output_dir / "stage_metrics_long.csv"
    write_csv(stage_metrics_path, stage_rows)
    written_files.append(stage_metrics_path.name)

    comparison_path = output_dir / "comparison_metrics.csv"
    write_csv(comparison_path, comparison_rows)
    written_files.append(comparison_path.name)

    run_diagnostics_path = output_dir / "run_diagnostics.csv"
    write_csv(run_diagnostics_path, diagnostics_rows)
    written_files.append(run_diagnostics_path.name)

    quality_checks_path = output_dir / "quality_checks.json"
    write_json_file(quality_checks_path, quality_checks)
    written_files.append(quality_checks_path.name)

    figure_files: list[str] = []
    if not skip_plots:
        figure_files = generate_plots(
            output_dir,
            context,
            quality_rows,
            comparison_rows,
            plot_formats,
        )

    manifest = build_analysis_manifest(
        report,
        output_dir,
        input_report_path=input_report_path,
        bootstrap_samples=bootstrap_samples,
        plot_formats=plot_formats,
        skip_plots=skip_plots,
        written_files=written_files,
        figure_files=figure_files,
        quality_rows=quality_rows,
    )
    analysis_manifest_path = output_dir / "analysis_manifest.json"
    write_json_file(analysis_manifest_path, manifest)
    written_files.insert(0, analysis_manifest_path.name)
    manifest["files_written"] = written_files
    write_json_file(analysis_manifest_path, manifest)

    return {
        "analysis_manifest": manifest,
        "quality_rows": quality_rows,
        "latency_rows": latency_rows,
        "artifact_rows": artifact_rows,
        "stage_rows": stage_rows,
        "comparison_rows": comparison_rows,
        "diagnostics_rows": diagnostics_rows,
        "quality_checks": quality_checks,
        "figure_files": figure_files,
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze a benchmark report JSON file.")
    parser.add_argument("report_path", help="Path to benchmark-report-*.json")
    parser.add_argument(
        "--output-dir",
        help="Output directory for analysis artifacts",
    )
    parser.add_argument(
        "--skip-plots",
        action="store_true",
        help="Skip figure generation",
    )
    parser.add_argument(
        "--bootstrap-samples",
        type=int,
        default=2000,
        help="Bootstrap resamples for median and ratio confidence intervals",
    )
    parser.add_argument(
        "--plot-formats",
        default="png,svg",
        help="Comma-separated plot formats, e.g. png,svg",
    )
    parser.add_argument(
        "--min-condition-success-rate",
        type=float,
        default=0.90,
        help="Minimum per-condition measured success rate",
    )
    parser.add_argument(
        "--min-server-coverage",
        type=float,
        default=1.00,
        help="Minimum per-condition server-attributed coverage",
    )
    parser.add_argument(
        "--max-relative-iqr",
        type=float,
        default=0.50,
        help="Maximum client-side IQR/median for valid comparison",
    )
    parser.add_argument(
        "--max-server-relative-iqr",
        type=float,
        default=0.50,
        help="Maximum server-side IQR/median for valid comparison",
    )
    parser.add_argument(
        "--min-samples",
        type=int,
        default=3,
        help="Minimum successful samples required per condition metric",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    report_path = Path(args.report_path).resolve()
    with report_path.open("r", encoding="utf-8") as handle:
        report = json.load(handle)

    output_dir = (
        Path(args.output_dir).resolve()
        if args.output_dir
        else report_path.parent / "analysis" / report_path.stem
    )
    plot_formats = [item.strip().lower() for item in args.plot_formats.split(",") if item.strip()]
    report_seed = resolve_report_seed(report)

    write_all_artifacts(
        report,
        output_dir,
        input_report_path=report_path,
        bootstrap_samples=args.bootstrap_samples,
        plot_formats=plot_formats,
        skip_plots=args.skip_plots,
        min_condition_success_rate=args.min_condition_success_rate,
        min_server_coverage=args.min_server_coverage,
        max_relative_iqr=args.max_relative_iqr,
        max_server_relative_iqr=args.max_server_relative_iqr,
        min_samples=args.min_samples,
        report_seed=report_seed,
    )
    return 0


def build_wide_summary_rows(
    context: AnalysisContext,
    quality_by_key: Mapping[ConditionKey, Mapping[str, Any]],
    metric_names: Sequence[str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in context.condition_keys:
        row = {
            **condition_base_dict(key),
            "measured_runs_total": quality_by_key.get(key, {}).get("measured_runs_total"),
            "measured_runs_success": quality_by_key.get(key, {}).get("measured_runs_success"),
            "measured_runs_failed": quality_by_key.get(key, {}).get("measured_runs_failed"),
            "scenario_success_rate": quality_by_key.get(key, {}).get("scenario_success_rate"),
            "verify_applicable_success_rate": quality_by_key.get(key, {}).get(
                "verify_applicable_success_rate"
            ),
            "server_total_coverage": quality_by_key.get(key, {}).get("server_total_coverage"),
            "valid_for_client_comparison": quality_by_key.get(key, {}).get(
                "valid_for_client_comparison"
            ),
            "valid_for_server_comparison": quality_by_key.get(key, {}).get(
                "valid_for_server_comparison"
            ),
        }
        for metric_name in metric_names:
            row.update(flatten_stats(metric_name, context.metric_stats(key, metric_name)))
        rows.append(row)
    rows.sort(key=condition_row_sort_key)
    return rows


def build_stage_metrics_long_rows_from_context(
    context: AnalysisContext,
    quality_by_key: Mapping[ConditionKey, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in context.condition_keys:
        quality_row = quality_by_key.get(key, {})
        measured_success = int(quality_row.get("measured_runs_success", 0) or 0)
        server_telemetry_configured = bool(quality_row.get("server_telemetry_configured", False))
        for spec in STAGE_METRIC_SPECS:
            stats = context.metric_stats(key, spec["name"])
            if spec["scope"] == "server" and not server_telemetry_configured:
                applicability = "not_configured"
            elif stats["n"] == 0:
                applicability = "not_applicable"
            else:
                applicability = "applicable"

            rows.append(
                {
                    **condition_base_dict(key),
                    "metric_name": spec["name"],
                    "metric_scope": spec["scope"],
                    "metric_group": spec["group"],
                    "metric_unit": spec["unit"],
                    "metric_applicability": applicability,
                    "n": stats["n"],
                    "coverage": (
                        stats["n"] / measured_success if measured_success and stats["n"] else None
                    ),
                    "mean": stats.get("mean"),
                    "median": stats["median"],
                    "iqr": stats["iqr"],
                    "p95": stats["p95"],
                    "p99": stats.get("p99"),
                    "min": stats.get("min"),
                    "max": stats.get("max"),
                    "ci95_low": stats["ci95_low"],
                    "ci95_high": stats["ci95_high"],
                    "cv": stats["cv"],
                    "p99_p50_ratio": stats.get("p99_p50_ratio"),
                    "valid_for_client_comparison": quality_row.get("valid_for_client_comparison"),
                    "valid_for_server_comparison": quality_row.get("valid_for_server_comparison"),
                }
            )
    rows.sort(
        key=lambda row: (
            condition_row_sort_key(row),
            row.get("metric_scope", ""),
            row.get("metric_group", ""),
            row.get("metric_name", ""),
        )
    )
    return rows


def bootstrap_median_ci(
    values: Sequence[float],
    samples: int,
    seed: int,
) -> tuple[float | None, float | None]:
    if samples <= 0 or len(values) < 2:
        return None, None
    rng = random.Random(seed)
    count = len(values)
    medians: list[float] = []
    for _ in range(samples):
        sample = sorted(values[rng.randrange(count)] for _ in range(count))
        medians.append(percentile(sample, 0.50))
    medians.sort()
    return percentile(medians, 0.025), percentile(medians, 0.975)


def coerce_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def csv_value(value: Any) -> Any:
    if isinstance(value, (list, dict)):
        return json.dumps(value, sort_keys=True)
    return value


def ordered_fieldnames(rows: Sequence[Mapping[str, Any]]) -> list[str]:
    fieldnames: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)
    return fieldnames


def flatten_stats(prefix: str, stats: Mapping[str, Any]) -> dict[str, Any]:
    return {
        f"{prefix}_n": stats.get("n"),
        f"{prefix}_mean": stats.get("mean"),
        f"{prefix}_median": stats.get("median"),
        f"{prefix}_iqr": stats.get("iqr"),
        f"{prefix}_p95": stats.get("p95"),
        f"{prefix}_p99": stats.get("p99"),
        f"{prefix}_min": stats.get("min"),
        f"{prefix}_max": stats.get("max"),
        f"{prefix}_ci95_low": stats.get("ci95_low"),
        f"{prefix}_ci95_high": stats.get("ci95_high"),
        f"{prefix}_cv": stats.get("cv"),
        f"{prefix}_p99_p50_ratio": stats.get("p99_p50_ratio"),
    }


def relative_iqr(stats: Mapping[str, Any]) -> float | None:
    median = coerce_float(stats.get("median"))
    iqr = coerce_float(stats.get("iqr"))
    if median is None or iqr is None or median <= 0.0:
        return None
    return iqr / median


def resolve_report_seed(report: Mapping[str, Any]) -> int:
    cli_config = report.get("cli_config") or {}
    configured_seed = cli_config.get("seed")
    if configured_seed is not None:
        try:
            return int(configured_seed)
        except (TypeError, ValueError):
            pass
    return 0


def stable_seed(base_seed: int, *parts: Any) -> int:
    h = hashlib.blake2b(digest_size=8)
    h.update(str(base_seed).encode("utf-8"))
    for part in parts:
        h.update(b"\0")
        h.update(str(part).encode("utf-8"))
    return int.from_bytes(h.digest(), "big")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def is_measured_phase(run: Mapping[str, Any]) -> bool:
    return str(run.get("phase", "")).lower() == "measured"


def is_scenario_success(run: Mapping[str, Any]) -> bool:
    scenario_status = run.get("scenario_status")
    if scenario_status is not None:
        return str(scenario_status).lower() == "ok"
    return bool(run.get("scenario_success"))


def verify_is_applicable(run: Mapping[str, Any]) -> bool:
    verify_outcome = run.get("verify_outcome")
    if verify_outcome is not None:
        return str(verify_outcome).lower() in {"ok", "failed"}
    return run.get("verify_overall_ok") is not None


def verify_is_ok(run: Mapping[str, Any]) -> bool:
    verify_outcome = run.get("verify_outcome")
    if verify_outcome is not None:
        return str(verify_outcome).lower() == "ok"
    return bool(run.get("verify_overall_ok"))


def has_server_telemetry_configured(run: Mapping[str, Any]) -> bool:
    status = run.get("server_telemetry_status")
    if status is not None:
        return str(status).lower() != "not_configured"
    return any(run.get(field) is not None for field in ("server_total_ms", "server_process_gateway_ms", "server_verify_gateway_ms"))


def has_available_server_telemetry(run: Mapping[str, Any]) -> bool:
    status = run.get("server_telemetry_status")
    if status is not None:
        return str(status).lower() == "available"
    return get_metric_value(run, "server_total_ms") is not None


def throughput_mib_per_s(file_size_bytes: Any, milliseconds: Any) -> float | None:
    size = coerce_float(file_size_bytes)
    duration_ms = coerce_float(milliseconds)
    if size is None or duration_ms is None or duration_ms <= 0.0:
        return None
    return (size / (1024.0 * 1024.0)) / (duration_ms / 1000.0)


def get_metric_value(run: Mapping[str, Any], field_name: str) -> float | None:
    direct = coerce_float(run.get(field_name))
    if direct is not None:
        return direct

    if field_name == "client_total_ms":
        values = [
            coerce_float(run.get("client_upload_ms")),
            coerce_float(run.get("client_process_ms")),
            coerce_float(run.get("client_verify_ms")),
        ]
        usable = [value for value in values if value is not None]
        if usable:
            return sum(usable)

    if field_name == "server_total_ms":
        values = [
            coerce_float(run.get("server_process_gateway_ms")),
            coerce_float(run.get("server_verify_gateway_ms")),
        ]
        usable = [value for value in values if value is not None]
        if usable:
            return sum(usable)

    ms_field = THROUGHPUT_MS_FIELD.get(field_name)
    if ms_field is not None:
        return throughput_mib_per_s(run.get("file_size_bytes"), run.get(ms_field))

    return None


def condition_profile(item: Mapping[str, Any]) -> str:
    return str(item.get("condition_signature_profile") or item.get("signature_profile") or "")


def condition_hash(item: Mapping[str, Any]) -> str:
    return str(item.get("condition_hash_algorithm") or item.get("hash_algorithm") or "")


def condition_bucket(item: Mapping[str, Any]) -> str:
    return str(item.get("condition_bucket") or item.get("bucket") or "")


def condition_scenario(item: Mapping[str, Any]) -> str:
    return str(item.get("benchmark_scenario") or item.get("scenario") or "")


def condition_storage_state(item: Mapping[str, Any]) -> str:
    return str(item.get("storage_state_label") or item.get("storage_state") or "")


def condition_key_from_run(run: Mapping[str, Any]) -> ConditionKey:
    return (
        condition_scenario(run),
        condition_storage_state(run),
        condition_profile(run),
        condition_hash(run),
        condition_bucket(run),
    )


def condition_key_from_summary(summary: Mapping[str, Any]) -> ConditionKey:
    return (
        condition_scenario(summary),
        condition_storage_state(summary),
        str(summary.get("signature_profile") or summary.get("condition_signature_profile") or ""),
        condition_hash(summary),
        condition_bucket(summary),
    )


def row_to_condition_key(row: Mapping[str, Any]) -> ConditionKey:
    return (
        str(row.get("benchmark_scenario") or ""),
        str(row.get("storage_state_label") or ""),
        str(row.get("signature_profile") or ""),
        str(row.get("hash_algorithm") or ""),
        str(row.get("bucket") or ""),
    )


def condition_base_dict(key: ConditionKey) -> dict[str, Any]:
    scenario, state, profile, hash_algorithm, bucket = key
    return {
        "benchmark_scenario": scenario,
        "storage_state_label": state,
        "signature_profile": profile,
        "profile_family": profile_family(profile),
        "hash_algorithm": hash_algorithm,
        "hash_family": hash_family(hash_algorithm),
        "bucket": bucket,
        "bucket_bytes": parse_bucket_to_bytes(bucket),
    }


def profile_family(profile: str) -> str:
    if profile in CLASSICAL_PROFILES:
        return "classical"
    if profile in PQC_PROFILES:
        return "pqc"
    if profile in HYBRID_PROFILES:
        return "hybrid"
    return "other"


def hash_family(hash_algorithm: str) -> str:
    if hash_algorithm == "sha256":
        return "classical"
    if hash_algorithm == "keccak256":
        return "pqc_adjacent"
    return "other"


def profile_display_name(profile: str) -> str:
    return PROFILE_DISPLAY.get(profile, profile)


def profile_color(profile: str) -> str:
    return PROFILE_COLORS.get(profile, "#5c6570")


def bucket_sort_key(label: str) -> tuple[int, str]:
    try:
        return parse_bucket_to_bytes(label), label
    except ValueError:
        return sys.maxsize, label


def condition_sort_key(key: ConditionKey) -> tuple[int, int, int, int, str]:
    scenario, state, profile, hash_algorithm, bucket = key
    return (
        SCENARIO_ORDER.index(scenario) if scenario in SCENARIO_ORDER else len(SCENARIO_ORDER),
        STORAGE_STATE_ORDER.index(state) if state in STORAGE_STATE_ORDER else len(STORAGE_STATE_ORDER),
        PROFILE_ORDER.index(profile) if profile in PROFILE_ORDER else len(PROFILE_ORDER),
        HASH_ORDER.index(hash_algorithm) if hash_algorithm in HASH_ORDER else len(HASH_ORDER),
        bucket_sort_key(bucket)[0],
    )


def condition_row_sort_key(row: Mapping[str, Any]) -> tuple[int, int, int, int, str]:
    return condition_sort_key(row_to_condition_key(row))


def scenario_display_name(scenario: str) -> str:
    mapping = {
        "workflow": "Workflow",
        "sign_only": "Sign Only",
        "verify_manifest": "Verify Manifest",
        "verify_stored": "Verify Stored",
        "verify_uploaded": "Verify Uploaded",
        "verify_full": "Verify Full",
    }
    return mapping.get(scenario, scenario.replace("_", " ").title())


def sign_stage_ms_for_run(run: Mapping[str, Any]) -> float | None:
    profile = condition_profile(run)
    fields = PROFILE_SIGN_FIELDS.get(profile, [])
    values = [coerce_float(run.get(field)) for field in fields]
    usable = [value for value in values if value is not None]
    if usable:
        return sum(usable)
    return None


def verify_stage_ms_for_run(run: Mapping[str, Any]) -> float | None:
    profile = condition_profile(run)
    fields = PROFILE_VERIFY_FIELDS.get(profile, [])
    values = [coerce_float(run.get(field)) for field in fields]
    usable = [value for value in values if value is not None]
    if usable:
        return sum(usable)
    signature_verify = coerce_float(run.get("server_signature_verify_ms"))
    if signature_verify is not None:
        return signature_verify
    return None


def generate_plots(
    output_dir: Path,
    context: AnalysisContext,
    quality_rows: Sequence[Mapping[str, Any]],
    comparison_rows: Sequence[Mapping[str, Any]],
    plot_formats: Sequence[str],
) -> list[str]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return []

    setup_matplotlib_style(plt)

    figures: list[str] = []
    plot_jobs: list[tuple[str, Callable[..., Any], tuple[Any, ...]]] = [
        ("fig_sign_latency_by_profile", plot_sign_latency_by_profile, (context,)),
        ("fig_verify_latency_by_profile", plot_verify_latency_by_profile, (context,)),
        ("fig_sign_latency_vs_payload", plot_sign_latency_vs_payload, (context,)),
        ("fig_signature_size_comparison", plot_signature_size_comparison, (context,)),
        ("fig_signature_overhead_pct", plot_signature_overhead_pct, (context,)),
        ("fig_hash_latency_by_algorithm", plot_hash_latency_by_algorithm, (context,)),
        ("fig_hash_throughput_vs_payload", plot_hash_throughput_vs_payload, (context,)),
        ("fig_total_latency_ci", plot_total_latency_ci, (context,)),
        ("fig_server_ratio_ci", plot_server_ratio_ci, (comparison_rows,)),
        ("fig_server_stage_breakdown", plot_server_stage_breakdown, (context,)),
        ("fig_e2e_throughput_comparison", plot_e2e_throughput_comparison, (context,)),
        ("fig_overhead_ratio_heatmap", plot_overhead_ratio_heatmap, (comparison_rows,)),
        ("fig_storage_amplification", plot_storage_amplification, (context,)),
        ("fig_scenario_comparison", plot_scenario_comparison, (context,)),
        ("fig_quality_heatmap", plot_quality_heatmap, (quality_rows,)),
        ("fig_cold_vs_warm", plot_cold_vs_warm, (context,)),
        ("fig_warmup_trajectory", plot_warmup_trajectory, (context,)),
        ("fig_cv_distribution", plot_cv_distribution, (quality_rows,)),
    ]

    for base_name, plotter, args in plot_jobs:
        try:
            figure = plotter(plt, *args)
        except Exception as exc:  # pragma: no cover - defensive plot fallback
            figure = fallback_figure(plt, f"{base_name}\n{exc}")
        save_figure(figure, output_dir / base_name, plot_formats)
        plt.close(figure)
        for fmt in plot_formats:
            figures.append(f"{base_name}.{fmt}")

    return figures


def setup_matplotlib_style(plt: Any) -> None:
    plt.rcParams.update(
        {
            "figure.dpi": 160,
            "savefig.dpi": 160,
            "font.size": 10,
            "axes.titlesize": 13,
            "axes.labelsize": 11,
            "axes.grid": True,
            "grid.alpha": 0.18,
            "grid.color": "#6d7480",
            "axes.facecolor": "#fbfaf7",
            "figure.facecolor": "white",
            "axes.edgecolor": "#30353a",
            "axes.titleweight": "bold",
            "legend.frameon": False,
        }
    )


def save_figure(figure: Any, base_path: Path, plot_formats: Sequence[str]) -> None:
    base_path.parent.mkdir(parents=True, exist_ok=True)
    for fmt in plot_formats:
        figure.savefig(base_path.with_suffix(f".{fmt}"), bbox_inches="tight")


def fallback_figure(plt: Any, message: str) -> Any:
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.axis("off")
    ax.text(0.5, 0.5, message, ha="center", va="center", fontsize=12)
    return fig


def no_data_axis(ax: Any, title: str, subtitle: str | None = None) -> None:
    ax.axis("off")
    text = title if subtitle is None else f"{title}\n{subtitle}"
    ax.text(0.5, 0.5, text, ha="center", va="center", fontsize=12)


def preferred_storage_state(context: AnalysisContext, scenario: str | None = None) -> str | None:
    available = {
        key[1]
        for key in context.condition_keys
        if scenario is None or key[0] == scenario
    }
    if "warm" in available:
        return "warm"
    if "cold" in available:
        return "cold"
    return sorted(available)[0] if available else None


def representative_bucket_for_context(
    context: AnalysisContext,
    *,
    scenario: str | None = None,
    state: str | None = None,
    hash_algorithm: str | None = None,
) -> str | None:
    buckets = sorted(
        {
            key[4]
            for key in context.condition_keys
            if (scenario is None or key[0] == scenario)
            and (state is None or key[1] == state)
            and (hash_algorithm is None or key[3] == hash_algorithm)
        },
        key=bucket_sort_key,
    )
    for preferred in ("1MB", "10MB", "100KB", "10KB", "50MB"):
        if preferred in buckets:
            return preferred
    if not buckets:
        return None
    return buckets[len(buckets) // 2]


def available_profiles(
    context: AnalysisContext,
    *,
    scenario: str | None = None,
    state: str | None = None,
    hash_algorithm: str | None = None,
    bucket: str | None = None,
) -> list[str]:
    profiles = {
        key[2]
        for key in context.condition_keys
        if (scenario is None or key[0] == scenario)
        and (state is None or key[1] == state)
        and (hash_algorithm is None or key[3] == hash_algorithm)
        and (bucket is None or key[4] == bucket)
    }
    return sorted(profiles, key=lambda profile: PROFILE_ORDER.index(profile) if profile in PROFILE_ORDER else len(PROFILE_ORDER))


def available_buckets(
    context: AnalysisContext,
    *,
    scenario: str | None = None,
    state: str | None = None,
    hash_algorithm: str | None = None,
) -> list[str]:
    buckets = {
        key[4]
        for key in context.condition_keys
        if (scenario is None or key[0] == scenario)
        and (state is None or key[1] == state)
        and (hash_algorithm is None or key[3] == hash_algorithm)
    }
    return sorted(buckets, key=bucket_sort_key)


def summary_for_custom_metric(
    context: AnalysisContext,
    key: ConditionKey,
    name: str,
    extractor: Callable[[Mapping[str, Any]], float | None],
) -> dict[str, Any]:
    values = [value for run in context.success_by_condition.get(key, []) if (value := extractor(run)) is not None]
    return compute_summary_stats(values, context.bootstrap_samples, stable_seed(context.seed, *key, name))


def plot_sign_latency_by_profile(plt: Any, context: AnalysisContext) -> Any:
    scenario = "sign_only" if any(key[0] == "sign_only" for key in context.condition_keys) else "workflow"
    state = preferred_storage_state(context, scenario) or preferred_storage_state(context)
    hash_algorithm = "sha256" if any(key[3] == "sha256" for key in context.condition_keys) else next((key[3] for key in context.condition_keys), None)
    bucket = representative_bucket_for_context(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm)
    fig, ax = plt.subplots(figsize=(11, 5.5))
    profiles = available_profiles(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm, bucket=bucket)
    if not profiles or bucket is None or hash_algorithm is None or state is None:
        no_data_axis(ax, "No signing-stage data available")
        return fig

    medians = []
    lows = []
    highs = []
    labels = []
    colors = []
    for profile in profiles:
        key = (scenario, state, profile, hash_algorithm, bucket)
        stats = summary_for_custom_metric(context, key, "sign_stage_ms", sign_stage_ms_for_run)
        medians.append(stats["median"] or 0.0)
        lows.append((stats["median"] or 0.0) - (stats["ci95_low"] if stats["ci95_low"] is not None else stats["median"] or 0.0))
        highs.append((stats["ci95_high"] if stats["ci95_high"] is not None else stats["median"] or 0.0) - (stats["median"] or 0.0))
        labels.append(profile_display_name(profile))
        colors.append(profile_color(profile))

    x_positions = list(range(len(profiles)))
    ax.bar(x_positions, medians, color=colors, edgecolor="#2c2c2c")
    ax.errorbar(x_positions, medians, yerr=[lows, highs], fmt="none", ecolor="#222222", capsize=3, linewidth=1)
    ax.set_xticks(x_positions)
    ax.set_xticklabels(labels, rotation=25, ha="right")
    ax.set_ylabel("Signing latency (ms)")
    ax.set_title("Signature Stage: Signing Latency by Profile")
    ax.text(0.01, 1.02, f"{scenario_display_name(scenario)} | {hash_algorithm} | {bucket} | {state}", transform=ax.transAxes, fontsize=9, color="#4a4f55")
    return fig


def plot_verify_latency_by_profile(plt: Any, context: AnalysisContext) -> Any:
    scenario = "workflow" if any(key[0] == "workflow" for key in context.condition_keys) else "verify_full"
    state = preferred_storage_state(context, scenario) or preferred_storage_state(context)
    hash_algorithm = "sha256" if any(key[3] == "sha256" for key in context.condition_keys) else next((key[3] for key in context.condition_keys), None)
    bucket = representative_bucket_for_context(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm)
    fig, ax = plt.subplots(figsize=(11, 5.5))
    profiles = available_profiles(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm, bucket=bucket)
    if not profiles or bucket is None or hash_algorithm is None or state is None:
        no_data_axis(ax, "No verification-stage data available")
        return fig

    medians = []
    lows = []
    highs = []
    labels = []
    colors = []
    for profile in profiles:
        key = (scenario, state, profile, hash_algorithm, bucket)
        stats = summary_for_custom_metric(context, key, "verify_stage_ms", verify_stage_ms_for_run)
        medians.append(stats["median"] or 0.0)
        lows.append((stats["median"] or 0.0) - (stats["ci95_low"] if stats["ci95_low"] is not None else stats["median"] or 0.0))
        highs.append((stats["ci95_high"] if stats["ci95_high"] is not None else stats["median"] or 0.0) - (stats["median"] or 0.0))
        labels.append(profile_display_name(profile))
        colors.append(profile_color(profile))

    x_positions = list(range(len(profiles)))
    ax.bar(x_positions, medians, color=colors, edgecolor="#2c2c2c")
    ax.errorbar(x_positions, medians, yerr=[lows, highs], fmt="none", ecolor="#222222", capsize=3, linewidth=1)
    ax.set_xticks(x_positions)
    ax.set_xticklabels(labels, rotation=25, ha="right")
    ax.set_ylabel("Verification latency (ms)")
    ax.set_title("Signature Stage: Verification Latency by Profile")
    ax.text(0.01, 1.02, f"{scenario_display_name(scenario)} | {hash_algorithm} | {bucket} | {state}", transform=ax.transAxes, fontsize=9, color="#4a4f55")
    return fig


def plot_sign_latency_vs_payload(plt: Any, context: AnalysisContext) -> Any:
    scenario = "sign_only" if any(key[0] == "sign_only" for key in context.condition_keys) else "workflow"
    state = preferred_storage_state(context, scenario) or preferred_storage_state(context)
    hash_algorithm = "sha256" if any(key[3] == "sha256" for key in context.condition_keys) else next((key[3] for key in context.condition_keys), None)
    fig, ax = plt.subplots(figsize=(11.5, 6))
    buckets = available_buckets(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm)
    profiles = available_profiles(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm)
    if not buckets or not profiles or state is None or hash_algorithm is None:
        no_data_axis(ax, "No signing-stage payload trend data available")
        return fig

    x_positions = list(range(len(buckets)))
    for profile in profiles:
        medians = []
        ci_low = []
        ci_high = []
        for bucket in buckets:
            key = (scenario, state, profile, hash_algorithm, bucket)
            stats = summary_for_custom_metric(context, key, "sign_stage_ms", sign_stage_ms_for_run)
            medians.append(stats["median"])
            ci_low.append(stats["ci95_low"] if stats["ci95_low"] is not None else stats["median"])
            ci_high.append(stats["ci95_high"] if stats["ci95_high"] is not None else stats["median"])
        if all(value is None for value in medians):
            continue
        ax.plot(x_positions, medians, marker="o", linewidth=2, color=profile_color(profile), label=profile_display_name(profile))
        ax.fill_between(x_positions, ci_low, ci_high, color=profile_color(profile), alpha=0.10)

    ax.set_xticks(x_positions)
    ax.set_xticklabels(buckets)
    ax.set_ylabel("Signing latency (ms)")
    ax.set_title("Signature Stage: Signing Latency vs Payload")
    ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1.0))
    return fig


def plot_signature_size_comparison(plt: Any, context: AnalysisContext) -> Any:
    fig, ax = plt.subplots(figsize=(10, 5.5))
    profile_values: list[tuple[str, float]] = []
    for profile in sorted({key[2] for key in context.condition_keys}, key=lambda item: PROFILE_ORDER.index(item) if item in PROFILE_ORDER else len(PROFILE_ORDER)):
        values: list[float] = []
        for key in context.condition_keys:
            if key[2] != profile:
                continue
            values.extend(context.metric_values(key, "total_signature_bytes"))
        if values:
            values.sort()
            profile_values.append((profile, percentile(values, 0.50)))

    if not profile_values:
        no_data_axis(ax, "No signature size data available")
        return fig

    profile_values.sort(key=lambda item: item[1])
    labels = [profile_display_name(profile) for profile, _ in profile_values]
    values = [value for _, value in profile_values]
    colors = [profile_color(profile) for profile, _ in profile_values]
    y_positions = list(range(len(labels)))
    ax.barh(y_positions, values, color=colors, edgecolor="#2c2c2c")
    ax.set_yticks(y_positions)
    ax.set_yticklabels(labels)
    ax.set_xscale("log")
    ax.set_xlabel("Signature bytes (log scale)")
    ax.set_title("Signature Stage: Absolute Signature Size")
    return fig


def plot_signature_overhead_pct(plt: Any, context: AnalysisContext) -> Any:
    scenario = "workflow" if any(key[0] == "workflow" for key in context.condition_keys) else next((key[0] for key in context.condition_keys), None)
    state = preferred_storage_state(context, scenario)
    hash_algorithm = "sha256" if any(key[3] == "sha256" for key in context.condition_keys) else next((key[3] for key in context.condition_keys), None)
    fig, ax = plt.subplots(figsize=(12, 6))
    buckets = available_buckets(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm)
    profiles = available_profiles(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm)
    if not buckets or not profiles or scenario is None or state is None or hash_algorithm is None:
        no_data_axis(ax, "No signature overhead data available")
        return fig

    width = 0.8 / max(len(profiles), 1)
    x_positions = list(range(len(buckets)))
    for profile_index, profile in enumerate(profiles):
        offsets = [position - 0.4 + (profile_index + 0.5) * width for position in x_positions]
        medians = []
        for bucket in buckets:
            key = (scenario, state, profile, hash_algorithm, bucket)
            medians.append(context.metric_stats(key, "signature_overhead_pct")["median"] or 0.0)
        ax.bar(offsets, medians, width=width, color=profile_color(profile), label=profile_display_name(profile))

    ax.set_xticks(x_positions)
    ax.set_xticklabels(buckets)
    ax.set_ylabel("Signature overhead (% of payload)")
    ax.set_title("Signature Stage: Signature Overhead by Bucket")
    ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1.0))
    return fig


def plot_hash_latency_by_algorithm(plt: Any, context: AnalysisContext) -> Any:
    scenario = "sign_only" if any(key[0] == "sign_only" for key in context.condition_keys) else "workflow"
    state = preferred_storage_state(context, scenario) or preferred_storage_state(context)
    profile = "rsa_pss" if any(key[2] == "rsa_pss" for key in context.condition_keys) else next((key[2] for key in context.condition_keys), None)
    fig, ax = plt.subplots(figsize=(10.5, 5.5))
    buckets = available_buckets(context, scenario=scenario, state=state)
    if not buckets or state is None or profile is None:
        no_data_axis(ax, "No hash latency data available")
        return fig

    algorithms = [algorithm for algorithm in HASH_ORDER if any(key[3] == algorithm for key in context.condition_keys)]
    width = 0.8 / max(len(algorithms), 1)
    x_positions = list(range(len(buckets)))
    colors = {"sha256": "#315c7c", "keccak256": "#c26a2d"}
    for algorithm_index, algorithm in enumerate(algorithms):
        offsets = [position - 0.4 + (algorithm_index + 0.5) * width for position in x_positions]
        medians = []
        lows = []
        highs = []
        for bucket in buckets:
            key = (scenario, state, profile, algorithm, bucket)
            stats = context.metric_stats(key, "server_hash_ms")
            medians.append(stats["median"] or 0.0)
            lows.append((stats["median"] or 0.0) - (stats["ci95_low"] if stats["ci95_low"] is not None else stats["median"] or 0.0))
            highs.append((stats["ci95_high"] if stats["ci95_high"] is not None else stats["median"] or 0.0) - (stats["median"] or 0.0))
        ax.bar(offsets, medians, width=width, color=colors.get(algorithm, "#777777"), edgecolor="#2c2c2c", label=algorithm)
        ax.errorbar(offsets, medians, yerr=[lows, highs], fmt="none", ecolor="#222222", capsize=3)

    ax.set_xticks(x_positions)
    ax.set_xticklabels(buckets)
    ax.set_ylabel("Hash latency (ms)")
    ax.set_title("Hash Stage: Hash Latency by Algorithm")
    ax.legend()
    return fig


def plot_hash_throughput_vs_payload(plt: Any, context: AnalysisContext) -> Any:
    scenario = "sign_only" if any(key[0] == "sign_only" for key in context.condition_keys) else "workflow"
    state = preferred_storage_state(context, scenario) or preferred_storage_state(context)
    profile = "rsa_pss" if any(key[2] == "rsa_pss" for key in context.condition_keys) else next((key[2] for key in context.condition_keys), None)
    fig, ax = plt.subplots(figsize=(10.5, 5.5))
    buckets = available_buckets(context, scenario=scenario, state=state)
    if not buckets or state is None or profile is None:
        no_data_axis(ax, "No hash throughput data available")
        return fig

    x_positions = list(range(len(buckets)))
    for algorithm in [algorithm for algorithm in HASH_ORDER if any(key[3] == algorithm for key in context.condition_keys)]:
        medians = []
        ci_low = []
        ci_high = []
        for bucket in buckets:
            key = (scenario, state, profile, algorithm, bucket)
            stats = context.metric_stats(key, "server_hash_mib_s")
            medians.append(stats["median"])
            ci_low.append(stats["ci95_low"] if stats["ci95_low"] is not None else stats["median"])
            ci_high.append(stats["ci95_high"] if stats["ci95_high"] is not None else stats["median"])
        ax.plot(x_positions, medians, marker="o", linewidth=2, label=algorithm)
        ax.fill_between(x_positions, ci_low, ci_high, alpha=0.10)

    ax.set_xticks(x_positions)
    ax.set_xticklabels(buckets)
    ax.set_ylabel("Hash throughput (MiB/s)")
    ax.set_title("Hash Stage: Hash Throughput vs Payload")
    ax.legend()
    return fig


def plot_total_latency_ci(plt: Any, context: AnalysisContext) -> Any:
    scenario = "workflow" if any(key[0] == "workflow" for key in context.condition_keys) else next((key[0] for key in context.condition_keys), None)
    state = preferred_storage_state(context, scenario) or preferred_storage_state(context)
    hash_algorithm = "sha256" if any(key[3] == "sha256" for key in context.condition_keys) else next((key[3] for key in context.condition_keys), None)
    fig, ax = plt.subplots(figsize=(13, 6.5))
    buckets = available_buckets(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm)
    profiles = available_profiles(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm)
    if not buckets or not profiles or scenario is None or state is None or hash_algorithm is None:
        no_data_axis(ax, "No end-to-end latency data available")
        return fig

    width = 0.82 / max(len(profiles), 1)
    x_positions = list(range(len(buckets)))
    for profile_index, profile in enumerate(profiles):
        offsets = [position - 0.41 + (profile_index + 0.5) * width for position in x_positions]
        medians = []
        lows = []
        highs = []
        for bucket in buckets:
            key = (scenario, state, profile, hash_algorithm, bucket)
            stats = context.metric_stats(key, "client_total_ms")
            medians.append(stats["median"] or 0.0)
            lows.append((stats["median"] or 0.0) - (stats["ci95_low"] if stats["ci95_low"] is not None else stats["median"] or 0.0))
            highs.append((stats["ci95_high"] if stats["ci95_high"] is not None else stats["median"] or 0.0) - (stats["median"] or 0.0))
        ax.bar(offsets, medians, width=width, color=profile_color(profile), edgecolor="#2c2c2c", label=profile_display_name(profile))
        ax.errorbar(offsets, medians, yerr=[lows, highs], fmt="none", ecolor="#222222", capsize=2.5)

    ax.set_xticks(x_positions)
    ax.set_xticklabels(buckets)
    ax.set_ylabel("Client total latency (ms)")
    ax.set_title("End-to-End Total Latency by Profile and Payload")
    ax.text(0.01, 1.02, f"{scenario_display_name(scenario)} | {hash_algorithm} | {state}", transform=ax.transAxes, fontsize=9, color="#4a4f55")
    ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1.0))
    return fig


def plot_server_ratio_ci(plt: Any, comparison_rows: Sequence[Mapping[str, Any]]) -> Any:
    fig, ax = plt.subplots(figsize=(10.5, 6))
    rows = [
        row
        for row in comparison_rows
        if row.get("metric_name") == "server_total_ms"
        and row.get("benchmark_scenario") == "workflow"
        and row.get("hash_algorithm") == "sha256"
    ]
    if rows:
        preferred_state = "warm" if any(row.get("storage_state_label") == "warm" for row in rows) else rows[0].get("storage_state_label")
        rows = [row for row in rows if row.get("storage_state_label") == preferred_state]
        preferred_bucket = representative_bucket_from_rows(rows)
        rows = [row for row in rows if row.get("bucket") == preferred_bucket]
    rows = sorted(rows, key=lambda row: PROFILE_ORDER.index(row["signature_profile"]) if row["signature_profile"] in PROFILE_ORDER else len(PROFILE_ORDER))
    if not rows:
        no_data_axis(ax, "No server comparison ratio data available")
        return fig

    y_positions = list(range(len(rows)))
    ratios = [coerce_float(row.get("ratio")) or 0.0 for row in rows]
    xerr_low = []
    xerr_high = []
    labels = []
    colors = []
    for row in rows:
        ratio = coerce_float(row.get("ratio")) or 0.0
        low = coerce_float(row.get("ci95_low"))
        high = coerce_float(row.get("ci95_high"))
        xerr_low.append(ratio - low if low is not None else 0.0)
        xerr_high.append(high - ratio if high is not None else 0.0)
        labels.append(profile_display_name(str(row.get("signature_profile"))))
        colors.append(profile_color(str(row.get("signature_profile"))))

    ax.axvline(1.0, color="#444444", linestyle="--", linewidth=1)
    ax.errorbar(ratios, y_positions, xerr=[xerr_low, xerr_high], fmt="o", color="#222222", ecolor="#555555", capsize=3)
    for y_position, ratio, color in zip(y_positions, ratios, colors):
        ax.scatter([ratio], [y_position], s=50, color=color, zorder=3)
    ax.set_yticks(y_positions)
    ax.set_yticklabels(labels)
    ax.set_xlabel("Ratio vs RSA-PSS")
    ax.set_title("End-to-End Server Ratio vs RSA-PSS")
    return fig


def plot_server_stage_breakdown(plt: Any, context: AnalysisContext) -> Any:
    scenario = "sign_only" if any(key[0] == "sign_only" for key in context.condition_keys) else "workflow"
    state = preferred_storage_state(context, scenario) or preferred_storage_state(context)
    hash_algorithm = "sha256" if any(key[3] == "sha256" for key in context.condition_keys) else next((key[3] for key in context.condition_keys), None)
    bucket = representative_bucket_for_context(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm)
    fig, ax = plt.subplots(figsize=(11.5, 6))
    profiles = available_profiles(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm, bucket=bucket)
    if not profiles or scenario is None or state is None or hash_algorithm is None or bucket is None:
        no_data_axis(ax, "No stage breakdown data available")
        return fig

    components = [
        ("Hash", lambda key: context.metric_stats(key, "server_hash_ms")["median"] or 0.0, "#315c7c"),
        ("Sign", lambda key: summary_for_custom_metric(context, key, "sign_stage_ms", sign_stage_ms_for_run)["median"] or 0.0, "#c26a2d"),
        ("Canonicalize", lambda key: context.metric_stats(key, "server_manifest_canonicalize_ms")["median"] or 0.0, "#5c8e7d"),
        ("DB", lambda key: context.metric_stats(key, "server_db_persist_ms")["median"] or 0.0, "#857b4b"),
        ("Object Store", lambda key: (context.metric_stats(key, "server_object_exists_check_ms")["median"] or 0.0) + (context.metric_stats(key, "server_object_store_ms")["median"] or 0.0), "#8f3b2f"),
    ]

    y_positions = list(range(len(profiles)))
    left = [0.0 for _ in profiles]
    for label, getter, color in components:
        widths = []
        for profile in profiles:
            key = (scenario, state, profile, hash_algorithm, bucket)
            widths.append(getter(key))
        ax.barh(y_positions, widths, left=left, color=color, edgecolor="white", label=label)
        left = [current_left + width for current_left, width in zip(left, widths)]

    ax.set_yticks(y_positions)
    ax.set_yticklabels([profile_display_name(profile) for profile in profiles])
    ax.set_xlabel("Server-attributed latency (ms)")
    ax.set_title("End-to-End Server Stage Breakdown")
    ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1.0))
    return fig


def plot_e2e_throughput_comparison(plt: Any, context: AnalysisContext) -> Any:
    scenario = "workflow" if any(key[0] == "workflow" for key in context.condition_keys) else next((key[0] for key in context.condition_keys), None)
    state = preferred_storage_state(context, scenario) or preferred_storage_state(context)
    hash_algorithm = "sha256" if any(key[3] == "sha256" for key in context.condition_keys) else next((key[3] for key in context.condition_keys), None)
    fig, ax = plt.subplots(figsize=(13, 6.5))
    buckets = available_buckets(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm)
    profiles = available_profiles(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm)
    if not buckets or not profiles or scenario is None or state is None or hash_algorithm is None:
        no_data_axis(ax, "No throughput data available")
        return fig

    width = 0.82 / max(len(profiles), 1)
    x_positions = list(range(len(buckets)))
    for profile_index, profile in enumerate(profiles):
        offsets = [position - 0.41 + (profile_index + 0.5) * width for position in x_positions]
        medians = []
        for bucket in buckets:
            key = (scenario, state, profile, hash_algorithm, bucket)
            medians.append(context.metric_stats(key, "server_total_mib_s")["median"] or 0.0)
        ax.bar(offsets, medians, width=width, color=profile_color(profile), edgecolor="#2c2c2c", label=profile_display_name(profile))

    ax.set_xticks(x_positions)
    ax.set_xticklabels(buckets)
    ax.set_ylabel("Server throughput (MiB/s)")
    ax.set_title("End-to-End Throughput by Profile and Payload")
    ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1.0))
    return fig


def plot_overhead_ratio_heatmap(plt: Any, comparison_rows: Sequence[Mapping[str, Any]]) -> Any:
    fig, ax = plt.subplots(figsize=(9, 6))
    rows = [
        row
        for row in comparison_rows
        if row.get("metric_name") == "server_total_ms"
        and row.get("benchmark_scenario") == "workflow"
        and row.get("hash_algorithm") == "sha256"
    ]
    if rows:
        preferred_state = "warm" if any(row.get("storage_state_label") == "warm" for row in rows) else rows[0].get("storage_state_label")
        rows = [row for row in rows if row.get("storage_state_label") == preferred_state]
    if not rows:
        no_data_axis(ax, "No ratio heatmap data available")
        return fig

    profiles = sorted({str(row.get("signature_profile")) for row in rows}, key=lambda profile: PROFILE_ORDER.index(profile) if profile in PROFILE_ORDER else len(PROFILE_ORDER))
    buckets = sorted({str(row.get("bucket")) for row in rows}, key=bucket_sort_key)
    matrix = []
    for profile in profiles:
        row_values = []
        for bucket in buckets:
            match = next((item for item in rows if item.get("signature_profile") == profile and item.get("bucket") == bucket), None)
            row_values.append(coerce_float(match.get("ratio")) if match else math.nan)
        matrix.append(row_values)

    image = ax.imshow(matrix, cmap="RdYlGn_r", aspect="auto")
    ax.set_xticks(range(len(buckets)))
    ax.set_xticklabels(buckets)
    ax.set_yticks(range(len(profiles)))
    ax.set_yticklabels([profile_display_name(profile) for profile in profiles])
    ax.set_title("Overhead Ratio vs RSA-PSS")
    for y_index, row_values in enumerate(matrix):
        for x_index, value in enumerate(row_values):
            if not math.isnan(value):
                ax.text(x_index, y_index, f"{value:.2f}", ha="center", va="center", fontsize=8)
    fig.colorbar(image, ax=ax, label="Ratio")
    return fig


def plot_storage_amplification(plt: Any, context: AnalysisContext) -> Any:
    scenario = "workflow" if any(key[0] == "workflow" for key in context.condition_keys) else next((key[0] for key in context.condition_keys), None)
    state = preferred_storage_state(context, scenario) or preferred_storage_state(context)
    hash_algorithm = "sha256" if any(key[3] == "sha256" for key in context.condition_keys) else next((key[3] for key in context.condition_keys), None)
    fig, ax = plt.subplots(figsize=(11, 5.5))
    buckets = available_buckets(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm)
    profiles = available_profiles(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm)
    if not buckets or not profiles or scenario is None or state is None or hash_algorithm is None:
        no_data_axis(ax, "No storage amplification data available")
        return fig

    x_positions = list(range(len(buckets)))
    for profile in profiles:
        medians = []
        for bucket in buckets:
            key = (scenario, state, profile, hash_algorithm, bucket)
            medians.append(context.metric_stats(key, "storage_amplification")["median"])
        ax.plot(x_positions, medians, marker="o", linewidth=2, color=profile_color(profile), label=profile_display_name(profile))

    ax.set_xticks(x_positions)
    ax.set_xticklabels(buckets)
    ax.set_ylabel("Storage amplification")
    ax.set_title("Storage Amplification vs Payload")
    ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1.0))
    return fig


def plot_scenario_comparison(plt: Any, context: AnalysisContext) -> Any:
    state = preferred_storage_state(context) or next((key[1] for key in context.condition_keys), None)
    hash_algorithm = "sha256" if any(key[3] == "sha256" for key in context.condition_keys) else next((key[3] for key in context.condition_keys), None)
    bucket = representative_bucket_for_context(context, state=state, hash_algorithm=hash_algorithm)
    scenarios = [scenario for scenario in SCENARIO_ORDER if any(key[0] == scenario for key in context.condition_keys)]
    profiles = available_profiles(context, state=state, hash_algorithm=hash_algorithm, bucket=bucket)
    fig, ax = plt.subplots(figsize=(13, 6))
    if not scenarios or not profiles or state is None or hash_algorithm is None or bucket is None:
        no_data_axis(ax, "No scenario comparison data available")
        return fig

    width = 0.82 / max(len(profiles), 1)
    x_positions = list(range(len(scenarios)))
    for profile_index, profile in enumerate(profiles):
        offsets = [position - 0.41 + (profile_index + 0.5) * width for position in x_positions]
        medians = []
        for scenario in scenarios:
            key = (scenario, state, profile, hash_algorithm, bucket)
            medians.append(context.metric_stats(key, "server_total_ms")["median"] or 0.0)
        ax.bar(offsets, medians, width=width, color=profile_color(profile), edgecolor="#2c2c2c", label=profile_display_name(profile))

    ax.set_xticks(x_positions)
    ax.set_xticklabels([scenario_display_name(scenario) for scenario in scenarios], rotation=20, ha="right")
    ax.set_ylabel("Server total latency (ms)")
    ax.set_title("Scenario Comparison at Representative Payload")
    ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1.0))
    return fig


def plot_quality_heatmap(plt: Any, quality_rows: Sequence[Mapping[str, Any]]) -> Any:
    fig_height = max(5.0, min(18.0, 1.6 + 0.22 * len(quality_rows)))
    fig, ax = plt.subplots(figsize=(9.5, fig_height))
    if not quality_rows:
        no_data_axis(ax, "No quality rows available")
        return fig

    rows = sorted(quality_rows, key=condition_row_sort_key)
    matrix = [
        [
            1.0 if row.get("valid_for_client_comparison") else 0.0,
            1.0 if row.get("valid_for_server_comparison") else 0.0,
        ]
        for row in rows
    ]
    image = ax.imshow(matrix, cmap="RdYlGn", aspect="auto", vmin=0.0, vmax=1.0)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Client", "Server"])
    labels = [
        f"{scenario_display_name(str(row.get('benchmark_scenario')))} | {row.get('storage_state_label')} | {row.get('hash_algorithm')} | {row.get('bucket')} | {profile_display_name(str(row.get('signature_profile')))}"
        for row in rows
    ]
    if len(labels) > 30:
        stride = max(1, len(labels) // 20)
        shown = [label if index % stride == 0 else "" for index, label in enumerate(labels)]
    else:
        shown = labels
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels(shown, fontsize=8)
    ax.set_title("Condition Validity Matrix")
    fig.colorbar(image, ax=ax, label="Valid")
    return fig


def plot_cold_vs_warm(plt: Any, context: AnalysisContext) -> Any:
    fig, ax = plt.subplots(figsize=(10.5, 5.5))
    if not any(key[1] == "cold" for key in context.condition_keys) or not any(key[1] == "warm" for key in context.condition_keys):
        no_data_axis(ax, "Only one storage state available")
        return fig

    scenario = "workflow" if any(key[0] == "workflow" for key in context.condition_keys) else next((key[0] for key in context.condition_keys), None)
    hash_algorithm = "sha256" if any(key[3] == "sha256" for key in context.condition_keys) else next((key[3] for key in context.condition_keys), None)
    bucket = representative_bucket_for_context(context, scenario=scenario, hash_algorithm=hash_algorithm)
    profiles = available_profiles(context, scenario=scenario, hash_algorithm=hash_algorithm, bucket=bucket)
    if not profiles or scenario is None or hash_algorithm is None or bucket is None:
        no_data_axis(ax, "No cold vs warm comparison data available")
        return fig

    x_positions = list(range(len(profiles)))
    cold_values = []
    warm_values = []
    for profile in profiles:
        cold_key = (scenario, "cold", profile, hash_algorithm, bucket)
        warm_key = (scenario, "warm", profile, hash_algorithm, bucket)
        cold_values.append(context.metric_stats(cold_key, "server_total_ms")["median"])
        warm_values.append(context.metric_stats(warm_key, "server_total_ms")["median"])

    ax.plot(x_positions, cold_values, marker="o", color="#315c7c", label="Cold")
    ax.plot(x_positions, warm_values, marker="o", color="#c26a2d", label="Warm")
    for x_position, cold_value, warm_value in zip(x_positions, cold_values, warm_values):
        if cold_value is not None and warm_value is not None:
            ax.plot([x_position, x_position], [cold_value, warm_value], color="#9a9a9a", linewidth=1)
    ax.set_xticks(x_positions)
    ax.set_xticklabels([profile_display_name(profile) for profile in profiles], rotation=20, ha="right")
    ax.set_ylabel("Server total latency (ms)")
    ax.set_title("Cold vs Warm Server Latency")
    ax.legend()
    return fig


def plot_warmup_trajectory(plt: Any, context: AnalysisContext) -> Any:
    fig, ax = plt.subplots(figsize=(11, 5.5))
    scenario = "workflow" if any(key[0] == "workflow" for key in context.condition_keys) else next((key[0] for key in context.condition_keys), None)
    state = preferred_storage_state(context, scenario) or preferred_storage_state(context)
    hash_algorithm = "sha256" if any(key[3] == "sha256" for key in context.condition_keys) else next((key[3] for key in context.condition_keys), None)
    bucket = representative_bucket_for_context(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm)
    profiles = available_profiles(context, scenario=scenario, state=state, hash_algorithm=hash_algorithm, bucket=bucket)
    if not profiles or scenario is None or state is None or hash_algorithm is None or bucket is None:
        no_data_axis(ax, "No warmup trajectory data available")
        return fig

    for profile in profiles:
        condition_runs = sorted(
            [
                run
                for run in context.raw_runs
                if condition_key_from_run(run) == (scenario, state, profile, hash_algorithm, bucket)
            ],
            key=lambda run: int(run.get("run_index", 0) or 0),
        )
        values = [get_metric_value(run, "server_total_ms") for run in condition_runs]
        ordinals = list(range(1, len(values) + 1))
        rolling = []
        for index in range(len(values)):
            window = [value for value in values[max(0, index - 2) : index + 1] if value is not None]
            rolling.append(statistics.median(window) if window else None)
        ax.plot(ordinals, rolling, marker="o", linewidth=1.8, color=profile_color(profile), label=profile_display_name(profile))

        first_measured = next(
            (
                ordinal
                for ordinal, run in zip(ordinals, condition_runs)
                if str(run.get("phase")).lower() == "measured"
            ),
            None,
        )
        if first_measured is not None:
            ax.axvline(first_measured - 0.5, color="#888888", linestyle=":", linewidth=0.7)

    ax.set_xlabel("Run ordinal within condition")
    ax.set_ylabel("Rolling median server total (ms)")
    ax.set_title("Warmup Trajectory")
    ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1.0))
    return fig


def plot_cv_distribution(plt: Any, quality_rows: Sequence[Mapping[str, Any]]) -> Any:
    fig, ax = plt.subplots(figsize=(8, 5))
    client_values = [coerce_float(row.get("client_total_cv")) for row in quality_rows]
    server_values = [coerce_float(row.get("server_total_cv")) for row in quality_rows]
    client_values = [value for value in client_values if value is not None]
    server_values = [value for value in server_values if value is not None]
    if not client_values and not server_values:
        no_data_axis(ax, "No coefficient-of-variation data available")
        return fig

    ax.boxplot(
        [client_values or [0.0], server_values or [0.0]],
        tick_labels=["Client", "Server"],
        patch_artist=True,
        boxprops={"facecolor": "#ddd3c3", "color": "#534a42"},
        medianprops={"color": "#8f3b2f", "linewidth": 2},
    )
    ax.set_ylabel("Coefficient of variation")
    ax.set_title("CV Distribution Across Conditions")
    return fig


def representative_bucket_from_rows(rows: Sequence[Mapping[str, Any]]) -> str | None:
    buckets = sorted({str(row.get("bucket")) for row in rows}, key=bucket_sort_key)
    for preferred in ("1MB", "10MB", "100KB", "10KB", "50MB"):
        if preferred in buckets:
            return preferred
    return buckets[0] if buckets else None


if __name__ == "__main__":
    raise SystemExit(main())
