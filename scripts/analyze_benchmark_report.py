#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class ConditionKey:
    benchmark_scenario: str
    storage_state_label: str
    signature_profile: str
    hash_alg: str
    bucket: str


@dataclass(frozen=True)
class ScenarioGroup:
    budget_class: str
    size_band: str
    scenario_family: str
    viable_threshold: float
    conditional_threshold: float


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze benchmark-cli JSON reports into validity, ratio, and recommendation outputs"
    )
    parser.add_argument("report_json", help="Path to benchmark-report-*.json")
    parser.add_argument(
        "--output-dir",
        help="Directory for analysis outputs (default: <report_dir>/analysis/<report_stem>)",
    )
    parser.add_argument(
        "--min-success-rate",
        type=float,
        default=0.90,
        help="Minimum measured scenario success rate required for a valid campaign (default: 0.90)",
    )
    parser.add_argument(
        "--min-condition-success-rate",
        type=float,
        default=0.90,
        help="Minimum per-condition measured scenario success rate (default: 0.90)",
    )
    parser.add_argument(
        "--min-server-coverage",
        type=float,
        default=1.00,
        help="Minimum per-condition server timing coverage (default: 1.00)",
    )
    parser.add_argument(
        "--max-relative-iqr",
        type=float,
        default=0.50,
        help="Maximum allowed relative IQR for comparison metrics (default: 0.50)",
    )
    parser.add_argument(
        "--hybrid-good-threshold",
        type=float,
        default=1.25,
        help="Base hybrid viable ratio threshold before scenario/bucket adjustments (default: 1.25)",
    )
    parser.add_argument(
        "--pqc-good-threshold",
        type=float,
        default=1.25,
        help="Base PQC viable ratio threshold before scenario/bucket adjustments (default: 1.25)",
    )
    parser.add_argument(
        "--pqc-staged-threshold",
        type=float,
        default=1.60,
        help="Base conditional ratio threshold before scenario/bucket adjustments (default: 1.60)",
    )
    parser.add_argument(
        "--bootstrap-samples",
        type=int,
        default=2000,
        help="Bootstrap resamples for ratio confidence intervals (default: 2000)",
    )
    return parser.parse_args()


def load_report(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def default_output_dir(report_path: Path) -> Path:
    return report_path.parent / "analysis" / report_path.stem


def write_csv(path: Path, rows: List[dict], fieldnames: List[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def summary_condition_key(entry: dict) -> ConditionKey:
    return ConditionKey(
        benchmark_scenario=str(entry.get("benchmark_scenario") or "workflow"),
        storage_state_label=str(entry.get("storage_state_label") or "warm"),
        signature_profile=str(entry.get("signature_profile")),
        hash_alg=str(entry.get("hash_algorithm")),
        bucket=str(entry.get("bucket")),
    )


def raw_condition_key(entry: dict) -> ConditionKey:
    return ConditionKey(
        benchmark_scenario=str(entry.get("benchmark_scenario") or "workflow"),
        storage_state_label=str(entry.get("storage_state_label") or "warm"),
        signature_profile=str(entry.get("condition_signature_profile")),
        hash_alg=str(entry.get("condition_hash_algorithm")),
        bucket=str(entry.get("condition_bucket")),
    )


def comparison_tuple(key: ConditionKey, comparison_profile: str) -> Tuple[str, str, str, str, str]:
    return (
        key.benchmark_scenario,
        key.storage_state_label,
        key.hash_alg,
        key.bucket,
        comparison_profile,
    )


def pick_metric(summary: dict, metric_name: str, key: str) -> Optional[float]:
    metric = summary.get(metric_name)
    if not isinstance(metric, dict):
        return None
    value = metric.get(key)
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def safe_num(value: Optional[float], digits: int = 3) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "n/a"
    return f"{value:.{digits}f}"


def percentile(sorted_values: Sequence[float], p: float) -> float:
    if len(sorted_values) == 1:
        return sorted_values[0]
    clamped = min(max(p, 0.0), 1.0)
    rank = clamped * (len(sorted_values) - 1)
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return sorted_values[lo]
    weight = rank - lo
    return sorted_values[lo] * (1.0 - weight) + sorted_values[hi] * weight


def summarize_values(values: Sequence[float], bootstrap_samples: int, seed: int) -> Optional[dict]:
    if not values:
        return None
    sorted_values = sorted(values)
    med = percentile(sorted_values, 0.50)
    q1 = percentile(sorted_values, 0.25)
    q3 = percentile(sorted_values, 0.75)
    p95 = percentile(sorted_values, 0.95)
    ci_low = None
    ci_high = None
    if len(sorted_values) >= 2 and bootstrap_samples > 0:
        rng = random.Random(seed)
        medians = []
        for _ in range(bootstrap_samples):
            sample = [sorted_values[rng.randrange(len(sorted_values))] for _ in sorted_values]
            sample.sort()
            medians.append(percentile(sample, 0.50))
        medians.sort()
        ci_low = percentile(medians, 0.025)
        ci_high = percentile(medians, 0.975)
    return {
        "n": len(sorted_values),
        "median": med,
        "iqr": q3 - q1,
        "p95": p95,
        "ci95_low": ci_low,
        "ci95_high": ci_high,
    }


def metric_seed(report_seed: int, *parts: object) -> int:
    digest = hashlib.sha256(
        ":".join([str(report_seed), *[str(part) for part in parts]]).encode("utf-8")
    ).digest()
    return int.from_bytes(digest[:8], "big")


def relative_iqr(summary: dict, metric_name: str) -> Optional[float]:
    median_value = pick_metric(summary, metric_name, "median")
    iqr_value = pick_metric(summary, metric_name, "iqr")
    if median_value is None or iqr_value is None or median_value <= 0:
        return None
    return iqr_value / median_value


def parse_bucket_to_bytes(label: str) -> Optional[int]:
    upper = label.strip().upper()
    if upper.endswith("KB"):
        return int(upper[:-2]) * 1024
    if upper.endswith("MB"):
        return int(upper[:-2]) * 1024 * 1024
    if upper.endswith("B"):
        return int(upper[:-1])
    if upper.isdigit():
        return int(upper)
    return None


def size_band(bucket: str) -> str:
    size = parse_bucket_to_bytes(bucket) or 0
    if size <= 100 * 1024:
        return "small"
    if size <= 10 * 1024 * 1024:
        return "medium"
    return "large"


def scenario_family(scenario: str) -> str:
    if scenario in {"workflow", "verify_full", "verify_uploaded"}:
        return "user_facing"
    return "backend"


def budget_policy(
    scenario: str,
    bucket: str,
    profile: str,
    evidence_scope: str,
    hybrid_good_threshold: float,
    pqc_good_threshold: float,
    pqc_staged_threshold: float,
) -> ScenarioGroup:
    band = size_band(bucket)
    family = scenario_family(scenario)
    base_viable = hybrid_good_threshold if profile == "hybrid" else pqc_good_threshold
    base_conditional = max(base_viable + 0.20, pqc_staged_threshold)

    adjustment = 0.0
    if band == "medium":
        adjustment += 0.10
    elif band == "large":
        adjustment += 0.20
    if family == "backend":
        adjustment += 0.10
    if evidence_scope == "server":
        adjustment = max(0.0, adjustment - 0.05)

    if family == "user_facing" and band == "small":
        budget = "tight"
    elif band == "large" or family == "backend":
        budget = "relaxed"
    else:
        budget = "balanced"

    return ScenarioGroup(
        budget_class=budget,
        size_band=band,
        scenario_family=family,
        viable_threshold=base_viable + adjustment,
        conditional_threshold=base_conditional + adjustment,
    )


def cliffs_delta(xs: Sequence[float], ys: Sequence[float]) -> Optional[float]:
    if not xs or not ys:
        return None
    gt = 0
    lt = 0
    for x in xs:
        for y in ys:
            if x > y:
                gt += 1
            elif x < y:
                lt += 1
    total = len(xs) * len(ys)
    if total == 0:
        return None
    return (gt - lt) / total


def cliffs_magnitude(delta: Optional[float]) -> str:
    if delta is None:
        return "n/a"
    value = abs(delta)
    if value < 0.147:
        return "negligible"
    if value < 0.33:
        return "small"
    if value < 0.474:
        return "medium"
    return "large"


def bootstrap_ratio(
    baseline: Sequence[float], comparison: Sequence[float], samples: int, seed: int
) -> Tuple[Optional[float], Optional[float], Optional[float]]:
    if not baseline or not comparison:
        return None, None, None
    baseline_med = median(baseline)
    comparison_med = median(comparison)
    if baseline_med <= 0:
        return None, None, None

    point_estimate = comparison_med / baseline_med
    if samples <= 0 or len(baseline) < 2 or len(comparison) < 2:
        return point_estimate, None, None

    rng = random.Random(seed)
    boot = []
    for _ in range(samples):
        base_sample = [baseline[rng.randrange(len(baseline))] for _ in baseline]
        comp_sample = [comparison[rng.randrange(len(comparison))] for _ in comparison]
        base_med = median(base_sample)
        comp_med = median(comp_sample)
        if base_med > 0:
            boot.append(comp_med / base_med)
    if not boot:
        return point_estimate, None, None
    boot.sort()
    return point_estimate, percentile(boot, 0.025), percentile(boot, 0.975)


def classify_storage_impact(manifest_overhead_pct: Optional[float]) -> str:
    if manifest_overhead_pct is None:
        return "unknown"
    if manifest_overhead_pct <= 5.0:
        return "low"
    if manifest_overhead_pct <= 25.0:
        return "moderate"
    return "high"


def collect_quality(report: dict) -> dict:
    raw_runs = report.get("raw_runs", [])
    warmup = [r for r in raw_runs if str(r.get("phase")) == "warmup"]
    measured = [r for r in raw_runs if str(r.get("phase")) == "measured"]

    warmup_transport_ok = sum(1 for run in warmup if run.get("error") is None)
    measured_transport_ok = sum(1 for run in measured if run.get("error") is None)
    warmup_scenario_ok = sum(1 for run in warmup if run.get("scenario_success"))
    measured_scenario_ok = sum(1 for run in measured if run.get("scenario_success"))

    return {
        "raw_total": len(raw_runs),
        "warmup_total": len(warmup),
        "measured_total": len(measured),
        "warmup_transport_ok": warmup_transport_ok,
        "measured_transport_ok": measured_transport_ok,
        "warmup_scenario_ok": warmup_scenario_ok,
        "measured_scenario_ok": measured_scenario_ok,
        "warmup_transport_success_rate": (warmup_transport_ok / len(warmup)) if warmup else 0.0,
        "measured_transport_success_rate": (measured_transport_ok / len(measured)) if measured else 0.0,
        "warmup_scenario_success_rate": (warmup_scenario_ok / len(warmup)) if warmup else 0.0,
        "measured_scenario_success_rate": (measured_scenario_ok / len(measured)) if measured else 0.0,
        "measured_errors": Counter((run.get("error") or "OK") for run in measured),
        "warmup_errors": Counter((run.get("error") or "OK") for run in warmup),
    }


def build_condition_quality_rows(
    report: dict,
    summaries: List[dict],
    min_condition_success_rate: float,
    min_server_coverage: float,
    max_relative_iqr: float,
) -> List[dict]:
    measured_runs = [
        run for run in report.get("raw_runs", []) if str(run.get("phase")) == "measured"
    ]
    measured_by_condition: Dict[ConditionKey, List[dict]] = defaultdict(list)
    for run in measured_runs:
        measured_by_condition[raw_condition_key(run)].append(run)

    rows: List[dict] = []
    for summary in summaries:
        key = summary_condition_key(summary)
        runs_for_condition = measured_by_condition.get(key, [])
        measured_total = len(runs_for_condition)
        transport_success = sum(1 for run in runs_for_condition if run.get("error") is None)
        scenario_success = sum(1 for run in runs_for_condition if run.get("scenario_success"))
        verify_success = sum(1 for run in runs_for_condition if run.get("verify_overall_ok") is True)
        server_covered = sum(
            1
            for run in runs_for_condition
            if run.get("scenario_success") and run.get("server_total_ms") is not None
        )
        condition_success_rate = (scenario_success / measured_total) if measured_total else 0.0
        transport_success_rate = (transport_success / measured_total) if measured_total else 0.0
        verify_success_rate = (verify_success / measured_total) if measured_total else 0.0
        server_coverage = (server_covered / measured_total) if measured_total else 0.0
        total_relative_iqr = relative_iqr(summary, "total_ms")
        server_total_relative_iqr = relative_iqr(summary, "server_total_ms")

        pass_success = condition_success_rate >= min_condition_success_rate
        pass_server_coverage = server_coverage >= min_server_coverage
        pass_dispersion = total_relative_iqr is not None and total_relative_iqr <= max_relative_iqr
        has_total_metric = pick_metric(summary, "total_ms", "median") is not None
        has_server_total_metric = pick_metric(summary, "server_total_ms", "median") is not None
        valid_for_client_comparison = has_total_metric and pass_success and pass_dispersion
        valid_for_server_comparison = (
            valid_for_client_comparison and has_server_total_metric and pass_server_coverage
        )

        rows.append(
            {
                "benchmark_scenario": key.benchmark_scenario,
                "storage_state_label": key.storage_state_label,
                "signature_profile": key.signature_profile,
                "hash_algorithm": key.hash_alg,
                "bucket": key.bucket,
                "measured_runs_total": measured_total,
                "measured_runs_transport_success": transport_success,
                "measured_runs_scenario_success": scenario_success,
                "transport_success_rate": transport_success_rate,
                "condition_success_rate": condition_success_rate,
                "verify_success_rate": verify_success_rate,
                "server_total_coverage": server_coverage,
                "relative_iqr_total_ms": total_relative_iqr,
                "relative_iqr_server_total_ms": server_total_relative_iqr,
                "pass_success_gate": pass_success,
                "pass_server_coverage_gate": pass_server_coverage,
                "pass_dispersion_gate": pass_dispersion,
                "valid_for_client_comparison": valid_for_client_comparison,
                "valid_for_server_comparison": valid_for_server_comparison,
            }
        )

    rows.sort(
        key=lambda row: (
            row["benchmark_scenario"],
            row["storage_state_label"],
            row["hash_algorithm"],
            row["bucket"],
            row["signature_profile"],
        )
    )
    return rows


def flatten_summaries(summaries: List[dict]) -> List[dict]:
    rows = []
    for summary in summaries:
        rows.append(
            {
                "benchmark_scenario": summary.get("benchmark_scenario"),
                "storage_state_label": summary.get("storage_state_label"),
                "signature_profile": summary.get("signature_profile"),
                "hash_algorithm": summary.get("hash_algorithm"),
                "bucket": summary.get("bucket"),
                "measured_runs_total": summary.get("measured_runs_total"),
                "measured_runs_success": summary.get("measured_runs_success"),
                "measured_runs_failed": summary.get("measured_runs_failed"),
                "scenario_success_rate": summary.get("scenario_success_rate"),
                "verify_success_rate": summary.get("verify_success_rate"),
                "total_ms_median": pick_metric(summary, "total_ms", "median"),
                "total_ms_iqr": pick_metric(summary, "total_ms", "iqr"),
                "total_ms_p95": pick_metric(summary, "total_ms", "p95"),
                "total_ms_ci95_low": pick_metric(summary, "total_ms", "ci95_low"),
                "total_ms_ci95_high": pick_metric(summary, "total_ms", "ci95_high"),
                "upload_ms_median": pick_metric(summary, "upload_ms", "median"),
                "process_ms_median": pick_metric(summary, "process_ms", "median"),
                "verify_ms_median": pick_metric(summary, "verify_ms", "median"),
                "server_hash_ms_median": pick_metric(summary, "server_hash_ms", "median"),
                "server_rsa_sign_ms_median": pick_metric(summary, "server_rsa_sign_ms", "median"),
                "server_dilithium_sign_ms_median": pick_metric(
                    summary, "server_dilithium_sign_ms", "median"
                ),
                "server_verify_ms_median": pick_metric(summary, "server_verify_ms", "median"),
                "server_total_ms_median": pick_metric(summary, "server_total_ms", "median"),
                "manifest_size_median": pick_metric(summary, "manifest_size_bytes", "median"),
                "signature_size_median": pick_metric(summary, "total_signature_bytes", "median"),
                "manifest_overhead_pct_median": pick_metric(
                    summary, "manifest_overhead_pct", "median"
                ),
                "signature_overhead_pct_median": pick_metric(
                    summary, "signature_overhead_pct", "median"
                ),
                "storage_amplification_median": pick_metric(
                    summary, "storage_amplification", "median"
                ),
                "client_total_mib_s_median": pick_metric(
                    summary, "client_total_mib_s", "median"
                ),
                "server_hash_mib_s_median": pick_metric(summary, "server_hash_mib_s", "median"),
                "server_verify_mib_s_median": pick_metric(
                    summary, "server_verify_mib_s", "median"
                ),
                "server_total_mib_s_median": pick_metric(
                    summary, "server_total_mib_s", "median"
                ),
                "s_pqc_vs_classical_total_median": summary.get("s_pqc_vs_classical_total_median"),
                "s_hybrid_vs_classical_total_median": summary.get(
                    "s_hybrid_vs_classical_total_median"
                ),
                "s_pqc_vs_classical_server_total_median": summary.get(
                    "s_pqc_vs_classical_server_total_median"
                ),
                "s_hybrid_vs_classical_server_total_median": summary.get(
                    "s_hybrid_vs_classical_server_total_median"
                ),
            }
        )
    return rows


def successful_measured_runs(report: dict) -> Dict[ConditionKey, List[dict]]:
    grouped: Dict[ConditionKey, List[dict]] = defaultdict(list)
    for run in report.get("raw_runs", []):
        if str(run.get("phase")) != "measured":
            continue
        if not run.get("scenario_success"):
            continue
        grouped[raw_condition_key(run)].append(run)
    return grouped


def metric_values(runs: Sequence[dict], field: str) -> List[float]:
    values = []
    for run in runs:
        value = run.get(field)
        if value is None:
            continue
        try:
            values.append(float(value))
        except (TypeError, ValueError):
            continue
    return values


def rate_from_runs(runs: Sequence[dict], field: str) -> Optional[float]:
    values = [run.get(field) for run in runs if run.get(field) is not None]
    if not values:
        return None
    return sum(1 for value in values if bool(value)) / len(values)


def build_stage_breakdown_rows(
    report: dict, bootstrap_samples: int, report_seed: int
) -> List[dict]:
    grouped = successful_measured_runs(report)
    metric_fields = [
        "server_object_exists_check_ms",
        "server_object_store_ms",
        "server_manifest_canonicalize_ms",
        "server_db_persist_ms",
        "server_manifest_fetch_db_lookup_ms",
        "server_verify_hash_ms",
        "server_verify_canonicalize_ms",
        "server_signature_verify_ms",
        "server_stored_object_verify_ms",
        "server_uploaded_content_verify_ms",
        "storage_bytes_written",
        "storage_bytes_read",
        "manifest_core_bytes",
        "manifest_envelope_bytes",
    ]
    rows = []
    for key, runs in sorted(
        grouped.items(),
        key=lambda item: (
            item[0].benchmark_scenario,
            item[0].storage_state_label,
            item[0].hash_alg,
            item[0].bucket,
            item[0].signature_profile,
        ),
    ):
        row = {
            "benchmark_scenario": key.benchmark_scenario,
            "storage_state_label": key.storage_state_label,
            "signature_profile": key.signature_profile,
            "hash_algorithm": key.hash_alg,
            "bucket": key.bucket,
            "object_store_hit_rate": rate_from_runs(runs, "server_object_store_hit"),
            "multipart_rate": rate_from_runs(runs, "server_multipart_used"),
        }
        for field in metric_fields:
            stats = summarize_values(
                metric_values(runs, field),
                bootstrap_samples=bootstrap_samples,
                seed=metric_seed(report_seed, "stage", field, key),
            )
            row[f"{field}_median"] = None if stats is None else stats["median"]
            row[f"{field}_iqr"] = None if stats is None else stats["iqr"]
        rows.append(row)
    return rows


def build_ratio_rows(
    report: dict,
    summaries: List[dict],
    condition_quality_rows: List[dict],
    bootstrap_samples: int,
    report_seed: int,
    hybrid_good_threshold: float,
    pqc_good_threshold: float,
    pqc_staged_threshold: float,
) -> List[dict]:
    grouped_runs = successful_measured_runs(report)
    summary_by_key = {summary_condition_key(summary): summary for summary in summaries}
    quality_by_key = {
        ConditionKey(
            benchmark_scenario=row["benchmark_scenario"],
            storage_state_label=row["storage_state_label"],
            signature_profile=row["signature_profile"],
            hash_alg=row["hash_algorithm"],
            bucket=row["bucket"],
        ): row
        for row in condition_quality_rows
    }

    comparison_space = sorted(
        {
            (
                key.benchmark_scenario,
                key.storage_state_label,
                key.hash_alg,
                key.bucket,
            )
            for key in summary_by_key
        }
    )

    rows: List[dict] = []
    for benchmark_scenario, storage_state_label, hash_alg, bucket in comparison_space:
        baseline_key = ConditionKey(
            benchmark_scenario=benchmark_scenario,
            storage_state_label=storage_state_label,
            signature_profile="classical",
            hash_alg=hash_alg,
            bucket=bucket,
        )
        baseline_runs = grouped_runs.get(baseline_key, [])
        baseline_summary = summary_by_key.get(baseline_key)
        baseline_quality = quality_by_key.get(baseline_key, {})
        if baseline_summary is None:
            continue

        for comparison_profile in ("pqc", "hybrid"):
            compare_key = ConditionKey(
                benchmark_scenario=benchmark_scenario,
                storage_state_label=storage_state_label,
                signature_profile=comparison_profile,
                hash_alg=hash_alg,
                bucket=bucket,
            )
            compare_runs = grouped_runs.get(compare_key, [])
            compare_summary = summary_by_key.get(compare_key)
            compare_quality = quality_by_key.get(compare_key, {})
            if compare_summary is None:
                continue

            for evidence_scope, metric_field, validity_field in (
                ("workflow", "client_total_ms", "valid_for_client_comparison"),
                ("server", "server_total_ms", "valid_for_server_comparison"),
            ):
                baseline_valid = bool(baseline_quality.get(validity_field))
                comparison_valid = bool(compare_quality.get(validity_field))
                valid = baseline_valid and comparison_valid
                baseline_metric_values = metric_values(baseline_runs, metric_field)
                comparison_metric_values = metric_values(compare_runs, metric_field)
                ratio_median, ratio_ci_low, ratio_ci_high = bootstrap_ratio(
                    baseline_metric_values,
                    comparison_metric_values,
                    samples=bootstrap_samples,
                    seed=metric_seed(
                        report_seed,
                        "ratio",
                        benchmark_scenario,
                        storage_state_label,
                        hash_alg,
                        bucket,
                        comparison_profile,
                        evidence_scope,
                    ),
                )
                delta = cliffs_delta(comparison_metric_values, baseline_metric_values)
                policy = budget_policy(
                    scenario=benchmark_scenario,
                    bucket=bucket,
                    profile=comparison_profile,
                    evidence_scope=evidence_scope,
                    hybrid_good_threshold=hybrid_good_threshold,
                    pqc_good_threshold=pqc_good_threshold,
                    pqc_staged_threshold=pqc_staged_threshold,
                )

                if not valid or ratio_median is None:
                    classification = "insufficient_evidence"
                elif ratio_ci_high is not None and ratio_ci_high <= policy.viable_threshold:
                    classification = "viable"
                elif ratio_ci_high is not None and ratio_ci_high <= policy.conditional_threshold:
                    classification = "conditional"
                else:
                    classification = "classical_preferred"

                baseline_manifest_overhead = pick_metric(
                    baseline_summary, "manifest_overhead_pct", "median"
                )
                compare_manifest_overhead = pick_metric(
                    compare_summary, "manifest_overhead_pct", "median"
                )
                baseline_signature_size = pick_metric(
                    baseline_summary, "total_signature_bytes", "median"
                )
                compare_signature_size = pick_metric(
                    compare_summary, "total_signature_bytes", "median"
                )
                signature_size_ratio = None
                if (
                    baseline_signature_size is not None
                    and baseline_signature_size > 0
                    and compare_signature_size is not None
                ):
                    signature_size_ratio = compare_signature_size / baseline_signature_size

                rows.append(
                    {
                        "benchmark_scenario": benchmark_scenario,
                        "storage_state_label": storage_state_label,
                        "hash_algorithm": hash_alg,
                        "bucket": bucket,
                        "comparison_profile": comparison_profile,
                        "evidence_scope": evidence_scope,
                        "baseline_profile": "classical",
                        "baseline_valid": baseline_valid,
                        "comparison_valid": comparison_valid,
                        "valid_for_recommendation": valid,
                        "baseline_samples": len(baseline_metric_values),
                        "comparison_samples": len(comparison_metric_values),
                        "baseline_median_ms": median(baseline_metric_values)
                        if baseline_metric_values
                        else None,
                        "comparison_median_ms": median(comparison_metric_values)
                        if comparison_metric_values
                        else None,
                        "ratio_median": ratio_median,
                        "ratio_ci95_low": ratio_ci_low,
                        "ratio_ci95_high": ratio_ci_high,
                        "cliffs_delta": delta,
                        "effect_magnitude": cliffs_magnitude(delta),
                        "budget_class": policy.budget_class,
                        "size_band": policy.size_band,
                        "scenario_family": policy.scenario_family,
                        "viable_threshold": policy.viable_threshold,
                        "conditional_threshold": policy.conditional_threshold,
                        "classification": classification,
                        "baseline_manifest_overhead_pct_median": baseline_manifest_overhead,
                        "comparison_manifest_overhead_pct_median": compare_manifest_overhead,
                        "comparison_storage_impact": classify_storage_impact(
                            compare_manifest_overhead
                        ),
                        "baseline_signature_size_median": baseline_signature_size,
                        "comparison_signature_size_median": compare_signature_size,
                        "signature_size_ratio": signature_size_ratio,
                    }
                )
    rows.sort(
        key=lambda row: (
            row["benchmark_scenario"],
            row["storage_state_label"],
            row["evidence_scope"],
            row["hash_algorithm"],
            row["bucket"],
            row["comparison_profile"],
        )
    )
    return rows


def build_recommendation_rows(ratio_rows: List[dict]) -> List[dict]:
    grouped: Dict[Tuple[str, str, str, str, str], List[dict]] = defaultdict(list)
    for row in ratio_rows:
        grouped[
            (
                row["benchmark_scenario"],
                row["storage_state_label"],
                row["hash_algorithm"],
                row["bucket"],
                row["comparison_profile"],
            )
        ].append(row)

    recommendations = []
    for key, candidates in sorted(grouped.items()):
        server_row = next((row for row in candidates if row["evidence_scope"] == "server"), None)
        workflow_row = next((row for row in candidates if row["evidence_scope"] == "workflow"), None)
        chosen = server_row if server_row and server_row["valid_for_recommendation"] else workflow_row
        if chosen is None:
            continue

        scenario, storage_state_label, hash_alg, bucket, comparison_profile = key
        classification = chosen["classification"]
        if classification == "viable":
            recommendation = (
                f"{comparison_profile} is viable for {chosen['budget_class']} latency budgets "
                f"on {chosen['evidence_scope']} evidence."
            )
        elif classification == "conditional":
            recommendation = (
                f"{comparison_profile} is acceptable only for relaxed or staged adoption on "
                f"{chosen['evidence_scope']} evidence."
            )
        elif classification == "classical_preferred":
            recommendation = (
                f"classical remains preferable for this condition because the ratio CI exceeds "
                f"the configured budget threshold on {chosen['evidence_scope']} evidence."
            )
        else:
            recommendation = "insufficient evidence for a condition-specific recommendation."

        recommendations.append(
            {
                "benchmark_scenario": scenario,
                "storage_state_label": storage_state_label,
                "hash_algorithm": hash_alg,
                "bucket": bucket,
                "comparison_profile": comparison_profile,
                "selected_evidence_scope": chosen["evidence_scope"],
                "classification": classification,
                "ratio_median": chosen["ratio_median"],
                "ratio_ci95_low": chosen["ratio_ci95_low"],
                "ratio_ci95_high": chosen["ratio_ci95_high"],
                "budget_class": chosen["budget_class"],
                "size_band": chosen["size_band"],
                "comparison_storage_impact": chosen["comparison_storage_impact"],
                "signature_size_ratio": chosen["signature_size_ratio"],
                "effect_magnitude": chosen["effect_magnitude"],
                "recommendation": recommendation,
            }
        )
    return recommendations


def build_migration_findings(recommendation_rows: List[dict]) -> List[str]:
    by_profile_bucket: Dict[Tuple[str, str, str, str], Dict[str, str]] = defaultdict(dict)
    for row in recommendation_rows:
        by_profile_bucket[
            (
                row["storage_state_label"],
                row["comparison_profile"],
                row["hash_algorithm"],
                row["bucket"],
            )
        ][row["benchmark_scenario"]] = row["classification"]

    findings = []
    for (storage_state, profile, hash_alg, bucket), classes in sorted(by_profile_bucket.items()):
        verify_ready = any(
            classes.get(scenario) in {"viable", "conditional"}
            for scenario in ("verify_manifest", "verify_stored", "verify_uploaded", "verify_full")
        )
        sign_ready = any(
            classes.get(scenario) in {"viable", "conditional"}
            for scenario in ("workflow", "sign_only")
        )
        if verify_ready and not sign_ready:
            findings.append(
                f"- {profile} | {hash_alg} | {bucket} | {storage_state}: verifier-first migration is indicated because verify scenarios pass while signing scenarios do not."
            )
    return findings


def try_generate_plots(out_dir: Path, summaries: List[dict], ratio_rows: List[dict]) -> List[str]:
    plot_files: List[str] = []
    try:
        import matplotlib.pyplot as plt  # type: ignore
    except Exception:
        return plot_files

    labels = []
    values = []
    for summary in summaries:
        labels.append(
            f"{summary.get('benchmark_scenario')}|{summary.get('signature_profile')}|"
            f"{summary.get('hash_algorithm')}|{summary.get('bucket')}"
        )
        values.append(float(summary.get("scenario_success_rate") or 0.0))

    if labels:
        fig = plt.figure(figsize=(18, 6))
        ax = fig.add_subplot(111)
        ax.bar(range(len(labels)), values)
        ax.set_ylim(0, 1.0)
        ax.set_title("Scenario success rate by condition")
        ax.set_ylabel("success rate")
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=90, fontsize=6)
        fig.tight_layout()
        path = out_dir / "plot_success_rate_by_condition.png"
        fig.savefig(path, dpi=160)
        plt.close(fig)
        plot_files.append(path.name)

    server_ratio_rows = [
        row
        for row in ratio_rows
        if row["evidence_scope"] == "server" and row["ratio_median"] is not None
    ]
    if server_ratio_rows:
        labels = [
            f"{row['benchmark_scenario']}|{row['comparison_profile']}|{row['hash_algorithm']}|{row['bucket']}"
            for row in server_ratio_rows
        ]
        values = [row["ratio_median"] for row in server_ratio_rows]
        fig = plt.figure(figsize=(18, 6))
        ax = fig.add_subplot(111)
        ax.bar(range(len(labels)), values)
        ax.axhline(1.0, linestyle="--", linewidth=1)
        ax.set_title("Server-attributed ratio vs classical")
        ax.set_ylabel("ratio")
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=90, fontsize=6)
        fig.tight_layout()
        path = out_dir / "plot_server_ratios_vs_classical.png"
        fig.savefig(path, dpi=160)
        plt.close(fig)
        plot_files.append(path.name)

    return plot_files


def build_markdown(
    report_path: Path,
    output_dir: Path,
    report: dict,
    quality: dict,
    condition_quality_rows: List[dict],
    recommendation_rows: List[dict],
    ratio_rows: List[dict],
    migration_findings: List[str],
    plot_files: List[str],
    min_success_rate: float,
) -> str:
    config = report.get("cli_config", {})
    environment = report.get("environment", {})
    summaries = report.get("summaries", [])

    measured_scenario_rate = quality["measured_scenario_success_rate"]
    overall_gate = measured_scenario_rate >= min_success_rate
    workflow_valid = all(row["valid_for_client_comparison"] for row in condition_quality_rows)
    server_valid = all(row["valid_for_server_comparison"] for row in condition_quality_rows)
    viable_recommendations = [
        row for row in recommendation_rows if row["classification"] in {"viable", "conditional"}
    ]
    insufficient_recommendations = [
        row for row in recommendation_rows if row["classification"] == "insufficient_evidence"
    ]
    failed_conditions = [
        row for row in condition_quality_rows if not row["valid_for_server_comparison"]
    ][:10]

    top_errors = quality["measured_errors"].most_common(5)
    workflow_ratio_rows = [
        row for row in ratio_rows if row["evidence_scope"] == "workflow" and row["ratio_median"] is not None
    ]
    server_ratio_rows = [
        row for row in ratio_rows if row["evidence_scope"] == "server" and row["ratio_median"] is not None
    ]

    lines: List[str] = []
    lines.append("# Benchmark Report Interpretation")
    lines.append("")
    lines.append(f"- Source report: `{report_path}`")
    lines.append(f"- Analysis dir: `{output_dir}`")
    lines.append(f"- Generated at: `{report.get('generated_at')}`")
    lines.append("")
    lines.append("## Quality gate")
    lines.append(
        f"- Measured scenario success rate: `{measured_scenario_rate:.3f}` (threshold `{min_success_rate:.2f}`)"
    )
    lines.append(
        f"- Measured transport success rate: `{quality['measured_transport_success_rate']:.3f}`"
    )
    lines.append(
        f"- Measured runs successful: scenario `{quality['measured_scenario_ok']}/{quality['measured_total']}`, transport `{quality['measured_transport_ok']}/{quality['measured_total']}`"
    )
    lines.append(
        f"- Warm-up runs successful: scenario `{quality['warmup_scenario_ok']}/{quality['warmup_total']}`, transport `{quality['warmup_transport_ok']}/{quality['warmup_total']}`"
    )
    lines.append(f"- Workflow comparison gate: `{'PASS' if overall_gate and workflow_valid else 'FAIL'}`")
    lines.append(f"- Server comparison gate: `{'PASS' if overall_gate and server_valid else 'FAIL'}`")
    lines.append("")

    lines.append("## Error profile")
    if top_errors:
        for error_message, count in top_errors:
            lines.append(f"- `{error_message}`: {count}")
    else:
        lines.append("- No measured-run errors.")
    lines.append("")

    lines.append("## Evidence quality")
    lines.append(
        f"- Condition summaries: `{len(summaries)}`; valid for workflow comparison: `{sum(1 for row in condition_quality_rows if row['valid_for_client_comparison'])}`; valid for server comparison: `{sum(1 for row in condition_quality_rows if row['valid_for_server_comparison'])}`."
    )
    lines.append(
        f"- Ratio rows with workflow evidence: `{len(workflow_ratio_rows)}`; ratio rows with server evidence: `{len(server_ratio_rows)}`."
    )
    if failed_conditions:
        for row in failed_conditions:
            reasons = []
            if not row["pass_success_gate"]:
                reasons.append(f"success={safe_num(row['condition_success_rate'])}")
            if not row["pass_server_coverage_gate"]:
                reasons.append(f"server_coverage={safe_num(row['server_total_coverage'])}")
            if not row["pass_dispersion_gate"]:
                reasons.append(f"relative_iqr={safe_num(row['relative_iqr_total_ms'])}")
            lines.append(
                f"- Failing condition: {row['benchmark_scenario']} | {row['signature_profile']} | {row['hash_algorithm']} | {row['bucket']} | {row['storage_state_label']} ({', '.join(reasons)})"
            )
    else:
        lines.append("- All conditions met the scenario-success, server-coverage, and dispersion gates.")
    lines.append("")

    lines.append("## Recommendation summary")
    if viable_recommendations:
        for row in viable_recommendations[:12]:
            lines.append(
                f"- {row['benchmark_scenario']} | {row['comparison_profile']} | {row['hash_algorithm']} | {row['bucket']} | {row['storage_state_label']}: {row['classification']} on {row['selected_evidence_scope']} evidence (ratio `{safe_num(row['ratio_median'])}`, CI `{safe_num(row['ratio_ci95_low'])}..{safe_num(row['ratio_ci95_high'])}`, storage impact `{row['comparison_storage_impact']}`)."
            )
    else:
        lines.append("- No condition reached viable or conditional status under the configured policy.")
    if insufficient_recommendations:
        lines.append(
            f"- `{len(insufficient_recommendations)}` condition/profile combinations remain below the evidence threshold and should not be used for conclusions."
        )
    lines.append("")

    lines.append("## Migration guidance")
    if migration_findings:
        lines.extend(migration_findings[:10])
    else:
        lines.append("- No verifier-first migration pattern was detected in this campaign.")
    lines.append("")

    lines.append("## Reproducibility metadata")
    lines.append(f"- Seed: `{config.get('seed')}`")
    lines.append(f"- Scenarios: `{config.get('scenarios')}`")
    lines.append(f"- Storage state label: `{config.get('storage_state_label')}`")
    lines.append(f"- Campaign label: `{config.get('campaign_label')}`")
    lines.append(f"- Repeat index: `{config.get('repeat_index')}`")
    lines.append(f"- Profiles: `{config.get('profiles')}`")
    lines.append(f"- Hashes: `{config.get('hashes')}`")
    lines.append(f"- Buckets: `{config.get('buckets')}`")
    lines.append(f"- Build profile: `{environment.get('build_profile')}`")
    lines.append(f"- Git commit: `{environment.get('git_commit')}`")
    lines.append(f"- CPU: `{environment.get('cpu_model')}`")
    lines.append(f"- RAM bytes: `{environment.get('total_memory_bytes')}`")
    if plot_files:
        lines.append("")
        lines.append("## Visualisation")
        for name in plot_files:
            lines.append(f"- `{name}`")
    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    report_path = Path(args.report_json)
    if not report_path.exists() or not report_path.is_file():
        raise SystemExit(f"Report file not found: {report_path}")

    report = load_report(report_path)
    summaries = report.get("summaries", [])
    out_dir = Path(args.output_dir) if args.output_dir else default_output_dir(report_path)
    out_dir.mkdir(parents=True, exist_ok=True)

    report_seed = int(report.get("cli_config", {}).get("seed") or 0)
    quality = collect_quality(report)
    condition_quality_rows = build_condition_quality_rows(
        report,
        summaries,
        min_condition_success_rate=args.min_condition_success_rate,
        min_server_coverage=args.min_server_coverage,
        max_relative_iqr=args.max_relative_iqr,
    )
    summary_rows = flatten_summaries(summaries)
    stage_rows = build_stage_breakdown_rows(report, args.bootstrap_samples, report_seed)
    ratio_rows = build_ratio_rows(
        report,
        summaries,
        condition_quality_rows,
        bootstrap_samples=args.bootstrap_samples,
        report_seed=report_seed,
        hybrid_good_threshold=args.hybrid_good_threshold,
        pqc_good_threshold=args.pqc_good_threshold,
        pqc_staged_threshold=args.pqc_staged_threshold,
    )
    recommendation_rows = build_recommendation_rows(ratio_rows)
    migration_findings = build_migration_findings(recommendation_rows)
    plot_files = try_generate_plots(out_dir, summaries, ratio_rows)

    md = build_markdown(
        report_path=report_path,
        output_dir=out_dir,
        report=report,
        quality=quality,
        condition_quality_rows=condition_quality_rows,
        recommendation_rows=recommendation_rows,
        ratio_rows=ratio_rows,
        migration_findings=migration_findings,
        plot_files=plot_files,
        min_success_rate=args.min_success_rate,
    )
    (out_dir / "interpretation.md").write_text(md, encoding="utf-8")

    write_csv(
        out_dir / "summary_flat.csv",
        summary_rows,
        [
            "benchmark_scenario",
            "storage_state_label",
            "signature_profile",
            "hash_algorithm",
            "bucket",
            "measured_runs_total",
            "measured_runs_success",
            "measured_runs_failed",
            "scenario_success_rate",
            "verify_success_rate",
            "total_ms_median",
            "total_ms_iqr",
            "total_ms_p95",
            "total_ms_ci95_low",
            "total_ms_ci95_high",
            "upload_ms_median",
            "process_ms_median",
            "verify_ms_median",
            "server_hash_ms_median",
            "server_rsa_sign_ms_median",
            "server_dilithium_sign_ms_median",
            "server_verify_ms_median",
            "server_total_ms_median",
            "manifest_size_median",
            "signature_size_median",
            "manifest_overhead_pct_median",
            "signature_overhead_pct_median",
            "storage_amplification_median",
            "client_total_mib_s_median",
            "server_hash_mib_s_median",
            "server_verify_mib_s_median",
            "server_total_mib_s_median",
            "s_pqc_vs_classical_total_median",
            "s_hybrid_vs_classical_total_median",
            "s_pqc_vs_classical_server_total_median",
            "s_hybrid_vs_classical_server_total_median",
        ],
    )

    error_rows = []
    for phase in ("warmup", "measured"):
        counter = quality[f"{phase}_errors"]
        for error_message, count in counter.most_common():
            error_rows.append({"phase": phase, "error": error_message, "count": count})
    write_csv(out_dir / "error_counts.csv", error_rows, ["phase", "error", "count"])

    write_csv(
        out_dir / "condition_quality.csv",
        condition_quality_rows,
        [
            "benchmark_scenario",
            "storage_state_label",
            "signature_profile",
            "hash_algorithm",
            "bucket",
            "measured_runs_total",
            "measured_runs_transport_success",
            "measured_runs_scenario_success",
            "transport_success_rate",
            "condition_success_rate",
            "verify_success_rate",
            "server_total_coverage",
            "relative_iqr_total_ms",
            "relative_iqr_server_total_ms",
            "pass_success_gate",
            "pass_server_coverage_gate",
            "pass_dispersion_gate",
            "valid_for_client_comparison",
            "valid_for_server_comparison",
        ],
    )

    write_csv(
        out_dir / "stage_breakdown.csv",
        stage_rows,
        [
            "benchmark_scenario",
            "storage_state_label",
            "signature_profile",
            "hash_algorithm",
            "bucket",
            "object_store_hit_rate",
            "multipart_rate",
            "server_object_exists_check_ms_median",
            "server_object_exists_check_ms_iqr",
            "server_object_store_ms_median",
            "server_object_store_ms_iqr",
            "server_manifest_canonicalize_ms_median",
            "server_manifest_canonicalize_ms_iqr",
            "server_db_persist_ms_median",
            "server_db_persist_ms_iqr",
            "server_manifest_fetch_db_lookup_ms_median",
            "server_manifest_fetch_db_lookup_ms_iqr",
            "server_verify_hash_ms_median",
            "server_verify_hash_ms_iqr",
            "server_verify_canonicalize_ms_median",
            "server_verify_canonicalize_ms_iqr",
            "server_signature_verify_ms_median",
            "server_signature_verify_ms_iqr",
            "server_stored_object_verify_ms_median",
            "server_stored_object_verify_ms_iqr",
            "server_uploaded_content_verify_ms_median",
            "server_uploaded_content_verify_ms_iqr",
            "storage_bytes_written_median",
            "storage_bytes_written_iqr",
            "storage_bytes_read_median",
            "storage_bytes_read_iqr",
            "manifest_core_bytes_median",
            "manifest_core_bytes_iqr",
            "manifest_envelope_bytes_median",
            "manifest_envelope_bytes_iqr",
        ],
    )

    write_csv(
        out_dir / "ratio_table.csv",
        ratio_rows,
        [
            "benchmark_scenario",
            "storage_state_label",
            "hash_algorithm",
            "bucket",
            "comparison_profile",
            "evidence_scope",
            "baseline_profile",
            "baseline_valid",
            "comparison_valid",
            "valid_for_recommendation",
            "baseline_samples",
            "comparison_samples",
            "baseline_median_ms",
            "comparison_median_ms",
            "ratio_median",
            "ratio_ci95_low",
            "ratio_ci95_high",
            "cliffs_delta",
            "effect_magnitude",
            "budget_class",
            "size_band",
            "scenario_family",
            "viable_threshold",
            "conditional_threshold",
            "classification",
            "baseline_manifest_overhead_pct_median",
            "comparison_manifest_overhead_pct_median",
            "comparison_storage_impact",
            "baseline_signature_size_median",
            "comparison_signature_size_median",
            "signature_size_ratio",
        ],
    )

    write_csv(
        out_dir / "scenario_recommendations.csv",
        recommendation_rows,
        [
            "benchmark_scenario",
            "storage_state_label",
            "hash_algorithm",
            "bucket",
            "comparison_profile",
            "selected_evidence_scope",
            "classification",
            "ratio_median",
            "ratio_ci95_low",
            "ratio_ci95_high",
            "budget_class",
            "size_band",
            "comparison_storage_impact",
            "signature_size_ratio",
            "effect_magnitude",
            "recommendation",
        ],
    )

    workflow_gate_pass = quality["measured_scenario_success_rate"] >= args.min_success_rate and all(
        row["valid_for_client_comparison"] for row in condition_quality_rows
    )
    server_gate_pass = workflow_gate_pass and all(
        row["valid_for_server_comparison"] for row in condition_quality_rows
    )
    quality_json = {
        "raw_total": quality["raw_total"],
        "warmup_total": quality["warmup_total"],
        "measured_total": quality["measured_total"],
        "warmup_transport_ok": quality["warmup_transport_ok"],
        "measured_transport_ok": quality["measured_transport_ok"],
        "warmup_scenario_ok": quality["warmup_scenario_ok"],
        "measured_scenario_ok": quality["measured_scenario_ok"],
        "warmup_transport_success_rate": quality["warmup_transport_success_rate"],
        "measured_transport_success_rate": quality["measured_transport_success_rate"],
        "warmup_scenario_success_rate": quality["warmup_scenario_success_rate"],
        "measured_scenario_success_rate": quality["measured_scenario_success_rate"],
        "min_success_rate_threshold": args.min_success_rate,
        "min_condition_success_rate_threshold": args.min_condition_success_rate,
        "min_server_coverage_threshold": args.min_server_coverage,
        "max_relative_iqr_threshold": args.max_relative_iqr,
        "workflow_gate_pass": workflow_gate_pass,
        "server_gate_pass": server_gate_pass,
        "conditions_total": len(condition_quality_rows),
        "conditions_valid_for_client_comparison": sum(
            1 for row in condition_quality_rows if row["valid_for_client_comparison"]
        ),
        "conditions_valid_for_server_comparison": sum(
            1 for row in condition_quality_rows if row["valid_for_server_comparison"]
        ),
        "recommendations_total": len(recommendation_rows),
        "recommendations_viable_or_conditional": sum(
            1 for row in recommendation_rows if row["classification"] in {"viable", "conditional"}
        ),
    }
    (out_dir / "quality_gate.json").write_text(
        json.dumps(quality_json, indent=2), encoding="utf-8"
    )

    print(f"Analysis written to: {out_dir}")
    print(f"- interpretation:          {out_dir / 'interpretation.md'}")
    print(f"- quality gate:            {out_dir / 'quality_gate.json'}")
    print(f"- summary csv:             {out_dir / 'summary_flat.csv'}")
    print(f"- error csv:               {out_dir / 'error_counts.csv'}")
    print(f"- condition csv:           {out_dir / 'condition_quality.csv'}")
    print(f"- stage breakdown csv:     {out_dir / 'stage_breakdown.csv'}")
    print(f"- ratio csv:               {out_dir / 'ratio_table.csv'}")
    print(f"- recommendations csv:     {out_dir / 'scenario_recommendations.csv'}")
    if plot_files:
        for name in plot_files:
            print(f"- plot:                    {out_dir / name}")
    else:
        print("- plot:                    not generated (matplotlib unavailable)")


if __name__ == "__main__":
    main()
