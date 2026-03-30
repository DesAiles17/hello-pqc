#!/usr/bin/env python3
import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median
from typing import Dict, List, Optional, Tuple


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Aggregate repeat-level benchmark analyses from campaign-manifest TSV"
    )
    parser.add_argument("manifest_tsv", help="Path to campaign-manifest-*.tsv")
    parser.add_argument(
        "--output-dir",
        help="Output dir (default: <manifest_dir>/analysis/<manifest_stem>)",
    )
    return parser.parse_args()


def default_output_dir(manifest_path: Path) -> Path:
    return manifest_path.parent / "analysis" / manifest_path.stem


def write_csv(path: Path, rows: List[dict], fieldnames: List[str], delimiter: str = ",") -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, delimiter=delimiter)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def read_tsv(path: Path) -> List[dict]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def read_csv_if_exists(path: Path) -> List[dict]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def to_float(value: Optional[str]) -> Optional[float]:
    if value in (None, "", "n/a"):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def campaign_recommendation_consensus(rows: List[dict]) -> List[dict]:
    grouped: Dict[Tuple[str, str, str, str, str], List[dict]] = defaultdict(list)
    for row in rows:
        grouped[
            (
                row["benchmark_scenario"],
                row["storage_state_label"],
                row["hash_algorithm"],
                row["bucket"],
                row["comparison_profile"],
            )
        ].append(row)

    out = []
    for key, entries in sorted(grouped.items()):
        classifications = Counter(entry["classification"] for entry in entries)
        ratio_values = [to_float(entry.get("ratio_median")) for entry in entries]
        ratio_values = [value for value in ratio_values if value is not None]
        ci_high_values = [to_float(entry.get("ratio_ci95_high")) for entry in entries]
        ci_high_values = [value for value in ci_high_values if value is not None]
        evidence_modes = sorted({entry["selected_evidence_scope"] for entry in entries})
        storage_impacts = Counter(entry.get("comparison_storage_impact") or "unknown" for entry in entries)

        dominant_classification, dominant_count = classifications.most_common(1)[0]
        out.append(
            {
                "benchmark_scenario": key[0],
                "storage_state_label": key[1],
                "hash_algorithm": key[2],
                "bucket": key[3],
                "comparison_profile": key[4],
                "repeats_total": len(entries),
                "viable_count": classifications.get("viable", 0),
                "conditional_count": classifications.get("conditional", 0),
                "classical_preferred_count": classifications.get("classical_preferred", 0),
                "insufficient_evidence_count": classifications.get("insufficient_evidence", 0),
                "dominant_classification": dominant_classification,
                "dominant_classification_fraction": dominant_count / len(entries),
                "all_repeats_same_classification": len(classifications) == 1,
                "selected_evidence_modes": ",".join(evidence_modes),
                "median_ratio_across_repeats": median(ratio_values) if ratio_values else None,
                "worst_ci95_high_across_repeats": max(ci_high_values) if ci_high_values else None,
                "storage_impact_modes": ",".join(sorted(storage_impacts)),
            }
        )
    return out


def campaign_condition_consensus(rows: List[dict]) -> List[dict]:
    grouped: Dict[Tuple[str, str, str, str, str], List[dict]] = defaultdict(list)
    for row in rows:
        grouped[
            (
                row["benchmark_scenario"],
                row["storage_state_label"],
                row["signature_profile"],
                row["hash_algorithm"],
                row["bucket"],
            )
        ].append(row)

    out = []
    for key, entries in sorted(grouped.items()):
        success_rates = [to_float(entry.get("condition_success_rate")) for entry in entries]
        success_rates = [value for value in success_rates if value is not None]
        coverage_rates = [to_float(entry.get("server_total_coverage")) for entry in entries]
        coverage_rates = [value for value in coverage_rates if value is not None]
        relative_iqrs = [to_float(entry.get("relative_iqr_total_ms")) for entry in entries]
        relative_iqrs = [value for value in relative_iqrs if value is not None]
        out.append(
            {
                "benchmark_scenario": key[0],
                "storage_state_label": key[1],
                "signature_profile": key[2],
                "hash_algorithm": key[3],
                "bucket": key[4],
                "repeats_total": len(entries),
                "min_condition_success_rate": min(success_rates) if success_rates else None,
                "min_server_total_coverage": min(coverage_rates) if coverage_rates else None,
                "max_relative_iqr_total_ms": max(relative_iqrs) if relative_iqrs else None,
                "all_repeats_client_valid": all(
                    entry.get("valid_for_client_comparison") == "True" for entry in entries
                ),
                "all_repeats_server_valid": all(
                    entry.get("valid_for_server_comparison") == "True" for entry in entries
                ),
            }
        )
    return out


def build_markdown(
    manifest_path: Path,
    manifest_rows: List[dict],
    recommendation_consensus: List[dict],
    condition_consensus: List[dict],
) -> str:
    viable_rows = [
        row
        for row in recommendation_consensus
        if row["dominant_classification"] in {"viable", "conditional"}
    ]
    unstable_rows = [
        row for row in recommendation_consensus if not row["all_repeats_same_classification"]
    ]
    failing_conditions = [
        row for row in condition_consensus if not row["all_repeats_server_valid"]
    ]

    lines = [
        "# Campaign Analysis",
        "",
        f"- Manifest: `{manifest_path}`",
        f"- Repeats recorded: `{len(manifest_rows)}`",
        "",
        "## Consensus summary",
        f"- Recommendation rows: `{len(recommendation_consensus)}`",
        f"- Rows with viable or conditional dominant outcome: `{len(viable_rows)}`",
        f"- Rows with unstable repeat classification: `{len(unstable_rows)}`",
        f"- Condition/profile rows failing repeat-level server validity: `{len(failing_conditions)}`",
        "",
        "## Stable recommendations",
    ]
    if viable_rows:
        for row in viable_rows[:12]:
            lines.append(
                f"- {row['benchmark_scenario']} | {row['comparison_profile']} | {row['hash_algorithm']} | {row['bucket']} | {row['storage_state_label']}: dominant `{row['dominant_classification']}` across `{row['repeats_total']}` repeats, median ratio `{row['median_ratio_across_repeats']}`."
            )
    else:
        lines.append("- No scenario/profile combination produced a viable or conditional dominant outcome.")

    lines.append("")
    lines.append("## Repeat instability")
    if unstable_rows:
        for row in unstable_rows[:12]:
            lines.append(
                f"- {row['benchmark_scenario']} | {row['comparison_profile']} | {row['hash_algorithm']} | {row['bucket']} | {row['storage_state_label']}: dominant `{row['dominant_classification']}` but classifications vary across repeats."
            )
    else:
        lines.append("- All recommendation rows had stable classifications across repeats.")

    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    manifest_path = Path(args.manifest_tsv)
    if not manifest_path.exists() or not manifest_path.is_file():
        raise SystemExit(f"Manifest file not found: {manifest_path}")

    manifest_rows = read_tsv(manifest_path)
    out_dir = Path(args.output_dir) if args.output_dir else default_output_dir(manifest_path)
    out_dir.mkdir(parents=True, exist_ok=True)

    recommendation_rows: List[dict] = []
    condition_rows: List[dict] = []
    quality_rows: List[dict] = []

    for manifest_row in manifest_rows:
        analysis_dir = Path(manifest_row["analysis_dir"])
        for row in read_csv_if_exists(analysis_dir / "scenario_recommendations.csv"):
            recommendation_rows.append(
                {
                    "state": manifest_row["state"],
                    "repeat_index": manifest_row["repeat_index"],
                    **row,
                }
            )
        for row in read_csv_if_exists(analysis_dir / "condition_quality.csv"):
            condition_rows.append(
                {
                    "state": manifest_row["state"],
                    "repeat_index": manifest_row["repeat_index"],
                    **row,
                }
            )
        quality_path = analysis_dir / "quality_gate.json"
        if quality_path.exists():
            quality_rows.append(
                {
                    "state": manifest_row["state"],
                    "repeat_index": manifest_row["repeat_index"],
                    **json.loads(quality_path.read_text(encoding="utf-8")),
                }
            )

    recommendation_consensus = campaign_recommendation_consensus(recommendation_rows)
    condition_consensus = campaign_condition_consensus(condition_rows)
    interpretation = build_markdown(
        manifest_path=manifest_path,
        manifest_rows=manifest_rows,
        recommendation_consensus=recommendation_consensus,
        condition_consensus=condition_consensus,
    )
    (out_dir / "interpretation.md").write_text(interpretation, encoding="utf-8")

    write_csv(
        out_dir / "campaign_recommendation_consensus.csv",
        recommendation_consensus,
        [
            "benchmark_scenario",
            "storage_state_label",
            "hash_algorithm",
            "bucket",
            "comparison_profile",
            "repeats_total",
            "viable_count",
            "conditional_count",
            "classical_preferred_count",
            "insufficient_evidence_count",
            "dominant_classification",
            "dominant_classification_fraction",
            "all_repeats_same_classification",
            "selected_evidence_modes",
            "median_ratio_across_repeats",
            "worst_ci95_high_across_repeats",
            "storage_impact_modes",
        ],
    )

    write_csv(
        out_dir / "campaign_condition_consensus.csv",
        condition_consensus,
        [
            "benchmark_scenario",
            "storage_state_label",
            "signature_profile",
            "hash_algorithm",
            "bucket",
            "repeats_total",
            "min_condition_success_rate",
            "min_server_total_coverage",
            "max_relative_iqr_total_ms",
            "all_repeats_client_valid",
            "all_repeats_server_valid",
        ],
    )

    write_csv(
        out_dir / "campaign_quality_gate_rows.csv",
        quality_rows,
        sorted({key for row in quality_rows for key in row.keys()}),
    )

    print(f"Campaign analysis written to: {out_dir}")
    print(f"- interpretation: {out_dir / 'interpretation.md'}")
    print(f"- recommendation consensus: {out_dir / 'campaign_recommendation_consensus.csv'}")
    print(f"- condition consensus:      {out_dir / 'campaign_condition_consensus.csv'}")
    print(f"- quality rows:             {out_dir / 'campaign_quality_gate_rows.csv'}")


if __name__ == "__main__":
    main()
