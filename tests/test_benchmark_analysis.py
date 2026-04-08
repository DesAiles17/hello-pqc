import csv
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT_ANALYZER_PATH = REPO_ROOT / "scripts" / "analyze_benchmark_report.py"


def load_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


REPORT_ANALYZER = load_module(REPORT_ANALYZER_PATH, "report_analyzer")

try:
    import matplotlib  # noqa: F401

    HAS_MATPLOTLIB = True
except Exception:
    HAS_MATPLOTLIB = False


def build_synthetic_report(
    *,
    noisy_server: bool = False,
    profile_scale_multiplier: float = 1.0,
    include_sparse_summaries: bool = False,
) -> dict:
    profiles = ["rsa_pss", "ml_dsa", "rsa_pss_ml_dsa"]
    hashes = ["sha256", "keccak256"]
    buckets = ["10KB", "1MB"]
    scenarios = ["workflow", "sign_only", "verify_full"]
    bucket_sizes = {"10KB": 10 * 1024, "1MB": 1024 * 1024}
    bucket_factors = {"10KB": 1.0, "1MB": 1.8}
    profile_factors = {
        "rsa_pss": 1.00,
        "ml_dsa": 1.22 * profile_scale_multiplier,
        "rsa_pss_ml_dsa": 1.48 * profile_scale_multiplier,
    }
    hash_factors = {"sha256": 1.00, "keccak256": 1.10}
    jitter_map = {"warmup": 0.0, "measured-1": -0.04, "measured-2": 0.03, "measured-3": 0.08}

    raw_runs = []
    run_index = 0
    for scenario in scenarios:
        for profile in profiles:
            for hash_algorithm in hashes:
                for bucket in buckets:
                    for phase_label in ["warmup", "measured-1", "measured-2", "measured-3"]:
                        run_index += 1
                        phase = "warmup" if phase_label == "warmup" else "measured"
                        bucket_factor = bucket_factors[bucket]
                        profile_factor = profile_factors[profile]
                        hash_factor = hash_factors[hash_algorithm]
                        jitter = jitter_map[phase_label]
                        file_size = bucket_sizes[bucket]

                        server_hash_ms = round((0.9 * bucket_factor * hash_factor) + jitter, 4)
                        server_object_exists_check_ms = round(0.12 + (0.01 * bucket_factor), 4)
                        server_object_store_ms = round(0.18 * bucket_factor, 4)
                        server_manifest_canonicalize_ms = round(0.25 + (0.03 * bucket_factor), 4)
                        server_db_persist_ms = round(0.30 + (0.02 * bucket_factor), 4)
                        server_rsa_sign_ms = (
                            round((0.55 * profile_factor) + 0.02 + jitter, 4)
                            if profile in {"rsa_pss", "rsa_pss_ml_dsa"}
                            else None
                        )
                        server_ml_dsa_sign_ms = (
                            round((0.85 * profile_factor) + 0.03 + jitter, 4)
                            if profile in {"ml_dsa", "rsa_pss_ml_dsa"}
                            else None
                        )
                        process_component_sum = sum(
                            value
                            for value in [
                                server_hash_ms,
                                server_object_exists_check_ms,
                                server_object_store_ms,
                                server_manifest_canonicalize_ms,
                                server_db_persist_ms,
                                server_rsa_sign_ms,
                                server_ml_dsa_sign_ms,
                            ]
                            if value is not None
                        )
                        server_process_gateway_ms = round(process_component_sum + 0.22 + (0.02 * bucket_factor), 4)

                        server_manifest_fetch_db_lookup_ms = round(0.10 + (0.01 * bucket_factor), 4)
                        server_verify_hash_ms = round((0.70 * bucket_factor * hash_factor) + jitter, 4)
                        server_verify_canonicalize_ms = round(0.20 + (0.02 * bucket_factor), 4)
                        server_signature_verify_ms = round((0.32 * profile_factor) + 0.02 + jitter, 4)
                        server_stored_object_verify_ms = round(0.08 + (0.01 * bucket_factor), 4)
                        server_uploaded_content_verify_ms = round(0.12 + (0.02 * bucket_factor), 4)
                        verify_component_sum = sum(
                            value
                            for value in [
                                server_manifest_fetch_db_lookup_ms,
                                server_verify_hash_ms,
                                server_verify_canonicalize_ms,
                                server_signature_verify_ms,
                                server_stored_object_verify_ms,
                                server_uploaded_content_verify_ms,
                            ]
                            if value is not None
                        )
                        server_verify_gateway_ms = round(verify_component_sum + 0.18 + (0.02 * bucket_factor), 4)

                        if noisy_server and scenario == "sign_only" and profile == "ml_dsa" and bucket == "10KB":
                            if phase_label == "measured-1":
                                server_process_gateway_ms *= 1.0
                            elif phase_label == "measured-2":
                                server_process_gateway_ms *= 3.5
                            elif phase_label == "measured-3":
                                server_process_gateway_ms *= 0.7
                            server_process_gateway_ms = round(server_process_gateway_ms, 4)

                        client_upload_ms = round((0.95 * bucket_factor) + 0.04, 4)
                        client_process_ms = round(server_process_gateway_ms + 0.85, 4)
                        client_verify_ms = round(server_verify_gateway_ms + 0.65, 4)

                        if scenario == "workflow":
                            client_total_ms = round(
                                client_upload_ms + client_process_ms + client_verify_ms,
                                4,
                            )
                            server_total_ms = round(
                                server_process_gateway_ms + server_verify_gateway_ms,
                                4,
                            )
                            upload_http_ok = True
                            process_http_ok = True
                            verify_http_ok = True
                            verify_overall_ok = True
                            storage_bytes_written = int(file_size * 1.02)
                            storage_bytes_read = int(file_size * 1.01)
                        elif scenario == "sign_only":
                            client_total_ms = round(client_upload_ms + client_process_ms, 4)
                            server_total_ms = round(server_process_gateway_ms, 4)
                            client_verify_ms = None
                            upload_http_ok = True
                            process_http_ok = True
                            verify_http_ok = False
                            verify_overall_ok = None
                            storage_bytes_written = int(file_size * 1.01)
                            storage_bytes_read = None
                        else:
                            client_upload_ms = None
                            client_process_ms = None
                            client_total_ms = round(client_verify_ms, 4)
                            server_total_ms = round(server_verify_gateway_ms, 4)
                            upload_http_ok = False
                            process_http_ok = False
                            verify_http_ok = True
                            verify_overall_ok = True
                            storage_bytes_written = None
                            storage_bytes_read = int(file_size * 1.00)

                        rsa_signature_bytes = 384 if profile in {"rsa_pss", "rsa_pss_ml_dsa"} else None
                        ml_dsa_signature_bytes = 3293 if profile in {"ml_dsa", "rsa_pss_ml_dsa"} else None
                        total_signature_bytes = sum(
                            value for value in [rsa_signature_bytes, ml_dsa_signature_bytes] if value is not None
                        )
                        manifest_core_bytes = 180 + (10 if hash_algorithm == "keccak256" else 0)
                        manifest_core_cbor_bytes = 128 + (8 if hash_algorithm == "keccak256" else 0)
                        manifest_envelope_bytes = 110
                        manifest_size_bytes = manifest_core_bytes + manifest_envelope_bytes + total_signature_bytes

                        raw_runs.append(
                            {
                                "run_index": run_index,
                                "phase": phase,
                                "condition_signature_profile": profile,
                                "condition_hash_algorithm": hash_algorithm,
                                "condition_bucket": bucket,
                                "benchmark_scenario": scenario,
                                "storage_state_label": "warm",
                                "campaign_label": "fixture-campaign",
                                "repeat_index": 1,
                                "file_path": f"fixtures/{bucket.lower()}-{scenario}-{profile}-{hash_algorithm}.bin",
                                "file_extension": "bin",
                                "file_size_bytes": file_size,
                                "request_id": f"req-{run_index:05d}",
                                "upload_http_ok": upload_http_ok,
                                "process_http_ok": process_http_ok,
                                "verify_http_ok": verify_http_ok,
                                "scenario_success": True,
                                "verify_overall_ok": verify_overall_ok,
                                "client_upload_ms": client_upload_ms,
                                "client_process_ms": client_process_ms,
                                "client_verify_ms": client_verify_ms,
                                "client_total_ms": client_total_ms,
                                "manifest_size_bytes": manifest_size_bytes,
                                "manifest_core_bytes": manifest_core_bytes,
                                "manifest_core_cbor_bytes": manifest_core_cbor_bytes,
                                "manifest_envelope_bytes": manifest_envelope_bytes,
                                "rsa_signature_bytes": rsa_signature_bytes,
                                "ml_dsa_signature_bytes": ml_dsa_signature_bytes,
                                "total_signature_bytes": total_signature_bytes,
                                "manifest_overhead_pct": round((manifest_size_bytes / file_size) * 100.0, 6),
                                "signature_overhead_pct": round((total_signature_bytes / file_size) * 100.0, 6),
                                "storage_amplification": round(manifest_size_bytes / file_size, 6),
                                "storage_bytes_written": storage_bytes_written,
                                "storage_bytes_read": storage_bytes_read,
                                "client_upload_mib_s": None,
                                "client_process_mib_s": None,
                                "client_verify_mib_s": None,
                                "client_total_mib_s": None,
                                "server_hash_mib_s": None,
                                "server_verify_mib_s": None,
                                "server_total_mib_s": None,
                                "server_process_gateway_ms": server_process_gateway_ms if scenario in {"workflow", "sign_only"} else None,
                                "server_verify_gateway_ms": server_verify_gateway_ms if scenario in {"workflow", "verify_full"} else None,
                                "server_hash_ms": server_hash_ms if scenario in {"workflow", "sign_only"} else None,
                                "server_object_exists_check_ms": server_object_exists_check_ms if scenario in {"workflow", "sign_only"} else None,
                                "server_object_store_ms": server_object_store_ms if scenario in {"workflow", "sign_only"} else None,
                                "server_object_store_hit": False if scenario in {"workflow", "sign_only"} else None,
                                "server_multipart_used": bucket == "1MB" if scenario in {"workflow", "sign_only"} else None,
                                "server_hash_bytes_read": file_size if scenario in {"workflow", "sign_only"} else None,
                                "server_hash_bytes_written": int(file_size * 1.01) if scenario in {"workflow", "sign_only"} else None,
                                "server_manifest_canonicalize_ms": server_manifest_canonicalize_ms if scenario in {"workflow", "sign_only"} else None,
                                "server_db_persist_ms": server_db_persist_ms if scenario in {"workflow", "sign_only"} else None,
                                "server_rsa_sign_ms": server_rsa_sign_ms if scenario in {"workflow", "sign_only"} else None,
                                "server_ml_dsa_sign_ms": server_ml_dsa_sign_ms if scenario in {"workflow", "sign_only"} else None,
                                "server_manifest_fetch_db_lookup_ms": server_manifest_fetch_db_lookup_ms if scenario in {"workflow", "verify_full"} else None,
                                "server_verify_hash_ms": server_verify_hash_ms if scenario in {"workflow", "verify_full"} else None,
                                "server_verify_canonicalize_ms": server_verify_canonicalize_ms if scenario in {"workflow", "verify_full"} else None,
                                "server_signature_verify_ms": server_signature_verify_ms if scenario in {"workflow", "verify_full"} else None,
                                "server_stored_object_verify_ms": server_stored_object_verify_ms if scenario in {"workflow", "verify_full"} else None,
                                "server_uploaded_content_verify_ms": server_uploaded_content_verify_ms if scenario in {"workflow", "verify_full"} else None,
                                "server_verify_ms": (
                                    round(
                                        server_verify_canonicalize_ms
                                        + server_signature_verify_ms
                                        + server_stored_object_verify_ms
                                        + server_uploaded_content_verify_ms,
                                        4,
                                    )
                                    if scenario in {"workflow", "verify_full"}
                                    else None
                                ),
                                "server_total_ms": server_total_ms,
                                "error_stage": None,
                                "error": None,
                            }
                        )

    report = {
        "generated_at": "2026-03-31T12:00:00Z",
        "cli_config": {
            "base_url": "http://localhost:3000",
            "dataset_dir": "./dataset",
            "output_dir": "./output/benchmarks",
            "profiles": profiles,
            "hashes": hashes,
            "buckets": buckets,
            "scenarios": scenarios,
            "measured_runs": 3,
            "warmup_runs": 1,
            "inter_run_delay_ms": 0,
            "seed": 42,
            "operations_endpoint": "http://localhost:3000/operations",
            "bootstrap_samples": 32,
            "storage_state_label": "warm",
            "campaign_label": "fixture-campaign",
            "repeat_index": 1,
        },
        "environment": {
            "git_commit": "fixture-commit",
            "git_dirty": False,
            "build_profile": "release",
            "os": "linux",
            "arch": "x86_64",
            "logical_cores": 8,
            "cpu_model": "Synthetic CPU",
            "total_memory_bytes": 16 * 1024 * 1024 * 1024,
            "hostname": "fixture-host",
        },
        "raw_runs": raw_runs,
        "summaries": (
            [
                {
                    "signature_profile": "rsa_pss",
                    "hash_algorithm": "sha256",
                    "bucket": "10KB",
                    "benchmark_scenario": "workflow",
                    "storage_state_label": "warm",
                    "measured_runs_total": 3,
                    "measured_runs_success": 3,
                    "measured_runs_failed": 0,
                    "scenario_success_rate": 1.0,
                    "verify_success_rate": 1.0,
                }
            ]
            if include_sparse_summaries
            else []
        ),
    }
    return report


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


class AnalyzerUnitTests(unittest.TestCase):
    def test_percentile(self):
        self.assertEqual(REPORT_ANALYZER.percentile([1.0, 2.0, 3.0], 0.5), 2.0)

    def test_coefficient_of_variation(self):
        cv = REPORT_ANALYZER.coefficient_of_variation([10.0, 12.0, 8.0])
        self.assertIsNotNone(cv)
        self.assertGreater(cv, 0.0)

    def test_bootstrap_ratio(self):
        ratio, low, high = REPORT_ANALYZER.bootstrap_ratio([10.0, 11.0], [15.0, 16.0], 64, 7)
        self.assertIsNotNone(ratio)
        self.assertGreater(ratio, 1.0)
        self.assertIsNotNone(low)
        self.assertIsNotNone(high)

    def test_known_server_stage_ms(self):
        run = {
            "server_hash_ms": 1.0,
            "server_object_exists_check_ms": 0.2,
            "server_rsa_sign_ms": 0.5,
            "server_verify_hash_ms": 0.7,
        }
        self.assertAlmostEqual(REPORT_ANALYZER.known_server_stage_ms(run), 2.4)

    def test_server_dispersion_gate_uses_server_relative_iqr(self):
        report = build_synthetic_report()
        target_runs = [
            run
            for run in report["raw_runs"]
            if run["phase"] == "measured"
            and run["benchmark_scenario"] == "sign_only"
            and run["condition_signature_profile"] == "ml_dsa"
            and run["condition_hash_algorithm"] == "sha256"
            and run["condition_bucket"] == "10KB"
        ]
        self.assertEqual(len(target_runs), 3)
        target_runs[0]["server_process_gateway_ms"] = 4.0
        target_runs[0]["server_total_ms"] = 4.0
        target_runs[0]["client_total_ms"] = 8.0
        target_runs[1]["server_process_gateway_ms"] = 12.0
        target_runs[1]["server_total_ms"] = 12.0
        target_runs[1]["client_total_ms"] = 8.2
        target_runs[2]["server_process_gateway_ms"] = 2.5
        target_runs[2]["server_total_ms"] = 2.5
        target_runs[2]["client_total_ms"] = 7.9
        rows = REPORT_ANALYZER.build_condition_quality_rows(
            report,
            min_condition_success_rate=0.90,
            min_server_coverage=1.00,
            max_relative_iqr=0.20,
            max_server_relative_iqr=0.20,
            min_samples=1,
            bootstrap_samples=32,
            report_seed=42,
        )
        target = next(
            row
            for row in rows
            if row["benchmark_scenario"] == "sign_only"
            and row["signature_profile"] == "ml_dsa"
            and row["hash_algorithm"] == "sha256"
            and row["bucket"] == "10KB"
        )
        self.assertTrue(target["valid_for_client_comparison"])
        self.assertFalse(target["valid_for_server_comparison"])


class AnalyzerIntegrationTests(unittest.TestCase):
    def run_report_analyzer(self, report: dict, out_dir: Path, *, skip_plots: bool) -> Path:
        report_path = out_dir / "benchmark-report-fixture.json"
        write_json(report_path, report)
        cmd = [
            sys.executable,
            str(REPORT_ANALYZER_PATH),
            str(report_path),
            "--output-dir",
            str(out_dir / "analysis"),
            "--bootstrap-samples",
            "32",
        ]
        if skip_plots:
            cmd.append("--skip-plots")
        subprocess.run(cmd, cwd=REPO_ROOT, check=True)
        return out_dir / "analysis"

    def test_report_analysis_outputs_and_no_recommendation_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            analysis_dir = self.run_report_analyzer(
                build_synthetic_report(),
                tmp_dir,
                skip_plots=True,
            )
            expected = {
                "analysis_manifest.json",
                "quality_checks.json",
                "condition_quality.csv",
                "latency_summary.csv",
                "artifact_summary.csv",
                "stage_metrics_long.csv",
                "comparison_metrics.csv",
                "run_diagnostics.csv",
            }
            self.assertTrue(expected.issubset({path.name for path in analysis_dir.iterdir()}))
            self.assertFalse((analysis_dir / "scenario_recommendations.csv").exists())
            self.assertFalse((analysis_dir / "interpretation.md").exists())
            self.assertFalse((analysis_dir / "ratio_table.csv").exists())
            self.assertFalse((analysis_dir / "stage_breakdown.csv").exists())

            with (analysis_dir / "comparison_metrics.csv").open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertTrue(any(row["metric_name"] == "server_total_ms" for row in rows))
            self.assertTrue(any(row["metric_name"] == "manifest_size_bytes" for row in rows))

    def test_sparse_summary_report_still_analyzes_via_raw_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            analysis_dir = self.run_report_analyzer(
                build_synthetic_report(include_sparse_summaries=True),
                tmp_dir,
                skip_plots=True,
            )
            self.assertTrue((analysis_dir / "latency_summary.csv").exists())
            self.assertTrue((analysis_dir / "artifact_summary.csv").exists())

    @unittest.skipUnless(HAS_MATPLOTLIB, "matplotlib not installed")
    def test_report_analysis_generates_png_and_svg_figures(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            analysis_dir = self.run_report_analyzer(
                build_synthetic_report(),
                tmp_dir,
                skip_plots=False,
            )
            self.assertTrue((analysis_dir / "fig_total_latency_ci.png").exists())
            self.assertTrue((analysis_dir / "fig_total_latency_ci.svg").exists())
            self.assertTrue((analysis_dir / "fig_server_ratio_ci.png").exists())
            self.assertTrue((analysis_dir / "fig_quality_heatmap.svg").exists())

if __name__ == "__main__":
    unittest.main()
