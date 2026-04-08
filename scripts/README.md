# Scripts

- [`run_benchmark_campaign.sh`](/home/denys/hello-pqc/scripts/run_benchmark_campaign.sh): the single benchmark runner for both formal campaigns and `--smoke` sanity runs
- [`generate_benchmark_dataset.py`](/home/denys/hello-pqc/scripts/generate_benchmark_dataset.py): deterministic dataset generation
- [`analyze_benchmark_report.py`](/home/denys/hello-pqc/scripts/analyze_benchmark_report.py): the single benchmark analyzer for report-level evidence outputs
- [`dev/`](/home/denys/hello-pqc/scripts/dev): operational and local-development helpers

The root-level `scripts/` entrypoints are kept lean: one benchmark runner, one
benchmark analyzer, and dataset generation. Less frequently used maintenance
helpers now live under `scripts/dev/`.
