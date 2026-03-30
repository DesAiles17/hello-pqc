#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import shutil
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

BUCKET_SIZES: Dict[str, int] = {
    "10KB": 10 * 1024,
    "100KB": 100 * 1024,
    "1MB": 1 * 1024 * 1024,
    "10MB": 10 * 1024 * 1024,
    "50MB": 50 * 1024 * 1024,
}

DEFAULT_FILE_TYPES = ["bin", "txt", "json", "csv", "md"]
ASCII_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def deterministic_bytes(seed: str, *parts: object, length: int) -> bytes:
    out = bytearray()
    counter = 0
    prefix = ":".join([seed, *[str(part) for part in parts]]).encode("utf-8")

    while len(out) < length:
        block = hashlib.sha256(prefix + b":" + str(counter).encode("utf-8")).digest()
        out.extend(block)
        counter += 1

    return bytes(out[:length])


def deterministic_int(seed: str, *parts: object, modulo: int) -> int:
    if modulo <= 0:
        return 0
    digest = hashlib.sha256(
        ":".join([seed, *[str(part) for part in parts]]).encode("utf-8")
    ).digest()
    return int.from_bytes(digest[:8], "big") % modulo


def bucket_bounds(bucket: str) -> Tuple[int, int]:
    ordered = list(BUCKET_SIZES.items())
    previous_upper = 0
    for label, upper in ordered:
        lower = previous_upper + 1
        if label == ordered[0][0]:
            lower = max(1, upper // 2)
        if label == bucket:
            return lower, upper
        previous_upper = upper
    raise KeyError(bucket)


def choose_size(seed: str, bucket: str, index: int, total: int) -> int:
    lower, upper = bucket_bounds(bucket)
    if lower >= upper:
        return upper

    width = upper - lower
    if total == 1:
        base_offset = width // 2
    else:
        base_offset = round(width * ((index - 1) / (total - 1)))
    jitter_window = max(1, width // max(total * 4, 1))
    jitter = deterministic_int(seed, bucket, index, "size", modulo=(jitter_window * 2) + 1)
    jitter -= jitter_window
    return max(lower, min(upper, lower + base_offset + jitter))


def deterministic_text(seed: str, bucket: str, index: int, length: int, label: str) -> str:
    if length <= 0:
        return ""
    chars: List[str] = []
    counter = 0
    while len(chars) < length:
        block = deterministic_bytes(seed, bucket, index, label, counter, length=32)
        for value in block:
            chars.append(ASCII_ALPHABET[value % len(ASCII_ALPHABET)])
            if len(chars) >= length:
                break
        counter += 1
    return "".join(chars[:length])


def render_text_document(
    seed: str, bucket: str, index: int, length: int, kind: str
) -> bytes:
    header = f"# benchmark-{kind} bucket={bucket} index={index}\n"
    body = deterministic_text(seed, bucket, index, max(0, length - len(header)), kind)
    return (header + body)[:length].encode("utf-8")


def render_csv_document(seed: str, bucket: str, index: int, length: int) -> bytes:
    header = "bucket,index,record_id,payload\n"
    if length <= len(header):
        return header[:length].encode("utf-8")

    rows = [header]
    remaining = length - len(header)
    row_index = 0
    while remaining > 0:
        row_index += 1
        payload_budget = max(1, min(remaining - 1, 128))
        payload = deterministic_text(seed, bucket, f"{index}:{row_index}", payload_budget, "csv")
        row = f"{bucket},{index},{row_index},{payload}\n"
        if len(row) > remaining:
            payload_budget = max(0, remaining - len(f"{bucket},{index},{row_index},\n"))
            payload = deterministic_text(
                seed, bucket, f"{index}:{row_index}:tail", payload_budget, "csv"
            )
            row = f"{bucket},{index},{row_index},{payload}\n"
        rows.append(row[:remaining])
        remaining -= len(rows[-1])
    return "".join(rows).encode("utf-8")[:length]


def render_json_document(seed: str, bucket: str, index: int, length: int) -> bytes:
    if length < 32:
        return render_text_document(seed, bucket, index, length, "json-fallback")

    prefix_obj = {
        "bucket": bucket,
        "index": index,
        "kind": "benchmark-json",
        "payload": "",
    }
    rendered = json.dumps(prefix_obj, separators=(",", ":"))
    payload_len = max(0, length - len(rendered))
    payload = deterministic_text(seed, bucket, index, payload_len, "json")
    prefix_obj["payload"] = payload
    document = json.dumps(prefix_obj, separators=(",", ":"))
    if len(document) < length:
        padding = deterministic_text(seed, bucket, f"{index}:pad", length - len(document), "json")
        prefix_obj["payload"] += padding
        document = json.dumps(prefix_obj, separators=(",", ":"))
    return document[:length].encode("utf-8")


def render_file(seed: str, bucket: str, index: int, size: int, file_type: str) -> bytes:
    if file_type == "bin":
        return deterministic_bytes(seed, bucket, index, "bin", length=size)
    if file_type == "txt":
        return render_text_document(seed, bucket, index, size, "txt")
    if file_type == "md":
        return render_text_document(seed, bucket, index, size, "md")
    if file_type == "csv":
        return render_csv_document(seed, bucket, index, size)
    if file_type == "json":
        return render_json_document(seed, bucket, index, size)
    raise ValueError(f"Unsupported file type: {file_type}")


def normalize_file_types(raw: str) -> List[str]:
    values = []
    for item in raw.split(","):
        normalized = item.strip().lower()
        if not normalized:
            continue
        if normalized not in {"bin", "txt", "json", "csv", "md"}:
            raise SystemExit(f"Unsupported file type '{normalized}'")
        if normalized not in values:
            values.append(normalized)
    if not values:
        raise SystemExit("At least one file type is required")
    return values


def clean_output_dir(output_root: Path, bucket_names: Iterable[str]) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    for bucket in bucket_names:
        bucket_dir = output_root / bucket
        if bucket_dir.exists():
            shutil.rmtree(bucket_dir)
    for name in ("dataset-manifest.csv", "dataset-metadata.json"):
        target = output_root / name
        if target.exists():
            target.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate deterministic mixed benchmark datasets for benchmark-cli"
    )
    parser.add_argument(
        "--output-dir",
        default="benchmark-dataset",
        help="Output directory (default: benchmark-dataset)",
    )
    parser.add_argument(
        "--files-per-bucket",
        type=int,
        default=32,
        help="Files to generate per bucket (default: 32)",
    )
    parser.add_argument(
        "--seed",
        default="pqc-hons-benchmark-dataset-v2",
        help="Deterministic seed string",
    )
    parser.add_argument(
        "--file-types",
        default=",".join(DEFAULT_FILE_TYPES),
        help="Comma-separated file types from: bin,txt,json,csv,md",
    )
    parser.add_argument(
        "--keep-existing",
        action="store_true",
        help="Do not clear existing bucket folders before generation",
    )

    args = parser.parse_args()

    if args.files_per_bucket < 1:
        raise SystemExit("--files-per-bucket must be >= 1")

    file_types = normalize_file_types(args.file_types)
    output_root = Path(args.output_dir)
    if not args.keep_existing:
        clean_output_dir(output_root, BUCKET_SIZES.keys())
    output_root.mkdir(parents=True, exist_ok=True)

    rows: List[dict] = []
    created = 0

    for bucket in BUCKET_SIZES:
        bucket_dir = output_root / bucket
        bucket_dir.mkdir(parents=True, exist_ok=True)

        for index in range(1, args.files_per_bucket + 1):
            file_type = file_types[(index - 1) % len(file_types)]
            size = choose_size(args.seed, bucket, index, args.files_per_bucket)
            file_name = f"{bucket.lower()}-{index:03d}.{file_type}"
            file_path = bucket_dir / file_name
            file_path.write_bytes(render_file(args.seed, bucket, index, size, file_type))
            created += 1
            rows.append(
                {
                    "bucket": bucket,
                    "index": index,
                    "file_type": file_type,
                    "size_bytes": size,
                    "relative_path": str(file_path.relative_to(output_root)),
                    "seed": args.seed,
                }
            )

    with (output_root / "dataset-manifest.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["bucket", "index", "file_type", "size_bytes", "relative_path", "seed"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    metadata = {
        "seed": args.seed,
        "files_per_bucket": args.files_per_bucket,
        "file_types": file_types,
        "bucket_upper_bounds": BUCKET_SIZES,
    }
    (output_root / "dataset-metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )

    print(f"Generated {created} files in {output_root.resolve()}")
    print(f"Seed: {args.seed}")
    print(f"File types: {','.join(file_types)}")
    for bucket in BUCKET_SIZES:
        bucket_rows = [row for row in rows if row["bucket"] == bucket]
        sizes = [row["size_bytes"] for row in bucket_rows]
        types = sorted({row["file_type"] for row in bucket_rows})
        print(
            f"- {bucket}: {len(bucket_rows)} files, size range {min(sizes)}..{max(sizes)} bytes, "
            f"types={','.join(types)}"
        )


if __name__ == "__main__":
    main()
