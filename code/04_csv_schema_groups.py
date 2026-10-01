#!/usr/bin/env python3
"""
04_csv_schema_groups.py

Fast schema inventory for every CSV under ../archive.

IMPORTANT:
- Reads ONLY the header / first chunk of each CSV.
- Does NOT load full CSV files into memory.
- Groups files that have the same normalized column set.
- Reports how much data belongs to each schema group.

Outputs under ../results:
  csv_schema_groups.csv
  csv_schema_groups.txt
  csv_file_inventory.csv
  csv_schema_errors.csv
"""

from __future__ import annotations

import csv
import re
from collections import defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = PROJECT_ROOT / "archive"
RESULTS_DIR = PROJECT_ROOT / "results"


def human_size(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size_bytes)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{size_bytes} B"


def normalize_column(name: str) -> str:
    name = name.strip().strip('"').strip("'")
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"[^A-Za-z0-9_]+", "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    return name.lower()


def detect_type(columns: list[str]) -> str:
    s = set(columns)

    network_markers = {
        "src_ip", "dst_ip", "src_port", "dst_port",
        "proto", "duration", "src_bytes", "dst_bytes"
    }
    radio_markers = {
        "rsrp", "rsrq", "rssi", "sinr", "cqi",
        "dlmcs", "ulmcs", "dlbler", "ulbler"
    }
    packet_markers = {
        "frame_number", "frame_time_epoch", "frame_len",
        "ip_src", "ip_dst", "tcp_srcport", "tcp_dstport"
    }

    network_score = len(s & network_markers)
    radio_score = len(s & radio_markers)
    packet_score = len(s & packet_markers)

    if network_score >= 4 and radio_score >= 3:
        return "mixed_network_radio"
    if radio_score >= 3:
        return "radio"
    if network_score >= 4:
        return "network_flow"
    if packet_score >= 3:
        return "packet_level"
    return "other"


def read_header(path: Path):
    encodings = ["utf-8-sig", "utf-8", "latin-1"]

    last_error = None

    for encoding in encodings:
        try:
            with path.open("r", encoding=encoding, errors="strict", newline="") as f:
                sample = f.read(131072)

            if not sample.strip():
                return [], ",", encoding

            try:
                dialect = csv.Sniffer().sniff(
                    sample,
                    delimiters=",;\t|"
                )
                delimiter = dialect.delimiter
            except csv.Error:
                delimiter = ","

            first_line = sample.splitlines()[0] if sample.splitlines() else ""
            row = next(csv.reader([first_line], delimiter=delimiter))

            columns = [
                normalize_column(x)
                for x in row
                if normalize_column(x)
            ]

            return columns, delimiter, encoding

        except Exception as exc:
            last_error = exc

    raise RuntimeError(str(last_error))


def main():
    if not DATA_ROOT.exists():
        raise SystemExit(f"Dataset folder not found: {DATA_ROOT}")

    RESULTS_DIR.mkdir(exist_ok=True)

    csv_files = sorted(DATA_ROOT.rglob("*.csv"))

    print("=" * 100)
    print("CSV SCHEMA GROUP ANALYSIS")
    print("=" * 100)
    print(f"Dataset root : {DATA_ROOT}")
    print(f"CSV files    : {len(csv_files):,}")
    print("Reading headers only...")
    print()

    parsed = []
    errors = []

    for i, path in enumerate(csv_files, start=1):
        rel = path.relative_to(DATA_ROOT)
        size = path.stat().st_size

        try:
            columns, delimiter, encoding = read_header(path)

            if not columns:
                raise RuntimeError("No header columns detected")

            canonical_schema = tuple(sorted(columns))

            parsed.append({
                "path": path,
                "relative_path": str(rel),
                "size_bytes": size,
                "columns": columns,
                "canonical_schema": canonical_schema,
                "delimiter": repr(delimiter),
                "encoding": encoding,
                "detected_type": detect_type(columns),
            })

        except Exception as exc:
            errors.append({
                "relative_path": str(rel),
                "size_bytes": size,
                "error": repr(exc),
            })

        if i % 20 == 0 or i == len(csv_files):
            print(f"Checked {i:,}/{len(csv_files):,} CSV files")

    grouped = defaultdict(list)
    for item in parsed:
        grouped[item["canonical_schema"]].append(item)

    groups = []

    for schema, items in grouped.items():
        total_bytes = sum(x["size_bytes"] for x in items)
        type_counts = defaultdict(int)
        for x in items:
            type_counts[x["detected_type"]] += 1

        detected_type = max(type_counts, key=type_counts.get)

        groups.append({
            "schema": schema,
            "items": items,
            "total_bytes": total_bytes,
            "file_count": len(items),
            "column_count": len(schema),
            "detected_type": detected_type,
        })

    groups.sort(
        key=lambda g: (g["total_bytes"], g["file_count"]),
        reverse=True
    )

    for idx, group in enumerate(groups, start=1):
        group["group_id"] = idx
        for item in group["items"]:
            item["group_id"] = idx

    total_csv_bytes = sum(x["size_bytes"] for x in parsed)

    print()
    print("=" * 100)
    print("SCHEMA GROUPS")
    print("=" * 100)
    print(f"Successfully inspected : {len(parsed):,} files")
    print(f"Errors                 : {len(errors):,} files")
    print(f"Total CSV bytes        : {human_size(total_csv_bytes)}")
    print(f"Distinct schema groups : {len(groups):,}")
    print()

    for group in groups:
        pct = (
            group["total_bytes"] / total_csv_bytes * 100
            if total_csv_bytes else 0
        )
        print(
            f"GROUP {group['group_id']:02d} | "
            f"{group['detected_type']:20} | "
            f"{group['file_count']:3d} files | "
            f"{human_size(group['total_bytes']):>10} | "
            f"{pct:6.2f}% of CSV bytes | "
            f"{group['column_count']} columns"
        )

        sample_items = sorted(
            group["items"],
            key=lambda x: x["size_bytes"],
            reverse=True
        )[:3]

        for item in sample_items:
            print(
                f"    {human_size(item['size_bytes']):>10} | "
                f"{item['relative_path']}"
            )

        print("    Columns:", ", ".join(group["schema"]))
        print()

    groups_csv = RESULTS_DIR / "csv_schema_groups.csv"
    inventory_csv = RESULTS_DIR / "csv_file_inventory.csv"
    errors_csv = RESULTS_DIR / "csv_schema_errors.csv"
    report_txt = RESULTS_DIR / "csv_schema_groups.txt"

    with groups_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow([
            "group_id",
            "detected_type",
            "file_count",
            "total_size_bytes",
            "total_size_gb",
            "percent_of_csv_bytes",
            "column_count",
            "columns",
            "largest_example",
        ])

        for group in groups:
            pct = (
                group["total_bytes"] / total_csv_bytes * 100
                if total_csv_bytes else 0
            )
            largest = max(
                group["items"],
                key=lambda x: x["size_bytes"]
            )

            writer.writerow([
                group["group_id"],
                group["detected_type"],
                group["file_count"],
                group["total_bytes"],
                round(group["total_bytes"] / (1024 ** 3), 6),
                round(pct, 4),
                group["column_count"],
                "|".join(group["schema"]),
                largest["relative_path"],
            ])

    with inventory_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow([
            "group_id",
            "detected_type",
            "relative_path",
            "size_bytes",
            "size_mb",
            "delimiter",
            "encoding",
            "column_count",
            "columns",
        ])

        for item in sorted(
            parsed,
            key=lambda x: (
                x["group_id"],
                -x["size_bytes"],
                x["relative_path"].lower(),
            ),
        ):
            writer.writerow([
                item["group_id"],
                item["detected_type"],
                item["relative_path"],
                item["size_bytes"],
                round(item["size_bytes"] / (1024 ** 2), 4),
                item["delimiter"],
                item["encoding"],
                len(item["columns"]),
                "|".join(item["columns"]),
            ])

    with errors_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["relative_path", "size_bytes", "error"]
        )
        writer.writeheader()
        writer.writerows(errors)

    lines = [
        "CSV SCHEMA GROUP ANALYSIS",
        "=" * 100,
        f"Dataset root: {DATA_ROOT}",
        f"CSV files found: {len(csv_files):,}",
        f"Successfully inspected: {len(parsed):,}",
        f"Errors: {len(errors):,}",
        f"Total CSV size: {human_size(total_csv_bytes)}",
        f"Distinct schema groups: {len(groups):,}",
        "",
    ]

    for group in groups:
        pct = (
            group["total_bytes"] / total_csv_bytes * 100
            if total_csv_bytes else 0
        )

        lines += [
            f"GROUP {group['group_id']:02d}",
            f"Detected type : {group['detected_type']}",
            f"Files         : {group['file_count']:,}",
            f"Data size     : {human_size(group['total_bytes'])}",
            f"CSV share     : {pct:.2f}%",
            f"Columns       : {group['column_count']}",
            "Column names  : " + ", ".join(group["schema"]),
            "Examples:",
        ]

        for item in sorted(
            group["items"],
            key=lambda x: x["size_bytes"],
            reverse=True
        )[:5]:
            lines.append(
                f"  {human_size(item['size_bytes']):>10} | "
                f"{item['relative_path']}"
            )

        lines += ["", "-" * 100, ""]

    report_txt.write_text(
        "\n".join(lines),
        encoding="utf-8"
    )

    print("=" * 100)
    print("SAVED")
    print("=" * 100)
    print(groups_csv)
    print(inventory_csv)
    print(errors_csv)
    print(report_txt)
    print()
    print("NEXT:")
    print("Choose a schema group with meaningful size, then run:")
    print("python .\\code\\05_pyspark_bigdata_pipeline.py --group-id <NUMBER>")


if __name__ == "__main__":
    main()
