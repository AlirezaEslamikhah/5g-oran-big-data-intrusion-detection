#!/usr/bin/env python3
"""
05_pyspark_bigdata_pipeline.py

Runs a real local PySpark big-data pipeline on ONE schema-compatible CSV group
created by 04_csv_schema_groups.py.

It measures:
- Number of input files
- Raw input bytes
- Spark row count
- Read time
- Cleaning time
- Duplicate removal
- Aggregations
- Parquet write time
- Parquet output size
- Parquet read time
- CSV vs Parquet storage ratio

This is intended as the local prototype of the later AWS Spark pipeline.

Usage:
  python .\code\05_pyspark_bigdata_pipeline.py --group-id 1

Requirements:
  pip install pyspark
  Java must be installed and available as `java`.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = PROJECT_ROOT / "archive"
RESULTS_DIR = PROJECT_ROOT / "results"
SPARK_OUTPUT_ROOT = PROJECT_ROOT / "spark_output"
INVENTORY = RESULTS_DIR / "csv_file_inventory.csv"


def human_size(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size_bytes)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{size_bytes} B"


def folder_size(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(
        p.stat().st_size
        for p in path.rglob("*")
        if p.is_file()
    )


def java_available() -> bool:
    try:
        proc = subprocess.run(
            ["java", "-version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return proc.returncode == 0
    except Exception:
        return False


def load_group(group_id: int):
    if not INVENTORY.exists():
        raise SystemExit(
            f"Missing {INVENTORY}\n"
            "Run 04_csv_schema_groups.py first."
        )

    rows = []

    with INVENTORY.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:
        reader = csv.DictReader(f)

        for row in reader:
            if int(row["group_id"]) == group_id:
                rows.append(row)

    if not rows:
        raise SystemExit(
            f"No CSV files found for schema group {group_id}."
        )

    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--group-id",
        type=int,
        required=True,
        help="Schema group ID produced by 04_csv_schema_groups.py."
    )
    parser.add_argument(
        "--shuffle-partitions",
        type=int,
        default=8,
        help="Spark SQL shuffle partitions. Default: 8."
    )
    args = parser.parse_args()

    if not java_available():
        raise SystemExit(
            "Java was not found.\n"
            "PySpark requires Java. Install a JDK and reopen PowerShell."
        )

    try:
        from pyspark.sql import SparkSession
        from pyspark.sql import functions as F
    except ImportError:
        raise SystemExit(
            "PySpark is not installed.\n"
            "Run: python -m pip install pyspark"
        )

    rows = load_group(args.group_id)

    raw_bytes = sum(int(x["size_bytes"]) for x in rows)
    detected_type = rows[0]["detected_type"]
    columns = rows[0]["columns"].split("|")

    file_paths = [
        (DATA_ROOT / row["relative_path"]).resolve()
        for row in rows
    ]

    missing = [p for p in file_paths if not p.exists()]
    if missing:
        raise SystemExit(
            "Some input files are missing:\n"
            + "\n".join(str(x) for x in missing[:10])
        )

    output_dir = SPARK_OUTPUT_ROOT / f"group_{args.group_id:02d}_parquet"
    metrics_path = RESULTS_DIR / f"spark_group_{args.group_id:02d}_metrics.json"
    aggregation_path = RESULTS_DIR / f"spark_group_{args.group_id:02d}_aggregations"

    if output_dir.exists():
        shutil.rmtree(output_dir)

    if aggregation_path.exists():
        shutil.rmtree(aggregation_path)

    RESULTS_DIR.mkdir(exist_ok=True)
    SPARK_OUTPUT_ROOT.mkdir(exist_ok=True)

    print("=" * 100)
    print("PYSPARK BIG DATA PIPELINE")
    print("=" * 100)
    print(f"Schema group       : {args.group_id}")
    print(f"Detected type      : {detected_type}")
    print(f"Input files        : {len(file_paths):,}")
    print(f"Raw input size     : {human_size(raw_bytes)}")
    print(f"Columns            : {len(columns)}")
    print(f"Shuffle partitions : {args.shuffle_partitions}")
    print()
    print("This job will read ALL rows in this schema group.")
    print()

    spark = (
        SparkSession.builder
        .appName(f"BigDataProject_Group_{args.group_id}")
        .master("local[*]")
        .config("spark.sql.shuffle.partitions", str(args.shuffle_partitions))
        .config("spark.sql.adaptive.enabled", "true")
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("WARN")

    metrics = {
        "group_id": args.group_id,
        "detected_type": detected_type,
        "input_file_count": len(file_paths),
        "raw_input_size_bytes": raw_bytes,
        "raw_input_size_human": human_size(raw_bytes),
        "column_count": len(columns),
        "input_columns": columns,
    }

    try:
        # ------------------------------------------------------------------
        # 1. CSV ingestion
        # ------------------------------------------------------------------
        print("[1/6] Reading CSV files with Spark...")
        read_start = time.time()

        spark_paths = [p.as_uri() for p in file_paths]

        df = (
            spark.read
            .option("header", "true")
            .option("inferSchema", "true")
            .option("mode", "PERMISSIVE")
            .csv(spark_paths)
        )

        input_rows = df.count()
        read_seconds = time.time() - read_start

        metrics["input_rows"] = input_rows
        metrics["csv_read_seconds"] = read_seconds

        print(f"      Rows read : {input_rows:,}")
        print(f"      Read time : {read_seconds:.2f} sec")
        print()

        # ------------------------------------------------------------------
        # 2. Cleaning
        # ------------------------------------------------------------------
        print("[2/6] Cleaning...")
        clean_start = time.time()

        # Drop rows where every column is null.
        cleaned = df.dropna(how="all")

        # Deduplicate full identical rows. This is intentionally a Spark
        # shuffle operation and is useful to demonstrate distributed cleaning.
        cleaned = cleaned.dropDuplicates()

        cleaned_rows = cleaned.count()
        clean_seconds = time.time() - clean_start

        metrics["cleaned_rows"] = cleaned_rows
        metrics["duplicates_or_empty_removed"] = input_rows - cleaned_rows
        metrics["cleaning_seconds"] = clean_seconds

        print(f"      Clean rows        : {cleaned_rows:,}")
        print(f"      Rows removed      : {input_rows - cleaned_rows:,}")
        print(f"      Cleaning time     : {clean_seconds:.2f} sec")
        print()

        lower_map = {c.lower(): c for c in cleaned.columns}

        # ------------------------------------------------------------------
        # 3. Big-data aggregations
        # ------------------------------------------------------------------
        print("[3/6] Running aggregations...")
        agg_start = time.time()

        aggregation_frames = []

        for candidate in [
            "traffic_type",
            "attack_category",
            "attack_type",
            "attack_subcategory",
            "proto",
            "service",
            "conn_state",
        ]:
            actual = lower_map.get(candidate)
            if actual:
                agg = (
                    cleaned
                    .groupBy(actual)
                    .count()
                    .orderBy(F.desc("count"))
                )
                aggregation_frames.append((candidate, agg))

        if detected_type in {"radio", "mixed_network_radio"}:
            numeric_candidates = [
                "rsrp", "rsrq", "rssi", "sinr", "cqi",
                "dlmcs", "ulmcs", "dlbler", "ulbler"
            ]

            expressions = []
            for candidate in numeric_candidates:
                actual = lower_map.get(candidate)
                if actual:
                    expressions += [
                        F.avg(F.col(actual).cast("double")).alias(f"{candidate}_avg"),
                        F.min(F.col(actual).cast("double")).alias(f"{candidate}_min"),
                        F.max(F.col(actual).cast("double")).alias(f"{candidate}_max"),
                    ]

            if expressions:
                summary_df = cleaned.agg(*expressions)
                aggregation_frames.append(("radio_numeric_summary", summary_df))

        # Materialize + save each aggregation as CSV.
        aggregation_path.mkdir(parents=True, exist_ok=True)

        aggregation_summaries = {}

        for name, agg_df in aggregation_frames:
            preview = [r.asDict() for r in agg_df.limit(20).collect()]
            aggregation_summaries[name] = preview

            target = aggregation_path / name
            if target.exists():
                shutil.rmtree(target)

            (
                agg_df.coalesce(1)
                .write
                .mode("overwrite")
                .option("header", "true")
                .csv(target.as_uri())
            )

        agg_seconds = time.time() - agg_start
        metrics["aggregation_seconds"] = agg_seconds
        metrics["aggregations"] = aggregation_summaries

        print(f"      Aggregations      : {len(aggregation_frames)}")
        print(f"      Aggregation time  : {agg_seconds:.2f} sec")
        print()

        # ------------------------------------------------------------------
        # 4. Write Parquet
        # ------------------------------------------------------------------
        print("[4/6] Writing Parquet...")
        write_start = time.time()

        write_df = cleaned.repartition(args.shuffle_partitions)

        partition_column = None
        for candidate in ["attack_category", "traffic_type"]:
            if candidate in lower_map:
                partition_column = lower_map[candidate]
                break

        writer = (
            write_df.write
            .mode("overwrite")
            .option("compression", "snappy")
        )

        if partition_column:
            writer = writer.partitionBy(partition_column)

        writer.parquet(output_dir.as_uri())

        write_seconds = time.time() - write_start
        parquet_bytes = folder_size(output_dir)

        metrics["parquet_write_seconds"] = write_seconds
        metrics["parquet_size_bytes"] = parquet_bytes
        metrics["parquet_size_human"] = human_size(parquet_bytes)
        metrics["partition_column"] = partition_column

        if raw_bytes:
            metrics["parquet_vs_csv_size_ratio"] = parquet_bytes / raw_bytes
            metrics["storage_reduction_percent"] = (
                1 - parquet_bytes / raw_bytes
            ) * 100

        print(f"      Parquet size      : {human_size(parquet_bytes)}")
        print(f"      Write time        : {write_seconds:.2f} sec")
        print(f"      Partition column  : {partition_column}")
        print()

        # ------------------------------------------------------------------
        # 5. Re-read Parquet benchmark
        # ------------------------------------------------------------------
        print("[5/6] Re-reading Parquet...")
        parquet_read_start = time.time()

        parquet_df = spark.read.parquet(output_dir.as_uri())
        parquet_rows = parquet_df.count()

        parquet_read_seconds = time.time() - parquet_read_start

        metrics["parquet_rows"] = parquet_rows
        metrics["parquet_read_seconds"] = parquet_read_seconds

        if parquet_read_seconds > 0:
            metrics["csv_vs_parquet_read_speedup"] = (
                read_seconds / parquet_read_seconds
            )

        print(f"      Rows              : {parquet_rows:,}")
        print(f"      Read time         : {parquet_read_seconds:.2f} sec")
        print()

        # ------------------------------------------------------------------
        # 6. Summary
        # ------------------------------------------------------------------
        print("[6/6] Final summary")
        print("-" * 100)
        print(f"Input CSV files       : {len(file_paths):,}")
        print(f"Input CSV size        : {human_size(raw_bytes)}")
        print(f"Rows read             : {input_rows:,}")
        print(f"Rows after cleaning   : {cleaned_rows:,}")
        print(f"CSV read time         : {read_seconds:.2f} sec")
        print(f"Cleaning time         : {clean_seconds:.2f} sec")
        print(f"Aggregation time      : {agg_seconds:.2f} sec")
        print(f"Parquet write time    : {write_seconds:.2f} sec")
        print(f"Parquet size          : {human_size(parquet_bytes)}")
        print(f"Parquet read time     : {parquet_read_seconds:.2f} sec")

        if raw_bytes:
            reduction = metrics["storage_reduction_percent"]
            print(f"Storage reduction     : {reduction:.2f}%")

        if parquet_read_seconds > 0:
            speedup = metrics["csv_vs_parquet_read_speedup"]
            print(f"Read speed ratio      : {speedup:.2f}x (CSV time / Parquet time)")

        metrics_path.write_text(
            json.dumps(metrics, indent=2),
            encoding="utf-8"
        )

        print()
        print("SAVED")
        print("-" * 100)
        print(metrics_path)
        print(output_dir)
        print(aggregation_path)

    finally:
        spark.stop()


if __name__ == "__main__":
    main()
