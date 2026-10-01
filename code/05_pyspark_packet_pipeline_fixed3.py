#!/usr/bin/env python3
r"""
05_pyspark_packet_pipeline_fixed2.py

Main local Big Data pipeline for Schema Group 01:
35 packet-level CSV files, about 6.39 GB.

Why this script is tailored to Group 01:
- Reads ALL files in the group.
- Avoids expensive full-row dropDuplicates by default.
- Reads columns as strings first, then casts known numeric fields.
- Adds source_file and scenario labels from filenames.
- Measures data volume, row counts, processing times, and storage reduction.
- Produces meaningful packet-level aggregations.
- Writes cleaned data as Snappy Parquet partitioned by scenario_group.
- Benchmarks CSV reading vs Parquet reading.

Expected project layout:
Big_Data_Project/
├── archive/
├── code/
│   ├── 04_csv_schema_groups.py
│   └── 05_pyspark_packet_pipeline_fixed2.py
├── results/
└── spark_output/

Requirements:
  python -m pip install pyspark
  Java/JDK available from PowerShell as: java -version

Run:
  cd C:\Users\aen593\Desktop\Big_Data_Project
  python .\code\05_pyspark_packet_pipeline_fixed2.py
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = PROJECT_ROOT / "archive"
RESULTS_DIR = PROJECT_ROOT / "results"
SPARK_OUTPUT_ROOT = PROJECT_ROOT / "spark_output"

INVENTORY = RESULTS_DIR / "csv_file_inventory.csv"
GROUP_ID = 1

NUMERIC_COLUMNS = [
    "frame_len",
    "icmp_code",
    "icmp_type",
    "ip_flags",
    "ip_id",
    "ip_len",
    # "ip_proto" intentionally kept as string; some rows contain values like "17,6".
    "ip_ttl",
    "tcp_ack",
    "tcp_dstport",
    "tcp_flags",
    "tcp_len",
    "tcp_seq",
    "tcp_srcport",
    "tcp_stream",
    "tcp_window_size_value",
    "udp_dstport",
    "udp_length",
    "udp_srcport",
]


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


def spark_local_path(path: Path) -> str:
    """
    Return a Spark/Hadoop-safe local file URI without percent-encoding spaces.

    pathlib.Path.as_uri() converts spaces to %20. On Windows, some Spark/Hadoop
    local-filesystem combinations then look for a literal path containing %20.
    Example wanted by Spark:
        file:///C:/Users/name/My Folder/data.csv
    not:
        file:///C:/Users/name/My%20Folder/data.csv
    """
    path = path.resolve()
    posix = path.as_posix()

    if os.name == "nt":
        return "file:///" + posix

    return "file://" + posix


def java_available() -> bool:
    try:
        p = subprocess.run(
            ["java", "-version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return p.returncode == 0
    except Exception:
        return False


def load_group_files():
    if not INVENTORY.exists():
        raise SystemExit(
            f"Missing inventory: {INVENTORY}\n"
            "Run 04_csv_schema_groups.py first."
        )

    rows = []
    with INVENTORY.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if int(row["group_id"]) == GROUP_ID:
                rows.append(row)

    if not rows:
        raise SystemExit("Schema Group 01 was not found in the inventory.")

    paths = []
    total_bytes = 0

    for row in rows:
        path = DATA_ROOT / row["relative_path"]
        if not path.exists():
            raise SystemExit(f"Missing input file: {path}")
        paths.append(path.resolve())
        total_bytes += int(row["size_bytes"])

    return rows, paths, total_bytes


def sanitize_spark_columns(df):
    """
    Rename Spark columns like 'frame.time' -> 'frame_time'.

    Spark treats dots in column names as nested-field separators unless they are
    escaped with backticks. Normalizing once after reading keeps the rest of the
    pipeline simple and avoids unresolved-column errors.
    """
    seen = set()
    renamed = df

    for old_name in df.columns:
        new_name = re.sub(r"[^A-Za-z0-9_]+", "_", old_name).strip("_").lower()
        new_name = re.sub(r"_+", "_", new_name)

        if not new_name:
            new_name = "column"

        base = new_name
        suffix = 2
        while new_name in seen:
            new_name = f"{base}_{suffix}"
            suffix += 1

        seen.add(new_name)

        if old_name != new_name:
            renamed = renamed.withColumnRenamed(old_name, new_name)

    return renamed


def scenario_from_filename_expr(F):
    """
    Create scenario labels only from explicit filename patterns.
    We keep the label simple and transparent.
    """
    name = F.lower(F.regexp_extract(F.col("source_file"), r"([^/\\]+)$", 1))

    return (
        F.when(name.rlike(r"filteredbenign\d+\.csv$"), F.lit("Benign"))
         .when(name.rlike(r"filteredddosicmp\d+\.csv$"), F.lit("DDoS_ICMP"))
         .when(name.rlike(r"filteredddossyn\d+\.csv$"), F.lit("DDoS_SYN"))
         .when(name.rlike(r"filteredddostcp\d+\.csv$"), F.lit("DDoS_TCP"))
         .when(name.rlike(r"filteredddosudp\d+\.csv$"), F.lit("DDoS_UDP"))
         .when(name.rlike(r"filteredportscan\d+\.csv$"), F.lit("Probe_PortScan"))
         .when(name.rlike(r"filteredsyn\d+\.csv$"), F.lit("DoS_SYN"))
         .when(name.rlike(r"filteredicmp\d+\.csv$"), F.lit("DoS_ICMP"))
         .when(name.rlike(r"filteredtcp\d+\.csv$"), F.lit("DoS_TCP"))
         .when(name.rlike(r"filteredudp\d+\.csv$"), F.lit("DoS_UDP"))
         .otherwise(F.lit("Other"))
    )


def main():
    if not java_available():
        raise SystemExit(
            "Java/JDK was not found.\n"
            "Run: java -version\n"
            "PySpark requires Java."
        )

    try:
        from pyspark.sql import SparkSession
        from pyspark.sql import functions as F
    except ImportError:
        raise SystemExit(
            "PySpark is not installed.\n"
            "Run: python -m pip install pyspark"
        )

    rows, paths, raw_bytes = load_group_files()

    RESULTS_DIR.mkdir(exist_ok=True)
    SPARK_OUTPUT_ROOT.mkdir(exist_ok=True)

    parquet_dir = SPARK_OUTPUT_ROOT / "group_01_packet_parquet"
    agg_dir = RESULTS_DIR / "group_01_packet_aggregations"
    metrics_path = RESULTS_DIR / "group_01_bigdata_metrics.json"
    summary_path = RESULTS_DIR / "group_01_bigdata_summary.txt"

    if parquet_dir.exists():
        shutil.rmtree(parquet_dir)
    if agg_dir.exists():
        shutil.rmtree(agg_dir)

    print("=" * 100)
    print("BIG DATA PIPELINE - GROUP 01 PACKET DATA")
    print("=" * 100)
    print(f"Input files     : {len(paths):,}")
    print(f"Raw input size  : {human_size(raw_bytes)}")
    print(f"CSV share       : 96.60% of all structured CSV bytes")
    print("Schema          : packet-level network data")
    print("Processing mode : FULL DATASET GROUP (not a sample)")
    print()
    print("This stage is for Big Data processing/analytics, not model tuning.")
    print()

    spark = (
        SparkSession.builder
        .appName("BigDataProject_PacketPipeline")
        .master("local[*]")
        .config("spark.sql.shuffle.partitions", "12")
        .config("spark.sql.adaptive.enabled", "true")
        .config("spark.sql.files.maxPartitionBytes", str(128 * 1024 * 1024))
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("WARN")

    metrics = {
        "schema_group": 1,
        "input_files": len(paths),
        "raw_input_size_bytes": raw_bytes,
        "raw_input_size_human": human_size(raw_bytes),
        "processing_scope": "full_group",
    }

    try:
        spark_paths = [spark_local_path(p) for p in paths]

        print("Spark path check:")
        print("      First input path :", spark_paths[0])
        print("      Last input path  :", spark_paths[-1])
        print()

        # ------------------------------------------------------------------
        # 1) Read all CSVs
        # ------------------------------------------------------------------
        print("[1/7] Reading all 35 CSV files with Spark...")
        t0 = time.time()

        raw = (
            spark.read
            .option("header", "true")
            .option("mode", "PERMISSIVE")
            .option("enforceSchema", "false")
            .csv(spark_paths)
            .withColumn("source_file", F.input_file_name())
        )

        # IMPORTANT: original headers contain dots such as frame.time and ip.src.
        # Spark interprets dots as nested-field separators, so normalize them once.
        raw = sanitize_spark_columns(raw)

        print("      Sanitized columns :", ", ".join(raw.columns))

        raw_rows = raw.count()
        csv_read_seconds = time.time() - t0

        metrics["raw_rows"] = raw_rows
        metrics["csv_read_seconds"] = csv_read_seconds

        print(f"      Rows read        : {raw_rows:,}")
        print(f"      CSV read time    : {csv_read_seconds:.2f} sec")
        print()

        # ------------------------------------------------------------------
        # 2) Add scenario metadata
        # ------------------------------------------------------------------
        print("[2/7] Adding file/scenario metadata...")
        t0 = time.time()

        df = (
            raw
            .withColumn("scenario_group", scenario_from_filename_expr(F))
            .withColumn(
                "traffic_type",
                F.when(F.col("scenario_group") == "Benign", F.lit(0))
                 .otherwise(F.lit(1))
            )
        )

        # Cast known numeric columns when they exist.
        lower_map = {c.lower(): c for c in df.columns}

        for candidate in NUMERIC_COLUMNS:
            actual = lower_map.get(candidate)
            if actual:
                # Real packet captures may contain occasional malformed or
                # multi-valued strings. try_cast returns NULL instead of
                # terminating the whole Spark job.
                escaped_actual = actual.replace("`", "``")
                df = df.withColumn(
                    actual,
                    F.expr(f"try_cast(`{escaped_actual}` AS double)")
                )

        metadata_seconds = time.time() - t0
        metrics["metadata_and_cast_seconds"] = metadata_seconds

        print(f"      Metadata time    : {metadata_seconds:.2f} sec")
        print()

        # ------------------------------------------------------------------
        # 3) Clean
        # ------------------------------------------------------------------
        print("[3/7] Cleaning rows...")
        t0 = time.time()

        # Packet rows should normally have frame_len after column sanitization.
        frame_len_col = lower_map.get("frame_len")

        if not frame_len_col:
            raise RuntimeError(
                "Expected packet column 'frame_len' was not found after sanitizing headers. "
                f"Columns are: {df.columns}"
            )

        cleaned = df.filter(F.col(frame_len_col).isNotNull())

        cleaned_rows = cleaned.count()
        clean_seconds = time.time() - t0

        metrics["cleaned_rows"] = cleaned_rows
        metrics["rows_removed"] = raw_rows - cleaned_rows
        metrics["cleaning_seconds"] = clean_seconds

        print(f"      Clean rows       : {cleaned_rows:,}")
        print(f"      Rows removed     : {raw_rows - cleaned_rows:,}")
        print(f"      Cleaning time    : {clean_seconds:.2f} sec")
        print()

        # ------------------------------------------------------------------
        # 4) Big Data analytics
        # ------------------------------------------------------------------
        print("[4/7] Running packet-level aggregations...")
        t0 = time.time()

        scenario_summary = (
            cleaned
            .groupBy("scenario_group", "traffic_type")
            .agg(
                F.count("*").alias("packet_count"),
                F.sum(F.col(frame_len_col)).alias("total_frame_bytes")
                if frame_len_col else F.lit(None).alias("total_frame_bytes"),
                F.avg(F.col(frame_len_col)).alias("avg_frame_bytes")
                if frame_len_col else F.lit(None).alias("avg_frame_bytes"),
                F.approx_count_distinct("ip_src").alias("approx_unique_src_ips")
                if "ip_src" in lower_map else F.lit(None).alias("approx_unique_src_ips"),
                F.approx_count_distinct("ip_dst").alias("approx_unique_dst_ips")
                if "ip_dst" in lower_map else F.lit(None).alias("approx_unique_dst_ips"),
            )
            .orderBy(F.desc("packet_count"))
        )

        protocol_summary = None
        if "ip_proto" in lower_map:
            protocol_col = lower_map["ip_proto"]

            # Some packet rows contain multiple protocol values such as
            # "17,6" or "17,1". Split them into separate protocol entries
            # instead of trying to cast the whole string to one number.
            protocol_summary = (
                cleaned
                .withColumn(
                    "ip_proto_value",
                    F.explode(
                        F.split(
                            F.col(protocol_col),
                            r"\s*,\s*"
                        )
                    )
                )
                .withColumn(
                    "ip_proto_value",
                    F.expr("try_cast(ip_proto_value AS int)")
                )
                .filter(F.col("ip_proto_value").isNotNull())
                .groupBy(
                    "scenario_group",
                    F.col("ip_proto_value").alias("ip_proto")
                )
                .count()
                .orderBy(F.desc("count"))
            )

        file_summary = (
            cleaned
            .groupBy("source_file", "scenario_group")
            .agg(
                F.count("*").alias("packet_count"),
                F.sum(F.col(frame_len_col)).alias("total_frame_bytes")
                if frame_len_col else F.lit(None).alias("total_frame_bytes"),
            )
            .orderBy(F.desc("packet_count"))
        )

        # Force materialization before timing ends.
        scenario_preview = [x.asDict() for x in scenario_summary.collect()]
        protocol_preview = (
            [x.asDict() for x in protocol_summary.limit(100).collect()]
            if protocol_summary is not None
            else []
        )
        file_preview = [x.asDict() for x in file_summary.collect()]

        aggregation_seconds = time.time() - t0

        metrics["aggregation_seconds"] = aggregation_seconds
        metrics["scenario_summary"] = scenario_preview
        metrics["protocol_summary_preview"] = protocol_preview
        metrics["file_summary"] = file_preview

        print(f"      Aggregation time : {aggregation_seconds:.2f} sec")
        print()
        print("      Scenario packet counts:")
        for row in scenario_preview:
            print(
                f"        {row['scenario_group']:18} "
                f"{row['packet_count']:,} packets"
            )
        print()

        # Save aggregations using Spark.
        agg_dir.mkdir(parents=True, exist_ok=True)

        scenario_summary.coalesce(1).write.mode("overwrite").option(
            "header", "true"
        ).csv(spark_local_path(agg_dir / "scenario_summary"))

        file_summary.coalesce(1).write.mode("overwrite").option(
            "header", "true"
        ).csv(spark_local_path(agg_dir / "file_summary"))

        if protocol_summary is not None:
            protocol_summary.coalesce(1).write.mode("overwrite").option(
                "header", "true"
            ).csv(spark_local_path(agg_dir / "protocol_summary"))

        # ------------------------------------------------------------------
        # 5) Write Parquet
        # ------------------------------------------------------------------
        print("[5/7] Writing cleaned data to partitioned Snappy Parquet...")
        t0 = time.time()

        (
            cleaned
            .repartition("scenario_group")
            .write
            .mode("overwrite")
            .option("compression", "snappy")
            .partitionBy("scenario_group")
            .parquet(spark_local_path(parquet_dir))
        )

        parquet_write_seconds = time.time() - t0
        parquet_bytes = folder_size(parquet_dir)

        metrics["parquet_write_seconds"] = parquet_write_seconds
        metrics["parquet_size_bytes"] = parquet_bytes
        metrics["parquet_size_human"] = human_size(parquet_bytes)
        metrics["storage_reduction_percent"] = (
            (1 - parquet_bytes / raw_bytes) * 100
            if raw_bytes else 0
        )

        print(f"      Parquet size     : {human_size(parquet_bytes)}")
        print(f"      Write time       : {parquet_write_seconds:.2f} sec")
        print(f"      Storage reduction: {metrics['storage_reduction_percent']:.2f}%")
        print()

        # ------------------------------------------------------------------
        # 6) Parquet benchmark
        # ------------------------------------------------------------------
        print("[6/7] Re-reading Parquet and counting rows...")
        t0 = time.time()

        parquet_df = spark.read.parquet(spark_local_path(parquet_dir))
        parquet_rows = parquet_df.count()

        parquet_read_seconds = time.time() - t0

        metrics["parquet_rows"] = parquet_rows
        metrics["parquet_read_seconds"] = parquet_read_seconds
        metrics["csv_to_parquet_read_speed_ratio"] = (
            csv_read_seconds / parquet_read_seconds
            if parquet_read_seconds else None
        )

        print(f"      Rows read        : {parquet_rows:,}")
        print(f"      Parquet read time: {parquet_read_seconds:.2f} sec")

        if parquet_read_seconds:
            print(
                f"      CSV/Parquet ratio: "
                f"{csv_read_seconds / parquet_read_seconds:.2f}x"
            )
        print()

        # ------------------------------------------------------------------
        # 7) Final report
        # ------------------------------------------------------------------
        metrics["total_pipeline_seconds"] = (
            csv_read_seconds
            + metadata_seconds
            + clean_seconds
            + aggregation_seconds
            + parquet_write_seconds
            + parquet_read_seconds
        )

        metrics_path.write_text(
            json.dumps(metrics, indent=2),
            encoding="utf-8"
        )

        summary_lines = [
            "BIG DATA PIPELINE - GROUP 01 PACKET DATA",
            "=" * 90,
            f"Input files             : {len(paths):,}",
            f"Raw CSV input           : {human_size(raw_bytes)}",
            f"Rows read               : {raw_rows:,}",
            f"Rows after cleaning     : {cleaned_rows:,}",
            f"CSV read time           : {csv_read_seconds:.2f} sec",
            f"Cleaning time           : {clean_seconds:.2f} sec",
            f"Aggregation time        : {aggregation_seconds:.2f} sec",
            f"Parquet write time      : {parquet_write_seconds:.2f} sec",
            f"Parquet output size     : {human_size(parquet_bytes)}",
            f"Storage reduction       : {metrics['storage_reduction_percent']:.2f}%",
            f"Parquet read time       : {parquet_read_seconds:.2f} sec",
        ]

        if parquet_read_seconds:
            summary_lines.append(
                f"CSV/Parquet read ratio  : "
                f"{csv_read_seconds / parquet_read_seconds:.2f}x"
            )

        summary_lines += [
            "",
            "Scenario packet counts:",
        ]

        for row in scenario_preview:
            summary_lines.append(
                f"  {row['scenario_group']:18} {row['packet_count']:,}"
            )

        summary_path.write_text(
            "\n".join(summary_lines),
            encoding="utf-8"
        )

        print("[7/7] DONE")
        print("=" * 100)
        print(f"Metrics      : {metrics_path}")
        print(f"Summary      : {summary_path}")
        print(f"Parquet      : {parquet_dir}")
        print(f"Aggregations : {agg_dir}")
        print()
        print("Send group_01_bigdata_summary.txt after this finishes.")

    finally:
        spark.stop()


if __name__ == "__main__":
    main()
