#!/usr/bin/env python3
"""
Analyze only six representative experiments from the 5G-NL-IDD dataset.

Selected experiments:
  Benign      -> benign.pcap            + benign.txt
  BruteForce  -> ftp_hydra.pcap         + ftp_hydra.txt
  DDoS        -> ddos_icmp_hping3.pcap  + ddos_icmp_hping3.txt
  DoS         -> slowloris.pcap         + slowloris.txt
  Probe       -> portscan_tcp3.pcap     + portscan_tcp3.txt
  Web         -> web_xss.pcap           + web_xss.txt

Outputs:
  selected_analysis/
    summary.csv
    summary.txt
    <Category>/
      capinfos.txt
      tshark_stats.txt
      packet_sample.csv
      lower_layer_sample.csv
      lower_layer_info.txt

Requirements:
  - Python 3
  - Wireshark/TShark installed
  - pandas installed
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pandas as pd


SELECTED = {
    "Benign": {
        "pcap": Path(r"Benign\Benign\Network_data\benign.pcap"),
        "txt": Path(r"Benign\Benign\Lower_Layer\benign.txt"),
    },
    "BruteForce": {
        "pcap": Path(r"BruteForce\BruteForce\Higher_Layer\ftp_hydra.pcap"),
        "txt": Path(r"BruteForce\BruteForce\Lower_Layer\ftp_hydra.txt"),
    },
    "DDoS": {
        "pcap": Path(r"DDOS\DDOS\Network_Layer\ddos_icmp_hping3.pcap"),
        "txt": Path(r"DDOS\DDOS\Lower_Layer\ddos_icmp_hping3.txt"),
    },
    "DoS": {
        "pcap": Path(r"DoS\DoS\Network_Layer\slowloris.pcap"),
        "txt": Path(r"DoS\DoS\Lower_Layer\slowloris.txt"),
    },
    "Probe": {
        "pcap": Path(r"Probe\Probe\Network_Layer\portscan_tcp3.pcap"),
        "txt": Path(r"Probe\Probe\Lower_Layer\portscan_tcp3.txt"),
    },
    "Web": {
        "pcap": Path(r"Web\Web\Network_Layer\web_xss.pcap"),
        "txt": Path(r"Web\Web\Lower_Layer\web_xss.txt"),
    },
}


COMMON_WINDOWS_DIRS = [
    Path(r"C:\Program Files\Wireshark"),
    Path(r"C:\Program Files (x86)\Wireshark"),
]


def find_executable(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found

    exe = name if name.lower().endswith(".exe") else name + ".exe"

    for folder in COMMON_WINDOWS_DIRS:
        candidate = folder / exe
        if candidate.exists():
            return str(candidate)

    return None


def run_command(cmd: list[str]) -> tuple[int, str, str, float]:
    started = time.time()

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )

    return (
        proc.returncode,
        proc.stdout,
        proc.stderr,
        time.time() - started
    )


def human_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)

    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024

    return f"{size} B"


def parse_capinfos(text: str) -> dict[str, str]:
    result = {}

    for line in text.splitlines():
        match = re.match(r"^\s*([^:]+):\s*(.*?)\s*$", line)

        if not match:
            continue

        key = match.group(1).strip().lower()
        key = re.sub(r"[^a-z0-9]+", "_", key).strip("_")

        value = match.group(2).strip()

        if key and key not in result:
            result[key] = value

    return result


def first_value(meta: dict, *keys: str) -> str:
    for key in keys:
        value = meta.get(key)

        if value not in (None, ""):
            return str(value)

    return ""


def try_read_lower_layer(path: Path):
    """
    Tries several common delimiters.
    The lower-layer files are small, so reading them fully is fine.
    """

    attempts = [
        {"sep": None, "engine": "python"},
        {"sep": ","},
        {"sep": r"\s+", "engine": "python"},
        {"sep": "\t"},
        {"sep": ";"},
    ]

    last_error = None

    for kwargs in attempts:
        try:
            df = pd.read_csv(path, **kwargs)

            if df.shape[1] > 1:
                return df, kwargs

        except Exception as exc:
            last_error = exc

    raise RuntimeError(
        f"Could not parse {path}. Last error: {last_error}"
    )


def find_time_column(df: pd.DataFrame) -> str | None:
    candidates = [
        "timestamp",
        "time",
        "ts",
        "datetime",
        "date_time",
        "epoch",
    ]

    lower_to_original = {
        str(col).strip().lower(): col
        for col in df.columns
    }

    for candidate in candidates:
        if candidate in lower_to_original:
            return lower_to_original[candidate]

    # fuzzy fallback
    for col in df.columns:
        low = str(col).lower()

        if "timestamp" in low or low.endswith("_time") or low == "time":
            return col

    return None


def describe_time_series(series: pd.Series):
    clean = series.dropna()

    if len(clean) == 0:
        return "", ""

    # Numeric epoch-like timestamps
    numeric = pd.to_numeric(clean, errors="coerce")

    if numeric.notna().mean() > 0.9:
        mn = float(numeric.min())
        mx = float(numeric.max())

        # Heuristic conversion only for reporting.
        try:
            if mn > 1e12:
                min_dt = pd.to_datetime(mn, unit="ms", utc=True)
                max_dt = pd.to_datetime(mx, unit="ms", utc=True)
            elif mn > 1e9:
                min_dt = pd.to_datetime(mn, unit="s", utc=True)
                max_dt = pd.to_datetime(mx, unit="s", utc=True)
            else:
                return str(mn), str(mx)

            return str(min_dt), str(max_dt)

        except Exception:
            return str(mn), str(mx)

    parsed = pd.to_datetime(clean, errors="coerce", utc=True)

    if parsed.notna().any():
        return str(parsed.min()), str(parsed.max())

    return str(clean.iloc[0]), str(clean.iloc[-1])


def analyze_lower_layer(path: Path, out_dir: Path):
    df, parsing_used = try_read_lower_layer(path)

    sample_path = out_dir / "lower_layer_sample.csv"
    df.head(50).to_csv(sample_path, index=False)

    time_col = find_time_column(df)

    time_min = ""
    time_max = ""

    if time_col is not None:
        time_min, time_max = describe_time_series(df[time_col])

    info_lines = [
        f"File: {path}",
        f"Rows: {len(df):,}",
        f"Columns: {len(df.columns)}",
        f"Parsing: {parsing_used}",
        "",
        "Columns:",
    ]

    for col in df.columns:
        info_lines.append(
            f"  - {col} ({df[col].dtype})"
        )

    info_lines += [
        "",
        f"Detected time column: {time_col}",
        f"Time minimum: {time_min}",
        f"Time maximum: {time_max}",
        "",
        "Missing values:",
        str(df.isnull().sum()),
    ]

    (out_dir / "lower_layer_info.txt").write_text(
        "\n".join(info_lines),
        encoding="utf-8"
    )

    return {
        "lower_rows": len(df),
        "lower_columns": len(df.columns),
        "lower_time_column": time_col or "",
        "lower_time_min": time_min,
        "lower_time_max": time_max,
    }


def analyze_pcap(
    pcap: Path,
    out_dir: Path,
    tshark: str,
    capinfos: str,
):
    # --------------------------------------------------------
    # Metadata
    # --------------------------------------------------------
    rc, cap_out, cap_err, cap_secs = run_command(
        [capinfos, str(pcap)]
    )

    (out_dir / "capinfos.txt").write_text(
        cap_out + (
            "\n\nSTDERR:\n" + cap_err
            if cap_err else ""
        ),
        encoding="utf-8"
    )

    meta = parse_capinfos(cap_out)

    # --------------------------------------------------------
    # Main statistical pass
    # --------------------------------------------------------
    stats_cmd = [
        tshark,
        "-n",
        "-r", str(pcap),
        "-q",
        "-z", "io,phs",
        "-z", "endpoints,ip",
        "-z", "conv,ip",
        "-z", "conv,tcp",
        "-z", "conv,udp",
        "-z", "io,stat,10",
        "-z", "expert",
    ]

    rc_stats, stats_out, stats_err, stats_secs = run_command(
        stats_cmd
    )

    (out_dir / "tshark_stats.txt").write_text(
        stats_out + (
            "\n\nSTDERR:\n" + stats_err
            if stats_err else ""
        ),
        encoding="utf-8"
    )

    # --------------------------------------------------------
    # First 500 packets as structured CSV
    # --------------------------------------------------------
    fields = [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "frame.protocols",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "tcp.flags",
        "icmp.type",
        "dns.qry.name",
        "http.request.method",
        "http.host",
    ]

    sample_cmd = [
        tshark,
        "-n",
        "-r", str(pcap),
        "-c", "500",
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ]

    for field in fields:
        sample_cmd += ["-e", field]

    rc_sample, sample_out, sample_err, sample_secs = run_command(
        sample_cmd
    )

    (out_dir / "packet_sample.csv").write_text(
        sample_out,
        encoding="utf-8"
    )

    if sample_err:
        (out_dir / "packet_sample.stderr.txt").write_text(
            sample_err,
            encoding="utf-8"
        )

    return {
        "pcap_size_bytes": pcap.stat().st_size,
        "pcap_size": human_size(pcap.stat().st_size),
        "packet_count": first_value(
            meta,
            "number_of_packets"
        ),
        "capture_duration": first_value(
            meta,
            "capture_duration"
        ),
        "first_packet_time": first_value(
            meta,
            "first_packet_time"
        ),
        "last_packet_time": first_value(
            meta,
            "last_packet_time"
        ),
        "average_packet_size": first_value(
            meta,
            "average_packet_size"
        ),
        "data_bit_rate": first_value(
            meta,
            "data_bit_rate"
        ),
        "pcap_scan_seconds": round(
            cap_secs + stats_secs + sample_secs,
            2
        ),
        "tshark_status": (
            "ok"
            if rc == 0 and rc_stats == 0
            else "partial/failed"
        ),
    }


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--root",
        required=True,
        help="Root of extracted archive folder."
    )

    parser.add_argument(
        "--out",
        default="selected_analysis",
        help="Output folder."
    )

    args = parser.parse_args()

    root = Path(args.root).resolve()
    out_root = Path(args.out).resolve()

    if not root.exists():
        raise SystemExit(
            f"Dataset root not found: {root}"
        )

    tshark = find_executable("tshark")
    capinfos = find_executable("capinfos")

    if not tshark or not capinfos:
        print("ERROR: TShark/capinfos not found.")
        print("Install Wireshark first.")
        print("tshark  :", tshark)
        print("capinfos:", capinfos)
        return 3

    out_root.mkdir(
        parents=True,
        exist_ok=True
    )

    rows = []

    print("=" * 100)
    print("SELECTED 6-SCENARIO ANALYSIS")
    print("=" * 100)
    print("Dataset:", root)
    print("Output :", out_root)
    print()

    for index, (category, paths) in enumerate(
        SELECTED.items(),
        start=1
    ):
        pcap = root / paths["pcap"]
        txt = root / paths["txt"]

        print(
            f"[{index}/6] {category}"
        )

        print(
            f"  PCAP: {pcap}"
        )

        print(
            f"  TXT : {txt}"
        )

        missing = []

        if not pcap.exists():
            missing.append(
                f"missing PCAP: {pcap}"
            )

        if not txt.exists():
            missing.append(
                f"missing TXT: {txt}"
            )

        category_out = out_root / category
        category_out.mkdir(
            parents=True,
            exist_ok=True
        )

        row = {
            "category": category,
            "pcap_path": str(
                pcap.relative_to(root)
            ),
            "lower_layer_path": str(
                txt.relative_to(root)
            ),
        }

        if missing:
            row["status"] = "missing files"
            row["error"] = "; ".join(missing)

            print(
                "  ERROR:",
                row["error"]
            )

            rows.append(row)
            continue

        started = time.time()

        try:
            pcap_info = analyze_pcap(
                pcap,
                category_out,
                tshark,
                capinfos,
            )

            lower_info = analyze_lower_layer(
                txt,
                category_out,
            )

            row.update(pcap_info)
            row.update(lower_info)

            row["status"] = "ok"

        except Exception as exc:
            row["status"] = "failed"
            row["error"] = repr(exc)

            (
                category_out / "error.txt"
            ).write_text(
                repr(exc),
                encoding="utf-8"
            )

        row["total_seconds"] = round(
            time.time() - started,
            2
        )

        rows.append(row)

        print(
            f"  -> {row['status']} "
            f"in {row['total_seconds']} seconds"
        )

        print()

    # --------------------------------------------------------
    # Write summary CSV
    # --------------------------------------------------------
    fieldnames = [
        "category",
        "status",
        "pcap_path",
        "pcap_size",
        "pcap_size_bytes",
        "packet_count",
        "capture_duration",
        "first_packet_time",
        "last_packet_time",
        "average_packet_size",
        "data_bit_rate",
        "pcap_scan_seconds",
        "tshark_status",
        "lower_layer_path",
        "lower_rows",
        "lower_columns",
        "lower_time_column",
        "lower_time_min",
        "lower_time_max",
        "total_seconds",
        "error",
    ]

    with (
        out_root / "summary.csv"
    ).open(
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )

        writer.writeheader()

        for row in rows:
            writer.writerow(row)

    # --------------------------------------------------------
    # Write readable text summary
    # --------------------------------------------------------
    lines = [
        "SELECTED 6-SCENARIO ANALYSIS",
        "=" * 100,
        "",
    ]

    for row in rows:
        lines += [
            f"Category: {row['category']}",
            f"Status: {row.get('status', '')}",
            f"PCAP: {row.get('pcap_path', '')}",
            f"PCAP size: {row.get('pcap_size', '')}",
            f"Packets: {row.get('packet_count', '')}",
            f"PCAP first packet: {row.get('first_packet_time', '')}",
            f"PCAP last packet: {row.get('last_packet_time', '')}",
            f"Lower-layer file: {row.get('lower_layer_path', '')}",
            f"Lower-layer rows: {row.get('lower_rows', '')}",
            f"Lower-layer time column: {row.get('lower_time_column', '')}",
            f"Lower-layer time min: {row.get('lower_time_min', '')}",
            f"Lower-layer time max: {row.get('lower_time_max', '')}",
            "",
            "-" * 100,
            "",
        ]

    (
        out_root / "summary.txt"
    ).write_text(
        "\n".join(lines),
        encoding="utf-8"
    )

    print("=" * 100)
    print("DONE")
    print("=" * 100)
    print(
        "Summary CSV:",
        out_root / "summary.csv"
    )
    print(
        "Summary TXT:",
        out_root / "summary.txt"
    )
    print()
    print(
        "Upload or paste summary.txt here "
        "after it finishes."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
