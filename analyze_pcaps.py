#!/usr/bin/env python3
"""
Analyze all PCAP/PCAPNG files under a dataset folder.

What it produces:
  pcap_analysis/
    manifest.csv              one row per capture
    summary.txt               totals by category
    errors.log                failures, if any
    reports/<id>/
        capinfos.txt          capture metadata
        tshark_stats.txt      protocol hierarchy, endpoints, conversations,
                              60-second traffic statistics, expert info
        packet_sample.csv     first N decoded packets/selected fields
        status.json           resume/checkpoint metadata

Requirements:
  - Python 3
  - Wireshark/TShark installed
    The script auto-detects the usual Windows Wireshark installation path.

Important:
  - It does NOT load a whole capture into RAM.
  - It processes captures sequentially.
  - It is resumable: completed files are skipped on the next run unless --force is used.
  - Full analysis of ~129 GB of packet captures can take hours.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path


COMMON_WINDOWS_DIRS = [
    Path(r"C:\Program Files\Wireshark"),
    Path(r"C:\Program Files (x86)\Wireshark"),
]


def find_executable(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found

    exe_name = name if name.lower().endswith(".exe") else name + ".exe"
    for folder in COMMON_WINDOWS_DIRS:
        candidate = folder / exe_name
        if candidate.exists():
            return str(candidate)

    return None


def run_command(cmd: list[str], timeout: int | None = None) -> tuple[int, str, str, float]:
    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        return proc.returncode, proc.stdout, proc.stderr, time.time() - started
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        return 124, stdout, stderr + "\nTIMEOUT", time.time() - started
    except Exception as exc:
        return 999, "", repr(exc), time.time() - started


def safe_slug(text: str, max_len: int = 70) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._")
    return (text[:max_len] or "capture")


def infer_category(relative_path: Path) -> str:
    s = str(relative_path).lower().replace("/", "\\")
    parts = [p.lower() for p in relative_path.parts]

    if any("benign" in p for p in parts):
        return "Benign"
    if any("ddos" in p for p in parts):
        return "DDoS"
    if any(p == "dos" or p.startswith("dos ") or p.startswith("dos_") for p in parts):
        return "DoS"
    if any("bruteforce" in p or "brute force" in p for p in parts):
        return "BruteForce"
    if any(p == "probe" or "probe" in p for p in parts):
        return "Probe"
    if any(p == "web" or p.startswith("web ") or p.startswith("web_") for p in parts):
        return "Web"
    if "attack (legacy)" in s:
        return "Legacy/Other"
    return "Unknown"


def parse_capinfos(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([^:]+):\s*(.*)\s*$", line)
        if not m:
            continue
        key = m.group(1).strip().lower()
        key = re.sub(r"[^a-z0-9]+", "_", key).strip("_")
        value = m.group(2).strip()
        if key and key not in result:
            result[key] = value
    return result


def get_first(meta: dict[str, str], *keys: str) -> str:
    for key in keys:
        if key in meta:
            return meta[key]
    return ""


def capture_id(relative_path: Path) -> str:
    digest = hashlib.sha1(str(relative_path).encode("utf-8")).hexdigest()[:10]
    return f"{safe_slug(relative_path.stem)}_{digest}"


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", errors="replace")


def analyze_capture(
    capture: Path,
    root: Path,
    out_dir: Path,
    tshark: str,
    capinfos: str,
    sample_packets: int,
    io_interval: int,
    force: bool,
) -> dict:
    relative = capture.relative_to(root)
    cid = capture_id(relative)
    report_dir = out_dir / "reports" / cid
    report_dir.mkdir(parents=True, exist_ok=True)

    status_file = report_dir / "status.json"

    if status_file.exists() and not force:
        try:
            old = json.loads(status_file.read_text(encoding="utf-8"))
            if old.get("status") == "ok" and old.get("relative_path") == str(relative):
                old["resumed"] = True
                return old
        except Exception:
            pass

    record = {
        "status": "running",
        "relative_path": str(relative),
        "absolute_path": str(capture),
        "category": infer_category(relative),
        "extension": capture.suffix.lower(),
        "filesystem_size_bytes": capture.stat().st_size,
        "filesystem_size_gb": round(capture.stat().st_size / (1024 ** 3), 4),
        "analysis_started": datetime.now().isoformat(timespec="seconds"),
        "report_dir": str(report_dir),
    }
    status_file.write_text(json.dumps(record, indent=2), encoding="utf-8")

    # ------------------------------------------------------------------
    # 1) Capture metadata with capinfos
    # ------------------------------------------------------------------
    rc, cap_out, cap_err, cap_seconds = run_command([capinfos, str(capture)])
    write_text(
        report_dir / "capinfos.txt",
        cap_out + (("\n\nSTDERR:\n" + cap_err) if cap_err else ""),
    )

    meta = parse_capinfos(cap_out)
    record["capinfos_returncode"] = rc
    record["capinfos_seconds"] = round(cap_seconds, 2)
    record["file_type"] = get_first(meta, "file_type")
    record["encapsulation"] = get_first(meta, "file_encapsulation")
    record["packet_count"] = get_first(meta, "number_of_packets")
    record["file_size_capinfos"] = get_first(meta, "file_size")
    record["data_size"] = get_first(meta, "data_size")
    record["capture_duration"] = get_first(meta, "capture_duration")
    record["first_packet_time"] = get_first(meta, "first_packet_time")
    record["last_packet_time"] = get_first(meta, "last_packet_time")
    record["data_byte_rate"] = get_first(meta, "data_byte_rate")
    record["data_bit_rate"] = get_first(meta, "data_bit_rate")
    record["average_packet_size"] = get_first(meta, "average_packet_size")
    record["sha256"] = get_first(meta, "sha256")

    # ------------------------------------------------------------------
    # 2) One full TShark pass with several statistical taps
    # ------------------------------------------------------------------
    stats_cmd = [
        tshark,
        "-n",
        "-r", str(capture),
        "-q",
        "-z", "io,phs",
        "-z", "endpoints,ip",
        "-z", "conv,ip",
        "-z", "conv,tcp",
        "-z", "conv,udp",
        "-z", f"io,stat,{io_interval}",
        "-z", "expert",
    ]

    rc, stats_out, stats_err, stats_seconds = run_command(stats_cmd)
    write_text(
        report_dir / "tshark_stats.txt",
        "COMMAND:\n" + " ".join(f'"{x}"' if " " in x else x for x in stats_cmd)
        + "\n\n"
        + stats_out
        + (("\n\nSTDERR:\n" + stats_err) if stats_err else ""),
    )

    record["tshark_stats_returncode"] = rc
    record["tshark_stats_seconds"] = round(stats_seconds, 2)

    # ------------------------------------------------------------------
    # 3) Small decoded packet sample, useful for understanding schemas
    # ------------------------------------------------------------------
    sample_fields = [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "frame.protocols",
        "eth.src",
        "eth.dst",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "tcp.flags",
        "dns.qry.name",
        "http.request.method",
        "http.host",
        "tls.handshake.extensions_server_name",
    ]

    sample_cmd = [
        tshark,
        "-n",
        "-r", str(capture),
        "-c", str(sample_packets),
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ]
    for field in sample_fields:
        sample_cmd.extend(["-e", field])

    rc, sample_out, sample_err, sample_seconds = run_command(sample_cmd)
    write_text(report_dir / "packet_sample.csv", sample_out)

    if sample_err:
        write_text(report_dir / "packet_sample.stderr.txt", sample_err)

    record["sample_returncode"] = rc
    record["sample_seconds"] = round(sample_seconds, 2)

    # Overall status: capinfos and stats are the important parts.
    if record["capinfos_returncode"] == 0 and record["tshark_stats_returncode"] == 0:
        record["status"] = "ok"
    else:
        record["status"] = "partial_or_failed"

    record["analysis_finished"] = datetime.now().isoformat(timespec="seconds")
    record["total_analysis_seconds"] = round(
        cap_seconds + stats_seconds + sample_seconds, 2
    )

    status_file.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def load_all_statuses(out_dir: Path) -> list[dict]:
    records = []
    reports_dir = out_dir / "reports"
    if not reports_dir.exists():
        return records

    for status_file in reports_dir.glob("*/status.json"):
        try:
            records.append(json.loads(status_file.read_text(encoding="utf-8")))
        except Exception:
            pass
    return records


def write_manifest(records: list[dict], out_dir: Path) -> None:
    fields = [
        "status",
        "relative_path",
        "category",
        "extension",
        "filesystem_size_bytes",
        "filesystem_size_gb",
        "file_type",
        "encapsulation",
        "packet_count",
        "capture_duration",
        "first_packet_time",
        "last_packet_time",
        "data_size",
        "data_byte_rate",
        "data_bit_rate",
        "average_packet_size",
        "capinfos_seconds",
        "tshark_stats_seconds",
        "sample_seconds",
        "total_analysis_seconds",
        "report_dir",
    ]

    manifest = out_dir / "manifest.csv"
    with manifest.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for r in sorted(records, key=lambda x: x.get("relative_path", "")):
            writer.writerow(r)


def write_summary(records: list[dict], out_dir: Path) -> None:
    by_category = defaultdict(lambda: {"files": 0, "bytes": 0, "ok": 0, "failed": 0})

    total_bytes = 0
    total_ok = 0
    total_failed = 0

    for r in records:
        cat = r.get("category", "Unknown")
        size = int(r.get("filesystem_size_bytes", 0) or 0)
        status = r.get("status", "")

        by_category[cat]["files"] += 1
        by_category[cat]["bytes"] += size
        total_bytes += size

        if status == "ok":
            by_category[cat]["ok"] += 1
            total_ok += 1
        else:
            by_category[cat]["failed"] += 1
            total_failed += 1

    lines = []
    lines.append("PCAP / PCAPNG ANALYSIS SUMMARY")
    lines.append("=" * 80)
    lines.append(f"Analyzed records : {len(records):,}")
    lines.append(f"Successful       : {total_ok:,}")
    lines.append(f"Partial/failed   : {total_failed:,}")
    lines.append(f"Total size       : {total_bytes / (1024 ** 3):,.2f} GB")
    lines.append("")
    lines.append("BY CATEGORY")
    lines.append("-" * 80)

    for cat, info in sorted(
        by_category.items(),
        key=lambda item: item[1]["bytes"],
        reverse=True
    ):
        gb = info["bytes"] / (1024 ** 3)
        lines.append(
            f"{cat:20}  files={info['files']:4d}  "
            f"size={gb:9.2f} GB  ok={info['ok']:4d}  "
            f"failed={info['failed']:4d}"
        )

    lines.append("")
    lines.append("Per-capture detail is in reports/<capture-id>/tshark_stats.txt")
    lines.append("The manifest is in manifest.csv")
    lines.append("")

    write_text(out_dir / "summary.txt", "\n".join(lines))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Recursively analyze all PCAP/PCAPNG files with Wireshark CLI tools."
    )
    parser.add_argument(
        "--root",
        required=True,
        help="Dataset root containing .pcap and .pcapng files.",
    )
    parser.add_argument(
        "--out",
        default="pcap_analysis",
        help="Output directory. Default: pcap_analysis",
    )
    parser.add_argument(
        "--sample-packets",
        type=int,
        default=100,
        help="Number of decoded packets to save as a CSV sample per capture. Default: 100",
    )
    parser.add_argument(
        "--io-interval",
        type=int,
        default=60,
        help="Seconds per traffic-rate bucket in TShark io,stat. Default: 60",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-analyze files that already completed successfully.",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    out_dir = Path(args.out).resolve()

    if not root.exists():
        print(f"ERROR: dataset root does not exist:\n{root}", file=sys.stderr)
        return 2

    tshark = find_executable("tshark")
    capinfos = find_executable("capinfos")

    if not tshark or not capinfos:
        print("\nERROR: Wireshark command-line tools were not found.")
        print("Install Wireshark with TShark/capinfos, then run this script again.")
        print("\nSearched PATH and the usual Windows folders:")
        for folder in COMMON_WINDOWS_DIRS:
            print("  ", folder)
        print("\nDetected:")
        print("  tshark  :", tshark)
        print("  capinfos:", capinfos)
        return 3

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "reports").mkdir(parents=True, exist_ok=True)

    captures = sorted(
        p for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in {".pcap", ".pcapng"}
    )

    total_bytes = sum(p.stat().st_size for p in captures)

    print("=" * 90)
    print("PCAP ANALYZER")
    print("=" * 90)
    print("Dataset root :", root)
    print("Output       :", out_dir)
    print("TShark       :", tshark)
    print("capinfos     :", capinfos)
    print(f"Capture files: {len(captures):,}")
    print(f"Capture size : {total_bytes / (1024 ** 3):,.2f} GB")
    print()
    print("This is a full sequential scan and may take hours.")
    print("It is resumable: Ctrl+C is safe; rerun the same command to continue.")
    print()

    errors_log = out_dir / "errors.log"

    try:
        for idx, capture in enumerate(captures, start=1):
            rel = capture.relative_to(root)
            size_gb = capture.stat().st_size / (1024 ** 3)

            print(f"[{idx:03d}/{len(captures):03d}] {size_gb:7.2f} GB | {rel}")

            before = time.time()
            record = analyze_capture(
                capture=capture,
                root=root,
                out_dir=out_dir,
                tshark=tshark,
                capinfos=capinfos,
                sample_packets=max(1, args.sample_packets),
                io_interval=max(1, args.io_interval),
                force=args.force,
            )

            elapsed = time.time() - before
            resumed = record.get("resumed", False)
            suffix = " (already complete)" if resumed else ""
            print(
                f"      -> {record.get('status')} "
                f"in {elapsed:,.1f}s{suffix}"
            )

            if record.get("status") != "ok":
                with errors_log.open("a", encoding="utf-8") as f:
                    f.write(
                        f"{datetime.now().isoformat()} | "
                        f"{record.get('status')} | {rel}\n"
                    )

            # Rebuild manifest after every capture so progress is never lost.
            all_records = load_all_statuses(out_dir)
            write_manifest(all_records, out_dir)
            write_summary(all_records, out_dir)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        print("Progress has been saved. Run the same command again to continue.")
        all_records = load_all_statuses(out_dir)
        write_manifest(all_records, out_dir)
        write_summary(all_records, out_dir)
        return 130

    all_records = load_all_statuses(out_dir)
    write_manifest(all_records, out_dir)
    write_summary(all_records, out_dir)

    print("\n" + "=" * 90)
    print("DONE")
    print("=" * 90)
    print("Summary :", out_dir / "summary.txt")
    print("Manifest:", out_dir / "manifest.csv")
    print("Reports :", out_dir / "reports")
    print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
