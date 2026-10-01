#!/usr/bin/env python3
"""
Fast alignment checker for the 6 selected PCAP experiments.

Purpose:
- Correctly parse lower-layer .txt files as JSON Lines (one JSON object per line)
- Read PCAP earliest/latest timestamps using capinfos in Unix epoch seconds
- Compare PCAP and lower-layer time ranges
- Search other lower-layer .txt files in the same category for better overlap candidates

This DOES NOT run a full TShark packet analysis.
It is intended to be much faster than scanning packet contents.

Outputs:
  alignment_check/
    alignment_report.txt
    alignment_report.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


SELECTED = {
    "Benign": {
        "pcap": Path(r"Benign\Benign\Network_data\benign.pcap"),
        "txt": Path(r"Benign\Benign\Lower_Layer\benign.txt"),
        "txt_dir": Path(r"Benign\Benign\Lower_Layer"),
    },
    "BruteForce": {
        "pcap": Path(r"BruteForce\BruteForce\Higher_Layer\ftp_hydra.pcap"),
        "txt": Path(r"BruteForce\BruteForce\Lower_Layer\ftp_hydra.txt"),
        "txt_dir": Path(r"BruteForce\BruteForce\Lower_Layer"),
    },
    "DDoS": {
        "pcap": Path(r"DDOS\DDOS\Network_Layer\ddos_icmp_hping3.pcap"),
        "txt": Path(r"DDOS\DDOS\Lower_Layer\ddos_icmp_hping3.txt"),
        "txt_dir": Path(r"DDOS\DDOS\Lower_Layer"),
    },
    "DoS": {
        "pcap": Path(r"DoS\DoS\Network_Layer\slowloris.pcap"),
        "txt": Path(r"DoS\DoS\Lower_Layer\slowloris.txt"),
        "txt_dir": Path(r"DoS\DoS\Lower_Layer"),
    },
    "Probe": {
        "pcap": Path(r"Probe\Probe\Network_Layer\portscan_tcp3.pcap"),
        "txt": Path(r"Probe\Probe\Lower_Layer\portscan_tcp3.txt"),
        "txt_dir": Path(r"Probe\Probe\Lower_Layer"),
    },
    "Web": {
        "pcap": Path(r"Web\Web\Network_Layer\web_xss.pcap"),
        "txt": Path(r"Web\Web\Lower_Layer\web_xss.txt"),
        "txt_dir": Path(r"Web\Web\Lower_Layer"),
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


def run_command(cmd: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    return proc.returncode, proc.stdout, proc.stderr


def epoch_to_utc(value: float | None) -> str:
    if value is None:
        return ""
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def parse_pcap_range(capinfos: str, pcap: Path):
    # -a = earliest timestamp
    # -e = latest timestamp
    # -S = print those timestamps as seconds since Unix epoch
    rc, out, err = run_command(
        [capinfos, "-a", "-e", "-S", str(pcap)]
    )

    if rc != 0:
        raise RuntimeError(
            f"capinfos failed for {pcap}\n{err}"
        )

    earliest = None
    latest = None

    for line in out.splitlines():
        low = line.lower()

        if "earliest packet time" in low:
            raw = line.split(":", 1)[1].strip()
            m = re.search(r"-?\d+(?:\.\d+)?", raw)
            if m:
                earliest = float(m.group(0))

        elif "latest packet time" in low:
            raw = line.split(":", 1)[1].strip()
            m = re.search(r"-?\d+(?:\.\d+)?", raw)
            if m:
                latest = float(m.group(0))

    if earliest is None or latest is None:
        raise RuntimeError(
            "Could not parse epoch timestamps from capinfos output:\n"
            + out
        )

    return earliest, latest


def parse_jsonl(path: Path):
    """
    The lower-layer .txt files are JSON Lines:
    one JSON object on each line.
    """
    rows = []
    bad_lines = 0

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace"
    ) as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(obj)
                else:
                    bad_lines += 1
            except json.JSONDecodeError:
                bad_lines += 1

    fields = sorted(
        {
            key
            for row in rows
            for key in row.keys()
        }
    )

    timestamps = []

    for row in rows:
        value = row.get("timestamp")

        if value is None:
            continue

        try:
            value = float(value)

            # Lower-layer timestamps appear to be milliseconds.
            if value > 1e11:
                value /= 1000.0

            timestamps.append(value)

        except (ValueError, TypeError):
            pass

    result = {
        "rows": len(rows),
        "bad_lines": bad_lines,
        "fields": fields,
        "has_timestamp": bool(timestamps),
        "time_start": min(timestamps) if timestamps else None,
        "time_end": max(timestamps) if timestamps else None,
    }

    return result


def interval_overlap(a_start, a_end, b_start, b_end):
    start = max(a_start, b_start)
    end = min(a_end, b_end)

    if end >= start:
        return end - start

    return 0.0


def interval_gap(a_start, a_end, b_start, b_end):
    if interval_overlap(
        a_start, a_end, b_start, b_end
    ) > 0:
        return 0.0

    if b_start > a_end:
        return b_start - a_end

    if a_start > b_end:
        return a_start - b_end

    return 0.0


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--root",
        required=True,
        help="Root folder of extracted archive."
    )

    parser.add_argument(
        "--out",
        default="alignment_check",
        help="Output folder."
    )

    args = parser.parse_args()

    root = Path(args.root).resolve()
    out_dir = Path(args.out).resolve()

    capinfos = find_executable("capinfos")

    if not capinfos:
        raise SystemExit(
            "capinfos.exe not found. Install Wireshark first."
        )

    out_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    rows_for_csv = []
    report = []

    report.append(
        "PCAP ↔ LOWER-LAYER TIME ALIGNMENT"
    )
    report.append("=" * 100)
    report.append("")

    for category, spec in SELECTED.items():

        pcap = root / spec["pcap"]
        selected_txt = root / spec["txt"]
        txt_dir = root / spec["txt_dir"]

        report.append(
            f"CATEGORY: {category}"
        )
        report.append("-" * 100)

        if not pcap.exists():
            report.append(
                f"PCAP MISSING: {pcap}"
            )
            report.append("")
            continue

        pcap_start, pcap_end = parse_pcap_range(
            capinfos,
            pcap
        )

        report.append(
            f"PCAP: {spec['pcap']}"
        )
        report.append(
            f"PCAP UTC start: {epoch_to_utc(pcap_start)}"
        )
        report.append(
            f"PCAP UTC end  : {epoch_to_utc(pcap_end)}"
        )
        report.append(
            f"PCAP duration : {pcap_end - pcap_start:.3f} sec"
        )
        report.append("")

        # ----------------------------------------------------
        # Selected lower-layer file
        # ----------------------------------------------------
        if selected_txt.exists():
            selected_info = parse_jsonl(
                selected_txt
            )

            report.append(
                f"SELECTED TXT: {spec['txt']}"
            )
            report.append(
                f"Rows: {selected_info['rows']:,}"
            )
            report.append(
                f"Bad JSON lines: {selected_info['bad_lines']:,}"
            )
            report.append(
                "Fields: "
                + ", ".join(selected_info["fields"])
            )

            if selected_info["has_timestamp"]:
                txt_start = selected_info["time_start"]
                txt_end = selected_info["time_end"]

                overlap = interval_overlap(
                    pcap_start,
                    pcap_end,
                    txt_start,
                    txt_end
                )

                gap = interval_gap(
                    pcap_start,
                    pcap_end,
                    txt_start,
                    txt_end
                )

                report.append(
                    f"TXT UTC start : {epoch_to_utc(txt_start)}"
                )
                report.append(
                    f"TXT UTC end   : {epoch_to_utc(txt_end)}"
                )
                report.append(
                    f"Overlap       : {overlap:.3f} sec"
                )
                report.append(
                    f"Gap           : {gap:.3f} sec"
                )

                if overlap > 0:
                    verdict = "YES — usable for time-based alignment"
                else:
                    verdict = "NO — selected pair does not overlap"

            else:
                txt_start = None
                txt_end = None
                overlap = 0.0
                gap = 0.0
                verdict = (
                    "NO TIMESTAMP FIELD — cannot directly time-align"
                )

            report.append(
                f"Selected pair : {verdict}"
            )

            rows_for_csv.append({
                "category": category,
                "pcap": str(spec["pcap"]),
                "selected_txt": str(spec["txt"]),
                "pcap_start_utc": epoch_to_utc(pcap_start),
                "pcap_end_utc": epoch_to_utc(pcap_end),
                "txt_start_utc": epoch_to_utc(txt_start),
                "txt_end_utc": epoch_to_utc(txt_end),
                "overlap_seconds": round(overlap, 3),
                "gap_seconds": round(gap, 3),
                "txt_rows": selected_info["rows"],
                "txt_has_timestamp": selected_info["has_timestamp"],
                "verdict": verdict,
            })

        else:
            report.append(
                f"SELECTED TXT MISSING: {selected_txt}"
            )

        # ----------------------------------------------------
        # Search every lower-layer TXT in same category
        # ----------------------------------------------------
        report.append("")
        report.append(
            "LOWER-LAYER CANDIDATES IN SAME CATEGORY:"
        )

        candidates = []

        if txt_dir.exists():

            for txt_file in sorted(
                txt_dir.glob("*.txt")
            ):
                info = parse_jsonl(
                    txt_file
                )

                if not info["has_timestamp"]:
                    candidates.append({
                        "file": txt_file,
                        "rows": info["rows"],
                        "has_timestamp": False,
                        "overlap": 0.0,
                        "gap": float("inf"),
                        "start": None,
                        "end": None,
                    })

                    continue

                overlap = interval_overlap(
                    pcap_start,
                    pcap_end,
                    info["time_start"],
                    info["time_end"],
                )

                gap = interval_gap(
                    pcap_start,
                    pcap_end,
                    info["time_start"],
                    info["time_end"],
                )

                candidates.append({
                    "file": txt_file,
                    "rows": info["rows"],
                    "has_timestamp": True,
                    "overlap": overlap,
                    "gap": gap,
                    "start": info["time_start"],
                    "end": info["time_end"],
                })

        candidates.sort(
            key=lambda x: (
                -x["overlap"],
                x["gap"],
                x["file"].name.lower()
            )
        )

        for candidate in candidates[:10]:

            if candidate["has_timestamp"]:
                report.append(
                    f"  {candidate['file'].name:28} "
                    f"rows={candidate['rows']:5,d} | "
                    f"overlap={candidate['overlap']:9.3f}s | "
                    f"gap={candidate['gap']:9.3f}s | "
                    f"{epoch_to_utc(candidate['start'])} "
                    f"→ {epoch_to_utc(candidate['end'])}"
                )
            else:
                report.append(
                    f"  {candidate['file'].name:28} "
                    f"rows={candidate['rows']:5,d} | "
                    f"NO TIMESTAMP"
                )

        best = next(
            (
                c for c in candidates
                if c["has_timestamp"]
            ),
            None
        )

        if best:
            report.append("")
            report.append(
                "BEST TIME CANDIDATE: "
                f"{best['file'].name} "
                f"(overlap={best['overlap']:.3f}s, "
                f"gap={best['gap']:.3f}s)"
            )
        else:
            report.append("")
            report.append(
                "BEST TIME CANDIDATE: none "
                "(no timestamped TXT file found)"
            )

        report.append("")
        report.append("=" * 100)
        report.append("")

    txt_path = out_dir / "alignment_report.txt"
    csv_path = out_dir / "alignment_report.csv"

    txt_path.write_text(
        "\n".join(report),
        encoding="utf-8"
    )

    fields = [
        "category",
        "pcap",
        "selected_txt",
        "pcap_start_utc",
        "pcap_end_utc",
        "txt_start_utc",
        "txt_end_utc",
        "overlap_seconds",
        "gap_seconds",
        "txt_rows",
        "txt_has_timestamp",
        "verdict",
    ]

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fields
        )
        writer.writeheader()

        for row in rows_for_csv:
            writer.writerow(row)

    print("\n".join(report))
    print()
    print("Saved:")
    print(txt_path)
    print(csv_path)


if __name__ == "__main__":
    main()
