

from __future__ import annotations

import argparse
import csv
import os
from collections import Counter, defaultdict
from pathlib import Path


def human_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{size} B"


def scan(root: Path):
    files = []
    dir_sizes = defaultdict(int)
    dir_file_counts = defaultdict(int)
    dir_ext_counts = defaultdict(Counter)

    for current, dirs, filenames in os.walk(root):
        current_path = Path(current)

        for filename in filenames:
            path = current_path / filename

            try:
                size = path.stat().st_size
            except OSError:
                continue

            rel = path.relative_to(root)
            ext = path.suffix.lower() or "[no extension]"

            files.append({
                "path": path,
                "relative": rel,
                "size": size,
                "ext": ext,
            })

            # Add file size/counts to this directory and every parent below root
            parent = rel.parent
            while True:
                dir_sizes[parent] += size
                dir_file_counts[parent] += 1
                dir_ext_counts[parent][ext] += 1

                if parent == Path("."):
                    break

                parent = parent.parent

    return files, dir_sizes, dir_file_counts, dir_ext_counts


def build_tree(root: Path, files, dir_sizes, dir_file_counts, depth: int) -> str:
    lines = []

    total_size = sum(x["size"] for x in files)

    lines.append("=" * 100)
    lines.append("DATASET / REPOSITORY TREE")
    lines.append("=" * 100)
    lines.append(f"Root       : {root}")
    lines.append(f"Total files: {len(files):,}")
    lines.append(f"Total size : {human_size(total_size)}")
    lines.append("")

    def recurse(folder: Path, prefix: str, level: int):
        if level > depth:
            return

        rel_folder = folder.relative_to(root) if folder != root else Path(".")
        try:
            children = list(folder.iterdir())
        except OSError:
            return

        dirs = sorted(
            [p for p in children if p.is_dir()],
            key=lambda p: p.name.lower()
        )
        fpaths = sorted(
            [p for p in children if p.is_file()],
            key=lambda p: p.name.lower()
        )

        entries = dirs + fpaths

        for idx, entry in enumerate(entries):
            is_last = idx == len(entries) - 1
            branch = "└── " if is_last else "├── "
            next_prefix = prefix + ("    " if is_last else "│   ")

            if entry.is_dir():
                rel = entry.relative_to(root)
                size = dir_sizes.get(rel, 0)
                count = dir_file_counts.get(rel, 0)

                lines.append(
                    f"{prefix}{branch}{entry.name}/ "
                    f"[{human_size(size)}, {count:,} files]"
                )

                if level < depth:
                    recurse(entry, next_prefix, level + 1)

            else:
                try:
                    size = entry.stat().st_size
                except OSError:
                    size = 0

                lines.append(
                    f"{prefix}{branch}{entry.name} "
                    f"[{human_size(size)}]"
                )

    lines.append(f"{root.name}/")
    recurse(root, "", 1)
    lines.append("")

    return "\n".join(lines)


def build_summary(root: Path, files, dir_sizes, dir_file_counts, dir_ext_counts) -> str:
    lines = []

    total_size = sum(x["size"] for x in files)

    lines.append("=" * 100)
    lines.append("TOP-LEVEL SUMMARY")
    lines.append("=" * 100)

    top_dirs = []

    try:
        for child in root.iterdir():
            if child.is_dir():
                rel = child.relative_to(root)
                top_dirs.append((
                    child.name,
                    dir_sizes.get(rel, 0),
                    dir_file_counts.get(rel, 0),
                    dir_ext_counts.get(rel, Counter())
                ))
    except OSError:
        pass

    for name, size, count, ext_counts in sorted(
        top_dirs,
        key=lambda x: x[1],
        reverse=True
    ):
        ext_text = ", ".join(
            f"{ext}:{cnt}"
            for ext, cnt in ext_counts.most_common()
        )

        lines.append(
            f"{name:35} "
            f"{human_size(size):>12} | "
            f"{count:4,} files | "
            f"{ext_text}"
        )

    root_files = [f for f in files if f["relative"].parent == Path(".")]

    if root_files:
        lines.append("")
        lines.append("ROOT FILES")
        lines.append("-" * 100)

        for item in sorted(root_files, key=lambda x: x["size"], reverse=True):
            lines.append(
                f"{human_size(item['size']):>12} | {item['relative']}"
            )

    lines.append("")
    lines.append("=" * 100)
    lines.append("FILE TYPE SUMMARY")
    lines.append("=" * 100)

    ext_count = Counter()
    ext_size = defaultdict(int)

    for item in files:
        ext_count[item["ext"]] += 1
        ext_size[item["ext"]] += item["size"]

    for ext, count in ext_count.most_common():
        lines.append(
            f"{ext:15} "
            f"{count:6,} files | "
            f"{human_size(ext_size[ext]):>12}"
        )

    lines.append("")
    lines.append("=" * 100)
    lines.append("30 LARGEST FILES")
    lines.append("=" * 100)

    for item in sorted(files, key=lambda x: x["size"], reverse=True)[:30]:
        lines.append(
            f"{human_size(item['size']):>12} | {item['relative']}"
        )

    lines.append("")
    lines.append("=" * 100)
    lines.append("PCAP / PCAPNG FILES BY TOP-LEVEL FOLDER")
    lines.append("=" * 100)

    pcap_by_top = defaultdict(lambda: {"count": 0, "bytes": 0, "files": []})

    for item in files:
        if item["ext"] not in {".pcap", ".pcapng"}:
            continue

        parts = item["relative"].parts
        top = parts[0] if len(parts) > 1 else "[ROOT]"

        pcap_by_top[top]["count"] += 1
        pcap_by_top[top]["bytes"] += item["size"]
        pcap_by_top[top]["files"].append(item)

    for top, info in sorted(
        pcap_by_top.items(),
        key=lambda x: x[1]["bytes"],
        reverse=True
    ):
        lines.append("")
        lines.append(
            f"{top} — {info['count']} captures, "
            f"{human_size(info['bytes'])}"
        )

        # Largest 5 captures in each top-level folder
        for item in sorted(
            info["files"],
            key=lambda x: x["size"],
            reverse=True
        )[:5]:
            lines.append(
                f"    {human_size(item['size']):>12} | {item['relative']}"
            )

    lines.append("")
    lines.append("=" * 100)
    lines.append("CSV / DB FILES")
    lines.append("=" * 100)

    interesting = [
        item for item in files
        if item["ext"] in {".csv", ".db", ".sqlite", ".sqlite3"}
    ]

    for item in sorted(
        interesting,
        key=lambda x: (x["ext"], -x["size"], str(x["relative"]).lower())
    ):
        lines.append(
            f"{item['ext']:8} | "
            f"{human_size(item['size']):>12} | "
            f"{item['relative']}"
        )

    lines.append("")
    lines.append("=" * 100)
    lines.append("SUGGESTED REPRESENTATIVE PCAPS")
    lines.append("=" * 100)
    lines.append(
        "These are only candidates based on folder names and size; "
        "we will choose after reviewing this output."
    )

    # One smaller + one larger candidate per top-level category
    for top, info in sorted(pcap_by_top.items()):
        candidates = sorted(
            info["files"],
            key=lambda x: x["size"]
        )

        if not candidates:
            continue

        nonzero = [x for x in candidates if x["size"] > 1024 * 1024]
        pool = nonzero or candidates

        smallest = pool[0]
        largest = pool[-1]

        lines.append("")
        lines.append(f"{top}:")
        lines.append(
            f"  smaller candidate: {human_size(smallest['size']):>12} | "
            f"{smallest['relative']}"
        )

        if largest["relative"] != smallest["relative"]:
            lines.append(
                f"  larger candidate : {human_size(largest['size']):>12} | "
                f"{largest['relative']}"
            )

    lines.append("")
    lines.append(
        f"Scanned total: {len(files):,} files, {human_size(total_size)}"
    )

    return "\n".join(lines)


def write_csv(files, output: Path):
    with output.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow([
            "relative_path",
            "extension",
            "size_bytes",
            "size_mb",
            "size_gb",
        ])

        for item in sorted(
            files,
            key=lambda x: str(x["relative"]).lower()
        ):
            writer.writerow([
                str(item["relative"]),
                item["ext"],
                item["size"],
                round(item["size"] / (1024 ** 2), 4),
                round(item["size"] / (1024 ** 3), 6),
            ])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        required=True,
        help="Root folder of the extracted dataset."
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=6,
        help="Maximum directory depth shown in tree. Default: 6"
    )
    parser.add_argument(
        "--out",
        default=".",
        help="Output directory. Default: current directory"
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    out_dir = Path(args.out).resolve()

    if not root.exists():
        raise SystemExit(f"Root does not exist: {root}")

    out_dir.mkdir(parents=True, exist_ok=True)

    print("Scanning filesystem metadata only...")
    files, dir_sizes, dir_file_counts, dir_ext_counts = scan(root)

    tree_text = build_tree(
        root,
        files,
        dir_sizes,
        dir_file_counts,
        max(1, args.depth)
    )

    summary_text = build_summary(
        root,
        files,
        dir_sizes,
        dir_file_counts,
        dir_ext_counts
    )

    txt_path = out_dir / "repository_tree.txt"
    csv_path = out_dir / "repository_inventory.csv"

    txt_path.write_text(
        tree_text + "\n\n" + summary_text,
        encoding="utf-8"
    )

    write_csv(files, csv_path)

    print()
    print("=" * 80)
    print("DONE")
    print("=" * 80)
    print(f"Tree report : {txt_path}")
    print(f"Inventory   : {csv_path}")
    print()
    print(tree_text)
    print(summary_text)


if __name__ == "__main__":
    main()
