from pathlib import Path
from collections import Counter, defaultdict
import sqlite3

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = PROJECT_ROOT / "archive"

def human_size(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size_bytes)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024

def main():
    if not DATA_ROOT.exists():
        raise SystemExit(f"Dataset folder not found: {DATA_ROOT}")

    print("=" * 90)
    print("BIG DATA PROJECT - DATA VOLUME PROFILE")
    print("=" * 90)
    print(f"Project root : {PROJECT_ROOT}")
    print(f"Dataset root : {DATA_ROOT}")

    ext_count = Counter()
    ext_size = defaultdict(int)
    top_size = defaultdict(int)
    top_count = Counter()
    total_size = 0
    total_files = 0

    for path in DATA_ROOT.rglob("*"):
        if not path.is_file():
            continue

        size = path.stat().st_size
        rel = path.relative_to(DATA_ROOT)
        top = rel.parts[0] if len(rel.parts) > 1 else "[ROOT]"
        ext = path.suffix.lower() or "[no extension]"

        total_files += 1
        total_size += size
        ext_count[ext] += 1
        ext_size[ext] += size
        top_size[top] += size
        top_count[top] += 1

    print("\nDATASET TOTAL")
    print("-" * 90)
    print(f"Files : {total_files:,}")
    print(f"Size  : {human_size(total_size)}")

    print("\nBY FILE TYPE")
    print("-" * 90)
    for ext, count in ext_count.most_common():
        print(f"{ext:12} {count:6,} files   {human_size(ext_size[ext]):>12}")

    print("\nBY TOP-LEVEL FOLDER")
    print("-" * 90)
    for name, size in sorted(top_size.items(), key=lambda x: x[1], reverse=True):
        print(f"{name:35} {top_count[name]:5,} files   {human_size(size):>12}")

    network_db = DATA_ROOT / "Network_Dataset.db"
    radio_db = DATA_ROOT / "Lower_Layer_Data.db"

    print("\nNETWORK DATASET")
    print("-" * 90)
    if network_db.exists():
        con = sqlite3.connect(f"file:{network_db}?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM network_data")
        rows = cur.fetchone()[0]
        print(f"Rows      : {rows:,}")
        print(f"DB size   : {human_size(network_db.stat().st_size)}")
        cur.execute("""
            SELECT traffic_type, COUNT(*)
            FROM network_data
            GROUP BY traffic_type
            ORDER BY traffic_type
        """)
        print("Classes   :", dict(cur.fetchall()))
        con.close()

    print("\nRADIO DATASET")
    print("-" * 90)
    if radio_db.exists():
        con = sqlite3.connect(f"file:{radio_db}?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM lower_layer_data")
        rows = cur.fetchone()[0]
        print(f"Rows      : {rows:,}")
        print(f"DB size   : {human_size(radio_db.stat().st_size)}")
        cur.execute("""
            SELECT traffic_type, COUNT(*)
            FROM lower_layer_data
            GROUP BY traffic_type
            ORDER BY traffic_type
        """)
        print("Classes   :", dict(cur.fetchall()))
        con.close()

    print("\nPROJECT DATA STORY")
    print("-" * 90)
    print("Raw packet captures  :", human_size(ext_size.get(".pcap", 0) + ext_size.get(".pcapng", 0)))
    print("Structured CSV data  :", human_size(ext_size.get(".csv", 0)))
    print("Prepared DB data     :", human_size(ext_size.get(".db", 0)))
    print("\nThis is the volume we will describe in the Big Data report.")
    print("Local ML uses prepared data for fast prototyping; AWS/PySpark will later process the larger structured collection.")

if __name__ == "__main__":
    main()
