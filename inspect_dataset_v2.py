from pathlib import Path
import sqlite3
import pandas as pd
from datetime import datetime, timezone

ROOT = Path(r"C:\Users\aen593\Desktop\Big_Data_Project\archive")

print("=" * 100)
print("SEARCHING CSV HEADERS")
print("=" * 100)

time_words = {"timestamp","time","ts","start_time","end_time","datetime","date"}
radio_words = {"rsrp","rsrq","rssi","sinr","cqi","dlmcs","ulmcs","dlbler","ulbler","ue_id","cellid","rnti"}
network_words = {"src_ip","dst_ip","src_port","dst_port","duration","src_bytes","dst_bytes","src_pkts","dst_pkts","proto"}

csv_files = list(ROOT.rglob("*.csv"))
print(f"\nCSV files found: {len(csv_files)}\n")

interesting_files = []

for file in csv_files:
    try:
        df = pd.read_csv(file, nrows=0)
        columns_original = list(df.columns)
        columns = {str(col).strip().lower() for col in columns_original}

        time_matches = sorted(columns & time_words)
        radio_matches = sorted(columns & radio_words)
        network_matches = sorted(columns & network_words)

        if time_matches or radio_matches:
            interesting_files.append({
                "path": file.relative_to(ROOT),
                "size_mb": file.stat().st_size / (1024 ** 2),
                "time": time_matches,
                "radio": radio_matches,
                "network": network_matches,
                "columns": columns_original
            })
    except Exception as e:
        print(f"Could not inspect: {file}")
        print(e)

print("\n" + "=" * 100)
print("CSV FILES WITH TIME OR RADIO COLUMNS")
print("=" * 100)

for info in interesting_files:
    print("\nFILE:")
    print(info["path"])
    print(f"Size: {info['size_mb']:.2f} MB")
    print("Time columns:", info["time"])
    print("Radio columns:", info["radio"])
    print("Network columns:", info["network"])
    print("All columns:", info["columns"])
    print("-" * 100)

network_db = ROOT / "Network_Dataset.db"

print("\n\n" + "=" * 100)
print("NETWORK DATABASE DISTRIBUTIONS")
print("=" * 100)

conn = sqlite3.connect(f"file:{network_db}?mode=ro", uri=True)
cursor = conn.cursor()

queries = {
    "TRAFFIC TYPE": """
        SELECT traffic_type, COUNT(*)
        FROM network_data
        GROUP BY traffic_type
        ORDER BY COUNT(*) DESC
    """,
    "ATTACK CATEGORY": """
        SELECT attack_category, COUNT(*)
        FROM network_data
        GROUP BY attack_category
        ORDER BY COUNT(*) DESC
    """,
    "ATTACK TYPE": """
        SELECT attack_type, COUNT(*)
        FROM network_data
        GROUP BY attack_type
        ORDER BY COUNT(*) DESC
    """
}

for name, query in queries.items():
    print("\n" + "-" * 80)
    print(name)
    print("-" * 80)
    cursor.execute(query)
    for value, count in cursor.fetchall():
        print(f"{str(value):30} {count:12,}")

conn.close()

radio_db = ROOT / "Lower_Layer_Data.db"

print("\n\n" + "=" * 100)
print("LOWER-LAYER DATABASE DISTRIBUTIONS")
print("=" * 100)

conn = sqlite3.connect(f"file:{radio_db}?mode=ro", uri=True)
cursor = conn.cursor()

queries = {
    "TRAFFIC TYPE": """
        SELECT traffic_type, COUNT(*)
        FROM lower_layer_data
        GROUP BY traffic_type
        ORDER BY COUNT(*) DESC
    """,
    "ATTACK CATEGORY": """
        SELECT attack_category, COUNT(*)
        FROM lower_layer_data
        GROUP BY attack_category
        ORDER BY COUNT(*) DESC
    """,
    "ATTACK SUBCATEGORY": """
        SELECT attack_subcategory, COUNT(*)
        FROM lower_layer_data
        GROUP BY attack_subcategory
        ORDER BY COUNT(*) DESC
    """,
    "UE IDs": """
        SELECT ue_id, COUNT(*)
        FROM lower_layer_data
        GROUP BY ue_id
        ORDER BY COUNT(*) DESC
    """,
    "CELL IDs": """
        SELECT cellid, COUNT(*)
        FROM lower_layer_data
        GROUP BY cellid
        ORDER BY COUNT(*) DESC
    """
}

for name, query in queries.items():
    print("\n" + "-" * 80)
    print(name)
    print("-" * 80)
    cursor.execute(query)
    for value, count in cursor.fetchall():
        print(f"{str(value):35} {count:12,}")

cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM lower_layer_data")
min_ts, max_ts = cursor.fetchone()

print("\n" + "-" * 80)
print("RADIO TIMESTAMP RANGE")
print("-" * 80)
print("Raw minimum:", min_ts)
print("Raw maximum:", max_ts)

def convert_timestamp(value):
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    except Exception:
        return None

print("Minimum UTC:", convert_timestamp(min_ts))
print("Maximum UTC:", convert_timestamp(max_ts))

conn.close()
