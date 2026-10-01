import sqlite3
from pathlib import Path


DATASETS = [
    Path(r"C:\Users\aen593\Desktop\Big_Data_Project\archive\Lower_Layer_Data.db"),
    Path(r"C:\Users\aen593\Desktop\Big_Data_Project\archive\Network_Dataset.db"),
]


for db_file in DATASETS:

    print("\n")
    print("=" * 100)
    print(f"DATABASE: {db_file.name}")
    print("=" * 100)

    try:
        connection = sqlite3.connect(
            f"file:{db_file}?mode=ro",
            uri=True
        )

        cursor = connection.cursor()

        cursor.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type='table'
            ORDER BY name
        """)

        tables = [row[0] for row in cursor.fetchall()]

        print("\nTables:")
        for table in tables:
            print(f"  - {table}")

        for table in tables:

            print("\n" + "-" * 100)
            print(f"TABLE: {table}")
            print("-" * 100)

            # Schema
            cursor.execute(f'PRAGMA table_info("{table}")')
            columns = cursor.fetchall()

            print("\nColumns:")

            for column in columns:

                cid, name, dtype, notnull, default, pk = column

                print(
                    f"{name:30} "
                    f"{dtype:15} "
                    f"PK={pk}"
                )

            # Record count
            cursor.execute(f'SELECT COUNT(*) FROM "{table}"')
            count = cursor.fetchone()[0]

            print(f"\nRows: {count:,}")

            # Sample rows
            cursor.execute(f'SELECT * FROM "{table}" LIMIT 5')
            rows = cursor.fetchall()

            print("\nFirst 5 rows:")

            for row in rows:
                print(row)

        connection.close()

    except Exception as e:
        print("Could not read database:")
        print(e)