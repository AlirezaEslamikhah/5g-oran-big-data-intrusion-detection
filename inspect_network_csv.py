import pandas as pd

FILE = r"C:\Users\aen593\Desktop\Big_Data_Project\archive\Network_Dataset.csv"

# Only read 10,000 rows initially
df = pd.read_csv(FILE, nrows=10_000)

print("=" * 80)
print("SHAPE OF SAMPLE")
print("=" * 80)

print(df.shape)


print("\n" + "=" * 80)
print("COLUMNS")
print("=" * 80)

for i, col in enumerate(df.columns):
    print(f"{i:2}: {col}")


print("\n" + "=" * 80)
print("DATA TYPES")
print("=" * 80)

print(df.dtypes)


print("\n" + "=" * 80)
print("FIRST 5 ROWS")
print("=" * 80)

print(df.head())


print("\n" + "=" * 80)
print("MISSING VALUES")
print("=" * 80)

missing = df.isnull().sum()
missing = missing[missing > 0].sort_values(ascending=False)

print(missing)


print("\n" + "=" * 80)
print("ATTACK CATEGORY")
print("=" * 80)

if "attack_category" in df.columns:
    print(df["attack_category"].value_counts(dropna=False))


print("\n" + "=" * 80)
print("ATTACK TYPE")
print("=" * 80)

if "attack_type" in df.columns:
    print(df["attack_type"].value_counts(dropna=False))


print("\n" + "=" * 80)
print("TRAFFIC TYPE")
print("=" * 80)

if "traffic_type" in df.columns:
    print(df["traffic_type"].value_counts(dropna=False))


print("\n" + "=" * 80)
print("PROTOCOL")
print("=" * 80)

if "proto" in df.columns:
    print(df["proto"].value_counts(dropna=False))


print("\n" + "=" * 80)
print("SERVICE")
print("=" * 80)

if "service" in df.columns:
    print(df["service"].value_counts(dropna=False).head(30))


print("\n" + "=" * 80)
print("CONNECTION STATE")
print("=" * 80)

if "conn_state" in df.columns:
    print(df["conn_state"].value_counts(dropna=False))