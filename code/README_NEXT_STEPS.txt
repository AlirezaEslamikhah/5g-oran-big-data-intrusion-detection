NEXT BIG DATA STEPS

Put these files inside:
C:\Users\aen593\Desktop\Big_Data_Project\code

1) Run the schema analysis first:

cd C:\Users\aen593\Desktop\Big_Data_Project; python .\code\04_csv_schema_groups.py

This creates:
results\csv_schema_groups.txt
results\csv_schema_groups.csv
results\csv_file_inventory.csv

Send csv_schema_groups.txt to ChatGPT so we can choose the correct large schema group.

2) Install PySpark before step 05:

python -m pip install pyspark

PySpark also requires Java.

3) After choosing a group ID:

cd C:\Users\aen593\Desktop\Big_Data_Project; python .\code\05_pyspark_bigdata_pipeline.py --group-id 1

Replace 1 with the group we choose after inspecting step 04.

Step 05 measures:
- input files
- input GB
- rows
- CSV read time
- cleaning time
- duplicate removal
- aggregations
- Parquet write time
- Parquet size
- Parquet read time
- storage reduction
- CSV-vs-Parquet read speed ratio
