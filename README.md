# 5G O-RAN Big Data Intrusion Detection on AWS

Cloud-based **5G O-RAN intrusion detection** and **Big Data analytics** using the **NetsLab 5G O-RAN IDD dataset**, **PySpark**, **Apache Spark**, **AWS S3**, **Amazon EMR Serverless**, and **Spark MLlib Random Forest** models.

This project processes large-scale 5G network data and evaluates attack detection using two views of the network: **network-flow traffic** and **lower-layer radio telemetry**.

## Project Highlights

- Profiled a **135.93 GB** 5G O-RAN security dataset containing 320 files.
- Processed **28,803,972 packet records** from 35 CSV files with PySpark.
- Converted the processed packet data to **Snappy Parquet** partitioned by attack scenario.
- Trained separate Random Forest models for **network-flow** and **radio-layer** intrusion detection.
- Used **AWS EC2, S3, IAM, and EMR Serverless** to build a reproducible cloud pipeline.
- Evaluated attacks including **DoS, DDoS, Probe/Port Scan, Brute Force, and Web attacks**.

## Architecture

```text
NetsLab 5G O-RAN Dataset
        ↓
Temporary Amazon EC2
        ↓
Amazon S3 Data Lake
        ↓
Amazon EMR Serverless + PySpark
        ↓
Snappy Parquet
        ↓
Spark MLlib Random Forest
        ↓
Metrics & Models in S3
```

The AWS design uses **IAM roles instead of static access keys** and short-lived/serverless compute rather than a permanent Spark cluster.

## Results

| Model | Records | Accuracy | Attack Precision | Attack Recall | Attack F1 | ROC AUC |
|---|---:|---:|---:|---:|---:|---:|
| Network Flow | 1,723,817 | 97.66% | 98.14% | 99.29% | 98.71% | 99.56% |
| Radio Telemetry | 45,244 | 98.90% | 98.77% | 99.81% | 99.29% | 99.90% |

The network model uses traffic features such as protocol, service, ports, duration, packet counts, and byte counts.

The radio model uses 16 lower-layer 5G measurements, including **RSRP, RSRQ, RSSI, SINR, CQI, MCS, BLER, PHR, and uplink/downlink measurements**.

Direct identifiers and attack-category fields were excluded from the predictors to reduce label leakage.

## Main Scripts

| Script | Purpose |
|---|---|
| `00_bigdata_profile.py` | Dataset profiling |
| `04_csv_schema_groups.py` | CSV schema grouping |
| `05_pyspark_packet_pipeline_fixed3.py` | Local PySpark feasibility test |
| `ingest_selected_to_s3.py` | Kaggle-to-S3 ingestion |
| `06_emr_serverless_packet_pipeline_v2.py` | EMR packet processing and Parquet transformation |
| `07_emr_network_rf_v2.py` | Network-flow Random Forest |
| `08_emr_radio_rf.py` | Radio-telemetry Random Forest |

## Technologies

**5G · O-RAN · Cybersecurity · Intrusion Detection · Big Data · Python · PySpark · Apache Spark · Spark MLlib · AWS · Amazon S3 · Amazon EC2 · Amazon EMR Serverless · Parquet · Random Forest · Machine Learning · Radio Telemetry**

## Project Setup

### 1. Get the Dataset

Download the **NetsLab 5G O-RAN Intrusion Detection Dataset** from Kaggle. The full dataset is large, so this project first profiles the repository and then selects the required packet, network-flow, and radio files.

### 2. Prepare AWS

Create:

- An **Amazon S3 bucket** for raw data, processed Parquet files, scripts, metrics, and trained models.
- An **IAM role** for the temporary EC2 ingestion instance.
- An **IAM runtime role** for Amazon EMR Serverless with access to the project S3 bucket.
- An **Amazon EMR Serverless** Spark application.

The project used **EMR 7.13.0 with Spark 3.5.6** in `ca-west-1`.

Recommended S3 layout:

```text
raw/packets/
raw/network/
raw/radio/
processed/packets_parquet/
scripts/
results/bigdata_metrics/
results/network_model/
results/radio_model/
```

### 3. Profile and Select the Data

Run the local profiling scripts first:

```text
00_bigdata_profile.py
04_csv_schema_groups.py
```

These scripts inspect the repository, summarize file/database structure, and identify the consistent packet workload used by the Spark pipeline.

### 4. Upload Data to S3

Use:

```text
ingest_selected_to_s3.py
```

The project uses a temporary Amazon EC2 instance to download the selected public dataset files and upload them to S3. After the transfer is verified, the instance can be terminated.

### 5. Run the Spark Jobs

Upload the PySpark scripts to S3 and submit them to EMR Serverless:

```text
06_emr_serverless_packet_pipeline_v2.py
07_emr_network_rf_v2.py
08_emr_radio_rf.py
```

They perform:

- packet cleaning and scenario analysis
- Snappy Parquet conversion
- network-flow Random Forest training
- radio-telemetry Random Forest training
- metric, model, confusion-matrix, and prediction output generation

> The repository does not require permanent AWS credentials in the source code. The cloud workflow uses IAM roles for access to S3 and EMR resources.

## Limitations & Future Work

The current results use random train/validation/test splits and should be treated as controlled-dataset baselines.

Future work includes **run-disjoint evaluation, time-based testing, cross-layer network/radio fusion, streaming intrusion detection, class-imbalance handling, and broader ML model comparison**.

## Dataset

**NetsLab 5G O-RAN Intrusion Detection Dataset** — a physical 5G O-RAN testbed dataset containing packet traffic, network-flow data, and lower-layer radio measurements.

## Author

**Alireza Eslamikhah**  
M.Sc. Computer Science — University of Regina
