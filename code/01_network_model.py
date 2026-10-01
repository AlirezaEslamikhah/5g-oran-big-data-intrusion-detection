from pathlib import Path
import argparse
import json
import time
import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.impute import SimpleImputer

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = PROJECT_ROOT / "archive"
RESULTS_DIR = PROJECT_ROOT / "results"
MODEL_DIR = PROJECT_ROOT / "models"

NETWORK_CSV = DATA_ROOT / "Network_Dataset.csv"

TARGET = "traffic_type"

NUMERIC_FEATURES = [
    "src_port",
    "dst_port",
    "duration",
    "src_bytes",
    "dst_bytes",
    "missed_bytes",
    "src_pkts",
    "src_ip_bytes",
    "dst_pkts",
    "dst_ip_bytes",
    "ip_proto",
    "http_trans_depth",
    "files_total_bytes",
    "is_GET_mthd",
    "http_status_error",
    "is_file_transfered",
]

CATEGORICAL_FEATURES = [
    "proto",
    "service",
    "conn_state",
]

DROP_FOR_LEAKAGE_OR_MEMORIZATION = [
    "uid",
    "src_ip",
    "dst_ip",
    "attack_category",
    "attack_type",
    "history",
]

USECOLS = NUMERIC_FEATURES + CATEGORICAL_FEATURES + [TARGET]

def human_size(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size_bytes)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--max-rows",
        type=int,
        default=300000,
        help="Rows used for LOCAL baseline. Use 0 for the full dataset. Default: 300000.",
    )
    parser.add_argument(
        "--trees",
        type=int,
        default=120,
        help="Number of Random Forest trees. Default: 120.",
    )
    args = parser.parse_args()

    if not NETWORK_CSV.exists():
        raise SystemExit(f"Missing file: {NETWORK_CSV}")

    RESULTS_DIR.mkdir(exist_ok=True)
    MODEL_DIR.mkdir(exist_ok=True)

    print("=" * 90)
    print("NETWORK MODEL - BENIGN VS ATTACK")
    print("=" * 90)
    print(f"Source file : {NETWORK_CSV}")
    print(f"File size   : {human_size(NETWORK_CSV.stat().st_size)}")
    print(f"Model       : Random Forest")
    print(f"Target      : {TARGET}")
    print(f"Excluded    : {', '.join(DROP_FOR_LEAKAGE_OR_MEMORIZATION)}")
    print()

    started = time.time()
    df = pd.read_csv(NETWORK_CSV, usecols=USECOLS)

    total_rows = len(df)
    print(f"Full available rows : {total_rows:,}")
    print("Full class counts   :")
    print(df[TARGET].value_counts().sort_index())

    memory_mb = df.memory_usage(deep=True).sum() / (1024 ** 2)
    print(f"Loaded memory       : {memory_mb:,.2f} MB")

    if args.max_rows > 0 and total_rows > args.max_rows:
        df, _ = train_test_split(
            df,
            train_size=args.max_rows,
            stratify=df[TARGET],
            random_state=42,
        )

    print(f"\nRows used locally   : {len(df):,}")
    print(f"Fraction of full set: {len(df) / total_rows:.2%}")
    print("Local class counts  :")
    print(df[TARGET].value_counts().sort_index())

    X = df.drop(columns=[TARGET])
    y = df[TARGET].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    numeric_pipe = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
    ])

    categorical_pipe = Pipeline([
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("onehot", OneHotEncoder(handle_unknown="ignore")),
    ])

    preprocess = ColumnTransformer([
        ("num", numeric_pipe, NUMERIC_FEATURES),
        ("cat", categorical_pipe, CATEGORICAL_FEATURES),
    ])

    model = RandomForestClassifier(
        n_estimators=args.trees,
        max_depth=18,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )

    pipeline = Pipeline([
        ("preprocess", preprocess),
        ("model", model),
    ])

    print(f"\nTraining rows : {len(X_train):,}")
    print(f"Testing rows  : {len(X_test):,}")
    print("Training...")
    train_start = time.time()
    pipeline.fit(X_train, y_train)
    train_seconds = time.time() - train_start

    pred = pipeline.predict(X_test)

    metrics = {
        "dataset": "network",
        "source_file_size_bytes": NETWORK_CSV.stat().st_size,
        "full_available_rows": total_rows,
        "rows_used_local_model": len(df),
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "model": "RandomForestClassifier",
        "trees": args.trees,
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred, zero_division=0),
        "recall": recall_score(y_test, pred, zero_division=0),
        "f1": f1_score(y_test, pred, zero_division=0),
        "training_seconds": train_seconds,
        "total_script_seconds": time.time() - started,
    }

    print("\nRESULTS")
    print("-" * 90)
    for key in ["accuracy", "precision", "recall", "f1"]:
        print(f"{key.capitalize():10}: {metrics[key]:.4f}")

    print("\nConfusion matrix:")
    cm = confusion_matrix(y_test, pred)
    print(cm)

    print("\nClassification report:")
    print(classification_report(y_test, pred, digits=4, zero_division=0))

    model_path = MODEL_DIR / "network_random_forest.joblib"
    metrics_path = RESULTS_DIR / "network_metrics.json"
    cm_path = RESULTS_DIR / "network_confusion_matrix.csv"

    joblib.dump(pipeline, model_path)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    pd.DataFrame(
        cm,
        index=["actual_benign_0", "actual_attack_1"],
        columns=["pred_benign_0", "pred_attack_1"],
    ).to_csv(cm_path)

    print("\nSAVED")
    print("-" * 90)
    print(model_path)
    print(metrics_path)
    print(cm_path)

if __name__ == "__main__":
    main()
