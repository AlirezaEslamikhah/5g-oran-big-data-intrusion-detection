from pathlib import Path
import json
import sqlite3
import time
import joblib
import pandas as pd

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
from sklearn.impute import SimpleImputer

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = PROJECT_ROOT / "archive"
RESULTS_DIR = PROJECT_ROOT / "results"
MODEL_DIR = PROJECT_ROOT / "models"

RADIO_DB = DATA_ROOT / "Lower_Layer_Data.db"
TARGET = "traffic_type"

FEATURES = [
    "dlBytes",
    "dlMcs",
    "dlBler",
    "ulBytes",
    "ulMcs",
    "ulBler",
    "ri",
    "phr",
    "pcmax",
    "rsrq",
    "sinr",
    "rsrp",
    "rssi",
    "cqi",
    "pucchSnr",
    "puschSnr",
]

EXCLUDED = [
    "attack_category",
    "attack_subcategory",
    "timestamp",
    "ue_id",
    "cellid",
    "rnti",
    "pmi",
]

def human_size(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size_bytes)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024

def main():
    if not RADIO_DB.exists():
        raise SystemExit(f"Missing file: {RADIO_DB}")

    RESULTS_DIR.mkdir(exist_ok=True)
    MODEL_DIR.mkdir(exist_ok=True)

    print("=" * 90)
    print("RADIO MODEL - BENIGN VS ATTACK")
    print("=" * 90)
    print(f"Source file : {RADIO_DB}")
    print(f"DB size     : {human_size(RADIO_DB.stat().st_size)}")
    print("Model       : Random Forest")
    print(f"Target      : {TARGET}")
    print(f"Features    : {len(FEATURES)} radio measurements")
    print(f"Excluded    : {', '.join(EXCLUDED)}")

    started = time.time()

    columns_sql = ", ".join([f'"{c}"' for c in FEATURES + [TARGET]])
    con = sqlite3.connect(f"file:{RADIO_DB}?mode=ro", uri=True)
    df = pd.read_sql_query(
        f"SELECT {columns_sql} FROM lower_layer_data",
        con
    )
    con.close()

    total_rows = len(df)
    print(f"\nRows used          : {total_rows:,} (FULL radio dataset)")
    print("Class counts       :")
    print(df[TARGET].value_counts().sort_index())

    memory_mb = df.memory_usage(deep=True).sum() / (1024 ** 2)
    print(f"Loaded memory      : {memory_mb:,.2f} MB")

    X = df[FEATURES]
    y = df[TARGET].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("model", RandomForestClassifier(
            n_estimators=150,
            max_depth=16,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=42,
            n_jobs=-1,
        )),
    ])

    print(f"\nTraining rows : {len(X_train):,}")
    print(f"Testing rows  : {len(X_test):,}")
    print("Training...")
    train_start = time.time()
    pipeline.fit(X_train, y_train)
    train_seconds = time.time() - train_start

    pred = pipeline.predict(X_test)

    metrics = {
        "dataset": "radio",
        "source_file_size_bytes": RADIO_DB.stat().st_size,
        "full_available_rows": total_rows,
        "rows_used_local_model": total_rows,
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "model": "RandomForestClassifier",
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

    model_path = MODEL_DIR / "radio_random_forest.joblib"
    metrics_path = RESULTS_DIR / "radio_metrics.json"
    cm_path = RESULTS_DIR / "radio_confusion_matrix.csv"

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
