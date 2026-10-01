from pathlib import Path
import json
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"

def main():
    paths = {
        "Network": RESULTS_DIR / "network_metrics.json",
        "Radio": RESULTS_DIR / "radio_metrics.json",
    }

    rows = []

    for name, path in paths.items():
        if not path.exists():
            print(f"Missing: {path}")
            continue

        data = json.loads(path.read_text(encoding="utf-8"))
        rows.append({
            "Model/Input": name,
            "Full rows available": data["full_available_rows"],
            "Rows used locally": data["rows_used_local_model"],
            "Train rows": data["train_rows"],
            "Test rows": data["test_rows"],
            "Accuracy": data["accuracy"],
            "Precision": data["precision"],
            "Recall": data["recall"],
            "F1": data["f1"],
            "Training seconds": data["training_seconds"],
        })

    if not rows:
        raise SystemExit("No model metric files found. Run 01 and 02 first.")

    df = pd.DataFrame(rows)
    print("=" * 110)
    print("MODEL COMPARISON")
    print("=" * 110)
    print(df.to_string(index=False))

    out = RESULTS_DIR / "model_comparison.csv"
    df.to_csv(out, index=False)
    print(f"\nSaved: {out}")

if __name__ == "__main__":
    main()
