import argparse
import os
import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty"
]

def load_nsl_kdd(path):
    df = pd.read_csv(path, header=None, names=COLUMNS)
    y = (df["label"].astype(str).str.strip() != "normal").astype(int)
    X = df.drop(columns=["label", "difficulty"])
    return X, y

def build_model(X):
    categorical = X.select_dtypes(include=["object"]).columns.tolist()
    numerical = [c for c in X.columns if c not in categorical]

    preprocessor = ColumnTransformer([
        ("categorical", OneHotEncoder(handle_unknown="ignore"), categorical),
        ("numerical", "passthrough", numerical),
    ])

    classifier = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
        max_features="sqrt",
    )

    return Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", classifier),
    ])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", required=True)
    parser.add_argument("--test", required=True)
    parser.add_argument("--output", default="ml/model.joblib")
    args = parser.parse_args()

    X_train, y_train = load_nsl_kdd(args.train)
    X_test, y_test = load_nsl_kdd(args.test)

    print(f"Training records: {len(X_train):,}")
    print(f"Testing records:  {len(X_test):,}")
    print(f"Features:         {X_train.shape[1]}")
    print(f"Attack rate train: {y_train.mean():.4f}")
    print(f"Attack rate test:  {y_test.mean():.4f}")

    model = build_model(X_train)

    print("\nTraining Random Forest...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\n=== Evaluation ===")
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print("\nClassification report:")
    print(classification_report(
        y_test,
        predictions,
        target_names=["Normal", "Attack"],
        digits=4,
    ))

    output_dir = os.path.dirname(os.path.abspath(args.output))
    os.makedirs(output_dir, exist_ok=True)
    joblib.dump(model, args.output)
    print(f"\nModel saved to: {os.path.abspath(args.output)}")

if __name__ == "__main__":
    main()
