import argparse
import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score

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

def load_test(path):
    df = pd.read_csv(path, header=None, names=COLUMNS)
    y = (df["label"].astype(str).str.strip() != "normal").astype(int)
    X = df.drop(columns=["label", "difficulty"])
    return X, y

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--test", required=True)
    args = parser.parse_args()

    model = joblib.load(args.model)
    X_test, y_test = load_test(args.test)

    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)[:, 1]

    print("=== Model Evaluation ===")
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print(f"ROC-AUC:  {roc_auc_score(y_test, probabilities):.4f}")
    print("\n=== Classification Report ===")
    print(classification_report(
        y_test, predictions,
        target_names=["Normal", "Attack"],
        digits=4
    ))
    print("=== Confusion Matrix ===")
    print(confusion_matrix(y_test, predictions))
    print("\n=== Example Threat Scores ===")
    for i in range(min(10, len(probabilities))):
        result = "ATTACK" if predictions[i] else "NORMAL"
        print(f"Record {i+1:2d}: {result:6s} threat_score={probabilities[i]:.4f}")

if __name__ == "__main__":
    main()
