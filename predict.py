import argparse
import joblib
import pandas as pd

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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--input", required=True)
    args = parser.parse_args()

    model = joblib.load(args.model)
    df = pd.read_csv(args.input, header=None, names=COLUMNS)
    X = df.drop(columns=["label", "difficulty"])

    predictions = model.predict(X)
    probabilities = model.predict_proba(X)[:, 1]

    for i, (prediction, probability) in enumerate(zip(predictions, probabilities), 1):
        result = "ATTACK" if prediction else "NORMAL"
        print(f"Record {i}: {result} | threat_score={probability:.4f}")

if __name__ == "__main__":
    main()
