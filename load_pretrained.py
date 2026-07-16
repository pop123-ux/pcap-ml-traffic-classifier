"""Download and run the pretrained CIC-IDS-2017 CatBoost model from Hugging Face.

This is a SEPARATE pipeline from `app.py`:

- `app.py`            → trains/infers on 4 raw packet-level features (packet_size,
                        ttl, protocol, tcp_flags) extracted directly from PCAPs
                        with Scapy. Fast, dependency-light, but only detects
                        attacks structurally similar to the training set.

- `load_pretrained.py` (this file) → uses the Hugging Face-hosted CatBoost model
                        trained on CIC-IDS-2017's 78 CICFlowMeter flow features.
                        You must pre-process your PCAPs with CICFlowMeter first;
                        the raw PCAP → flow-feature step is not done here.

CICFlowMeter: https://github.com/ahlashkari/CICFlowMeter

Usage:
    python3 load_pretrained.py path/to/cicflowmeter_output.csv
"""
import sys

REPO_ID = "pop123/pcap-ml-traffic-classifier"   # <-- edit to your HF handle
MODEL_FILENAME = "cicids_catboost.cbm"


def load_model():
    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        sys.exit(
            "[-] huggingface_hub not installed. Run:  pip install huggingface_hub"
        )
    from catboost import CatBoostClassifier

    print(f"[*] Downloading {MODEL_FILENAME} from {REPO_ID} ...")
    path = hf_hub_download(repo_id=REPO_ID, filename=MODEL_FILENAME)
    model = CatBoostClassifier()
    model.load_model(path)
    print(f"[+] Loaded model ({model.tree_count_} trees, "
          f"{len(model.feature_names_)} features)")
    return model


def classify_csv(csv_path):
    import pandas as pd

    model = load_model()

    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip()
    df = df.replace([float("inf"), float("-inf")], pd.NA).dropna()

    expected = list(model.feature_names_)
    missing = [c for c in expected if c not in df.columns]
    if missing:
        sys.exit(
            f"[-] Input CSV is missing {len(missing)} required CICFlowMeter "
            f"features. First few: {missing[:5]}. "
            "Re-run CICFlowMeter on your PCAP to produce the full 78-column output."
        )

    X = df[expected]
    preds = model.predict(X).astype(int).flatten()
    probs = model.predict_proba(X)[:, 1]

    total = len(preds)
    malicious = int((preds == 1).sum())
    benign = total - malicious
    print("\n--> Detection results:")
    print(f"    Total flows scanned : {total}")
    print(f"    Benign flows        : {benign}")
    print(f"    Malicious flows     : {malicious} ({malicious / total:.1%})")

    if malicious:
        top = probs.argsort()[::-1][:10]
        print("\n    Top 10 highest-confidence malicious flows (index, p_malicious):")
        for i in top:
            if preds[i] == 1:
                print(f"      row {i:>7} | p={probs[i]:.4f}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 load_pretrained.py <cicflowmeter_output.csv>")
    classify_csv(sys.argv[1])
