# PCAP-ML Traffic Classifier

### Machine Learning–Powered Network Intrusion Detection via Heuristic Packet Classification

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)
![CatBoost](https://img.shields.io/badge/CatBoost-Gradient%20Boosting-yellow)
![Scapy](https://img.shields.io/badge/Scapy-Packet%20Dissection-green)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## Abstract

Traditional signature-based firewalls and IDS rules (e.g., static Snort signatures) detect only **known** attack patterns — they fail silently against novel or obfuscated traffic. This project takes a **heuristic, learning-based approach**: instead of matching byte signatures, it learns the *statistical fingerprint* of malicious traffic directly from labeled packet captures.

The system ingests raw `.pcap` / `.pcapng` files, dissects each frame at L3/L4 with **Scapy**, engineers a compact behavioral feature vector, and trains a **CatBoost gradient-boosted classifier** to discriminate malicious from benign streams. At inference time, it produces both a per-packet verdict and an **automated Threat Intelligence report** attributing hostile frames back to their source IP addresses — turning raw detection into actionable incident-response output.

---

## Core Features

- **Raw PCAP ingestion** — Robust dual-reader logic (`PcapReader` → `PcapNgReader` fallback) transparently handles both classic libpcap and modern PCAPNG capture formats.
- **L3/L4 feature extraction** — Per-packet dissection of IP and TCP/UDP layers via Scapy, with graceful handling of non-TCP transport (UDP and raw IP frames are normalized rather than dropped).
- **Dynamic categorical feature handling** — `protocol` and `tcp_flags` are declared as native categorical features, letting CatBoost's **symmetric (oblivious) decision trees** apply ordered target statistics instead of naive one-hot expansion. No manual encoding pipeline required.
- **Class-imbalance resilience** — `auto_class_weights='Balanced'` prevents the degenerate "predict everything benign" failure mode common on real-world traffic (see [Under the Hood](#under-the-hood-handling-extreme-class-imbalance)).
- **Automated Incident Response / Threat Intel mapping** — Malicious verdicts are aggregated by `src_ip` and ranked, producing a **Top Attacker IP** table that maps ML output directly onto the first step of an IR playbook: source attribution.
- **Regularized, overfit-resistant training** — Shallow trees (`depth=3`) with L2 leaf regularization (`l2_leaf_reg=5`) and a stratified 70/30 hold-out evaluation set with full classification report (precision / recall / F1).

---

## Pipeline Architecture

```
 ┌─────────────┐    ┌──────────────────┐    ┌──────────────────┐    ┌─────────────────┐
 │  Raw PCAP   │───▶│  Scapy Dissector │───▶│ Feature Matrix   │───▶│ CatBoost        │
 │ (.pcap/ng)  │    │  (L3/L4 layers)  │    │ (Pandas DF)      │    │ Classifier      │
 └─────────────┘    └──────────────────┘    └──────────────────┘    └────────┬────────┘
                                                                             │
                                                    ┌────────────────────────▼───────┐
                                                    │  Verdicts + Threat Intel Report│
                                                    │  (Top Attacker IP Attribution) │
                                                    └────────────────────────────────┘
```

### Feature Selection Rationale

The model trains on a **deliberately reduced feature set**:

| Feature | Type | Why it matters |
|---|---|---|
| `packet_size` | Numeric | Scans, floods, and C2 beacons exhibit characteristic frame-size distributions (e.g., minimal 40–60 B probes vs. full MTU data transfer). |
| `ttl` | Numeric | TTL anomalies expose crafted packets, OS-fingerprint mismatches, and spoofing artifacts. |
| `protocol` | Categorical | Protocol mix (TCP/UDP/ICMP) shifts sharply under scanning and flooding behavior. |
| `tcp_flags` | Categorical | The single strongest heuristic signal: bare-ACK probes, SYN floods, FIN/NULL/Xmas scans all produce abnormal flag combinations. |

### Deliberately Excluded Features

Although `src_port`, `dst_port`, and `src_ip` / `dst_ip` **are extracted** during dissection, they are **excluded from the training matrix by design**:

- **Ephemeral ports** are OS-randomized per connection — they carry near-zero generalizable signal and are a classic overfitting trap.
- **IP addresses** would cause the model to memorize *who* attacked in the training capture rather than learn *how* attacks behave — a hardcoded routing bias that collapses the moment the attacker changes address. Excluding them forces the model to generalize on behavioral features only.
- `src_ip` is instead retained **out-of-band** and rejoined post-inference for the Threat Intel attribution report — attribution without contamination.

---

## Setup & Installation

```bash
# 1. Clone the repository
git clone https://github.com/pop123-ux/pcap-ml-traffic-classifier.git
cd pcap-ml-traffic-classifier

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

> **Note:** Reading PCAPs requires no elevated privileges. Root/admin is only needed if you extend the tool to live-capture from an interface.

---

## CLI Usage

### 1. Training Mode

Provide one benign (clean baseline) capture and one malicious (attack) capture:

```bash
python3 app.py --train clean.pcap attack.pcap
```

Example output:

```
--> Training Mode Activated
[*] Processing: clean.pcap
[+] Successfully extracted 43 packets.
[*] Processing: attack.pcap
[+] Successfully extracted 2000 packets.

[*] The state-of-the-art CatBoost Classifier is training...
[+] Model Accuracy: 99.84%
[+] The model was saved in the file 'traffic_model.pkl'.
```

### 2. Inference & Threat Intel Mode

Point the tool at any unlabeled capture:

```bash
python3 app.py --analyze suspicious.pcap
# (a bare file argument also works: python3 app.py suspicious.pcap)
```

Example output:

```
--> Traffic Analysis Mode Activated
--> Detection Results:
Total scanned packets: 1500
Benign packets: 212
Malicious packets: 1288

Percentage of malicious traffic detected: 85.86

 TOP ATTACKER IP ADDRESSES (THREAT INTEL)
Source IP Address    | Malicious Packets Generated
192.168.1.105        | 1140
10.0.0.44            | 148
```

---

## Under the Hood: Handling Extreme Class Imbalance

Real network captures are pathologically imbalanced — a capture may contain 50 benign frames against thousands of scan probes, or the inverse. A naively trained classifier minimizes loss by simply predicting the majority class, yielding a model that reports **"0 malicious packets"** with high accuracy but zero recall.

This project neutralizes that failure mode at the loss-function level:

```python
model = CatBoostClassifier(
    iterations=30,
    learning_rate=0.05,
    depth=3,
    l2_leaf_reg=5,
    auto_class_weights='Balanced',   # <-- the critical line
    random_state=42
)
```

`auto_class_weights='Balanced'` re-weights each class inversely proportional to its frequency (`w_c = N_total / (N_classes × N_c)`), so misclassifying a rare malicious frame costs the model far more than misclassifying an abundant benign one. Combined with **stratified train/test splitting** (preserving class ratios in the hold-out set) and evaluation via the **full classification report** rather than raw accuracy, the pipeline is validated on precision/recall/F1 — the metrics that actually matter for a detector.

---

## Pretrained Model

A production-grade CatBoost model trained on the full **CIC-IDS-2017** dataset (all 8 daily capture files, ~2.8 M labeled flows) is published on Hugging Face:

- **Model:** https://huggingface.co/pop123ux/pcap-ml-traffic-classifier
- **Binary mirror:** [GitHub Releases](https://github.com/pop123-ux/pcap-ml-traffic-classifier/releases/latest)

### Reported metrics (stratified hold-out, 848,363 flows)

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| Benign | 1.000 | 0.999 | 0.999 | 681,396 |
| **Malicious** | **0.995** | **1.000** | **0.997** | 166,967 |
| **Accuracy** | | | **0.999** | 848,363 |

> Same-file hold-out. Cross-network generalization to unseen environments is expected to be lower — treat as a strong CIC-IDS-2017 benchmark, not a plug-and-play production IDS.

### Using the pretrained model

The CIC-IDS-2017 model consumes the standard **CICFlowMeter** 78-feature flow schema, so raw PCAPs must be pre-processed with [CICFlowMeter](https://github.com/ahlashkari/CICFlowMeter) first:

```bash
# 1. Convert your PCAP → CICFlowMeter CSV (external tool, one-time setup)
cicflowmeter -f suspicious.pcap -c flows.csv

# 2. Fetch the model from Hugging Face and classify
pip install huggingface_hub
python3 load_pretrained.py flows.csv
```

`load_pretrained.py` downloads the model on first run (cached under `~/.cache/huggingface`), verifies the input has all 78 required columns, and prints per-flow verdicts plus the top-confidence malicious flows.

### Two pipelines — pick the one that fits your use case

| Pipeline | Features | Training source | Strengths | Trade-offs |
|---|---|---|---|---|
| `app.py` | 4 packet-level (packet_size, ttl, protocol, tcp_flags) | Your own labeled PCAP pairs | Zero preprocessing, works on any PCAP directly, fast to retrain | Limited generalization across attack families — see the training notes in `app.py`'s docstring |
| `load_pretrained.py` | 78 CICFlowMeter flow-level | CIC-IDS-2017 (pretrained) | State-of-the-art CIC-IDS benchmark scores | Requires CICFlowMeter preprocessing step |

---

## Project Structure

```
pcap-ml-traffic-classifier/
├── app.py               # Standalone pipeline: PCAP extraction, training, inference, threat intel
├── load_pretrained.py   # Loads the CIC-IDS-2017 CatBoost model from Hugging Face
├── requirements.txt     # Pinned dependency ranges
├── .gitignore           # Excludes PCAPs, model binaries, CatBoost artifacts
└── README.md
```

---

## Roadmap

- [ ] Flow-level (bidirectional stream) aggregation features
- [ ] Live-interface sniffing mode (`scapy.sniff`) for real-time detection
- [ ] Multi-class attack taxonomy (scan / flood / exfiltration)
- [ ] JSON/SIEM-compatible alert export

---

## Ethical Use

This tool is built for **defensive security research, education, and authorized network monitoring only**. Only analyze traffic captured on networks you own or are explicitly authorized to monitor.

## License

MIT
