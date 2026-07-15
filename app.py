import os
import sys
import pickle
import pandas as pd
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP
from scapy.all import PcapReader, PcapNgReader
from catboost import CatBoostClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split

FEATURES = ['packet_size', 'ttl', 'protocol', 'src_port', 'dst_port', 'tcp_flags']
MODEL_FILE = 'traffic_model.pkl'

def extract_features_from_pcap(pcap_path, label=None):
    """
    Reads a PCAP file and extracts network features for the Machine Learning pipeline.
    label: 0 for benign (safe), 1 for malicious (attack)
    """
    print(f"[*] Processing: {pcap_path}")
    if not os.path.exists(pcap_path):
        print(f"[-] Error: File {pcap_path} not found.")
        return []
    
    packets = []
    try:
        # We try to open with classic PCAP or PCAPNG
        with PcapReader(pcap_path) as reader:
            packets = reader.read_all()
    except Exception:
        try:
            with PcapNgReader(pcap_path) as reader:
                packets = reader.read_all()
        except Exception as e:
            print("[-] Critical Error: The format of the file is not supported")
            return []
        
    packet_list = []

    for pkt in packets:
        if IP in pkt:
            # Core network layer features
            pkt_size = len(pkt)
            ttl = pkt[IP].ttl
            proto = pkt[IP].proto
            src_ip = pkt[IP].src

            # Transport layer features
            sport = 0
            dport = 0
            tcp_flags = 0

            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                tcp_flags = int(pkt[TCP].flags)
            elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

            # Append the features and the target label
            packet_data = {
                'packet_size': pkt_size,
                'ttl': ttl,
                'protocol': proto,
                'src_port': sport,
                'dst_port': dport,
                'tcp_flags': tcp_flags,
                'src_ip': src_ip
            }

            if label is not None:
                packet_data['label'] = label

            packet_list.append(packet_data)

    print(f"[+] Successfully extracted {len(packet_list)} packets.")
    return packet_list

def train_mode(benign_path, malicious_path):
    """Processes the known data and saves the intelligent model"""
    print("\n--> Training Mode Activated")
    benign_data = extract_features_from_pcap(benign_path, label=0)
    malicious_data = extract_features_from_pcap(malicious_path, label=1)

    all_packets = benign_data + malicious_data
    if not all_packets:
        print("[-] Insufficient Data for training")
        return
    
    df = pd.DataFrame(all_packets)
    REDUCED_FEATURES = ['packet_size', 'ttl', 'protocol', 'tcp_flags']
    X = df[REDUCED_FEATURES]
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

    print("\n[*] The state-of-the-art CatBoost Classifier is training...")
    model = CatBoostClassifier(iterations=300, learning_rate=0.05, depth=3, l2_leaf_reg=5, auto_class_weights='Balanced', verbose=25, random_state=42)

    cat_features_indices = [2, 3]
    # early_stopping_rounds lets the model self-tune: it stops when the eval_set
    # score hasn't improved for 50 rounds, so 300 iterations is a ceiling, not a fixed cost.
    model.fit(X_train, y_train, cat_features=cat_features_indices, eval_set=(X_test, y_test), early_stopping_rounds=50)

    predictions = model.predict(X_test)
    print(f"\n[+] Model Accuracy: {accuracy_score(y_test, predictions) * 100:.2f}%")
    print(f"\nClassification Report: {classification_report(y_test, predictions, zero_division=0)}")

    model.save_model(MODEL_FILE)
    print(f"[+] The model was saved in the file '{MODEL_FILE}.")

def analyze_mode(target_pcap):
    """Classify an external PCAP file"""
    print("\n--> Traffic Analysis Mode Activated")
    
    if not os.path.exists(MODEL_FILE):
        print(f"[-] Error: The '{MODEL_FILE}' model does not exist, you have to run --train firstly")
        return

    # We extract the unlabeled packets characteristics 
    unknown_data = extract_features_from_pcap(target_pcap, label=None)

    if not unknown_data or len(unknown_data) == 0:
        print(f"[-] There were no packets found for analysis.")
        return
    
    model = CatBoostClassifier()
    model.load_model(MODEL_FILE)
    
    df = pd.DataFrame(unknown_data)

    # We run the predictions
    REDUCED_FEATURES = ['packet_size', 'ttl', 'protocol', 'tcp_flags']
    predictions = model.predict(df[REDUCED_FEATURES])

    df['is_malicious'] = predictions

    total_packets = len(predictions)
    malicious_count = sum(predictions)
    benign_count = total_packets - malicious_count

    print("\n--> Detection Results:")
    print(f"Total scanned packets: {total_packets}")
    print(f"Benign packets: {benign_count}")
    print(f"Malicious packets: {malicious_count}")

    if malicious_count > 0:
        percentage = (malicious_count / total_packets) * 100
        print(f"\nPercentage of malicious traffic detected: {percentage}")
        # The tool also filters the malicious IPs
        malicious_ips = df[df['is_malicious'] == 1]['src_ip']
        ip_counts = Counter(malicious_ips)

        print("\n TOP ATTACKER IP ADDRESSES (THREAT INTEL)")
        print(f"{'Source IP Address'}:<20 | {'Malicious Packets Generated':<10}")

        # It shows the first 5 most active aggressor IPs
        for ip, count in ip_counts.most_common(5):
            print(f"{ip:<20} | {count:<10}")
    else:
        print("\n[+] The file seems peachy. The model did not detect any anomalies")

def print_usage():
    print("\nHow should you use this tool:")
    print("  1. Train the model: python3 app.py --train <benign.pcap> <malicious.pcap>")
    print("  2. File analysis: python3 app.py --analyze <suspected_pcap.pcap>")
    print("     (or simply: python3 app.py <suspected_pcap.pcap>)\n")

def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
    
    if sys.argv[1] == '--train':
        if len(sys.argv) != 4:
            print ("[-] Error: The --train mode needs exactly 2 PCAP files (Benign and Malicious)")
            print_usage()
            sys.exit(1)
        train_mode(sys.argv[2], sys.argv[3])

    elif sys.argv[1] == '--analyze':
        if len(sys.argv) != 3:
            print("[-] Error: The --analyze mode needs exactly 1 PCAP file")
            print_usage()
            sys.exit(1)
        analyze_mode(sys.argv[2])

    else:
        # Backward compatible: a bare file argument is treated as the file to analyze
        analyze_mode(sys.argv[1])

if __name__ == "__main__":
    main()

    

