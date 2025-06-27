import os
import json
import csv

META_FILE = "metadata.json"

def load_metadata():
    if os.path.exists(META_FILE):
        with open(META_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_metadata(data):
    with open(META_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def export_metadata(metadata, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Encrypted Filename", "Original Name", "Timestamp", "SHA-256 Hash"])
        for fname, meta in metadata.items():
            writer.writerow([fname, meta["original_name"], meta["timestamp"], meta["sha256"]])
    print(f"[✔] Metadata exported to {output_file}")
