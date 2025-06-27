import json
import csv
import os

def export_metadata_to_csv(json_path='metadata.json', csv_path='metadata.csv'):
    if not os.path.exists(json_path):
        print(f"[!] Metadata file not found: {json_path}")
        return

    with open(json_path, 'r') as json_file:
        metadata = json.load(json_file)

    if not metadata:
        print("[!] Metadata is empty.")
        return

    with open(csv_path, 'w', newline='') as csv_file:
        fieldnames = ['encrypted_name', 'original_name', 'timestamp', 'sha256']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for enc_name, data in metadata.items():
            writer.writerow({
                'encrypted_name': enc_name,
                'original_name': data.get('original_name', ''),
                'timestamp': data.get('timestamp', ''),
                'sha256': data.get('sha256', '')
            })

    print(f"[✔] Metadata exported to {csv_path}")
