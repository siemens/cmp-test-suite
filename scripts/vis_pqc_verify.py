# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Display the data of the invalid signatures from the validation_pem_files.txt file."""

# Run: pip install pandas
# for better visualization of the data.
import os.path
import pandas as pd


file_path = '../validation_pem_files.txt'


cert_data = []


with open(file_path, 'r', encoding='utf-8') as file:
    for line in file:

        if line.startswith("SKIPPING PUBLIC KEY FILE"):
            continue

        if line.startswith("INVALID SIGNATURE"):
            parts = line.split('\t')
            status = parts[0]
            file_path = parts[1].strip()
            cert_data.append({"status": status, "file": file_path})

        if line.startswith("VALID KEY LOAD CERT") or line.startswith("VALID SIGNATURE"):
            parts = line.split('\t')
            status = parts[0]
            key_name = parts[1]
            file_path = parts[2]
            cert_data.append({"status": status, "key_name": key_name, "file": file_path})


df = pd.DataFrame(cert_data)


# Filter for invalid signatures
invalid_signatures = df[df["status"] == "INVALID SIGNATURE"]
files = invalid_signatures["file"].tolist()

for x in files:
    name = os.path.basename(x)
    print("file_name:", name)

