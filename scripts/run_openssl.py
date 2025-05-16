# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Example script to generate an RSA private key, create a CSR, and run CMP IR command using OpenSSL.

Can be used to send a certificate request to the Mock-CA.
"""

import os
import subprocess


def generate_rsa_private_key(filepath: str = "new-private-key-rsa.pem", overwrite: bool = False):
    """Generate an RSA private key.

    :param filepath: The output file for the private key. Defaults to `new-private-key-rsa.pem`.
    :param overwrite: Whether to overwrite the key file if it already exists. Defaults to `False`.
    """
    if os.path.exists(filepath) and not overwrite:
        print(f"Private key '{filepath}' already exists. Skipping generation.")
        return
    cmd = ["openssl", "genpkey", "-algorithm", "RSA", "-out", filepath, "-pkeyopt", "rsa_keygen_bits:2048"]
    print(f"Generating RSA private key: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    print(f"Private key saved to: {filepath}")


def generate_csr(keyfile="new-private-key-rsa.pem", csrfile="csr-rsa.pem", cn="Hans the Tester", overwrite=False):
    """Generate a CSR using the specified private key.

    :param keyfile: The private key file to use. Defaults to `new-private-key-rsa.pem`.
    :param csrfile: The output file for the CSR. Defaults to `csr-rsa.pem`.
    :param cn: The common name for the certificate. Defaults to `Hans the Tester`.
    :param overwrite: Whether to overwrite the CSR file if it already exists. Defaults to `False`.
    """
    if os.path.exists(csrfile) and not overwrite:
        print(f"CSR '{csrfile}' already exists. Skipping generation.")
        return
    cmd = ["openssl", "req", "-new", "-key", keyfile, "-subj", f"/CN={cn}", "-out", csrfile]
    print(f"Generating CSR: {' '.join(cmd)}")
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    print("Command output:", result.stdout)
    print(f"CSR saved to: {csrfile}")


def run_cmp_ir(
    csrfile: str = "csr-rsa.pem",
    keyfile: str = "new-private-key-rsa.pem",
    certout: str = "result-cert.pem",
    reqout: str = "req-ir.pkimessage.der",
    cn: str = "Hans the Tester",
    server: str = "http://localhost:5000/issuing",
    sender_kid: str = "CN=Hans the Tester",
    secret: str = "pass:SiemensIT",
    implicit_confirm: bool = True,
) -> None:
    """Run the CMP IR command to request a certificate.

    :param csrfile: The CSR file to use. Defaults to `csr-rsa.pem`.
    :param keyfile: The private key file to use. Defaults to `new-private-key-rsa.pem`.
    :param certout: The output file for the certificate. Defaults to `result-cert.pem`.
    :param reqout: The output file for the request. Defaults to `req-ir.pkimessage.der`.
    :param cn: The common name for the certificate. Defaults to `Hans the Tester`.
    :param server: The CMP server URL. Defaults to `http://localhost:5000/issuing`.
    :param sender_kid: The sender key identifier. Defaults to `CN=Hans the Tester`.
    :param secret: The pre-shared-secret for the CMP server. Defaults to `pass:SiemensIT`.
    :param implicit_confirm: Whether to use implicit confirmation. Defaults to `True`.
    """
    base_cmd = [
        "openssl",
        "cmp",
        "-cmd",
        "ir",
        "-server",
        server,
        "-recipient",
        f"/CN={cn}",
        "-subject",
        f"/CN={cn}",
        "-ref",
        sender_kid,
    ]

    cmd = base_cmd + [
        "-csr",
        csrfile,
        "-secret",
        secret,
        "-popo",
        "1",
        "-certout",
        certout,
        "-newkey",
        keyfile,
        "-reqout",
        reqout,
        "-unprotected_errors",
        "-verbosity",
        "8",
    ]

    if implicit_confirm:
        cmd.append("-implicit_confirm")

    print(f"Running CMP IR command: {' '.join(cmd)}")
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    print(f"Command output: {result.stdout}")
    if result.returncode != 0:
        print(f"Command failed with return code: {result.returncode}")
        print(f"Command error output: {result.stderr}")
        print(f"Command std output: {result.stdout}")
        print("CMP IR command failed.")
    else:
        print("CMP IR command executed successfully.")
        print(f"CMP IR completed. Certificate written to: {certout}")

    # For better readability, you can uncomment the following line to see the curl command.
    # curl -X POST http://localhost:5000/issuing
    # -H "Content-Type: application/pkixcmp" --data-binary @req-ir.pkimessage.der


# Example usage
if __name__ == "__main__":
    generate_rsa_private_key(overwrite=False)
    generate_csr(overwrite=False)
    run_cmp_ir(implicit_confirm=False)
