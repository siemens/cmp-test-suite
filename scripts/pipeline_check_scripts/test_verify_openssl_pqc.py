# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Tiny OpenSSL PQC Sanity Check (sign/verify + KEM encap/decap + version info)

Checks exactly one variant each:
- ML-DSA (keygen + sign + verify)
- SLH-DSA (keygen + sign + verify)
- ML-KEM (keygen + pubkey + encapsulation + decapsulation + secret match)

Also prints OpenSSL version information from:
- cryptography backend (if available; non-fatal if missing)
- Python ssl module
- openssl CLI

Exit codes:
  0 -> All PQC checks OK (ML-DSA, SLH-DSA, ML-KEM)
  1 -> At least one PQC check failed
"""

import os
import ssl
import subprocess
import sys
import tempfile
from typing import List, Union

from cryptography.hazmat.backends.openssl import backend

# One sensible default per family.
ALG_ML_DSA = "ML-DSA-65"
ALG_SLH_DSA = "SLH-DSA-SHA2-192s"  # or SLH-DSA-SHAKE-192s
ALG_ML_KEM = "ML-KEM-768"


def print_section(title: str) -> None:
    """Print a section header with a title."""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def run(cmd: Union[str, List[str]], timeout: int = 25) -> subprocess.CompletedProcess:
    """Run a command and return the result.

    :param cmd: The command to run as a list of arguments.
    :param timeout: Timeout in seconds for the command execution.
    :return: The result of the command execution.
    """
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def test_openssl_version():
    """Test and display OpenSSL version information."""
    print_section("OpenSSL Version Information")

    success = True

    # Try to print `cryptography` backend version if available.
    try:
        print(f"cryptography backend: {backend.openssl_version_text()}")
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"✗ cryptography backend error: {e}")
        success = False

    try:
        # Test ssl module
        print(f"ssl module         : {ssl.OPENSSL_VERSION}")
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"✗ ssl module error: {e}")
        success = False

    try:
        # Test OpenSSL CLI
        result = run(["openssl", "version"], timeout=10)
        if result.returncode == 0:
            print(f"openssl (CLI)      : {result.stdout.strip()}")
        else:
            print(f"✗ openssl CLI error: {result.stderr}")
            success = False
    except FileNotFoundError:
        print("✗ openssl command not found in PATH")
        success = False
    except subprocess.TimeoutExpired:
        print("✗ openssl command timed out")
        success = False
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"✗ openssl CLI error: {e}")
        success = False

    return success


def check_sig_keygen_sign_verify(algorithm: str) -> bool:
    """Validate the ML-DSA or SLH-DSA commands.

    For a signature algorithm:
      - genpkey (private)
      - pkey -pubout (public)
      - pkeyutl -sign
      - pkeyutl -verify
    """
    print_section(f"{algorithm} (sign/verify)")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            key = os.path.join(tmp, "key.pem")
            pub = os.path.join(tmp, "pub.pem")
            msg = os.path.join(tmp, "msg.bin")
            sig = os.path.join(tmp, "sig.bin")

            with open(msg, "wb") as f:
                f.write(b"hello pqc\n")

            gen = run(["openssl", "genpkey", "-algorithm", algorithm, "-out", key])
            if gen.returncode != 0:
                print(f"✗ key generation failed: {gen.stderr.strip()}")
                return False
            print("✔ private key generation")

            pubres = run(["openssl", "pkey", "-in", key, "-pubout", "-out", pub])
            if pubres.returncode != 0:
                print(f"✗ public key extraction failed: {pubres.stderr.strip()}")
                return False
            print("✔ public key extraction")

            sign = run(["openssl", "pkeyutl", "-sign", "-inkey", key, "-in", msg, "-out", sig])
            if sign.returncode != 0:
                print(f"✗ signing failed: {sign.stderr.strip()}")
                return False
            print("✔ signing")

            ver = run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub, "-in", msg, "-sigfile", sig])
            if ver.returncode != 0:
                print(f"✗ verification failed: {ver.stderr.strip()}")
                return False
            print("✔ verification")
            return True

    except FileNotFoundError:
        print("✗ openssl CLI not found in PATH")
        return False
    except subprocess.TimeoutExpired:
        print("✗ operation timed out")
        return False
    except Exception as e:
        print(f"✗ unexpected error: {e}")
        return False


def check_kem_encap_decap(algorithm: str) -> bool:
    """Validate the ML-KEM commands.

    For a KEM:
      - genpkey (private)
      - pkey -pubout (public)
      - pkeyutl -encap (produce ciphertext + shared secret)
      - pkeyutl -decap (recover shared secret)
      - compare secrets
    """
    print_section(f"{algorithm} (encap/decap)")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            key = os.path.join(tmp, "key.pem")
            pub = os.path.join(tmp, "pub.pem")
            ct = os.path.join(tmp, "ct.bin")
            ss1 = os.path.join(tmp, "ss.encap.bin")
            ss2 = os.path.join(tmp, "ss.decap.bin")

            gen = run(["openssl", "genpkey", "-algorithm", algorithm, "-out", key])
            if gen.returncode != 0:
                print(f"✗ key generation failed: {gen.stderr.strip()}")
                return False
            print("✔ private key generation")

            pubres = run(["openssl", "pkey", "-in", key, "-pubout", "-out", pub])
            if pubres.returncode != 0:
                print(f"✗ public key extraction failed: {pubres.stderr.strip()}")
                return False
            print("✔ public key extraction")

            # Encapsulate using the public key
            encap = run(["openssl", "pkeyutl", "-encap", "-pubin", "-inkey", pub, "-out", ct, "-secret", ss1])
            if encap.returncode != 0:
                print(f"✗ encapsulation failed (your CLI may not expose it): {encap.stderr.strip()}")
                return False
            print("✔ encapsulation")

            # Decapsulate using the private key
            decap = run(["openssl", "pkeyutl", "-decap", "-inkey", key, "-in", ct, "-secret", ss2])
            if decap.returncode != 0:
                print(f"✗ decapsulation failed: {decap.stderr.strip()}")
                return False
            print("✔ decapsulation")

            # Compare secrets
            with open(ss1, "rb") as f1, open(ss2, "rb") as f2:
                s1 = f1.read()
                s2 = f2.read()

            print(f"  shared secret sizes: encap={len(s1)} bytes, decap={len(s2)} bytes")
            if s1 != s2:
                print("✗ secret mismatch")
                return False
            if len(s1) not in (32,):  # ML-KEM typically yields 32-byte secrets
                print("⚠ unusual secret size (expected 32 bytes)")
            print("✔ secret verification (match)")
            return True

    except FileNotFoundError:
        print("✗ openssl CLI not found in PATH")
        return False
    except subprocess.TimeoutExpired:
        print("✗ operation timed out")
        return False
    except Exception as e:
        print(f"✗ unexpected error: {e}")
        return False


def main():
    """Perform the sanity check for OpenSSL PQC."""
    print("Tiny OpenSSL PQC Sanity Check")
    print("=" * 60)

    version_ok = test_openssl_version()  # informational; does not affect exit code

    ok_mldsa = check_sig_keygen_sign_verify(ALG_ML_DSA)
    ok_slh = check_sig_keygen_sign_verify(ALG_SLH_DSA)
    ok_mlkem = check_kem_encap_decap(ALG_ML_KEM)

    print_section("Summary")
    print(f"Version info       : {'OK' if version_ok else 'ISSUES FOUND'}")
    print(f"{ALG_ML_DSA:20s}: {'OK' if ok_mldsa else 'FAIL'} (sign/verify)")
    print(f"{ALG_SLH_DSA:20s}: {'OK' if ok_slh else 'FAIL'} (sign/verify)")
    print(f"{ALG_ML_KEM:20s}: {'OK' if ok_mlkem else 'FAIL'} (encap/decap)")

    all_ok = ok_mldsa and ok_slh and ok_mlkem
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
