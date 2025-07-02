"""This script generates XMSS and XMSSMT keys with.

The keys take a long time, so they cannot be generated on every test run.
"""

import datetime
import os
import time

from pq_logic.combined_factory import CombinedKeyFactory
from resources.ca_ra_utils import is_nist_approved_xmss, is_nist_approved_xmssmt
from resources.keyutils import generate_key, save_key

ALL_REQUEST_BODY_NAMES = [
    "ir",
    "cr",
    "kur",
    "p10cr",
    "ccr",
    "added-protection-inner-ir",
    "added-protection-inner-cr",
    "added-protection-inner-kur",
    "added-protection-inner-p10cr",
    "added-protection-inner-ccr",
    "batch-inner-ir",
    "batch-inner-cr",
    "batch-inner-kur",
    "batch-inner-p10cr",
    "batch-inner-ccr",
]


def print_time_taken(start_time) -> str:
    """Calculate and print the time taken for key generation."""
    elapsed_time = time.time() - start_time
    if elapsed_time < 60:
        return f"{elapsed_time:.2f} seconds"
    elif elapsed_time < 3600:
        return f"{elapsed_time / 60:.2f} minutes"
    else:
        return f"{elapsed_time / 3600:.2f} hours"


def _key_exists(alg_name: str, body_name: str, reason: str) -> bool:
    """Check if the key already exists.

    :param alg_name: The name of the algorithm.
    :param body_name: The name of the request body.
    :param reason: The reason for the key generation (what is tested).
    """
    dir_name = "data/keys/xmss_xmssmt_keys_verbose"
    path = os.path.join(dir_name, f"{alg_name}_{body_name}_{reason}.pem")
    return os.path.exists(path)


def _generate_key_and_save(alg, body_name, reason):
    """Generate a key and save it to the specified path.

    :param alg: The algorithm name.
    :param body_name: The name of the request body.
    :param reason: The reason for the key generation (what is tested).
    """
    dir_name = "data/keys/xmss_xmssmt_keys_verbose"
    alg_name = alg.replace("/", "_layers_") if "/" in alg else alg
    path = os.path.join(dir_name, f"{alg_name}_{body_name}_{reason}.pem")

    if not os.path.exists(path):
        key = generate_key(alg.lower())
        save_key(key, path)
        return True
    return False


def generate_verbose_xmssmt_keys():
    """Generate XMSSMT keys with verbose output.

    Saves the keys in the `data/keys/xmss_xmssmt_keys_verbose` directory.
    """
    print("Generating XMSSMT keys...")
    print("This may take a while, please be patient...")
    print("All keys will be saved in the `data/keys/xmss_xmssmt_keys_verbose` directory.")
    if not os.path.exists("data/keys/xmss_xmssmt_keys_verbose"):
        os.makedirs("data/keys/xmss_xmssmt_keys_verbose", exist_ok=True)
    start_time = time.time()
    for body_name in ALL_REQUEST_BODY_NAMES:
        for alg in CombinedKeyFactory.get_stateful_sig_algorithms()["xmssmt"]:
            if not is_nist_approved_xmssmt(alg):
                print(f"Skipping non-NIST approved algorithm: {alg}")
                reason = "nist_disapproved"
                _generate_key_and_save(alg, body_name, "bad_pop")
                print("Finished Key: ", f"{alg.lower()}_{body_name}_{reason}", print_time_taken(start_time))
                continue

            for reason in ["bad_pop", "popo", "bad_params", "bad_key_size", "exhausted", "cert_conf"]:
                _generate_key_and_save(alg, body_name, reason)
                print("Finished Key: ", f"{alg.lower()}_{body_name}_{reason}", print_time_taken(start_time))

            print("Finished algorithm", alg.lower(), "for body name", body_name, datetime.datetime.now())
            start_time = time.time()  # Reset timer for next algorithm
    print("All XMSSMT keys generated successfully.")


def generate_verbose_xmss_keys():
    """Generate XMSS keys with verbose output.

    Saves the keys in the `data/keys/xmss_xmssmt_keys_verbose` directory.
    """
    print("Generating XMSS keys...")
    print("This may take a while, please be patient...")
    print("All keys will be saved in the `data/keys/xmss_xmssmt_keys_verbose` directory.")
    if not os.path.exists("data/keys/xmss_xmssmt_keys_verbose"):
        os.makedirs("data/keys/xmss_xmssmt_keys_verbose", exist_ok=True)
    start_time = time.time()
    for body_name in ALL_REQUEST_BODY_NAMES:
        for alg in CombinedKeyFactory.get_stateful_sig_algorithms()["xmss"]:
            if not is_nist_approved_xmss(alg):
                print(f"Skipping non-NIST approved algorithm: {alg}")
                reason = "nist_disapproved"
                _generate_key_and_save(alg, body_name, "bad_pop")
                print("Finished Key: ", f"{alg.lower()}_{body_name}_{reason}", print_time_taken(start_time))
                continue

            for reason in ["bad_pop", "popo", "bad_params", "bad_key_size", "exhausted", "cert_conf"]:
                _generate_key_and_save(alg, body_name, reason)
                print("Finished Key: ", f"{alg.lower()}_{body_name}_{reason}", print_time_taken(start_time))

            print("Finished algorithm", alg.lower(), "for body name", body_name, datetime.datetime.now())
            start_time = time.time()  # Reset timer for next algorithm
    print("All XMSS keys generated successfully.")


if __name__ == "__main__":
    generate_verbose_xmss_keys()
    print("All keys generated successfully.")
