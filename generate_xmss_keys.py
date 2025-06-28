import os

from pq_logic.combined_factory import CombinedKeyFactory
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


for alg in CombinedKeyFactory.get_stateful_sig_algorithms()["xmss"]:
    for body_name in ALL_REQUEST_BODY_NAMES:
        for reason in ["bad_pop", "popo", "bad_params", "bad_key_size", "exhausted"]:
            dir_name = "data/keys/xmss_xmssmt_key_verbose"
            path = os.path.join(dir_name, f"{alg.lower()}_{body_name}_{reason}.pem")
            if os.path.exists(path):
                continue

            key = generate_key(alg.lower())
            save_key(
                key, path
            )

            print("Finished Key: ", f"{alg.lower()}_{body_name}_{reason}")

    print("Finished algorithm", alg.lower())
