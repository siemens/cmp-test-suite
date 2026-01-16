"""Generate all test cases for all algorithms."""

# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import sys

sys.path.append(".")

from pq_logic.tmp_oids import (
    CHEMPAT_NAME_2_OID,
    COMPOSITE_KEM_NAME_2_OID,
    COMPOSITE_SIG_NAME_TO_OID,
)
from resources.oidutils import PQ_KEM_NAME_2_OID, PQ_SIG_NAME_2_OID, PQ_SIG_PRE_HASH_NAME_2_OID


def generate_pq_sig_tests():
    """Generalized test case generator for pq signatures."""
    test_cases = []

    for name in PQ_SIG_NAME_2_OID:
        # Replace part of name dynamically
        base_name = "PQ Sig " + name.upper()

        # Generate test case names
        invalid_test_name = f"Invalid {base_name} Request"
        valid_test_name = f"Valid {base_name} Request"

        if name in PQ_SIG_PRE_HASH_NAME_2_OID:
            pre_hash = True
            hash_alg = name.split("-")[-1]
        else:
            pre_hash = False
            hash_alg = "${None}"

        # Tag generator
        def generate_tags(test_type: str):
            tags = []
            tags.append(test_type)
            if name.startswith("falcon"):
                tags.append("falcon")

            if name.startswith("ml-dsa"):
                tags.append("ml-dsa")

            if name.startswith("slh-dsa"):
                tags.append("slh-dsa")

            if pre_hash:
                tags.append("pre_hash")

            return tags

        # Invalid case
        test_cases.append(
            {
                "test_name": invalid_test_name.strip(),
                "arguments": {"algorithm": name, "hash_alg": hash_alg, "badPOP": "True"},
                "tags": generate_tags("negative"),
            }
        )

        # Valid case
        test_cases.append(
            {
                "test_name": valid_test_name.strip(),
                "arguments": {"algorithm": name, "hash_alg": hash_alg, "badPOP": "False"},
                "tags": generate_tags("positive"),
            }
        )

    return test_cases


def generate_composite_sig_tests(name_list, replace_name: str, name_to_replace: str):
    """Generalized test case generator for composite signatures.

    :param name_list: List of algorithm names (strings).
    :param replace_name: The string to replace (e.g., 'composite-sig-13-').
    :param name_to_replace: The string to replace with (e.g., 'Composite Sig13 ').
    :return: List of test case dictionaries.
    """
    test_cases = []
    _found_entries = []

    for name in name_list:
        use_pss = name.endswith("-pss")

        # Replace part of name dynamically
        base_name = name.replace(replace_name, name_to_replace).replace("ml-dsa", "ML-DSA").upper()

        # Generate test case names
        invalid_test_name = f"Invalid {base_name} Request"
        valid_test_name = f"Valid {base_name} Request"

        # Tag generator
        def generate_tags(test_type: str):
            tags = []
            tags.append(test_type)
            lowered_name = name.lower()
            if "rsa" in lowered_name:
                tags.append("rsa")
            if "pss" in lowered_name:
                tags.append("rsa-pss")
            if "ecdsa" in lowered_name:
                entries = lowered_name.split("-")
                try:
                    ind = entries.index("ecdsa")
                    curve_name = entries[ind + 1]
                    tags.append("ecdsa")
                    tags.append(curve_name)
                    if f"{curve_name}-{test_type}" in _found_entries:
                        tags.append("completeness")
                    else:
                        _found_entries.append(f"{curve_name}-{test_type}")
                except ValueError:
                    pass  # ecdsa not found

            if "ed448" in lowered_name:
                tags.append("ed448")
                if f"ed448-{test_type}" in _found_entries:
                    tags.append("completeness")
                else:
                    _found_entries.append(f"ed448-{test_type}")

            if "ed25519" in lowered_name:
                tags.append("ed25519")
                if f"ed25519-{test_type}" in _found_entries:
                    tags.append("completeness")
                else:
                    _found_entries.append(f"ed25519-{test_type}")

            return tags

        # Invalid case
        test_cases.append(
            {
                "test_name": invalid_test_name.strip(),
                "arguments": {"algorithm": name, "use_pss": use_pss, "invalid": True},
                "tags": generate_tags("negative"),
            }
        )

        # Valid case
        test_cases.append(
            {
                "test_name": valid_test_name.strip(),
                "arguments": {"algorithm": name, "use_pss": use_pss, "invalid": False},
                "tags": generate_tags("positive"),
            }
        )

    return test_cases


def generate_pq_kem_tests():
    """Generalized test case generator for pq kem."""
    test_cases = []

    for name in PQ_KEM_NAME_2_OID:
        base_name = name.upper()

        # Generate test case names
        invalid_test_name = f"Invalid {base_name} Key Size"
        valid_test_name = f"Valid {base_name} Request"

        # Tag generator
        def generate_tags(test_type: str):
            tags = []
            tags.append(test_type)
            if name.startswith("ml-kem"):
                tags.append("ml-kem")

            if name.startswith("sntrup761"):
                tags.append("sntrup761")

            if name.startswith("frodokem"):
                tags.append("frodokem")

            if name.startswith("mceliece"):
                tags.append("mceliece")

            return tags

        # Invalid case
        test_cases.append(
            {
                "test_name": invalid_test_name.strip(),
                "arguments": {"algorithm": name, "invalid_key_size": "True"},
                "tags": generate_tags("negative"),
            }
        )

        # Valid case
        test_cases.append(
            {
                "test_name": valid_test_name.strip(),
                "arguments": {"algorithm": name, "invalid_key_size": "False"},
                "tags": generate_tags("positive"),
            }
        )

    return test_cases


def _generate_hybrid_kem_tests():
    """Generalized test case generator for hybrid kem."""
    test_cases = []

    for hybrid_type, name_list in {
        "xwing": {"xwing"},
        "chempat": CHEMPAT_NAME_2_OID,
        "composite-kem": COMPOSITE_KEM_NAME_2_OID,
    }.items():
        for name in name_list:
            if "composite-dhkem" in name:
                continue

            base_name = name.upper()
            # Generate test case names
            invalid_test_name = f"Invalid {base_name} Key Size"
            valid_test_name = f"Valid {base_name} Request"

            # Tag generator
            def generate_tags(test_type: str):
                tags = []
                tags.append(test_type)
                tags.append(hybrid_type)
                if "ml-kem" in name:
                    tags.append("ml-kem")

                if "sntrup761" in name:
                    tags.append("sntrup761")

                if "frodokem" in name:
                    tags.append("frodokem")

                if "mceliece" in name:
                    tags.append("mceliece")

                if "rsa" in name:
                    tags.append("rsa")

                if "ecdh" in name:
                    tags.append("ecdh")
                    name_parts = name.split("-")
                    curve_name = name_parts[name_parts.index("ecdh") + 1]
                    tags.append(curve_name)
                if "x448" in name:
                    tags.append("x448")
                if "x25519" in name:
                    tags.append("x25519")

                return tags

            # Invalid case
            test_cases.append(
                {
                    "test_name": invalid_test_name.strip(),
                    "arguments": {"algorithm": name, "invalid_key_size": "True"},
                    "tags": generate_tags("negative"),
                }
            )

            # Valid case
            test_cases.append(
                {
                    "test_name": valid_test_name.strip(),
                    "arguments": {"algorithm": name, "invalid_key_size": "False"},
                    "tags": generate_tags("positive"),
                }
            )

    return test_cases


def _write_comp_sig_to_txt_file():
    f = open("composite_sig_test_cases.txt", "w", encoding="utf-8")
    _spacer = " " * 4  # 4 spaces between columns as per your requirement
    extra = f"ALGORITHM{_spacer}USE_RSA_PSS{_spacer}badPOP\n"
    f.write(f"*** Test Cases ***{_spacer}{extra}")
    test_cases = generate_composite_sig_tests(COMPOSITE_SIG_NAME_TO_OID, "composite-sig-", "COMPOSITE-SIG-")
    for test in test_cases:
        tmp = _write_to_file(test)
        f.write(tmp)


def _write_to_file(test_case: dict):
    tmp = f"{test_case['test_name']}\n"
    # Print arguments with 4 spaces between
    spacer = " " * 4  # 4 spaces between columns as per your requirement
    args = test_case["arguments"]
    args_str = f"{args['algorithm']}{spacer}{str(args['use_pss'])}{spacer}{str(args['invalid'])}"
    tmp += f"     ...    {args_str}\n"
    tags_str = "  ".join(test_case["tags"])
    tmp += f"     [Tags]    {tags_str}\n\n"
    return tmp


def _write_to_file_pq(test_case: dict):
    # Print arguments with 4 spaces between
    args = test_case["arguments"]
    _spacer = " " * 4  # 4 spaces between columns as per your requirement
    args_str = f"{_spacer}".join(args.values())
    tmp = f"{test_case['test_name']}{_spacer}{args_str}\n"
    tags_str = "  ".join(test_case["tags"])
    tmp += f"     [Tags]    {tags_str}\n\n"
    return tmp


def _write_pq_test():
    """Write pq sig tests to a file."""
    test_cases = generate_pq_sig_tests()
    f = open("pq_sig_test_cases.txt", "w", encoding="utf-8")
    _spacer = " " * 4  # 4 spaces between columns as per your requirement
    extra = f"ALGORITHM{_spacer}HASH_ALG{_spacer}badPOP\n"
    f.write(f"*** Test Cases *** {_spacer}{extra}\n\n")
    for test in test_cases:
        tmp = _write_to_file_pq(test)
        f.write(tmp)


def _write_pq_kem_tests():
    """Write pq kem tests to a file."""
    test_cases = generate_pq_kem_tests()
    f = open("pq_kem_test_cases.txt", "w", encoding="utf-8")
    _spacer = " " * 4  # 4 spaces between columns as per your requirement
    extra = f"ALGORITHM{_spacer}INVALID_KEY_SIZE\n"
    f.write(f"*** Test Cases *** {_spacer}{extra}\n\n")
    for test in test_cases:
        tmp = _write_to_file_pq(test)
        f.write(tmp)


def _write_hybrid_kem_tests():
    """Write hybrid kem tests to a file."""
    test_cases = _generate_hybrid_kem_tests()
    f = open("hybrid_kem_test_cases.txt", "w", encoding="utf-8")
    _spacer = " " * 4  # 4 spaces between columns as per your requirement
    extra = f"ALGORITHM{_spacer}INVALID_KEY_SIZE\n"
    f.write(f"*** Test Cases *** {_spacer}{extra}")
    for test in test_cases:
        tmp = _write_to_file_pq(test)
        f.write(tmp)


_write_comp_sig_to_txt_file()
_write_hybrid_kem_tests()
