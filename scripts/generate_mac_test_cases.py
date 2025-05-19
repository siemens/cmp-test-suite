# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Generate test cases for MAC algorithm, which include different hash algorithms and all supported ones."""

import sys

sys.path.append("..")

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from resources.oidutils import (
    AES_GMAC_NAME_2_OID,
    HMAC_NAME_2_OID,
    HMAC_SHA3_NAME_2_OID,
    HMAC_SHA_NAME_2_OID,
    KMAC_OID_2_NAME,
)


@dataclass
class MACArguments:
    """Class to represent the arguments for a MAC test case.

    Arguments:
    ---------
        protection (str): The type of protection (e.g., "signature", "hmac").
        hash_alg (str): The hash algorithm used (e.g., "sha256").
        secondary_hash_alg (Optional[str]): The secondary hash algorithm used (e.g., "sha512").
        bad_message_check (bool): Flag to indicate if the message is expected to be bad.

    """

    protection: str
    hash_alg: str
    secondary_hash_alg: Optional[str] = None
    bad_message_check: bool = False

    def get_args(self) -> Tuple[str, str, bool, str]:
        """Return the arguments for the test case."""
        return self.protection, self.hash_alg, self.bad_message_check, self.secondary_hash_alg


@dataclass
class ReturnValue:
    """Class to represent a MAC entry with its name, hash algorithm, and expected result."""

    name: str
    protection: str
    hash_alg: str
    bad_message_check: bool
    tags: List[str] = field(default_factory=list)

    def get_args(self) -> Tuple[str, str, bool]:
        """Return the arguments for the test case."""
        return self.protection, self.hash_alg, self.bad_message_check


@dataclass
class MACReturn:
    """Class to represent a MAC entry with its name, hash algorithm, and expected result."""

    name: str
    protection: str
    hash_alg: Optional[str]
    tags: List[str] = field(default_factory=list)
    mac_alg: Optional[str] = None

    def get_args(self) -> Tuple[str, str, List[str], Optional[str]]:
        """Return the arguments for the test case."""
        return self.protection, self.hash_alg, self.tags, self.mac_alg


def _get_hash_alg_tag(name: str) -> MACReturn:
    """Get the hash algorithm tag based on the name."""
    if name.startswith("hmac-"):
        hash_alg = name.replace("hmac-", "")
        if hash_alg == "sha1":
            return MACReturn(name.upper(), "hmac", hash_alg, ["hmac", "sha1", "deprecated"])
        elif hash_alg.startswith("sha3_"):
            return MACReturn(name.upper(), "hmac", hash_alg, ["hmac", "sha3", "rfc9688-validation"])
        return MACReturn(name.upper(), "hmac", hash_alg, ["hmac", "sha2"])

    elif name.startswith("kmac-"):
        hash_alg = name.replace("kmac-", "")
        return MACReturn(name.upper(), "kmac", hash_alg, ["kmac", "shake", hash_alg])

    elif name.startswith("aes"):
        return MACReturn(name.upper(), name, None, ["gmac"])

    else:
        raise ValueError(f"Unknown MAC algorithm name: {name}")


def _generate_simple_mac_test_cases() -> List[MACReturn]:
    """Generate test cases for simple MAC algorithms with different hash algorithms."""
    test_cases = []

    for name in (
        list(HMAC_SHA_NAME_2_OID.keys())
        + list(HMAC_SHA3_NAME_2_OID.keys())
        + list(KMAC_OID_2_NAME.values())
        + list(AES_GMAC_NAME_2_OID.keys())
    ):
        if name in ["aes-gmac", "aes_gmac"]:
            continue
        mac_value = _get_hash_alg_tag(name)
        test_cases.append(mac_value)

    return test_cases


def _gen_upper_mac_test_cases(
    protection: str, prefix_name: str, mac_options: List[str], tags: List[str]
) -> List[MACReturn]:
    """Generate test cases for upper MAC algorithms with different hash algorithms."""
    tests = []
    for x in mac_options:
        if x in ["aes-gmac", "aes_gmac"]:
            continue

        mac_ret = _get_hash_alg_tag(x)

        hash_alg = mac_ret.hash_alg
        if hash_alg == "shake128":
            hash_alg = "sha3_256"
        elif hash_alg == "shake256":
            hash_alg = "sha3_512"

        if "AES" in mac_ret.name:
            hash_alg = "sha256"

        val = MACReturn(
            name=prefix_name.upper() + "-" + mac_ret.name,
            protection=protection,
            hash_alg=hash_alg,
            tags=tags + mac_ret.tags,
        )
        tests.append(val)
    return tests


def _generate_pbmac1() -> List[ReturnValue]:
    """Generate test cases for PBMAC1 algorithm with different hash algorithms."""
    test_cases = []

    mac_options = list(HMAC_NAME_2_OID)

    kdf_options = ["pbkdf2"]

    for kdf in kdf_options:
        tags = ["pbmac1", kdf]
        test_cases.extend(_gen_upper_mac_test_cases("pbmac1", "pbmac1", mac_options, tags))

    return test_cases


def _generate_password_based_mac() -> List[ReturnValue]:
    """Generate test cases for Password-based MAC algorithms with different hash algorithms."""
    test_cases = []

    mac_options = list(HMAC_NAME_2_OID)

    owf_options = ["empty"]

    for _ in owf_options:
        test_cases.extend(_gen_upper_mac_test_cases("password_based_mac", "PBM", mac_options, ["pbm"]))

    print("Password-based MAC test cases generated:", len(test_cases))
    return test_cases


@dataclass
class MACTestCase:
    """Class to represent a MAC test case."""

    name: str
    args: MACArguments
    tags: List[str] = field(default_factory=list)

    def get_args(self) -> Tuple:
        """Return the arguments for the test case."""
        return self.args.get_args()

    def get_args_out(self) -> List[str]:
        """Return the tags for the test case."""
        args_out = []

        for arg in self.args.get_args():
            if isinstance(arg, str):
                args_out.append(arg)
            elif isinstance(arg, bool):
                args_out.append(str(arg))
            elif arg is None:
                args_out.append("${None}")
            else:
                raise ValueError(f"Unknown argument type: {type(arg)}")
        return args_out

    def create_test_case(self) -> str:
        """Create a test case string."""
        indent = " " * 4
        args = f"{indent}".join(self.get_args_out())
        next_line = "\n" + " " * 5 + f"[Tags]{indent}"
        tags_line = f"{indent}".join(self.tags) + "\n"
        return f"{self.name}{indent}{args}{next_line}{tags_line}"


def _generate_simple_test_cases() -> List[str]:
    # Generate HMAC,KMAC test cases
    test_cases = []
    test_cases.extend(_generate_simple_mac_test_cases())
    test_cases.extend(_generate_pbmac1())
    test_cases.extend(_generate_password_based_mac())

    data = []

    out_cases = []
    for option in test_cases:
        correct_name = "CA MUST Accept {} Protected Request"
        negative_name = "CA Reject Invalid {} Protected Request"
        # Generate test cases for each option

        t1 = MACTestCase(
            name=correct_name.format(option.name),
            args=MACArguments(
                protection=option.protection,
                hash_alg=option.hash_alg,
                bad_message_check=False,
                secondary_hash_alg=option.mac_alg,
            ),
            tags=["positive"] + option.tags,
        )
        t2 = MACTestCase(
            name=negative_name.format(option.name),
            args=MACArguments(
                protection=option.protection,
                hash_alg=option.hash_alg,
                bad_message_check=True,
                secondary_hash_alg=option.mac_alg,
            ),
            tags=["negative"] + option.tags,
        )

        out_cases.append(t1)
        out_cases.append(t2)

    print("Generated test cases:")
    for test_case in out_cases:
        data.append(test_case.create_test_case())

    with open("../mac_test_cases.txt", "w") as f:
        for test_case in data:
            f.write(test_case)
            f.write("\n")
        f.close()
    return data


if __name__ == "__main__":
    # Generate and print the test cases
    _generate_simple_test_cases()
