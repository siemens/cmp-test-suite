# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
"""Generate PKIProtection Tests for Robot Framework."""

import sys

sys.path.append(".")

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from pq_logic.tmp_oids import FALCON_NAME_2_OID
from resources.oidutils import (
    ECDSA_SHA3_OID_2_NAME,
    ECDSA_SHA_OID_2_NAME,
    HYBRID_SIG_NAME_2_OID,
    ML_DSA_NAME_2_OID,
    MSG_SIG_ALG_NAME_2_OID,
    PQ_SIG_NAME_2_OID,
    PQ_SIG_PRE_HASH_NAME_2_OID,
    RSA_SHA2_OID_2_NAME,
    RSA_SHA3_OID_2_NAME,
    RSASSA_PSS_OID_2_NAME,
    SLH_DSA_NAME_2_OID,
)


@dataclass
class Entry:
    """Dataclass to hold the entry information for the Robot Framework tests."""

    test_name: str
    cert: str
    private_key: str
    protection: str
    hash_alg: str
    bad_message_check: bool
    tags: List[str] = field(default_factory=list)

    def get_arguments(self) -> Tuple:
        """Get the arguments for the test case."""
        bad = "True" if self.bad_message_check else "False"
        hash_alg = "${None}" if self.hash_alg is None else self.hash_alg
        return self.protection, self.private_key, self.cert, hash_alg, bad

    def get_pq_arguments(self) -> Tuple[str, str, str]:
        """Get the arguments for the test case.

        :returns: The algorithm name, hash algorithm, and bad message check.
        """
        bad = "True" if self.bad_message_check else "False"
        hash_alg = "${None}" if self.hash_alg is None else self.hash_alg
        return self.cert, hash_alg, bad


@dataclass
class ReturnValue:
    """Dataclass to hold the return value information for the Robot Framework tests."""

    name: str
    tags: List[str] = field(default_factory=list)
    hash_alg: Optional[str] = None
    protection: str = "signature"

    def get_name(self) -> str:
        """Get the name of the algorithm plus the hash algorithm."""
        if self.hash_alg is not None:
            tmp_name = self.name + "-" + self.hash_alg
        else:
            tmp_name = self.name
        return tmp_name

    def get_test_name(self, test_case: str) -> str:
        """Get the name of the test case."""
        tmp_name = self.get_name()
        return test_case.format(tmp_name.upper())

    def get_vals(self, test_case: str, add_tags: List) -> Dict:
        """Get the values of the test case."""
        test_name = self.get_test_name(test_case)
        return {
            "protection": self.protection,
            "hash_alg": self.hash_alg,
            "tags": self.tags + add_tags,
            "test_name": test_name,
        }


PQ_BASE_ALG_NAMES = {
    "ml-dsa": list(ML_DSA_NAME_2_OID.keys()),
    "slh-dsa": list(SLH_DSA_NAME_2_OID.keys()),
    "falcon": list(FALCON_NAME_2_OID.keys()),
}


def _get_name_and_tags(name: str) -> ReturnValue:
    """Get the name of the test suite and the test case."""
    if name in ECDSA_SHA3_OID_2_NAME.values():
        hash_alg = name.split("-")[1]
        return ReturnValue(name="ecdsa", tags=["ecdsa", "sha3", "rfc9688-validation"], hash_alg=hash_alg)

    if name in RSA_SHA3_OID_2_NAME.values():
        hash_alg = name.split("-")[1]
        return ReturnValue(name="rsa", tags=["rsa", "sha3", "rfc9688-validation"], hash_alg=hash_alg)

    if name in RSA_SHA2_OID_2_NAME.values():
        hash_alg = name.split("-")[1]
        return ReturnValue(name="rsa", tags=["rsa", "rfc9481-validation"], hash_alg=hash_alg)

    if name == "rsa-sha1":
        return ReturnValue(name="rsa", tags=["rsa", "rfc9481-validation", "deprecated"], hash_alg="sha1")

    if name in ECDSA_SHA_OID_2_NAME.values():
        hash_alg = name.split("-")[1]
        return ReturnValue(name="ecdsa", tags=["ecdsa", "rfc9481-validation"], hash_alg=hash_alg)
    if name == "ed25519" or name == "ed448":
        return ReturnValue(name=name, tags=[name, "rfc9481-validation"], hash_alg=None)
    if name in RSASSA_PSS_OID_2_NAME.values():
        hash_alg = name.split("-")[1]

        if hash_alg == "sha256":
            tags = ["rsa-pss", "rsa", "rfc9481-validation"]
        else:
            # Not all `OpenSSL` builds support `shake128` and `shake256`.
            # As an example, the default version of `WSL2.0` does not support it.
            tags = ["rsa-pss", "rsa", "robot:skip-on-failure", "rfc9481-validation"]

        return ReturnValue(
            name="rsa-pss",
            tags=tags,
            hash_alg=hash_alg,
            protection="rsassa-pss",
        )
    if name in PQ_SIG_PRE_HASH_NAME_2_OID:
        alg_name = None
        for alg_name, vals in PQ_BASE_ALG_NAMES.items():
            if name in vals:
                break

        if alg_name is None:
            raise NotImplementedError(
                "The requested algorithm is not implemented,PLease update the `PQ_BASE_ALG_NAMES` dictionary."
            )

        hash_alg = name.split("-")[-1]
        base_name = name.replace("-" + hash_alg, "", 1)
        return ReturnValue(name=base_name, tags=[base_name, alg_name, "pq-sig", "pre-hash"], hash_alg=hash_alg)
    elif name in PQ_SIG_NAME_2_OID:
        alg_name = None
        for alg_name, vals in PQ_BASE_ALG_NAMES.items():
            if name in vals:
                break

        if alg_name is None:
            raise NotImplementedError(
                "The requested algorithm is not implemented,PLease update the `PQ_BASE_ALG_NAMES` dictionary."
            )

        return ReturnValue(name=name, tags=["pq-sig", alg_name, name], hash_alg=None)
    elif name in HYBRID_SIG_NAME_2_OID:
        raise NotImplementedError("The hybrid signature algorithm is not implemented yet.")
    else:
        raise NotImplementedError(f"The requested algorithm is not implemented.: {name}")


def generate_ecdsa_sig_tests(allowed_curves: List[str]) -> List[Entry]:
    """Generate the ECDSA Signature tests for the Robot Framework."""
    raise NotImplementedError("The ECDSA signature tests are not implemented yet.")


def generate_trad_sig_tests() -> List[Entry]:
    """Generate the Traditional Signature tests for the Robot Framework."""
    alg_to_key = {"rsa": "${RSA_KEY}", "ecdsa": "${ECDSA_KEY}", "ed25519": "${ED25519_KEY}", "ed448": "${ED448_KEY}"}
    alg_to_cert = {
        "rsa": "${RSA_CERT}",
        "ecdsa": "${ECDSA_CERT}",
        "ed25519": "${ED25519_CERT}",
        "ed448": "${ED448_CERT}",
    }
    entries = []

    values = (
        list(MSG_SIG_ALG_NAME_2_OID.keys())
        + ["rsa-sha1"]
        + list(RSA_SHA3_OID_2_NAME.values())
        + list(ECDSA_SHA3_OID_2_NAME.values())
    )

    for x in values:
        correct_name = "CA MUST Accept {} Protected Request"
        negative_name = "CA Reject Invalid {} Protected Request"

        ret_val = _get_name_and_tags(x)

        cert_name = ret_val.name.replace("rsa-pss", "rsa")

        en1 = Entry(
            **ret_val.get_vals(correct_name, ["positive"]),
            bad_message_check=False,
            cert=alg_to_cert[cert_name],
            private_key=alg_to_key[cert_name],
        )

        en2 = Entry(
            **ret_val.get_vals(negative_name, ["negative"]),
            bad_message_check=True,
            cert=alg_to_cert[cert_name],
            private_key=alg_to_key[cert_name],
        )

        entries.extend([en1, en2])

    return entries


def generate_pq_sig_tests() -> List[Entry]:
    """Generate the PQ Signature tests for the Robot Framework."""
    entries = []
    for x in PQ_SIG_NAME_2_OID:
        correct_name = "CA MUST Accept {} Protected Request"
        negative_name = "CA Reject Invalid {} Protected Request"

        ret_val = _get_name_and_tags(x)

        key_name = ret_val.get_name()
        cert_name = ret_val.get_name()

        en1 = Entry(
            **ret_val.get_vals(correct_name, ["positive"]),
            bad_message_check=False,
            cert=cert_name,
            private_key=key_name,
        )

        en2 = Entry(
            **ret_val.get_vals(negative_name, ["negative"]),
            bad_message_check=True,
            cert=cert_name,
            private_key=key_name,
        )

        entries.extend([en1, en2])
    return entries


def _write_to_test_case(test_case: Entry):
    """Write the test case to the Robot Framework format."""
    # Print arguments with 4 spaces between
    name = test_case.test_name
    args = test_case.get_arguments()
    tags = test_case.tags
    _spacer = " " * 4  # 4 spaces between columns as per your requirement
    args_str = f"{_spacer}".join(args)
    tmp = f"{name}{_spacer}{args_str}\n"
    tags_str = "  ".join(tags)
    tmp += f"     [Tags]    {tags_str}\n\n"
    return tmp


def _write_to_pq_test_case(test_case: Entry):
    """Write the test case to the Robot Framework format."""
    # Print arguments with 4 spaces between
    name = test_case.test_name
    args = test_case.get_pq_arguments()
    tags = test_case.tags
    _spacer = " " * 4  # 4 spaces between columns as per your requirement
    args_str = f"{_spacer}".join(args)
    tmp = f"{name}{_spacer}{args_str}\n"
    tags_str = "  ".join(tags)
    tmp += f"     [Tags]    {tags_str}\n\n"
    return tmp


def trad_entries_to_test_case(
    entries: List[Entry],
    filepath: str = "pki_protection_test.txt",
    ends_with_keywords: bool = True,
) -> None:
    """Convert the entries to test cases for the Robot Framework."""
    # ${protection}  ${sign_key}   ${cert}  ${hash_alg}   ${bad_message_check}
    f = open(filepath, "w", encoding="utf-8")
    _spacer = " " * 4  # 4 spaces between columns as per your requirement
    field_names = ["PROTECTION", "SIGN_KEY", "CERT", "HASH_ALG", "BAD"]
    extra = f"{_spacer}".join(field_names) + "\n"
    f.write(f"*** Test Cases *** {_spacer}{extra}")
    # Test cases have to start directly after the Section header.
    for entry in entries[:-1]:
        tmp = _write_to_test_case(entry)
        f.write(tmp)

    last_entry = entries[-1]
    last_entry_str = _write_to_test_case(last_entry)
    if not ends_with_keywords:
        last_entry_str = last_entry_str[:-1]

    # Remove the last "\n", so that the RF linter will not complain.
    f.write(last_entry_str)


def pq_entries_to_test_case(
    entries: List[Entry],
    filepath: str = "pki_protection_test.txt",
    ends_with_keywords: bool = True,
) -> None:
    """Convert the entries to test cases for the Robot Framework."""
    # ${protection}  ${sign_key}   ${cert}  ${hash_alg}   ${bad_message_check}
    f = open(filepath, "w", encoding="utf-8")
    _spacer = " " * 4  # 4 spaces between columns as per your requirement
    field_names = ["ALGORITHM", "HASH_ALG", "BAD_PROTECTION"]
    extra = f"{_spacer}".join(field_names) + "\n"
    f.write(f"*** Test Cases *** {_spacer}{extra}")
    # Test cases have to start directly after the Section header.
    for entry in entries[:-1]:
        tmp = _write_to_pq_test_case(entry)
        f.write(tmp)

    last_entry = entries[-1]
    last_entry_str = _write_to_test_case(last_entry)
    if not ends_with_keywords:
        last_entry_str = last_entry_str[:-1]

    # Remove the last "\n", so that the RF linter will not complain.
    f.write(last_entry_str)


if __name__ == "__main__":
    test_cases = generate_trad_sig_tests()
    pq_tests = generate_pq_sig_tests()
    trad_entries_to_test_case(test_cases, "pki_protection_test.txt", ends_with_keywords=True)

    pq_entries_to_test_case(
        pq_tests,
        "pki_protection_test_pq.txt",
        ends_with_keywords=True,
    )
