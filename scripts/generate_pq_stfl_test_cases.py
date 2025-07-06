# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
"""Generate test cases for post-quantum stateful signature algorithms.

Creates the test cases for XMSS and XMSSMT algorithms, including both NIST-approved
and non-NIST-approved algorithms, and writes them to a file in Robot Framework format.
So that the test cases can be used in automated testing environments and just have to be
copied to the `tests_pq_and_hybrid/pq_stateful_sig_alg.robot` file.
"""

import sys
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from scripts.verbose_test_dataclasses import (
    ALL_BODY_NAMES,
    AbstractSingleTestCase,
    AbstractTestCase,
    get_body_name_tags,
)

from resources.ca_ra_utils import (
    is_nist_approved_xmss,
    is_nist_approved_xmssmt,
)

sys.path.append(".")


@dataclass
class TestCase(AbstractTestCase):
    """Representation of a Robot Framework test case."""

    def get_args(self) -> str:
        """Return the arguments for the test case in Robot Framework format."""
        raise NotImplementedError("This method should be implemented in subclasses.")

    name: str
    algorithm: str
    bad_pop: str = "False"
    exhausted: str = "False"
    invalid_parameters: str = "False"
    invalid_key_size: str = "False"
    already_in_use: str = "False"
    tags: List[str] = field(default_factory=list)
    function: List[Tuple[str, List[Dict[str, str]]]] = field(default_factory=list)

    def _get_function(self) -> List[str]:
        return [
            self.algorithm,
            self.bad_pop,
            self.exhausted,
            self.invalid_parameters,
            self.invalid_key_size,
            self.already_in_use,
        ]

    def get_args_as_dicts(self) -> List[Dict[str, str]]:
        """Return the arguments for the test case as a list of dictionaries."""
        keys = [
            "algorithm",
            "bad_pop",
            "exhausted",
            "invalid_parameters",
            "invalid_key_size",
            "already_in_use",
        ]
        return [{k: v} for k, v in zip(keys, self._get_function())]

    def create_test_case(self) -> str:
        indent = " " * 4
        args = f"{indent}".join(self._get_function())
        tags_line = f"{indent}".join(self.tags) + "\n"
        data = f"{self.name}{indent}{args}\n    [Tags]{indent}{tags_line}"
        for keyword, param_dicts in self.function:
            if self.args_as_kwargs:
                param_str = "    ".join(f"{k}={v}" for d in param_dicts for k, v in d.items())
            else:
                param_str = "    ".join(d.get("arg", "") for d in param_dicts)
            data += f"     {keyword}    {param_str}\n"
        return data

    def generate_test_case(self) -> str:
        """Generate the test case in Robot Framework format."""
        return self.create_test_case()


@dataclass
class SingleStatefulSigTestCase(AbstractSingleTestCase):
    """Specialized test case for NIST-approved stateful signature requests."""

    name: str
    algorithm: str
    body_name: str
    bad_pop: bool = False
    exhausted: bool = False
    invalid_parameters: bool = False
    invalid_key_size: bool = False
    already_in_use: bool = False
    tags: List[str] = field(default_factory=list)
    _function_name: str = "Request With Stateful Sig Key"
    args_as_kwargs: bool = False  # ensure kwargs formatting
    function: List[Tuple[str, Dict[str, str]]] = field(init=False)

    def __post_init__(self):
        self.function = [(self._function_name, self.get_args_as_dicts())]

    def get_args_as_dicts(self) -> Dict[str, str]:
        """Return the arguments for the test case as a dictionary."""
        keys = [
            "algorithm",
            "body_name",
            "bad_pop",
            "exhausted",
            "invalid_parameters",
            "invalid_key_size",
            "already_in_use",
        ]
        values = [
            self.algorithm,
            self.body_name,
            self.bad_pop,
            self.exhausted,
            self.invalid_parameters,
            self.invalid_key_size,
            self.already_in_use,
        ]
        return {k: self._convert_value_to_robot(v) for k, v in zip(keys, values)}

    def get_args(self) -> str:
        """Return the arguments for the test case in Robot Framework format."""
        raise NotImplementedError("This method is not implemented for SingleStatefulSigTestCase.")

    def generate_test_case(self) -> str:
        """Generate the test case in Robot Framework format."""
        data = self.name + "\n"
        data += self.get_tags() + "\n"
        data += self._get_function((self._function_name, self.get_args_as_dicts())) + "\n"
        return data


@dataclass
class HSSSingleStatefulSigTestCase(AbstractTestCase):
    """Specialized test case for HSS stateful signature requests."""

    def create_test_case(self) -> str:
        """Create a test case string."""
        return self.generate_test_case()

    name: str
    algorithm: str
    body_name: str
    invalid_length: bool = False
    zero_length: bool = False
    tags: List[str] = field(default_factory=list)
    _function_name: str = "Request For Only HSS Stateful Sig Key"

    def __post_init__(self):
        self.function = [(self._function_name, self.get_args_as_dicts())]

    def get_args_as_dicts(self) -> Dict[str, str]:
        """Return the arguments for the test case as a dictionary."""
        keys = ["algorithm", "body_name", "invalid_length", "zero_length"]
        values = [
            self.algorithm,
            self.body_name,
            self.invalid_length,
            self.zero_length,
        ]
        return {k: self._convert_value_to_robot(v) for k, v in zip(keys, values)}

    def get_args(self) -> str:
        """Return the arguments for the test case in Robot Framework format."""
        raise NotImplementedError("This method is not implemented for SingleStatefulSigTestCase.")

    def generate_test_case(self) -> str:
        """Generate the test case in Robot Framework format."""
        data = self.name + "\n"
        data += self.get_tags() + "\n"
        data += self._get_function((self._function_name, self.get_args_as_dicts())) + "\n"
        return data


@dataclass
class SinglePKIProtectionTestCase(AbstractSingleTestCase):
    """Specialized test case that uses PKIProtected function call."""

    name: str
    algorithm: str
    body_name: str
    bad_message_check: bool = False
    invalid_parameters: bool = False
    exhausted: bool = False
    used_index: bool = False
    popo_exhausted_key: bool = False
    tags: List[str] = field(default_factory=list)
    _function_name: str = "Request With PKIProtected Stateful Sig Key"
    args_as_kwargs: bool = False  # ensure kwargs formatting
    function: List[Tuple[str, Dict[str, str]]] = field(init=False)

    def __post_init__(self):
        """Initialize the function attribute with the function name and arguments."""
        self.function = [(self._function_name, self.get_args_as_dicts())]

    def get_args_as_dicts(self) -> Dict[str, str]:
        """Return the arguments for the test case as a list of dictionaries."""
        keys = [
            "algorithm",
            "body_name",
            "bad_message_check",
            "invalid_parameters",
            "exhausted",
            "used_index",
            "popo_exhausted_key",
        ]
        values = [
            self.algorithm,
            self.body_name,
            self.bad_message_check,
            self.invalid_parameters,
            self.exhausted,
            self.used_index,
            self.popo_exhausted_key,
        ]

        out = {}
        for key, value in zip(keys, values):
            out[key] = self._convert_value_to_robot(value)
        return out

    def get_args(self) -> str:
        """Return the arguments for the test case in Robot Framework format."""
        raise NotImplementedError("This method is not implemented for SinglePKIProtectionTestCase.")

    def generate_test_case(self) -> str:
        """Generate the test case in Robot Framework format."""
        data = self.name + "\n"
        data += self.get_tags() + "\n"
        data += self._get_function((self._function_name, self.get_args_as_dicts())) + "\n"
        return data


@dataclass
class SingleEmptyTestCase(AbstractSingleTestCase):
    """A test case that does not perform any actions, used for empty test cases."""

    def generate_test_case(self) -> str:
        """Generate an empty test case in Robot Framework format."""
        return self.create_test_case()

    name: str
    body_name: str
    tags: List[str] = field(default_factory=list)
    function: List[Tuple[str, Dict[str, str]]] = field(default_factory=list)
    args_as_kwargs: bool = False  # ensure kwargs formatting

    def get_args(self) -> str:
        """Return the arguments for the test case in Robot Framework format."""
        return ""

    def create_test_case(self) -> str:
        """Create a test case string."""
        data = self.name + "\n"
        data += self.get_tags() + "\n"
        for fun in self.function:
            keyword, param_dicts = fun
            data += self._get_function((keyword, param_dicts)) + "\n"

        return data


def _generate_nist_approved_test_cases(alg: str, body_name: str, tag: str) -> List[SingleStatefulSigTestCase]:
    """Generate test cases for NIST-approved algorithms using SingleStatefulSigTestCase."""
    function_name = "Request For PQ Stateful Sig Key"

    def make_case(name: str, **kwargs) -> SingleStatefulSigTestCase:
        return SingleStatefulSigTestCase(
            name=name,
            algorithm=alg,
            body_name=kwargs["body"],
            bad_pop=kwargs.get("bad_pop", False),
            exhausted=kwargs.get("exhausted", False),
            invalid_parameters=kwargs.get("invalid_parameters", False),
            invalid_key_size=kwargs.get("invalid_key_size", False),
            already_in_use=kwargs.get("already_in_use", False),
            tags=kwargs.get("tags", []),
            _function_name=function_name,
        )

    base_tags = [tag, alg, "nist_approved"]
    tests: List[SingleStatefulSigTestCase] = []

    if body_name in ["added-protection", "batch"]:
        return tests

    tmp_tags = base_tags + get_body_name_tags(body_name)
    tests += [
        make_case(
            name=f"Invalid Stateful Sig {alg.upper()} {body_name.upper()} Request",
            bad_pop=True,
            body=body_name,
            tags=["negative", "badPOP"] + base_tags,
        ),
        make_case(
            name=f"Exhausted Stateful Sig {alg.upper()} {body_name.upper()} Request",
            exhausted=True,
            body=body_name,
            tags=["negative"] + tmp_tags + ["exhausted"],
        ),
        make_case(
            name=f"Invalid Stateful Sig {alg.upper()} {body_name.upper()} Algorithm Parameters",
            invalid_parameters=True,
            body=body_name,
            tags=["negative"] + tmp_tags + ["invalid_parameters", "strict"],
        ),
        make_case(
            name=f"Invalid Stateful Sig {alg.upper()} {body_name.upper()} Key Size",
            invalid_key_size=True,
            body=body_name,
            tags=["negative"] + tmp_tags + ["invalid_key_sizestrict"],
        ),
        make_case(
            name=f"Valid Stateful Sig {alg.upper()} {body_name.upper()} Request",
            body=body_name,
            tags=["positive"] + base_tags,
        ),
        make_case(
            name=f"Invalid Stateful Sig {alg.upper()} Already In Use {body_name.upper()} Request",
            already_in_use=True,
            body=body_name,
            tags=["negative"] + tmp_tags + ["already_in_use", "same_key"],
        ),
    ]

    return tests


def _generate_pkiprotected_test_cases(alg: str, body_name: str, tag: str) -> List[SinglePKIProtectionTestCase]:
    """Generate test cases for PKI-protected algorithms."""
    function_name = "Request With PKIProtected Stateful Sig Key"
    if alg.startswith("xmss-"):
        nist_approved = is_nist_approved_xmss(alg)
    elif alg.startswith("xmssmt-"):
        nist_approved = is_nist_approved_xmssmt(alg)
    else:
        nist_approved = is_nist_approved_hss(alg)

    nist_tag = "nist_approved" if nist_approved else "nist_disapproved"
    shared_tags = [tag, alg, nist_tag, "PKIProtection"]

    name_to_add = f"{body_name.upper()} Request"

    return [
        SinglePKIProtectionTestCase(
            name=f"Valid PKIProtected {alg.upper()} {name_to_add}",
            algorithm=alg,
            body_name=body_name,
            used_index=False,
            tags=["positive"] + shared_tags,
            _function_name=function_name,
        ),
        SinglePKIProtectionTestCase(
            name=f"Invalid PKIProtected {alg.upper()} {name_to_add}",
            body_name=body_name,
            algorithm=alg,
            bad_message_check=True,
            tags=["negative"] + shared_tags + ["bad_message_check"],
            _function_name=function_name,
        ),
        SinglePKIProtectionTestCase(
            name=f"Invalid PKIProtected {alg.upper()} {name_to_add} with Invalid Parameters",
            body_name=body_name,
            algorithm=alg,
            invalid_parameters=True,
            tags=["negative"] + shared_tags + ["invalid_parameters", "strict"],
            _function_name=function_name,
        ),
        SinglePKIProtectionTestCase(
            name=f"Invalid PKIProtected {alg.upper()} {name_to_add} with Exhausted Key",
            body_name=body_name,
            algorithm=alg,
            exhausted=True,
            tags=["negative"] + shared_tags + ["exhausted"],
            _function_name=function_name,
        ),
        SinglePKIProtectionTestCase(
            name=f"Invalid PKIProtected {alg.upper()} {name_to_add} with Already Used Key Index",
            body_name=body_name,
            algorithm=alg,
            exhausted=False,
            used_index=True,
            tags=["negative"] + shared_tags + ["exhausted", "used_stfl_key_index"],
            _function_name=function_name,
        ),
        SinglePKIProtectionTestCase(
            name=f"Invalid PKIProtected {alg.upper()} {name_to_add} with POPO Exhausted Key",
            body_name=body_name,
            algorithm=alg,
            exhausted=False,
            popo_exhausted_key=True,
            tags=["negative"] + shared_tags + ["exhausted", "popo_exhausted_key"],
            _function_name=function_name,
        ),
    ]


def _geneerate_cert_conf_test_cases(alg: str, body_name: str, tag: str) -> List[SingleEmptyTestCase]:
    """Generate test cases for certificate confirmation message."""
    return [
        SingleEmptyTestCase(
            name=f"Valid Cert Conf for {alg.upper()} {body_name.upper()} Request",
            tags=["positive", tag, alg, "certConf"],
            body_name=body_name,
            function=[("Build Certificate Confirmation Test", {"algorithm": alg, "body_name": body_name})],
        ),
        SingleEmptyTestCase(
            name=f"Invalid Cert Conf for {alg.upper()} {body_name.upper()} Request With Used Key Index",
            tags=["negative", tag, alg, "certConf", "used_stfl_key_index"],
            function=[("Build Certificate Confirmation Used Key Test", {"algorithm": alg, "body_name": body_name})],
            body_name=body_name,
            args_as_kwargs=False,
        ),
    ]


def is_nist_approved_hss(alg: str) -> bool:
    """Check if the HSS algorithm is NIST-approved."""
    print("Checking if HSS algorithm is NIST-approved:", alg)
    # name format: hss_lms_sha256_m32_h15_lmots_sha256_n32_w4
    lms_alg = alg.split("_")[1:4]  # Extract LMS algorithm part
    lmots_alg = alg.split("_")[5:8]  # Extract LMOTS algorithm part
    lms_hash_alg = lms_alg[1]  # e.g., sha256
    lmots_hash_alg = lmots_alg[1]  # e.g., sha256
    # Check if LMS and LMOTS hash algorithms match
    return lms_hash_alg == lmots_hash_alg


def _generate_xmss_test_cases() -> List[TestCase]:
    """Generate test cases for XMSS algorithms."""
    test_cases = []
    from pq_logic.keys.pq_stateful_sig_factory import PQStatefulSigFactory

    algorithms = PQStatefulSigFactory.get_algorithms_by_family()["xmss"]

    for body_name in ALL_BODY_NAMES:
        if body_name not in ["ir", "p10cr"]:
            continue
        for alg in algorithms:
            if is_nist_approved_xmss(alg):
                test_cases.extend(_generate_nist_approved_test_cases(alg, body_name, "xmss"))
                test_cases.extend(_generate_pkiprotected_test_cases(alg, body_name, "xmss"))
                test_cases.extend(_geneerate_cert_conf_test_cases(alg, body_name, "xmss"))
            else:
                test_cases.append(
                    SingleEmptyTestCase(
                        name=f"Invalid NIST Disapproved {alg.upper()} {body_name.upper()} Request",
                        tags=["negative", "xmss", alg, "nist_disapproved"],
                        args_as_kwargs=False,
                        body_name=body_name,
                        function=[
                            (
                                "Request For NIST Disapproved PQ Stateful Sig Key",
                                {"algorithm": alg, "body_name": body_name},
                            )
                        ],
                    )
                )
    return test_cases


def _generate_xmssmt_test_cases() -> List[TestCase]:
    """Generate test cases for XMSSMT algorithms."""
    test_cases = []
    from pq_logic.keys.pq_stateful_sig_factory import PQStatefulSigFactory

    algorithms = PQStatefulSigFactory.get_algorithms_by_family()["xmssmt"]
    for body_name in ALL_BODY_NAMES:
        if body_name not in ["ir", "p10cr"]:
            continue
        for alg in algorithms:
            if is_nist_approved_xmssmt(alg):
                test_cases.extend(_generate_nist_approved_test_cases(alg, body_name, "xmssmt"))
                test_cases.extend(_generate_pkiprotected_test_cases(alg, body_name, "xmssmt"))
                test_cases.extend(_geneerate_cert_conf_test_cases(alg, body_name, "xmssmt"))
            else:
                test_cases.append(
                    SingleEmptyTestCase(
                        name=f"Invalid NIST Disapproved {alg.upper()} {body_name.upper()} Request",
                        tags=["negative", "xmssmt", alg, "nist_disapproved"],
                        args_as_kwargs=False,
                        body_name=body_name,
                        function=[
                            (
                                "Request For NIST Disapproved PQ Stateful Sig Key",
                                {"algorithm": alg, "body_name": body_name},
                            )
                        ],
                    )
                )
    return test_cases


def _generate_hss_approved_test_cases(alg: str, body_name: str, tag: str) -> List[TestCase]:
    """Generate test cases for HSS algorithms."""
    function_name = "Request For Only HSS Stateful Sig Key"

    def make_case(name: str, **kwargs) -> HSSSingleStatefulSigTestCase:
        return HSSSingleStatefulSigTestCase(
            name=name,
            algorithm=alg,
            body_name=kwargs["body"],
            invalid_length=kwargs.get("invalid_length", False),
            tags=kwargs.get("tags", []),
            _function_name=function_name,
        )

    tmp_tags = [tag, alg]

    test_cases = _generate_nist_approved_test_cases(alg, body_name, "hss")

    other_test_cases = [
        make_case(
            name=f"Invalid Stateful Sig {alg.upper()} Invalid HSS Length {body_name.upper()} Request",
            invalid_length=True,
            body=body_name,
            tags=["negative"] + tmp_tags + ["hss_key_length"],
        ),
        make_case(
            name=f"Invalid Stateful Sig {alg.upper()} Zero HSS Length {body_name.upper()} Request",
            zero_length=True,
            body=body_name,
            tags=["negative"] + tmp_tags + ["hss_key_length"],
        ),
    ]

    test_cases.extend(other_test_cases)  # type: ignore
    return test_cases  # type: ignore


def _generate_hss_test_cases() -> List[TestCase]:
    """Generate test cases for HSS algorithms."""
    test_cases = []
    from pq_logic.keys.pq_stateful_sig_factory import PQStatefulSigFactory

    algorithms = PQStatefulSigFactory.get_algorithms_by_family()["hss"]
    for body_name in ALL_BODY_NAMES:
        if body_name not in ["ir", "p10cr"]:
            continue
        for alg in algorithms:
            if is_nist_approved_hss(alg):
                test_cases.extend(_generate_hss_approved_test_cases(alg, body_name, "hss"))
                test_cases.extend(_generate_pkiprotected_test_cases(alg, body_name, "hss"))
                test_cases.extend(_geneerate_cert_conf_test_cases(alg, body_name, "hss"))
            else:
                test_cases.append(
                    SingleEmptyTestCase(
                        name=f"Invalid NIST Disapproved {alg.upper()} {body_name.upper()} Request",
                        tags=["negative", "hss", alg, "nist_disapproved"],
                        args_as_kwargs=False,
                        body_name=body_name,
                        function=[
                            (
                                "Request For NIST Disapproved PQ Stateful Sig Key",
                                {"algorithm": alg, "body_name": body_name},
                            )
                        ],
                    )
                )
    return test_cases


def generate_pq_stateful_sig_tests() -> List[TestCase]:
    """Return test cases for XMSS, XMSSMT and HSS algorithms."""
    test_cases = _generate_xmss_test_cases()
    test_cases.extend(_generate_xmssmt_test_cases())
    return test_cases


def write_pq_stateful_sig_tests(path: str = "stateful_sig_test_cases.txt") -> int:
    """Write the generated tests to `path` in Robot Framework format."""
    header = "*** Test Cases ***\n"
    test_cases = generate_pq_stateful_sig_tests()

    with open(path, "w", encoding="utf-8") as f:
        f.write(header)
        for case in test_cases:
            f.write(case.generate_test_case())
            f.write("\n")

    return len(test_cases)


if __name__ == "__main__":
    count = write_pq_stateful_sig_tests()
    print(
        "Post-Quantum Stateful Signature test cases generated successfully. Total tests:",
        count,
    )
