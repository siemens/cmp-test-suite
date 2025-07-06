# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Factory for creating stateful post-quantum signature keys."""

import importlib.util
import logging
from typing import Dict, List, Optional, Type

from pyasn1_alt_modules import rfc5280

from pq_logic.keys.abstract_key_factory import AbstractKeyFactory
from pq_logic.keys.abstract_stateful_hash_sig import PQHashStatefulSigPrivateKey, PQHashStatefulSigPublicKey
from pq_logic.keys.stateful_sig_keys import (
    XMSSMTPrivateKey,
    XMSSMTPublicKey,
    XMSSPrivateKey,
    XMSSPublicKey,
)
from resources import utils
from resources.exceptions import InvalidKeyData, MismatchingKey
from resources.oid_mapping import may_return_oid_to_name
from resources.oidutils import PQ_STATEFUL_HASH_SIG_OID_2_NAME
from resources.typingutils import PrivateKey

if importlib.util.find_spec("oqs") is not None:
    import oqs  # pylint: disable=import-error
else:
    logging.warning("oqs module is not installed. Some functionalities may be disabled.")
    oqs = None  # pylint: disable=invalid-name


class PQStatefulSigFactory(AbstractKeyFactory):
    """Factory class for creating stateful PQ keys."""

    _sig_prefix_2_priv_class: Dict[str, Type[PQHashStatefulSigPrivateKey]] = {
        "xmss": XMSSPrivateKey,
        "xmssmt": XMSSMTPrivateKey,
    }
    _sig_prefix_2_pub_class: Dict[str, Type[PQHashStatefulSigPublicKey]] = {
        "xmss": XMSSPublicKey,
        "xmssmt": XMSSMTPublicKey,
    }

    @staticmethod
    def generate_key_by_name(algorithm: str) -> PrivateKey:
        """Generate a stateful PQ key based on the specified algorithm name."""
        return PQStatefulSigFactory.generate_pq_stateful_key(algorithm)

    @staticmethod
    def get_supported_keys() -> List[str]:
        """Return a list of supported stateful PQ keys."""
        return ["xmss", "xmssmt"]

    @staticmethod
    def supported_algorithms() -> list:
        """Return a list of supported stateful PQ algorithms."""
        return (
            PQStatefulSigFactory.get_algorithms_by_family()["xmss"]
            + PQStatefulSigFactory.get_algorithms_by_family()["xmssmt"]
        )

    @classmethod
    def get_algorithms_by_family(cls) -> Dict[str, List[str]]:
        """Return a list of algorithms by family."""
        algorithms = []
        if oqs is not None and hasattr(oqs, "get_enabled_stateful_sig_mechanisms"):
            algorithms = oqs.get_enabled_stateful_sig_mechanisms()
            algorithms = [x.lower() for x in algorithms]

        return {
            "xmss": cls._get_alg_family(algorithms, "xmss-"),
            "xmssmt": cls._get_alg_family(algorithms, "xmssmt-"),
        }

    @staticmethod
    def generate_pq_stateful_key(algorithm: str, **kwargs) -> PQHashStatefulSigPrivateKey:
        """Generate a stateful PQ object based on the specified type.

        :param algorithm: The algorithm to use for the PQ.
        :return: An instance of the specified PQ type.
        """
        prefix = PQStatefulSigFactory._get_matching_prefix(algorithm, PQStatefulSigFactory.get_supported_keys())
        algorithms = PQStatefulSigFactory.supported_algorithms() + [prefix]
        if algorithm not in algorithms:
            msg = (
                f"Unsupported {prefix.upper()} algorithm: {algorithm}. "
                f"Supported algorithms are: {PQStatefulSigFactory.get_algorithms_by_family()[prefix]}"
            )
            raise ValueError(msg)

        private_key_type = PQStatefulSigFactory._sig_prefix_2_priv_class[prefix]
        if prefix == "hss":
            return private_key_type(algorithm, length=int(kwargs.get("length", 1)))  # type: ignore
        return private_key_type(algorithm)

    @staticmethod
    def load_public_key_from_spki(spki: rfc5280.SubjectPublicKeyInfo) -> PQHashStatefulSigPublicKey:
        """Load a public key from a SubjectPublicKeyInfo object.

        :param spki: The SubjectPublicKeyInfo object containing the public key.
        :return: An instance of the corresponding stateful signature public key class.
        """
        oid = spki["algorithm"]["algorithm"]
        public_key_bytes = spki["subjectPublicKey"].asOctets()
        algorithm = PQ_STATEFUL_HASH_SIG_OID_2_NAME[oid]

        alg_id = spki["algorithm"]
        if alg_id["parameters"].isValue:
            raise InvalidKeyData(f"The `parameters` field in the SPKI is not allowed to be set for: {algorithm}")

        prefix = PQStatefulSigFactory._get_matching_prefix(algorithm, PQStatefulSigFactory.get_supported_keys())

        if prefix in PQStatefulSigFactory._sig_prefix_2_pub_class:
            pub_class = PQStatefulSigFactory._sig_prefix_2_pub_class[prefix]
            return pub_class.from_public_bytes(public_key_bytes)

        raise NotImplementedError(f"Unsupported PQ STFL algorithm in SPKI: {algorithm}")


    @staticmethod
    def _load_private_key_from_pkcs8(
        alg_id: rfc5280.AlgorithmIdentifier,
        private_key_bytes: bytes,
        public_key_bytes: Optional[bytes] = None,
    ) -> PQHashStatefulSigPrivateKey:
        """Load a private key from raw PKCS#8 bytes.

        :param alg_id: The AlgorithmIdentifier containing the algorithm OID.
        :param private_key_bytes: The raw bytes of the private key.
        :param public_key_bytes: Optional raw bytes of the public key.
        """
        alg_name = PQ_STATEFUL_HASH_SIG_OID_2_NAME[alg_id["algorithm"]]
        prefix = PQStatefulSigFactory._get_matching_prefix(alg_name, PQStatefulSigFactory.get_supported_keys())

        if prefix not in PQStatefulSigFactory._sig_prefix_2_priv_class:
            raise NotImplementedError(f"Unsupported PQ STFL algorithm in PKCS#8: {alg_name}")

        private_key_class = PQStatefulSigFactory._sig_prefix_2_priv_class[prefix]
        private_key = private_key_class.from_private_bytes(private_key_bytes)
        if public_key_bytes is None:
            return private_key

        PQStatefulSigFactory._validate_public_key(
            alg_name,
            private_key,
            public_key_bytes,
        )
        return private_key

    @staticmethod
    def _prepare_invalid_private_key(
        private_key: PrivateKey,
    ) -> bytes:
        """Prepare an invalid private key for testing purposes."""
        private_key_bytes = private_key.private_bytes_raw()
        private_key_bytes = utils.manipulate_first_byte(private_key_bytes)
        return private_key_bytes
