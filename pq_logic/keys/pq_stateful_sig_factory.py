"""Factory for creating stateful post-quantum signature keys."""

import importlib.util
import logging
from typing import Dict, List, Optional

from pq_logic.keys.abstract_key_factory import AbstractKeyFactory
from resources import utils
from resources.typingutils import PrivateKey

if importlib.util.find_spec("oqs") is not None:
    import oqs  # pylint: disable=import-error
else:
    logging.warning("oqs module is not installed. Some functionalities may be disabled.")
    oqs = None  # pylint: disable=invalid-name

from pyasn1_alt_modules import rfc5280, rfc5958

from pq_logic.keys.abstract_stateful_hash_sig import PQHashStatefulSigPrivateKey, PQHashStatefulSigPublicKey
from pq_logic.keys.stateful_sig_keys import (
    HSSPrivateKey,
    HSSPublicKey,
    XMSSMTPrivateKey,
    XMSSMTPublicKey,
    XMSSPrivateKey,
    XMSSPublicKey,
)
from resources.oidutils import PQ_STATEFUL_HASH_SIG_OID_2_NAME


class PQStatefulSigFactory(AbstractKeyFactory):
    """Factory class for creating stateful PQ keys."""

    @staticmethod
    def generate_key_by_name(algorithm: str) -> PrivateKey:
        """Generate a stateful PQ key based on the specified algorithm name."""
        return PQStatefulSigFactory.generate_pq_stateful_key(algorithm)

    @staticmethod
    def get_supported_keys() -> List[str]:
        """Return a list of supported stateful PQ keys."""
        return ["hss", "xmss", "xmssmt"]

    @staticmethod
    def supported_algorithms() -> list:
        """Return a list of supported stateful PQ algorithms."""
        return PQStatefulSigFactory._get_algs()["xmss"] + PQStatefulSigFactory._get_algs()["xmssmt"]

    @classmethod
    def _get_algs(cls) -> Dict[str, List[str]]:
        """Return a list of algorithms by family."""
        if oqs is not None and hasattr(oqs, "get_enabled_stateful_sig_mechanisms"):
            algorithms = oqs.get_enabled_stateful_sig_mechanisms()
            algorithms = [x.lower() for x in algorithms]
        else:
            algorithms = [
                "hss_lms_sha256_m32_w1",
                "hss_lms_sha256_m32_w2",
                "hss_lms_sha256_m32_w4",
                "hss_lms_sha256_m32_w8",
            ]
        return {
            "lms": cls._get_alg_family(algorithms, "lms"),
            "xmss": cls._get_alg_family(algorithms, "xmss-"),
            "xmssmt": cls._get_alg_family(algorithms, "xmssmt-"),
            "hss": cls._get_alg_family(algorithms, "hss-"),
        }

    @staticmethod
    def generate_pq_stateful_key(algorithm: str, **kwargs) -> PQHashStatefulSigPrivateKey:
        """Generate a stateful PQ object based on the specified type.

        :param algorithm: The algorithm to use for the PQ.
        :return: An instance of the specified PQ type.
        """
        if algorithm.startswith("xmss-") or algorithm == "xmss":
            if algorithm not in PQStatefulSigFactory.supported_algorithms() + ["xmss"]:
                msg = (
                    f"Unsupported XMSS algorithm: {algorithm}. "
                    f"Supported algorithms are: {PQStatefulSigFactory._get_algs()['xmss']}"
                )
                raise ValueError(msg)
            return XMSSPrivateKey(algorithm)

        elif algorithm.startswith("xmssmt-") or algorithm == "xmssmt":
            if algorithm not in PQStatefulSigFactory.supported_algorithms() + ["xmssmt"]:
                msg = (
                    f"Unsupported XMSSMT algorithm: {algorithm}. "
                    f"Supported algorithms are: {PQStatefulSigFactory._get_algs()['xmssmt']}"
                )
                raise ValueError(msg)
            return XMSSMTPrivateKey(algorithm)

        elif algorithm.startswith("hss"):
            if algorithm not in PQStatefulSigFactory.supported_algorithms() + ["hss"]:
                msg = (
                    f"Unsupported HSS algorithm: {algorithm}. "
                    f"Supported algorithms are: {PQStatefulSigFactory._get_algs()['lms']}"
                )
                raise ValueError(msg)
            return HSSPrivateKey(algorithm, length=int(kwargs.get("length", 1)))
        else:
            raise ValueError(
                f"Unsupported algorithm: {algorithm}. "
                f"Supported algorithms are: {PQStatefulSigFactory.supported_algorithms()}"
            )

    @staticmethod
    def load_public_key_from_spki(spki: rfc5280.SubjectPublicKeyInfo) -> PQHashStatefulSigPublicKey:
        """Load a public key from a SubjectPublicKeyInfo object.

        :param spki: The SubjectPublicKeyInfo object containing the public key.
        :return: An instance of the corresponding stateful signature public key class.
        """
        oid = spki["algorithm"]["algorithm"]
        public_key_bytes = spki["subjectPublicKey"].asOctets()
        algorithm = PQ_STATEFUL_HASH_SIG_OID_2_NAME[oid]
        if algorithm == "xmss":
            return XMSSPublicKey.from_public_bytes(public_key_bytes)
        elif algorithm == "xmssmt":
            return XMSSMTPublicKey.from_public_bytes(public_key_bytes)
        elif algorithm == "hss":
            return HSSPublicKey.from_public_bytes(public_key_bytes)
        else:
            raise ValueError(f"Unsupported algorithm in SPKI: {algorithm}")

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
        if alg_name.startswith("xmss-"):
            private_key = XMSSPrivateKey.from_private_bytes(private_key_bytes)
        elif alg_name.startswith("xmssmt-"):
            private_key = XMSSMTPrivateKey.from_private_bytes(private_key_bytes)
        elif alg_name.startswith("hss"):
            private_key = HSSPrivateKey.from_private_bytes(private_key_bytes)
        else:
            raise ValueError(
                f"Unsupported algorithm: {alg_name}. "
                f"Supported algorithms are: {PQStatefulSigFactory.supported_algorithms()}"
            )
        return private_key.__class__(private_key.name, private_key_bytes, public_key_bytes)

    @staticmethod
    def load_private_key_from_one_asym_key(one_asym_key: rfc5958.OneAsymmetricKey) -> PQHashStatefulSigPrivateKey:
        """Load a private key from a OneAsymmetricKey object.

        :param one_asym_key: The OneAsymmetricKey object containing the private key.
        :return: An instance of the corresponding stateful signature private key class.
        """
        oid = one_asym_key["privateKeyAlgorithm"]["algorithm"]
        algorithm = PQ_STATEFUL_HASH_SIG_OID_2_NAME[oid]
        public_key_bytes = None
        private_key_bytes = one_asym_key["privateKey"].asOctets()
        if one_asym_key["publicKey"].isValue:
            public_key_bytes = one_asym_key["publicKey"].asOctets()
        if algorithm == "xmss":
            private_key = XMSSPrivateKey.from_private_bytes(private_key_bytes)
            if public_key_bytes:
                return XMSSPrivateKey(private_key.name, private_key_bytes, public_key_bytes)
            return private_key
        elif algorithm == "xmssmt":
            private_key = XMSSMTPrivateKey.from_private_bytes(private_key_bytes)
            if public_key_bytes:
                return XMSSMTPrivateKey(private_key.name, private_key_bytes, public_key_bytes)
            return private_key
        elif algorithm == "hss":
            raise NotImplementedError("HSS private key loading from OneAsymmetricKey is not implemented yet.")
        else:
            raise ValueError(f"Unsupported algorithm in OneAsymmetricKey: {algorithm}")

    @staticmethod
    def _prepare_invalid_private_key(
        private_key: PrivateKey,
    ) -> bytes:
        """Prepare an invalid private key for testing purposes."""
        private_key_bytes = private_key.private_bytes_raw()
        private_key_bytes = utils.manipulate_first_byte(private_key_bytes)
        return private_key_bytes
