# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Factory class to generate and load post-quantum keys in various input formats."""

from typing import List

import resources.oidutils
from pyasn1_alt_modules import rfc5280, rfc5958
from resources.oidutils import FRODOKEM_NAME_2_OID, MCELIECE_NAME_2_OID, PQ_NAME_2_OID, PQ_SIG_PRE_HASH_OID_2_NAME

from pq_logic.keys.kem_keys import (
    FrodoKEMPrivateKey,
    FrodoKEMPublicKey,
    McEliecePrivateKey,
    McEliecePublicKey,
    MLKEMPrivateKey,
    MLKEMPublicKey,
    Sntrup761PrivateKey,
)
from pq_logic.keys.sig_keys import (
    FalconPrivateKey,
    FalconPublicKey,
    MLDSAPrivateKey,
    MLDSAPublicKey,
    SLHDSAPrivateKey,
    SLHDSAPublicKey,
)


def _check_starts_with(algorithm: str, prefixes: List[str]) -> bool:
    """Check if the algorithm starts with any of the specified prefixes."""
    return any(algorithm.startswith(prefix) for prefix in prefixes)


class PQKeyFactory:
    """Factory class for creating post-quantum keys from various input formats."""

    @staticmethod
    def get_all_kem_alg():
        """Return a list of all supported post-quantum KEM algorithms."""
        return (
            ["ml-kem-512", "ml-kem-768", "ml-kem-1024", "sntrup761"]
            + list(MCELIECE_NAME_2_OID.keys())
            + list(FRODOKEM_NAME_2_OID.keys())
        )

    @staticmethod
    def supported_algorithms() -> List[str]:
        """Return a list of supported post-quantum algorithms."""
        return [
            "slh-dsa",
            "sntrup761",
            "mceliece",
            "falcon",
            "frodokemml-kem",
            "ml-dsa",
        ]

    @staticmethod
    def get_all_callable_algs() -> List[str]:
        """Return a list of all supported post-quantum algorithms.

        Which the Test-Suite currently can generate and operate with.
        """
        return list(PQ_NAME_2_OID.keys())

    @staticmethod
    def generate_pq_key(algorithm: str):
        """Generate a post-quantum private key based on the specified algorithm.

        :param algorithm: The algorithm name, which can be one of the following:
                          - For ML-KEM: 'ml-kem-512', 'ml-kem-768', 'ml-kem-1024'.
                          - For ML-DSA: 'ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87'.
        :return: An instance of `MLKEMPrivateKey` or `MLDSAPrivateKey` depending on the algorithm.

        :raises ValueError: If the algorithm name does not match any known ML-KEM or ML-DSA algorithms.
        """
        algorithm = algorithm.lower()

        if algorithm in ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]:
            return MLKEMPrivateKey(kem_alg=algorithm)

        if algorithm in ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]:
            return MLDSAPrivateKey(sig_alg=algorithm.upper())

        if algorithm == "slh-dsa" or algorithm in resources.oidutils.SLH_DSA_NAME_2_OID:
            algorithm = "slh-dsa-sha2-256s" if algorithm == "slh-dsa" else algorithm
            return SLHDSAPrivateKey(sig_alg=algorithm)

        if algorithm == "sntrup761":
            return Sntrup761PrivateKey(kem_alg="sntrup761")

        if algorithm.startswith("mceliece"):
            return McEliecePrivateKey(kem_alg=algorithm)

        if algorithm.startswith("falcon"):
            return FalconPrivateKey(sig_alg=algorithm)

        if algorithm.startswith("frodokem"):
            return FrodoKEMPrivateKey(kem_alg=algorithm)

        raise ValueError(f"Invalid algorithm name provided: '{algorithm}'.")

    @staticmethod
    def may_be_pq_alg(algorithm: str) -> bool:
        """Check if the name starts with the prefix of a post-quantum algorithm.

        :param algorithm: The algorithm name to check.
        :return: Whether the name starts with a recognized prefix or not.
        """
        return _check_starts_with(
            algorithm, prefixes=["ml-dsa", "ml-kem", "slh-dsa", "sntrup761", "mceliece", "falcon", "frodokem"]
        )

    @staticmethod
    def from_one_asym_key(one_asy_key: rfc5958.OneAsymmetricKey):
        """Create a post-quantum private key from an `rfc5958.OneAsymmetricKey` object.

        Used if the `envelopedData` contained an ML-DSA keypair.

        :param one_asy_key: An `rfc5958.OneAsymmetricKey` object containing the private key information.
        :return: A post-quantum private key instance.

        :raises KeyError: If the algorithm identifier from the provided key is not recognized.
        """
        oid = one_asy_key["privateKeyAlgorithm"]["algorithm"]
        private_bytes = one_asy_key["privateKey"].asOctets()
        public_bytes = one_asy_key["publicKey"].asOctets()

        try:
            name = resources.oidutils.PQ_OID_2_NAME[oid]
        except KeyError as err:
            raise KeyError(f"Unrecognized algorithm identifier: {oid}") from err

        if name.startswith("ml-dsa-"):
            key = MLDSAPrivateKey(sig_alg=name, private_bytes=private_bytes, public_key=public_bytes)

        elif name.startswith("slh-dsa"):
            key = SLHDSAPrivateKey(sig_alg=name, private_bytes=private_bytes, public_key=public_bytes)

        elif name.startswith("falcon"):
            key = FalconPrivateKey(sig_alg=name, private_bytes=private_bytes, public_key=public_bytes)

        elif name == "sntrup761":
            key = Sntrup761PrivateKey(kem_alg=name, private_bytes=private_bytes, public_key=public_bytes)

        elif name.startswith("ml-kem-"):
            key = MLKEMPrivateKey(kem_alg=name, private_bytes=private_bytes, public_key=public_bytes)

        else:
            raise NotImplementedError(f"Unimplemented algorithm: {name}")

        return key

    @staticmethod
    def load_public_key_from_spki(spki: rfc5280.SubjectPublicKeyInfo):
        """Load a public key from a given `SubjectPublicKeyInfo` (spki) structure.

        :param spki: An `rfc5280.SubjectPublicKeyInfo` object containing the public key.
        :return: An instance of `MLKEMPublicKey` or `MLDSAPublicKey`.
        :raises KeyError: If the algorithm identifier from the SPKI is not recognized.
        """
        public_bytes = spki["subjectPublicKey"].asOctets()
        oid = spki["algorithm"]["algorithm"]

        name = resources.oidutils.PQ_OID_2_NAME.get(str(oid))
        name = name or resources.oidutils.PQ_OID_2_NAME.get(oid)

        if name is None:
            raise KeyError(f"Unrecognized algorithm identifier: {oid}")

        if name.startswith("ml-dsa-"):
            hash_alg = PQ_SIG_PRE_HASH_OID_2_NAME.get(oid)
            if hash_alg is not None:
                name = name.replace("-" + name.split("-")[-1], "")

            public_key = MLDSAPublicKey(public_key=public_bytes, sig_alg=name.upper().replace("-SHA512", ""))

        elif name.startswith("slh-dsa"):
            hash_alg = PQ_SIG_PRE_HASH_OID_2_NAME.get(oid)
            if hash_alg is not None:
                name = name.replace("-" + name.split("-")[-1], "")

            public_key = SLHDSAPublicKey(public_key=public_bytes, sig_alg=name)

        elif name.startswith("ml-kem-"):
            public_key = MLKEMPublicKey(public_key=public_bytes, kem_alg=name.upper())

        elif name.startswith("falcon"):
            public_key = FalconPublicKey(sig_alg=name, public_key=public_bytes)

        elif name.startswith("mceliece"):
            public_key = McEliecePublicKey(kem_alg=name, public_key=public_bytes)

        elif name.startswith("frodokem"):
            public_key = FrodoKEMPublicKey(kem_alg=name, public_key=public_bytes)

        else:
            raise NotImplementedError(f"Unimplemented algorithm identifier: {name}")

        return public_key
