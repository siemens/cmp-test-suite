# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Factory class to generate and load post-quantum keys in various input formats."""

import logging
from typing import List, Optional, Tuple, Type, Union

import resources.oidutils
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5280, rfc5958
from resources.exceptions import BadAlg, InvalidKeyData
from resources.oid_mapping import may_return_oid_to_name
from resources.oidutils import (
    FRODOKEM_NAME_2_OID,
    MCELIECE_NAME_2_OID,
    PQ_NAME_2_OID,
    PQ_SIG_PRE_HASH_NAME_2_OID,
    PQ_SIG_PRE_HASH_OID_2_NAME,
)

from pq_logic.keys.abstract_wrapper_keys import PQPrivateKey, PQPublicKey
from pq_logic.keys.kem_keys import (
    FrodoKEMPrivateKey,
    FrodoKEMPublicKey,
    McEliecePrivateKey,
    McEliecePublicKey,
    MLKEMPrivateKey,
    MLKEMPublicKey,
    Sntrup761PrivateKey,
    Sntrup761PublicKey,
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


def _load_and_validate(
    private_cls: "Type[PQPrivateKey]",
    name: str,
    private_bytes: bytes,
    public_bytes: Optional[bytes],
) -> PQPrivateKey:
    """Load and validate a private key object.

    :param private_cls: The private key class.
    :param name: The name of the algorithm.
    :param private_bytes: The private key data.
    :param public_bytes: The public key data. If None, the public key is not validated.
    """
    key = private_cls.from_private_bytes(data=private_bytes, name=name)  # type: ignore

    if public_bytes:
        pub = key.public_key().from_public_bytes(data=public_bytes, name=name)

        if key.public_key() != pub:
            raise ValueError(f"{name} public key does not match the private key.")

    return private_cls(
        alg_name=name,
        private_bytes=key.private_bytes_raw(),
        public_key=public_bytes,
        seed=key._seed,  # pylint: disable=protected-access
    )


def _load_key_from_one_asym_key(
    name: str,
    private_bytes: bytes,
    public_bytes: Optional[bytes],
) -> PQPrivateKey:
    """Load a post-quantum key from a `rfc5958.OneAsymmetricKey` object.

    :param name: The name of the algorithm.
    :param private_bytes: The private key bytes.
    :param public_bytes: The public key bytes.
    :return: The post-quantum private key instance.
    :raises NotImplementedError: If the algorithm is not implemented (e.g., if the algorithm
    is not ML-DSA, SLH-DSA, or ML-KEM).
    """
    if name in PQ_SIG_PRE_HASH_NAME_2_OID:
        hash_alg = name.split("-")[-1]
        name = name.replace("-" + hash_alg, "")

    if name.startswith("ml-dsa-"):
        class_name = MLDSAPrivateKey
    elif name.startswith("slh-dsa"):
        class_name = SLHDSAPrivateKey
    elif name.startswith("ml-kem"):
        class_name = MLKEMPrivateKey
    else:
        raise NotImplementedError(f"Unimplemented algorithm: {name}")

    return _load_and_validate(class_name, name, private_bytes, public_bytes)


class PQKeyFactory:
    """Factory class for creating post-quantum keys from various input formats."""

    _prefixes = ["ml-dsa", "ml-kem", "slh-dsa", "sntrup761", "mceliece", "falcon", "frodokem"]

    _prefixes_2_pub_class = {
        "ml-dsa": MLDSAPublicKey,
        "slh-dsa": SLHDSAPublicKey,
        "ml-kem": MLKEMPublicKey,
        "sntrup761": Sntrup761PublicKey,
        "mceliece": McEliecePublicKey,
        "falcon": FalconPublicKey,
        "frodokem": FrodoKEMPublicKey,
    }

    _prefixes_2_priv_class = {
        "ml-dsa": MLDSAPrivateKey,
        "slh-dsa": SLHDSAPrivateKey,
        "ml-kem": MLKEMPrivateKey,
        "sntrup761": Sntrup761PrivateKey,
        "mceliece": McEliecePrivateKey,
        "falcon": FalconPrivateKey,
        "frodokem": FrodoKEMPrivateKey,
    }

    @staticmethod
    def get_all_kem_algs() -> List[str]:
        """Return a list of all supported post-quantum KEM algorithms."""
        return (
            ["ml-kem-512", "ml-kem-768", "ml-kem-1024", "sntrup761"]
            + list(MCELIECE_NAME_2_OID.keys())
            + list(FRODOKEM_NAME_2_OID.keys())
        )

    @staticmethod
    def get_all_callable_algs() -> List[str]:
        """Return a list of all supported post-quantum algorithms.

        Which the Test-Suite currently can generate and operate with.
        """
        return list(PQ_NAME_2_OID.keys())

    @staticmethod
    def supported_algorithms() -> List[str]:
        """Return a list of supported post-quantum algorithms."""
        return ["slh-dsa"] + PQKeyFactory.get_all_callable_algs()

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

        if algorithm in PQ_SIG_PRE_HASH_NAME_2_OID:
            hash_alg = algorithm.split("-")[-1]
            algorithm = algorithm.replace(f"-{hash_alg}", "")
            logging.info("The Test-Suite treats PQ Signature algorithms with hash algorithms as the algorithm.")

        if algorithm in ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]:
            return MLKEMPrivateKey(alg_name=algorithm)

        if algorithm.startswith("ml-dsa"):
            return MLDSAPrivateKey(alg_name=algorithm.upper())

        if algorithm == "slh-dsa" or algorithm in resources.oidutils.SLH_DSA_NAME_2_OID:
            algorithm = "slh-dsa-sha2-256s" if algorithm == "slh-dsa" else algorithm
            return SLHDSAPrivateKey(alg_name=algorithm)

        if algorithm == "sntrup761":
            return Sntrup761PrivateKey(alg_name="sntrup761")

        if algorithm.startswith("mceliece"):
            return McEliecePrivateKey(alg_name=algorithm)

        if algorithm.startswith("falcon"):
            return FalconPrivateKey(alg_name=algorithm)

        if algorithm.startswith("frodokem"):
            return FrodoKEMPrivateKey(alg_name=algorithm)

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
    def get_pq_alg_name(algorithm: str) -> str:
        """Return the full name of the post-quantum algorithm.

        :param algorithm: The algorithm name to check.
        :return: The full name of the post-quantum algorithm.
        :raises ValueError: If the algorithm name is not recognized.
        """
        for x in PQ_NAME_2_OID:
            if x in algorithm:
                return x
        raise ValueError(f"Invalid PQ algorithm name provided: '{algorithm}'.")

    @staticmethod
    def from_private_bytes(name: str, data: bytes, allow_rest: bool = False) -> Tuple[PQPrivateKey, bytes]:
        """Load a PQ private key from the given private key bytes.

        :param name: The name of the algorithm.
        :param data: The private key bytes.
        :param allow_rest: If True, allow additional data after the private key. Defaults to `False`.
        :return: The private key instance.
        """
        pq_name = PQKeyFactory.get_pq_alg_name(name)
        pq_key = PQKeyFactory.generate_pq_key(pq_name)
        key_size = pq_key.key_size

        pq_data = data[:key_size]
        key = pq_key.from_private_bytes(data=pq_data, name=pq_key.name)

        if not allow_rest and len(data) != key_size:
            raise InvalidKeyData(f"Invalid key data length, for the provided {pq_name} key.")

        return key, data[key_size:]

    @staticmethod
    def from_public_bytes(name: str, data: bytes, allow_rest: bool = False) -> Tuple[PQPublicKey, bytes]:
        """Load a PQ public key from the given public key bytes.

        :param name: The name of the algorithm.
        :param data: The public key bytes.
        :param allow_rest: If True, allow additional data after the public key. Defaults to `False`.
        :return: The public key instance.
        """
        pq_name = PQKeyFactory.get_pq_alg_name(name)
        pq_key = PQKeyFactory.generate_pq_key(pq_name)
        key_size = pq_key.public_key().key_size

        pq_data = data[:key_size]
        key = pq_key.public_key().from_public_bytes(data=pq_data, name=pq_key.name)

        if not allow_rest and len(data) != key_size:
            raise InvalidKeyData(f"Invalid key data length, for the provided {pq_name} key.")

        return key, data[key_size:]

    @staticmethod
    def from_one_asym_key(
        one_asym_key: Union[rfc5958.OneAsymmetricKey, bytes],  # type: ignore
        must_be_version_2: bool = False,
    ) -> PQPrivateKey:
        """Create a post-quantum private key from an `rfc5958.OneAsymmetricKey` object.

        Used if the `envelopedData` contained an ML-DSA keypair.

        :param one_asym_key: An `rfc5958.OneAsymmetricKey` object containing the private key information.
        :param must_be_version_2: If True, the key must be a version 2 key (public key present).
        :return: A post-quantum private key instance.

        :raises KeyError: If the algorithm identifier from the provided key is not recognized.
        """
        if isinstance(one_asym_key, bytes):
            one_asym_key = decoder.decode(one_asym_key, asn1Spec=rfc5958.OneAsymmetricKey())[0]  # type: ignore

        one_asym_key: rfc5958.OneAsymmetricKey

        if must_be_version_2 and one_asym_key["version"] != 1:
            raise ValueError("The provided key must be a version 2 key.")

        oid = one_asym_key["privateKeyAlgorithm"]["algorithm"]
        private_bytes = one_asym_key["privateKey"].asOctets()
        if one_asym_key["publicKey"].isValue:
            public_bytes = one_asym_key["publicKey"].asOctets()
        else:
            public_bytes = None

        try:
            name = resources.oidutils.PQ_OID_2_NAME.get(oid)
            if name is None:
                name = resources.oidutils.PQ_OID_2_NAME[str(oid)]
        except KeyError as err:
            _name = may_return_oid_to_name(oid)
            raise KeyError(f"Unrecognized algorithm identifier: {_name}") from err

        if _check_starts_with(name, ["ml-dsa", "slh-dsa", "ml-kem"]):
            return _load_key_from_one_asym_key(name, private_bytes, public_bytes)

        if name.startswith("falcon"):
            key = FalconPrivateKey(alg_name=name, private_bytes=private_bytes, public_key=public_bytes)

        elif name == "sntrup761":
            key = Sntrup761PrivateKey(alg_name=name, private_bytes=private_bytes, public_key=public_bytes)

        elif name.startswith("mceliece"):
            key = McEliecePrivateKey(alg_name=name, private_bytes=private_bytes, public_key=public_bytes)

        elif name.startswith("frodokem"):
            key = FrodoKEMPrivateKey(alg_name=name, private_bytes=private_bytes, public_key=public_bytes)

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

        name = resources.oidutils.PQ_OID_2_NAME.get(oid)

        if name is None:
            raise BadAlg(f"Unrecognized PQ algorithm identifier: {oid}")

        if name.startswith("ml-dsa-"):
            hash_alg = PQ_SIG_PRE_HASH_OID_2_NAME.get(oid)
            if hash_alg is not None:
                name = name.replace("-" + name.split("-")[-1], "")

            public_key = MLDSAPublicKey(public_key=public_bytes, alg_name=name.upper().replace("-SHA512", ""))

        elif name.startswith("slh-dsa"):
            hash_alg = PQ_SIG_PRE_HASH_OID_2_NAME.get(oid)
            if hash_alg is not None:
                name = name.replace("-" + name.split("-")[-1], "")

            public_key = SLHDSAPublicKey(public_key=public_bytes, alg_name=name)

        elif name.startswith("ml-kem-"):
            public_key = MLKEMPublicKey(public_key=public_bytes, alg_name=name.upper())

        elif name.startswith("falcon"):
            public_key = FalconPublicKey(alg_name=name, public_key=public_bytes)

        elif name.startswith("mceliece"):
            public_key = McEliecePublicKey(alg_name=name, public_key=public_bytes)

        elif name.startswith("frodokem"):
            public_key = FrodoKEMPublicKey(alg_name=name, public_key=public_bytes)

        elif name == "sntrup761":
            public_key = Sntrup761PublicKey(alg_name=name, public_key=public_bytes)

        else:
            raise NotImplementedError(f"Unimplemented algorithm identifier: {name}")

        if len(public_bytes) != public_key.key_size:
            raise InvalidKeyData(
                f"Invalid key data length, for the provided {name} key."
                f"Expected {public_key.key_size}, but got {len(public_bytes)}."
            )

        return public_key
