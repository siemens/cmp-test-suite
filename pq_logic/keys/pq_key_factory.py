# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Factory class to generate and load post-quantum keys in various input formats."""

import logging
import os
from typing import List, Optional, Tuple, Type, Union

import pyasn1
from pyasn1.codec.der import decoder, encoder
from pyasn1.error import ValueConstraintError
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5280, rfc5958

from pq_logic.hybrid_structures import (
    MLDSA44PrivateKeyASN1,
    MLDSA65PrivateKeyASN1,
    MLDSA87PrivateKeyASN1,
    MLKEM512PrivateKeyASN1,
    MLKEM768PrivateKeyASN1,
    MLKEM1024PrivateKeyASN1,
)
from pq_logic.keys.abstract_key_factory import AbstractKeyFactory
from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQSignaturePrivateKey
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
from resources.asn1utils import try_decode_pyasn1
from resources.exceptions import BadAlg, BadAsn1Data, InvalidKeyData, MismatchingKey
from resources.oid_mapping import may_return_oid_to_name
from resources.oidutils import (
    FRODOKEM_NAME_2_OID,
    MCELIECE_NAME_2_OID,
    PQ_KEM_NAME_2_OID,
    PQ_NAME_2_OID,
    PQ_OID_2_NAME,
    PQ_SIG_NAME_2_OID,
    PQ_SIG_PRE_HASH_NAME_2_OID,
    PQ_SIG_PRE_HASH_OID_2_NAME,
    SLH_DSA_NAME_2_OID,
)
from resources.suiteenums import KeySaveType


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
    :return: The private key instance.
    :raises InvalidKeyData: If the key data is invalid or does not match the expected format.
    :raises MismatchingKey: If the public key does not match the private key.
    """
    key = private_cls.from_private_bytes(data=private_bytes, name=name)  # type: ignore

    if public_bytes:
        pub = key.public_key().from_public_bytes(data=public_bytes, name=name)

        if key.public_key() != pub:
            raise MismatchingKey(f"{name} public key does not match the private key.")

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


class PQKeyFactory(AbstractKeyFactory):
    """Factory class for creating post-quantum keys from various input formats."""

    @staticmethod
    def generate_key_by_name(algorithm: str) -> PQPrivateKey:
        """Generate a post-quantum key based on the specified algorithm name.

        :param algorithm: The name of the algorithm to generate a key for (e.g., 'ml-kem-512', 'ml-dsa-44-sha512').
        """
        if algorithm in PQ_SIG_PRE_HASH_NAME_2_OID:
            hash_alg = algorithm.split("-")[-1]
            algorithm = algorithm.replace(f"-{hash_alg}", "")
        return PQKeyFactory.generate_pq_key(algorithm)

    @staticmethod
    def get_supported_keys():
        """Return a list of supported post-quantum keys."""
        return PQKeyFactory._prefixes

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

    _pq_name_2_ser_structures = {
        "ml-dsa-44": MLDSA44PrivateKeyASN1,
        "ml-dsa-65": MLDSA65PrivateKeyASN1,
        "ml-dsa-87": MLDSA87PrivateKeyASN1,
        "ml-kem-512": MLKEM512PrivateKeyASN1,
        "ml-kem-768": MLKEM768PrivateKeyASN1,
        "ml-kem-1024": MLKEM1024PrivateKeyASN1,
    }

    @staticmethod
    def _get_choice_type_and_key_data(
        data,
    ) -> Tuple[KeySaveType, Optional[bytes], Optional[bytes]]:
        """Get the choice type for the given algorithm name.

        :param data: The ML-KEM or ML-DSA structure, which contains the key data.
        :return: The save type, seed, and raw bytes.
        """
        if not data.isValue:
            raise ValueError("The provided data is not a valid ASN.1 structure.")

        seed = None
        raw_bytes = None

        type_name = data.getName()

        if type_name == "seed":
            seed = data["seed"].asOctets()
            got_type = KeySaveType.SEED
        elif type_name == "expandedKey":
            raw_bytes = data["expandedKey"].asOctets()
            got_type = KeySaveType.RAW
        elif type_name == "both":
            seed = data["both"]["seed"].asOctets()
            raw_bytes = data["both"]["expandedKey"].asOctets()
            got_type = KeySaveType.SEED_AND_RAW
        else:
            raise NotImplementedError("The provided key does not contain a valid seed or expanded key.")

        return got_type, seed, raw_bytes

    @staticmethod
    def load_ml_private_key_from_one_asym_key(
        name: str,
        private_bytes: bytes,
        public_key_bytes: Optional[bytes],
        must_be_type: Optional[KeySaveType] = None,
    ) -> Union[MLDSAPrivateKey, MLKEMPrivateKey]:
        """Load a post-quantum private key from an `rfc5958.OneAsymmetricKey` object.

        :param name: The name of the algorithm.
        :param private_bytes: The private key bytes.
        :param public_key_bytes: The public key bytes.
        :param must_be_type: The expected key save type (e.g., SEED, RAW, SEED_AND_RAW).
        :return: The loaded ML-DSA or ML-KEM private key.
        :raises NotImplementedError: If the algorithm is not implemented/invalid.
        :raises ValueError: If the key save type does not match the expected type.
        :raises InvalidKeyData: If the key data is invalid or does not match the expected format.
        :raises MismatchingKey: If the public key does not match the private key.
        """
        if name not in PQKeyFactory._pq_name_2_ser_structures:
            raise NotImplementedError(f"Unimplemented algorithm: {name}. For loading a Choice ML-DSA or ML-KEM key.")

        structure = PQKeyFactory._pq_name_2_ser_structures[name]
        data, rest = decoder.decode(private_bytes, asn1Spec=structure())

        if rest:
            class_name = type(data).__name__
            raise InvalidKeyData(BadAsn1Data(class_name).message)

        got_type, seed, raw_bytes = PQKeyFactory._get_choice_type_and_key_data(data)

        if got_type != must_be_type and must_be_type is not None:
            raise ValueError(f"Invalid key save type. Expected: {must_be_type}, Got: {got_type}.")

        if name.startswith("ml-dsa-"):
            class_name = MLDSAPrivateKey
        else:
            class_name = MLKEMPrivateKey

        if seed is not None and raw_bytes is not None:
            key = class_name.from_private_bytes(name=name, data=seed)
            key2 = class_name.from_private_bytes(name=name, data=raw_bytes)

            if key != key2:
                raise MismatchingKey(f"{name} private key does not match the seed and raw bytes.")

        elif seed is not None:
            key = class_name.from_private_bytes(name=name, data=seed)

        else:
            if raw_bytes is None:
                raise NotImplementedError("The if case is not possible, if both are None.")

            key = class_name.from_private_bytes(name=name, data=raw_bytes)

        if public_key_bytes is not None:
            pub = key.public_key().from_public_bytes(data=public_key_bytes, name=name)

            if key.public_key() != pub:
                raise MismatchingKey(f"{name} public key does not match the private key.")

        return key

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
    def generate_pq_kem_key(algorithm: str) -> PQKEMPrivateKey:
        """Generate a post-quantum KEM private key based on the specified algorithm.

        :param algorithm: The algorithm name, which can be one of the following:
                          - For ML-KEM: 'ml-kem-512', 'ml-kem-768', 'ml-kem-1024'.
                          - For Sntrup761: 'sntrup761'.
                          - For McEliece: 'mceliece-xxx'.
                          - For FrodoKEM: 'frodokem-xxx'.
        :return: An instance of `MLKEMPrivateKey`, `Sntrup761PrivateKey`, `McEliecePrivateKey`, or `FrodoKEMPrivateKey`
                 depending on the algorithm.
        """
        if algorithm in ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]:
            pq_kem_key = MLKEMPrivateKey(alg_name=algorithm)

        elif algorithm == "sntrup761":
            pq_kem_key = Sntrup761PrivateKey(alg_name="sntrup761")

        elif algorithm.startswith("mceliece"):
            pq_kem_key = McEliecePrivateKey(alg_name=algorithm)

        elif algorithm.startswith("frodokem"):
            pq_kem_key = FrodoKEMPrivateKey(alg_name=algorithm)

        else:
            raise ValueError(f"Invalid algorithm name provided: '{algorithm}'.")

        return pq_kem_key

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

        if algorithm.startswith("ml-dsa"):
            return MLDSAPrivateKey(alg_name=algorithm.upper())

        if algorithm == "slh-dsa" or algorithm in SLH_DSA_NAME_2_OID:
            algorithm = "slh-dsa-sha2-256s" if algorithm == "slh-dsa" else algorithm
            return SLHDSAPrivateKey(alg_name=algorithm)

        if algorithm in PQKeyFactory.get_all_kem_algs():
            return PQKeyFactory.generate_pq_kem_key(algorithm)

        if algorithm.startswith("falcon"):
            return FalconPrivateKey(alg_name=algorithm)

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
    def from_private_bytes(name: str, data: bytes) -> PQPrivateKey:
        """Load a PQ private key from the given private key bytes.

        :param name: The name of the algorithm.
        :param data: The private key bytes or seed or both.
        :return: The private key instance.
        """
        pq_name = PQKeyFactory.get_pq_alg_name(name)
        pq_key = PQKeyFactory.generate_pq_key(pq_name)
        key_size = pq_key.key_size
        pq_data = data[:key_size]
        key = pq_key.from_private_bytes(data=pq_data, name=pq_key.name)
        return key

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
    def _load_private_kem_key(
        name: str, private_key_bytes: bytes, public_key_bytes: Optional[bytes] = None
    ) -> PQKEMPrivateKey:
        """Load a post-quantum KEM private key from the given bytes.

        :param name: The name of the algorithm.
        :param private_key_bytes: The private key bytes.
        :param public_key_bytes: Optional public key bytes. If provided, it will be validated against the private key.
        :return: The post-quantum KEM private key instance.
        """
        if name.startswith("ml-kem-"):
            private_key = MLKEMPrivateKey.from_private_bytes(data=private_key_bytes, name=name)
            if public_key_bytes:
                if private_key_bytes != private_key.public_key().public_bytes_raw():
                    raise MismatchingKey(f"{name} public key does not match the private key.")
            return private_key
        elif name.startswith("sntrup761"):
            private_key = Sntrup761PrivateKey.from_private_bytes(data=private_key_bytes, name=name)
        elif name.startswith("mceliece"):
            private_key = McEliecePrivateKey.from_private_bytes(data=private_key_bytes, name=name)
        elif name.startswith("frodokem"):
            private_key = FrodoKEMPrivateKey.from_private_bytes(data=private_key_bytes, name=name)
        else:
            raise NotImplementedError(f"Unimplemented algorithm: {name}")

        if public_key_bytes:
            private_key._public_key_bytes = public_key_bytes  # pylint: disable=protected-access
        return private_key

    @staticmethod
    def _load_private_sig_key(
        name: str, private_key_bytes: bytes, public_key_bytes: Optional[bytes] = None
    ) -> PQSignaturePrivateKey:
        """Load a post-quantum signature private key from the given bytes.

        :param name: The name of the algorithm.
        :param private_key_bytes: The private key bytes.
        :param public_key_bytes: Optional public key bytes. If provided, it will be validated against the private key.
        :return: The post-quantum signature private key instance.
        """
        if name.startswith("ml-dsa-"):
            private_key = MLDSAPrivateKey.from_private_bytes(data=private_key_bytes, name=name)
            if public_key_bytes:
                if private_key_bytes != private_key.public_key().public_bytes_raw():
                    raise MismatchingKey(f"{name} public key does not match the private key.")
        elif name.startswith("slh-dsa"):
            private_key = SLHDSAPrivateKey.from_private_bytes(data=private_key_bytes, name=name)
            if public_key_bytes:
                if private_key_bytes != private_key.public_key().public_bytes_raw():
                    raise MismatchingKey(f"{name} public key does not match the private key.")

        elif name.startswith("falcon"):
            _ = FalconPrivateKey.from_private_bytes(data=private_key_bytes, name=name)
            return FalconPrivateKey(alg_name=name, private_bytes=private_key_bytes, public_key=public_key_bytes)
        else:
            raise NotImplementedError(f"Unimplemented algorithm: {name}")
        return private_key

    @staticmethod
    def _load_private_key_from_pkcs8(
        alg_id: rfc5280.AlgorithmIdentifier, private_key_bytes: bytes, public_key_bytes: Optional[bytes] = None
    ) -> PQPrivateKey:
        """Load a private key from raw PKCS.

        :param alg_id: The AlgorithmIdentifier containing the algorithm OID.
        :param private_key_bytes: The raw bytes of the private key.
        :param public_key_bytes: Optional raw bytes of the public key.
        """
        alg_name = PQ_OID_2_NAME.get(alg_id["algorithm"])
        if alg_name is None:
            raise BadAlg(f"Unsupported algorithm OID: {alg_id['algorithm']}")

        if alg_name in PQ_KEM_NAME_2_OID:
            return PQKeyFactory._load_private_kem_key(
                name=alg_name,
                private_key_bytes=private_key_bytes,
                public_key_bytes=public_key_bytes,
            )
        if alg_name in PQ_SIG_NAME_2_OID:
            return PQKeyFactory._load_private_sig_key(
                name=alg_name,
                private_key_bytes=private_key_bytes,
                public_key_bytes=public_key_bytes,
            )
        raise NotImplementedError(f"Unrecognized algorithm identifier: {alg_name}")

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
        :raises InvalidKeyData: If the key data is invalid or does not match the expected format.
        :raises KeyError: If the algorithm identifier from the provided key is not recognized.
        :raises ValueError: If the key is not a version 2 key and `must_be_version_2` is True.
        :raises NotImplementedError: If the algorithm is not implemented.
        :raises MismatchingKey: If the public key does not match the private key, or the seed, does not
        match the raw bytes.
        """
        if isinstance(one_asym_key, bytes):
            one_asym_key = decoder.decode(one_asym_key, asn1Spec=rfc5958.OneAsymmetricKey())[0]  # type: ignore

        one_asym_key: rfc5958.OneAsymmetricKey

        version = int(one_asym_key["version"])
        if version not in [0, 1]:
            raise InvalidKeyData(f"Invalid `OneAsymmetricKey` version: {version}. Supported versions are 0 and 1.")

        if must_be_version_2 and one_asym_key["version"] != 1:
            raise ValueError("The provided key must be a version 2 key.")

        oid = one_asym_key["privateKeyAlgorithm"]["algorithm"]
        private_bytes = one_asym_key["privateKey"].asOctets()
        if one_asym_key["publicKey"].isValue:
            public_bytes = one_asym_key["publicKey"].asOctets()
        else:
            public_bytes = None

        try:
            name = PQ_OID_2_NAME.get(oid)
            if name is None:
                name = PQ_OID_2_NAME[str(oid)]
        except KeyError as err:
            _name = may_return_oid_to_name(oid)
            raise KeyError(f"Unrecognized algorithm identifier: {_name}") from err

        try:
            if name.startswith("ml-kem-") or name.startswith("ml-dsa-"):
                return PQKeyFactory.load_ml_private_key_from_one_asym_key(
                    name=name,
                    private_bytes=private_bytes,
                    public_key_bytes=public_bytes,
                )

        except ValueConstraintError as e:
            raise InvalidKeyData(f"Invalid key data for {name} algorithm.") from e

        except pyasn1.error.PyAsn1Error:
            pass

        if _check_starts_with(name, ["ml-dsa", "slh-dsa", "ml-kem"]):
            return _load_key_from_one_asym_key(name, private_bytes, public_bytes)

        key = PQKeyFactory._load_private_key_from_pkcs8(
            alg_id=one_asym_key["privateKeyAlgorithm"],
            private_key_bytes=private_bytes,
            public_key_bytes=public_bytes,
        )

        return key

    @staticmethod
    def load_pq_kem_public_key_from_spki(
        public_bytes: bytes,
        name: str,
    ) -> Union[MLKEMPublicKey, Sntrup761PublicKey, McEliecePublicKey, FrodoKEMPublicKey]:
        """Load a post-quantum KEM public key from the given bytes.

        :param public_bytes: The public key bytes.
        :param name: The algorithm name.
        :return: The post-quantum KEM public key instance.
        """
        if name.startswith("ml-kem-"):
            public_key = MLKEMPublicKey(public_key=public_bytes, alg_name=name.upper())

        elif name.startswith("mceliece"):
            public_key = McEliecePublicKey(alg_name=name, public_key=public_bytes)

        elif name.startswith("frodokem"):
            public_key = FrodoKEMPublicKey(alg_name=name, public_key=public_bytes)

        elif name == "sntrup761":
            public_key = Sntrup761PublicKey(alg_name=name, public_key=public_bytes)

        else:
            raise NotImplementedError(f"Unimplemented pq-kem algorithm: {name}")

        return public_key

    @staticmethod
    def load_public_key_from_spki(spki: rfc5280.SubjectPublicKeyInfo):
        """Load a public key from a given `SubjectPublicKeyInfo` (spki) structure.

        :param spki: An `rfc5280.SubjectPublicKeyInfo` object containing the public key.
        :return: An instance of `MLKEMPublicKey` or `MLDSAPublicKey`.
        :raises InvalidKeyData: If the SPKI Algorithm parameters are present for PQ algorithms
        or the key data length is invalid.
        :raises BadAlg: If the algorithm identifier from the SPKI is not recognized.
        """
        public_bytes = spki["subjectPublicKey"].asOctets()
        oid = spki["algorithm"]["algorithm"]

        name = PQ_OID_2_NAME.get(oid)

        if name is None:
            raise BadAlg(f"Unrecognized PQ algorithm identifier: {oid}")

        if spki["algorithm"]["parameters"].isValue:
            raise InvalidKeyData(
                f"The SPKI Algorithm parameters MUST be absent for PQ algorithms,but was present for {name}."
            )

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

        elif name.startswith("falcon"):
            public_key = FalconPublicKey(alg_name=name, public_key=public_bytes)

        elif name in PQKeyFactory.get_all_kem_algs():
            public_key = PQKeyFactory.load_pq_kem_public_key_from_spki(
                public_bytes=public_bytes,
                name=name,
            )

        else:
            raise NotImplementedError(f"Unimplemented algorithm identifier: {name}")

        if len(public_bytes) != public_key.key_size:
            raise InvalidKeyData(
                f"Invalid key data length, for the provided {name} key."
                f"Expected {public_key.key_size}, but got {len(public_bytes)}."
            )

        return public_key

    @staticmethod
    def _prepare_ml_private_key(
        private_key: Union[MLKEMPrivateKey, MLDSAPrivateKey],
        save_type: KeySaveType = KeySaveType.SEED,
        invalid_key: bool = False,
    ) -> bytes:
        """Prepare the private key for ML-DSA or ML-KEM.

        :param private_key: The private key to be saved.
        :param save_type: The type of key to save. Defaults to `KeySaveType.SEED`.
        :return: The private key in ASN.1 format.
        """
        structure = PQKeyFactory._pq_name_2_ser_structures[private_key.name]()

        to_add = os.urandom(4) if invalid_key else b""

        if save_type == KeySaveType.SEED:
            structure["seed"] = private_key.private_numbers() + to_add
        elif save_type == KeySaveType.SEED_AND_RAW:
            structure["both"]["seed"] = private_key.private_numbers()
            if not invalid_key:
                structure["both"]["expandedKey"] = private_key.private_bytes_raw()
            else:
                structure["both"]["expandedKey"] = os.urandom(private_key.key_size)
        elif save_type == KeySaveType.RAW:
            structure["expandedKey"] = private_key.private_bytes_raw() + to_add
        else:
            raise ValueError(f"Invalid key save type: {save_type}")

        return encoder.encode(structure)

    @staticmethod
    def save_keys_with_support_seed(
        private_key: PQPrivateKey,
        key_type: KeySaveType,
        invalid_key: bool = False,
    ) -> bytes:
        """Save the private key in a format that supports the seed.

        :param private_key: The private key to be saved.
        :param key_type: The type of key to save. Can be one of the following
            - "seed": Save the seed.
            - "raw": Save the private key.
            - "seed_and_raw": Save the seed and the private key.
        :param invalid_key: If True, the key will be saved in an invalid format.
        :return: The private key in ASN.1 format.
        """
        if isinstance(private_key, (MLDSAPrivateKey, MLKEMPrivateKey)):
            return PQKeyFactory._prepare_ml_private_key(private_key, key_type, invalid_key)

        if isinstance(private_key, SLHDSAPrivateKey):
            if key_type == KeySaveType.SEED:
                return private_key.private_numbers()
            if key_type == KeySaveType.SEED_AND_RAW:
                return private_key.private_numbers() + private_key.private_bytes_raw()

        return private_key.private_bytes_raw()

    @staticmethod
    def _may_get_pub_key(
        private_key: PQPrivateKey,
        public_key: Optional[PQPublicKey],
        include_pub_key: Optional[bool] = True,
        version: int = 1,
        unsafe: bool = False,
    ) -> Optional[bytes]:
        """May get the public key from the private key.

        :param private_key: The private key to be saved.
        :param public_key: The public key to be included in the `OneAsymmetricKey` object. Defaults to `None`.
        :param include_pub_key: If True, include the public key in the `OneAsymmetricKey` object. Used
        for negative testing. Defaults to `None` will be determined by the version.
        :param version: The version of the `OneAsymmetricKey` object. Defaults to `1`.
        :param unsafe: The PQ liboqs keys do not allow one to derive the public key from the
        private key, disables the exception call. Defaults to `False`.
        :raise NotImplementedError: Version 1 is not supported for `liboqs` keys.
        """
        # safety check, because the public key cannot be generated from the private key
        # if the private key is a `liboqs` key.
        if not isinstance(private_key, (MLDSAPrivateKey, MLKEMPrivateKey, SLHDSAPrivateKey)):
            if version == 0 or include_pub_key == False and not unsafe:  # noqa: E712
                raise NotImplementedError("The `OneAsymmetricKey` version 1 is not supported for a `liboqs` keys.")

        if include_pub_key:
            public_key = private_key.public_key()
            return public_key.public_bytes_raw()

        if version == 1:
            public_key = public_key or private_key.public_key()
            return public_key.public_bytes_raw()

        return None

    @staticmethod
    def save_private_key_one_asym_key(
        private_key: PQPrivateKey,
        public_key: Optional[PQPublicKey] = None,
        version: int = 1,
        save_type: Union[KeySaveType, str] = "seed",
        include_public_key: Optional[bool] = True,
        unsafe: bool = False,
        invalid_key: bool = False,
    ) -> bytes:
        """Load the private key into a `OneAsymmetricKey` object.

        :param private_key: The private key to be saved.
        :param version: The version of the `OneAsymmetricKey` object. Defaults to 1.
        :param include_public_key: If True, include the public key in the `OneAsymmetricKey` object.
        Used for negative testing. Defaults to `None` will be determined by the version.
        :param public_key: The public key to be included in the `OneAsymmetricKey` object. Defaults to `None`.
        :param save_type: The type of key to save. Can be one of the following:
            - "seed": Save the seed.
            - "raw": Save the private key.
            - "seed_and_raw": Save the seed and the private key.
        :param unsafe: The PQ liboqs keys do not allow one to derive the public key from the
        private key, disables the exception call. Defaults to `False`.
        :param invalid_key: If True, the key will be saved in an invalid for ML-DSA or ML-KEM keys.
        Defaults to `False`.
        :return: The DER-encoded `OneAsymmetricKey` object.
        :raises NotImplementedError: Version 1 is not supported for `liboqs` keys.
        """
        key_type = KeySaveType.get(save_type)

        one_asym_key = rfc5958.OneAsymmetricKey()
        one_asym_key["version"] = version
        one_asym_key["privateKeyAlgorithm"]["algorithm"] = private_key.get_oid()

        private_key_bytes = PQKeyFactory.save_keys_with_support_seed(private_key, key_type, invalid_key)
        one_asym_key["privateKey"] = private_key_bytes

        public_key_bytes = PQKeyFactory._may_get_pub_key(
            private_key,
            public_key,
            include_public_key,
            version=version,
            unsafe=unsafe,
        )

        if public_key_bytes is not None:
            public_key_asn1 = univ.BitString(hexValue=public_key_bytes.hex()).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            )
            one_asym_key["publicKey"] = public_key_asn1

        der_data = encoder.encode(one_asym_key)
        return der_data

    @staticmethod
    def validate_ml_key_export_single(
        private_key: Union[MLDSAPrivateKey, MLKEMPrivateKey],
        private_key_bytes: bytes,
        key_type: KeySaveType,
    ) -> None:
        """Validate the key export type for a single ML key.

        :param private_key: The private key to validate.
        :param private_key_bytes: The bytes of the private key.
        :param key_type: The type of key export (e.g., "seed", "raw", "seed_and_raw").
        :raises InvalidKeyData: If the key data is invalid.
        """
        name = private_key.name
        if name not in PQKeyFactory._pq_name_2_ser_structures:
            raise NotImplementedError(f"Unimplemented algorithm: {name}. For loading a Choice ML-DSA or ML-KEM key.")
        structure = PQKeyFactory._pq_name_2_ser_structures[name]
        data, rest = try_decode_pyasn1(private_key_bytes, structure())  # type: ignore
        data: univ.Choice

        if rest:
            raise InvalidKeyData(BadAsn1Data(type(data).__name__).message)

        if not data.isValue:
            raise ValueError("The provided data is not a valid ASN.1 structure.")

        got_type, seed, raw_bytes = PQKeyFactory._get_choice_type_and_key_data(data)
        if got_type != key_type:
            raise InvalidKeyData(f"Invalid key save type. Expected: {key_type}, Got: {got_type}.")

        if seed != private_key.private_numbers() and seed is not None:
            raise InvalidKeyData("The private key bytes do not match the private key data, for type `seed`.")

        if raw_bytes != private_key.private_bytes_raw() and raw_bytes is not None:
            raise InvalidKeyData("The private key bytes do not match the private key data, for type `raw`.")

    @staticmethod
    def validate_pq_key_export(
        private_key: PQPrivateKey,
        private_key_bytes: bytes,
        key_type: KeySaveType,
    ) -> None:
        """Validate the key export type for a post-quantum key.

        :param private_key: The private key to validate.
        :param private_key_bytes: The bytes of the private key.
        :param key_type: The type of key export (e.g., "KeySaveType.SEED",
        KeySaveType.RAW", "KeySaveType.SEED_AND_RAW").
        :raises ValueError: If the ML key export type is invalid.
        :raises NotImplementedError: If the algorithm is not implemented.
        :raises InvalidKeyData: If the key data is invalid.
        """
        if isinstance(private_key, (MLDSAPrivateKey, MLKEMPrivateKey)):
            PQKeyFactory.validate_ml_key_export_single(private_key, private_key_bytes, key_type)

        elif isinstance(private_key, SLHDSAPrivateKey):
            if key_type == KeySaveType.SEED:
                if private_key_bytes != private_key.private_numbers():  # type: ignore
                    raise InvalidKeyData("The private key bytes do not match the private key data, for type `seed`.")

            elif key_type == KeySaveType.SEED_AND_RAW:
                data = private_key.private_numbers() + private_key.private_bytes_raw()  # type: ignore
                if private_key_bytes != data:
                    raise InvalidKeyData(
                        "The private key bytes do not match the private key data, for type `seed_and_raw`."
                    )

            elif key_type == KeySaveType.RAW:
                if private_key_bytes != private_key.private_bytes_raw():  # type: ignore
                    raise InvalidKeyData("The private key bytes do not match the private key data, for type `raw`.")

        else:
            if key_type != KeySaveType.RAW:
                raise NotImplementedError(
                    f"Unimplemented algorithm: {private_key.name}. Can only compare the raw bytes for the key."
                )

            if private_key_bytes != private_key.private_bytes_raw():
                raise InvalidKeyData(f"Invalid key data, for the provided {private_key.name} key.")
