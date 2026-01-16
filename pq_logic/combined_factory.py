# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Key factory to create all supported keys."""

import base64
import logging
import textwrap
from typing import Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, load_der_public_key
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc3370, rfc5280, rfc5915, rfc5958, rfc6664, rfc8017

import pq_logic.keys.pq_stateful_sig_factory
from pq_logic.keys.abstract_pq import PQKEMPrivateKey
from pq_logic.keys.abstract_wrapper_keys import (
    HybridPrivateKey,
    HybridPublicKey,
    PQPrivateKey,
    PQPublicKey,
    TradKEMPrivateKey,
    WrapperPrivateKey,
)
from pq_logic.keys.chempat_key import ChempatPublicKey
from pq_logic.keys.composite_kem import (
    CompositeDHKEMRFC9180PrivateKey,
    CompositeDHKEMRFC9180PublicKey,
    CompositeKEMPrivateKey,
    CompositeKEMPublicKey,
)
from pq_logic.keys.composite_sig import (
    CompositeSigPrivateKey,
    CompositeSigPublicKey,
)
from pq_logic.keys.hybrid_key_factory import HybridKeyFactory
from pq_logic.keys.kem_keys import MLKEMPrivateKey
from pq_logic.keys.pq_key_factory import PQKeyFactory
from pq_logic.keys.serialize_utils import prepare_enc_key_pem
from pq_logic.keys.sig_keys import MLDSAPrivateKey, MLDSAPublicKey
from pq_logic.keys.trad_kem_keys import DHKEMPrivateKey, RSADecapKey, RSAEncapKey
from pq_logic.keys.trad_key_factory import (
    generate_trad_key,
    load_trad_public_key,
    parse_trad_key_from_one_asym_key,
    prepare_trad_private_key_one_asym_key,
)
from pq_logic.keys.xwing import XWingPrivateKey, XWingPublicKey
from pq_logic.tmp_oids import (
    CHEMPAT_OID_2_NAME,
    COMPOSITE_KEM_NAME_2_OID,
    COMPOSITE_KEM_OID_2_NAME,
    COMPOSITE_SIG_OID_TO_NAME,
    id_rsa_kem_spki,
    COMPOSITE_KEM_VERSION,
    COMPOSITE_SIG_VERSION,
)
from resources.asn1utils import try_decode_pyasn1
from resources.exceptions import BadAlg, BadAsn1Data, InvalidKeyCombination, InvalidKeyData, MismatchingKey
from resources.oid_mapping import get_curve_instance, may_return_oid_by_name
from resources.oidutils import (
    CURVE_NAMES_TO_INSTANCES,
    PQ_NAME_2_OID,
    PQ_OID_2_NAME,
    PQ_STATEFUL_HASH_SIG_OID_2_NAME,
    TRAD_STR_OID_TO_KEY_NAME,
    XWING_OID_STR,
)
from resources.suiteenums import KeySaveType
from resources.typingutils import PrivateKey, PublicKey, TradPrivateKey


def _any_string_in_string(string: str, options: List[str]) -> str:
    """Check if any of the options is in the string and return the first match.

    :param string: The string to check.
    :param options: The list of options to check for.
    :return: The first option that is in the string.
    :raises ValueError: If none of the options is in the string.
    """
    for option in options:
        if option in string:
            return option
    raise ValueError(f"Invalid key type: {string} not in {options}")


class CombinedKeyFactory:
    """Factory for creating all known key types."""

    _composite_prefixes = [f"sig-{COMPOSITE_SIG_VERSION}", f"kem-{COMPOSITE_KEM_VERSION}", f"kem{COMPOSITE_KEM_VERSION}", "dhkem", "kem", "sig"]

    @staticmethod
    def get_stateful_sig_algorithms() -> Dict[str, List[str]]:
        """Get all supported stateful signature algorithms.

        :return: List of supported stateful signature algorithms.
        """
        return pq_logic.keys.pq_stateful_sig_factory.PQStatefulSigFactory.get_algorithms_by_family()

    @staticmethod
    def _generate_composite_key_by_name(algorithm: str):
        """Generate a composite key based on the provided key type.

        :param algorithm: The type of key to generate (e.g., "composite-kem", "composite-sig", "composite-dhkem").
        :return: A generated key object.
        :raises InvalidKeyCombination: If the key type is not supported.
        """
        algorithm = algorithm.lower()
        prefix = _any_string_in_string(algorithm, CombinedKeyFactory._composite_prefixes)
        pq_name = PQKeyFactory.get_pq_alg_name(algorithm=algorithm)
        pq_key = PQKeyFactory.generate_pq_key(pq_name)

        if "-hash" in algorithm:
            algorithm = algorithm.replace("-hash", "", 1)

        rest = algorithm.replace(f"composite-{prefix}-{pq_name}-", "", 1)
        trad_name = _any_string_in_string(rest, ["rsa", "ecdsa", "ecdh", "ec", "ed25519", "ed448", "x25519", "x448"])
        rest = rest.replace(f"{trad_name}", "").replace("-pss", "").strip()

        curve = None
        length = None
        if rest.isdigit():
            length = rest
        else:
            curve = rest.replace("-", "", 1).lower() if rest else None

        trad_key = generate_trad_key(trad_name, curve=curve, length=length)
        key = CombinedKeyFactory.generate_key(
            f"composite-{prefix}",
            pq_key=pq_key,
            trad_key=trad_key,
        )

        pub_key = key.public_key()
        # RSA is only allowed as PSS for ML-DSA-87 combinations.
        if isinstance(pub_key, CompositeSigPublicKey) and trad_name.startswith("rsa"):
            _ = pub_key.get_oid(use_pss=True)
            return key

        # verify that a correct key was generated.
        # privates are allowed to be invalid for composite-sig keys, because
        # of RSA.
        pub_key.get_oid()
        return key

    @staticmethod
    def _generate_chempat_key_by_name(algorithm: str):
        """Generate a Chempat key based on the provided key type.

        :param algorithm: The type of key to generate (e.g., "chempat").
        :return: A generated key object.
        :raises ValueError: If the key type is not supported.
        """
        pq_name, trad_name_with_curve = CombinedKeyFactory.get_pq_and_trad_name_form_hybrid_name(algorithm)

        # Extract trad_name and curve from the remaining part
        trad_name = _any_string_in_string(trad_name_with_curve, ["ecdh", "x448", "x25519"])
        rest = trad_name_with_curve.replace(trad_name, "", 1)
        curve = rest.replace("-", "", 1) if rest else None

        return HybridKeyFactory.generate_hybrid_key("chempat", pq_name=pq_name, trad_name=trad_name, curve=curve)

    @staticmethod
    def generate_key_from_name(algorithm: str):
        """Generate a key based on the provided key type, including composite CMS keys.

        :param algorithm: The type of key to generate (e.g., "rsa", "ml-kem-768", "composite-kem-ml-kem-768-rsa2048").
        :return: Generated key object.
        :raises ValueError: If the key type is not supported.
        """
        if algorithm.startswith("composite"):
            return CombinedKeyFactory._generate_composite_key_by_name(algorithm)

        if algorithm.startswith("chempat") or algorithm.startswith("Chempat"):
            return CombinedKeyFactory._generate_chempat_key_by_name(algorithm)

        return CombinedKeyFactory.generate_key(algorithm)

    @staticmethod
    def get_all_kem_coms_as_dict() -> Dict[str, List[Dict]]:
        """Return all KEM composites key combinations as a dictionary.

        Enables to display all possible key combinations, or generate keys with
        in all valid combinations.

        :return: Dictionary with all KEM composites key combinations.
        """
        return HybridKeyFactory.get_all_kem_coms_as_dict()

    @staticmethod
    def generate_key(algorithm: str, **kwargs):
        """Generate a key based on the provided key type, including composite CMS keys.

        :param algorithm: The type of key to generate (e.g., "rsa", "ml-kem-768", "composite", "composite_cms").
        :param kwargs: Additional parameters required by the specific key generator.
        :return: Generated key object.
        :raises ValueError: If the key type is not supported.
        """
        if kwargs.get("by_name", False):
            return CombinedKeyFactory.generate_key_from_name(algorithm)

        if algorithm in ["rsa", "ecdsa", "ed25519", "ed448", "bad_rsa_key"]:
            return generate_trad_key(algorithm, **kwargs)

        if algorithm.startswith("xmss") or algorithm.startswith("hss"):
            return pq_logic.keys.pq_stateful_sig_factory.PQStatefulSigFactory.generate_pq_stateful_key(
                algorithm, **kwargs
            )

        if algorithm == "rsa-kem":
            trad_key = kwargs.get("trad_key") or generate_trad_key("rsa", **kwargs)
            if not isinstance(trad_key, (RSAPrivateKey, RSADecapKey)):
                raise InvalidKeyCombination("RSA-KEM requires a valid RSA or RSA-KEM private key.")
            return RSADecapKey(trad_key)

        if PQKeyFactory.may_be_pq_alg(algorithm=algorithm):
            return PQKeyFactory.generate_pq_key(algorithm=algorithm)

        if algorithm in HybridKeyFactory.supported_algorithms():
            if kwargs.get("pq_key") is not None or kwargs.get("trad_key") is not None:
                return HybridKeyFactory.from_keys(
                    algorithm=algorithm, pq_key=kwargs.get("pq_key"), trad_key=kwargs.get("trad_key")
                )
            return HybridKeyFactory.generate_hybrid_key(algorithm=algorithm, **kwargs)

        options = ", ".join(CombinedKeyFactory.supported_algorithms())
        msg = f"Unsupported key type: {algorithm}. Supported are {options}."
        raise ValueError(msg)

    @staticmethod
    def _comp_load_trad_key(
        public_key: bytes,
        trad_name: str,
        curve: Optional[str],
    ):
        """Load a traditional composite public key from the provided bytes.

        :param public_key: The public key bytes.
        :param trad_name: The traditional key type.
        :param curve: The name of the elliptic curve.
        :return: The loaded public key.
        :raises ValueError: If the traditional key type is not supported or cannot be loaded.
        """
        return load_trad_public_key(trad_name=trad_name, data=public_key, curve_name=curve)

    @staticmethod
    def _get_pq_and_trad_names(
        name: str,
    ) -> Tuple[str, str, Optional[str], Optional[str]]:
        """Get the post-quantum and traditional key names from the provided hybrid key name.

        :return: The post-quantum and traditional key names and the curve and RSA length.
        """
        # names starts with <pq_name>-<trad_name><trad_params>.
        pq_name = PQKeyFactory.get_pq_alg_name(algorithm=name)
        rest = name.replace(f"{pq_name}-", "", 1)
        trad_name = _any_string_in_string(rest, ["rsa", "ecdsa", "ecdh", "ec", "ed25519", "x25519", "x448", "ed448"])
        rest = rest.replace(f"{trad_name}", "")

        curve = None
        length = None

        if trad_name in ["ed25519", "ed448", "x25519", "x448"]:
            pass

        elif not rest.isdigit():
            curve = rest.replace("-", "") if rest else None
        else:
            length = rest

        return pq_name, trad_name, curve, length

    @staticmethod
    def _load_composite_kem07_public_key(oid: univ.ObjectIdentifier, public_key: bytes):
        """Load a composite KEM 06 public key from the provided OID and public key bytes.

        :param oid: The OID of the key.
        :param public_key: The public key bytes.
        :return: The loaded public key.
        :raises BadAsn1Data: If the public key structure is invalid or cannot be decoded.
        :raises InvalidKeyCombination: If the key is invalid or the combination is not supported.
        """
        orig_name = COMPOSITE_KEM_OID_2_NAME[oid]

        pq_name, trad_name = CombinedKeyFactory.get_pq_and_trad_name_form_hybrid_name(orig_name)
        pq_key, rest = PQKeyFactory.from_public_bytes(pq_name, public_key, allow_rest=True)

        if trad_name == "x25519":
            trad_key = X25519PublicKey.from_public_bytes(rest)
        elif trad_name == "x448":
            trad_key = X448PublicKey.from_public_bytes(rest)
        elif trad_name.startswith("ecdh-"):
            curve_name = trad_name.replace("ecdh-", "")
            curve = CURVE_NAMES_TO_INSTANCES.get(curve_name)
            if curve is None:
                raise ValueError(f"Unsupported ECDH curve: {curve_name}")
            trad_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, rest)
        elif trad_name.startswith("rsa"):
            num = int(trad_name.replace("rsa", ""))
            trad_key = load_der_public_key(rest)
            if not isinstance(trad_key, rsa.RSAPublicKey):
                raise InvalidKeyCombination(f"Expected RSA public key, but got {type(trad_key)}")
            if trad_key.key_size != num:
                raise InvalidKeyCombination(
                    f"Expected RSA key size {num}, but got {trad_key.key_size} for {trad_name}."
                )
            trad_key = RSAEncapKey(trad_key)
        else:
            raise ValueError(f"Unsupported traditional key type: {trad_name}")

        if "dhkem" not in orig_name:
            return CompositeKEMPublicKey(pq_key, trad_key)  # type: ignore
        return CompositeDHKEMRFC9180PublicKey(pq_key, trad_key)  # type: ignore

    @staticmethod
    def _load_hybrid_key_from_spki(spki: rfc5280.SubjectPublicKeyInfo):
        """Load a hybrid public key from an SPKI structure.

        :param spki: rfc5280.SubjectPublicKeyInfo structure.
        :return: The loaded hybrid public key.
        """
        oid = spki["algorithm"]["algorithm"]

        if str(oid) == XWING_OID_STR:
            return XWingPublicKey.from_public_bytes(spki["subjectPublicKey"].asOctets())

        if oid in COMPOSITE_SIG_OID_TO_NAME:
            name = COMPOSITE_SIG_OID_TO_NAME[oid]
            return CombinedKeyFactory._load_composite_sig_from_public_bytes(
                algorithm=name,
                public_key_bytes=spki["subjectPublicKey"].asOctets(),
            )

        if oid in COMPOSITE_KEM_OID_2_NAME:
            return CombinedKeyFactory._load_composite_kem07_public_key(oid, spki["subjectPublicKey"].asOctets())

        if oid in CHEMPAT_OID_2_NAME or oid in CHEMPAT_OID_2_NAME:
            return CombinedKeyFactory.load_chempat_key(spki)

        raise BadAlg(f"Unsupported hybrid key OID: {oid}")

    @staticmethod
    def load_public_key_from_spki(spki: Union[rfc5280.SubjectPublicKeyInfo, bytes]):  # type: ignore
        """Load a public key from an SPKI structure.

        :param spki: rfc5280.SubjectPublicKeyInfo structure.
        :return: The loaded public key.
        """
        if isinstance(spki, bytes):
            spki = try_decode_pyasn1(spki, rfc5280.SubjectPublicKeyInfo())[0]  # type: ignore

        spki: rfc5280.SubjectPublicKeyInfo

        oid = spki["algorithm"]["algorithm"]

        if str(oid) == XWING_OID_STR:
            return XWingPublicKey.from_public_bytes(spki["subjectPublicKey"].asOctets())

        if oid in COMPOSITE_SIG_OID_TO_NAME or oid in COMPOSITE_KEM_OID_2_NAME or oid in CHEMPAT_OID_2_NAME:
            return CombinedKeyFactory._load_hybrid_key_from_spki(spki)

        if oid in PQ_STATEFUL_HASH_SIG_OID_2_NAME:
            return pq_logic.keys.pq_stateful_sig_factory.PQStatefulSigFactory.load_public_key_from_spki(spki)

        if oid in PQ_OID_2_NAME or str(oid) in PQ_OID_2_NAME:
            return PQKeyFactory.load_public_key_from_spki(spki=spki)

        if oid == id_rsa_kem_spki:
            return RSAEncapKey.from_spki(spki)

        return serialization.load_der_public_key(encoder.encode(spki))

    @staticmethod
    def supported_algorithms():
        """List all supported key types by this factory.

        :return: List of supported key types.
        """
        trad_names = ["rsa", "ecdsa", "ed25519", "ed448", "bad-rsa-key", "x25519", "x448", "rsa-kem"]
        hybrid_names = HybridKeyFactory.supported_algorithms()
        pq_names = PQKeyFactory.supported_algorithms()
        return trad_names + pq_names + hybrid_names

    @staticmethod
    def load_chempat_key(spki: rfc5280.SubjectPublicKeyInfo):
        """Load a Chempat public key from an SPKI structure.

        :param spki: rfc5280.SubjectPublicKeyInfo structure.
        :return: Instance of the appropriate ChempatPublicKey subclass.
        :raises KeyError: If the key OID is invalid.
        """
        oid = spki["algorithm"]["algorithm"]
        alg_name = CHEMPAT_OID_2_NAME.get(oid)
        if alg_name is None:
            raise KeyError(f"Invalid Chempat key OID: {oid}")
        raw_bytes = spki["subjectPublicKey"].asOctets()
        return ChempatPublicKey.from_public_bytes(data=raw_bytes, name=alg_name)

    @staticmethod
    def _load_hybrid_public_key(name: str, public_key_bytes: Optional[bytes]) -> Optional[HybridPublicKey]:
        """Load a hybrid public key from the provided bytes.

        :param name: The name of the key.
        :param public_key_bytes: The public key bytes.
        :return: The loaded hybrid public key.
        """
        if public_key_bytes is None:
            return None

        spki = rfc5280.SubjectPublicKeyInfo()
        spki["algorithm"]["algorithm"] = may_return_oid_by_name(name)
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(public_key_bytes)
        loaded_key = CombinedKeyFactory.load_public_key_from_spki(spki=spki)

        if not isinstance(loaded_key, HybridPublicKey):
            raise InvalidKeyData("The loaded key is not a valid hybrid public key.")
        return loaded_key

    @staticmethod
    def _load_trad_private_key_from_data(name, trad_data, curve: Optional[str] = None):
        """Load a traditional private key from the provided data."""
        if name in ["x25519", "x448", "ecdh"]:
            key = DHKEMPrivateKey.from_private_bytes(name=name, data=trad_data, curve=curve)
            return key._private_key
        if name == "ed25519":
            return Ed25519PrivateKey.from_private_bytes(data=trad_data)
        if name == "ed448":
            return Ed448PrivateKey.from_private_bytes(data=trad_data)
        if name == "ecdsa":
            if curve is None:
                raise ValueError("EdDSA and EdDH curves are not provided.")

            trad_key = serialization.load_der_private_key(trad_data, password=None)
        else:
            trad_key = serialization.load_der_private_key(trad_data, password=None)

        return trad_key

    @staticmethod
    def _load_composite_kem07_from_private_bytes(algorithm: str, private_key: bytes) -> CompositeKEMPrivateKey:
        """Load a Composite KEM v7 public key from private key bytes.

        :param algorithm: The name of the algorithm.
        :param private_key: The private key bytes.
        :return: A CompositeKEMPublicKey instance.
        """
        logging.info("Loading composite KEM-%s private key: %s", COMPOSITE_KEM_VERSION, algorithm)

        pq_name, trad_name = CombinedKeyFactory.get_pq_and_trad_name_form_hybrid_name(algorithm)
        tmp_pq_key = PQKeyFactory.generate_pq_key(pq_name)

        if hasattr(tmp_pq_key, "private_numbers"):
            seed_size = len(tmp_pq_key.private_numbers())  # type: ignore
        else:
            seed_size = len(tmp_pq_key.private_bytes_raw())

        pq_data = private_key[:seed_size]
        pq_key = tmp_pq_key.from_private_bytes(pq_data, name=pq_name)
        trad_bytes = private_key[seed_size:]

        trad_key = CombinedKeyFactory._load_trad_composite_private_key(
            trad_name=trad_name,
            trad_key_bytes=trad_bytes,
            prefix=f"KEM v{COMPOSITE_KEM_VERSION}" if "dhkem" not in algorithm.lower() else f"dhkem v{COMPOSITE_KEM_VERSION}",
        )

        if not isinstance(trad_key, rsa.RSAPrivateKey):
            trad_key = DHKEMPrivateKey(private_key=trad_key, use_rfc9180=False)  # type: ignore[ArgumentError]

        if not isinstance(pq_key, PQKEMPrivateKey):
            raise InvalidKeyCombination("The composite post-quantum key is not a valid PQKEMPrivateKey.")

        if algorithm.startswith("composite-dhkem"):
            if isinstance(trad_key, RSAPrivateKey):
                raise InvalidKeyCombination("Composite-DHKEM with RSA is not supported.")

            composite_key = CompositeDHKEMRFC9180PrivateKey(
                pq_key=pq_key,
                trad_key=trad_key,
            )
        else:
            composite_key = CompositeKEMPrivateKey(
                pq_key=pq_key,
                trad_key=trad_key,
            )

        # Check if the key is valid.
        composite_key.get_oid()
        return composite_key

    @staticmethod
    def _decode_composite_kem07(
        name: str,
        private_key_bytes: bytes,
        public_key: Optional[bytes],
    ) -> CompositeKEMPrivateKey:
        """Decode a composite KEM-07 private key."""
        private_key = CombinedKeyFactory._load_composite_kem07_from_private_bytes(
            algorithm=name,
            private_key=private_key_bytes,
        )

        if public_key is not None:
            spki = rfc5280.SubjectPublicKeyInfo()
            spki["algorithm"]["algorithm"] = COMPOSITE_KEM_NAME_2_OID[name]
            spki["subjectPublicKey"] = univ.BitString.fromOctetString(public_key)
            try:
                pub_key = CombinedKeyFactory.load_public_key_from_spki(spki)
            except (ValueError, InvalidKeyData) as e:
                raise InvalidKeyData(
                    f"Failed to load public key for composite KEM-06 from `OneAsymmetricKey`: {e}"
                ) from e

            if pub_key != private_key.public_key():
                raise MismatchingKey("The composite KEM-06 public key does not match the private key.")

        return private_key

    @staticmethod
    def _load_pq_key(name: str, data: bytes) -> PQPrivateKey:
        """Load a post-quantum key from the provided bytes.

        Necessary for loading hybrid keys, to ensure that the old key loading logic and the
        new key loading logic are compatible (ML-KEM and ML-DSA keys).

        :param name: The name of the key.
        :param data: The key bytes.
        :return: The loaded post-quantum key.
        """
        pq_one_asym_key = rfc5958.OneAsymmetricKey()
        pq_one_asym_key["version"] = 0
        pq_one_asym_key["privateKeyAlgorithm"]["algorithm"] = PQ_NAME_2_OID[name]
        pq_one_asym_key["privateKey"] = data
        return PQKeyFactory.from_one_asym_key(pq_one_asym_key)

    @staticmethod
    def load_private_key_from_one_asym_key(
        data: Union[bytes, rfc5958.OneAsymmetricKey], must_be_version_2: bool = False
    ):
        """Parse a key from a OneAsymmetricKey structure.

        :param data: The OneAsymmetricKey structure or DER encoded data.
        :param must_be_version_2: If True, the key must be version 2 (include the public key). Defaults to `False`.
        :return: The loaded private key.
        :raises ValueError: If the key type is invalid.
        :raises BadAlg: If the algorithm is not supported.
        :raises InvalidKeyData: If the key data is invalid.
        :raises InvalidKeyCombination: If the key combination is invalid.
        :raises MismatchingKey: If the private key does not match the public key.
        """
        if isinstance(data, bytes):
            one_asym_key, _ = decoder.decode(data, asn1Spec=rfc5958.OneAsymmetricKey())
        else:
            one_asym_key = data

        version = int(one_asym_key["version"])
        if version not in [0, 1]:
            raise InvalidKeyData(f"Invalid `OneAsymmetricKey` version: {version}. Supported versions are 0 and 1.")

        oid = one_asym_key["privateKeyAlgorithm"]["algorithm"]
        private_bytes = one_asym_key["privateKey"].asOctets()
        public_bytes = one_asym_key["publicKey"].asOctets() if one_asym_key["publicKey"].isValue else None

        if version == 0 and public_bytes is not None:
            raise InvalidKeyData("Version 0 keys do not support public key data.")

        if oid in COMPOSITE_SIG_OID_TO_NAME:
            name = COMPOSITE_SIG_OID_TO_NAME[oid]
            return CombinedKeyFactory._load_composite_sig_key(name, private_bytes, public_bytes)

        if oid in COMPOSITE_KEM_OID_2_NAME:
            _name = COMPOSITE_KEM_OID_2_NAME[oid]
            return CombinedKeyFactory._decode_composite_kem07(_name, private_bytes, public_bytes)

        if oid == id_rsa_kem_spki:
            return RSADecapKey.from_pkcs8(one_asym_key)

        if str(oid) in TRAD_STR_OID_TO_KEY_NAME or oid == rfc6664.id_ecPublicKey:
            return parse_trad_key_from_one_asym_key(one_asym_key=one_asym_key, must_be_version_2=must_be_version_2)

        if oid in PQ_STATEFUL_HASH_SIG_OID_2_NAME:
            return pq_logic.keys.pq_stateful_sig_factory.PQStatefulSigFactory.load_private_key_from_one_asym_key(
                one_asym_key
            )

        if oid in PQ_OID_2_NAME:
            return PQKeyFactory.from_one_asym_key(one_asym_key)

        return HybridKeyFactory.from_one_asym_key(one_asym_key)

    @staticmethod
    def generate_key_from_seed(algorithm: str, seed: Union[int, bytes], curve: Optional[str] = None) -> PrivateKey:
        """Generate a key from the provided seed or private value for the given algorithm.

        :param algorithm: The type of key to generate (e.g., "rsa", "ecdsa", "x25519").
        :param seed: The seed value for key generation.
        :param curve: The name of the elliptic curve (if applicable).
        """
        if algorithm in ["ecc", "ecdsa", "ecdh", "ec"] and curve is not None and isinstance(seed, int):
            curve_inst = get_curve_instance(curve_name=curve)
            return ec.derive_private_key(curve=curve_inst, private_value=seed)

        if not isinstance(seed, bytes):
            raise ValueError(f"The seed must be a byte string, for the algorithm: {algorithm}.")

        if algorithm in ["x25519", "x448", "ecdsa", "ecc", "ed448", "ed25519"]:
            return _load_traditional_ecc_private_key(
                name=algorithm,
                private_data=seed,
            )

        if algorithm.startswith("ml-dsa") or algorithm.startswith("slh-dsa") or algorithm.startswith("ml-kem"):
            return PQKeyFactory.from_private_bytes(algorithm, seed)

        if algorithm == "xwing":
            return XWingPrivateKey.from_seed(seed)

        if algorithm == "rsa":
            return serialization.load_der_private_key(seed, password=None)

        if algorithm == "rsa-kem":
            key = serialization.load_der_private_key(seed, password=None)
            if not isinstance(key, RSAPrivateKey):
                raise InvalidKeyData("Invalid RSA KEM key")
            return RSADecapKey(key)

        raise BadAlg(f"Unknown algorithm: {algorithm}")

    @staticmethod
    def save_private_key_one_asym_key(
        private_key: PrivateKey,
        password: Optional[str] = "11111",
        public_key: Optional[PublicKey] = None,
        version: Optional[int] = None,
        save_type: Union[str, KeySaveType] = "seed",
        include_public_key: Optional[bool] = None,
        encoding: Encoding = Encoding.DER,
        invalid_private_key: bool = False,
        unsafe: bool = False,
    ) -> bytes:
        """Save a private key to DER format.

        :param private_key: The private key to save.
        :param public_key: Optional public key for hybrid keys.
        :param include_public_key: If True, include the public key in the output.
        :param password: Optional password for encryption.
        :param version: The version of the key format. Defaults to `0`.
        :param save_type: The type of key to save (e.g., "seed", "raw", "seed_and_raw").
        :param encoding: The encoding format (DER or PEM).
        :param unsafe: The PQ liboqs keys do not allow to derive the public key from the
        private key, disables the exception call. Defaults to `False`.
        :param invalid_private_key: If True, the private key is invalid, only supported for RSA,ECC and
        ML-KEM and ML-DSA keys.
        Defaults to `False`.
        :return: The DER encoded private key data.
        :raises TypeError: If the key type is not supported.
        """
        if encoding not in [Encoding.DER, Encoding.PEM]:
            raise NotImplementedError(f"Unsupported encoding: {encoding}. Only DER and PEM are supported.")

        if password is not None and encoding == Encoding.DER:
            raise NotImplementedError("Encryption is not supported for DER encoding, only for PEM.")

        if isinstance(private_key, PQPrivateKey):
            if not isinstance(public_key, PQPublicKey) and public_key is not None:
                raise InvalidKeyCombination("The public key must be a PQ public key, if provided.")

            if version is None:
                version = 1

            der_data = PQKeyFactory.save_private_key_one_asym_key(
                private_key=private_key,
                public_key=public_key,
                version=version,
                save_type=save_type,
                include_public_key=include_public_key,
                unsafe=unsafe,
                invalid_key=invalid_private_key,
            )
        elif isinstance(private_key, (TradPrivateKey, TradKEMPrivateKey)):
            if version is None:
                version = 0

            der_data = prepare_trad_private_key_one_asym_key(
                private_key=private_key,
                public_key=public_key,
                version=version,
                include_public_key=include_public_key,
                invalid_private_key=invalid_private_key,
            )
        elif isinstance(private_key, HybridPrivateKey):
            if not isinstance(public_key, HybridPublicKey) and public_key is not None:
                raise InvalidKeyCombination("The public key must be a hybrid public key, if provided.")

            if version is None:
                version = 1

            der_data = HybridKeyFactory.save_private_key_one_asym_key(
                private_key=private_key,
                public_key=public_key,
                version=version,
                save_type=save_type,
                include_public_key=include_public_key,
            )
        else:
            raise TypeError(f"Unsupported key type: {type(private_key)}")

        if isinstance(private_key, WrapperPrivateKey) and Encoding.PEM == encoding:
            header_name = private_key._get_header_name()  # pylint: disable=protected-access

        elif Encoding.DER == encoding:
            return der_data
        else:
            raise TypeError(f"Unsupported key type: {type(private_key)} for PEM encoding.")

        if password is not None:
            return prepare_enc_key_pem(password, der_data, key_name=header_name)  # pylint: disable=protected-access

        if encoding == Encoding.PEM:
            if isinstance(header_name, bytes):
                header_name = header_name.decode("ascii")

            b64_encoded = base64.b64encode(der_data).decode("ascii")
            b64_encoded = "\n".join(textwrap.wrap(b64_encoded, width=64))
            pem_str = (
                f"-----BEGIN {header_name} PRIVATE KEY-----\n{b64_encoded}\n-----END {header_name} PRIVATE KEY-----\n"
            )
            return pem_str.encode("ascii")

        return der_data

    @staticmethod
    def _validate_key_export_single(
        private_key: Union[PQPrivateKey, HybridPrivateKey],
        private_key_bytes: bytes,
        key_type: KeySaveType,
    ) -> None:
        """Validate the key export type for a single key.

        :param private_key: The private key to validate.
        :param private_key_bytes: The bytes of the private key.
        :param key_type: The type of key export (e.g., "seed", "raw", "seed_and_raw").
        :raises InvalidKeyData: If the key data is invalid.
        :raises NotImplementedError: If the key export type is not supported for that key.
        """
        if isinstance(private_key, (MLDSAPrivateKey, MLKEMPrivateKey)):
            PQKeyFactory.validate_ml_key_export_single(private_key, private_key_bytes, key_type)
            return

        if not hasattr(private_key, "private_numbers"):
            raise NotImplementedError(
                "The private key does not have private numbers.Can not determine the key export type of the key."
            )

        if not callable(getattr(private_key, "private_numbers")):
            raise NotImplementedError("The private key does not have private numbers `method`.")

        if not hasattr(private_key, "private_bytes_raw"):
            raise NotImplementedError("The private key does not have private bytes `method`.")

        if not callable(getattr(private_key, "private_bytes_raw")):
            raise NotImplementedError("The private key does not have private bytes `method`.")

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
            raise NotImplementedError(f"Unsupported key export type: {key_type.value}.")

    @staticmethod
    def validate_key_export_type(
        private_key: Union[PQPrivateKey, HybridPrivateKey],
        private_key_bytes: bytes,
        key_save_type: Union[str, KeySaveType],
    ) -> None:
        """Validate the key export type for PQ and hybrid keys.

        :param private_key: The private key to validate.
        :param private_key_bytes: The bytes of the private key.
        :param key_save_type: The type of key export (e.g., "seed", "raw", "seed_and_raw").
        :raises InvalidKeyData: If the key data is invalid.
        :raises NotImplementedError: If the key export type is not supported for that key.
        :raises TypeError: If the key type is not supported.
        """
        key_type = KeySaveType.get(key_save_type)

        if isinstance(private_key, PQPrivateKey):
            PQKeyFactory.validate_pq_key_export(private_key, private_key_bytes, key_type)
        elif isinstance(private_key, XWingPrivateKey):
            CombinedKeyFactory._validate_key_export_single(private_key, private_key_bytes, key_type)
        elif isinstance(private_key, HybridPrivateKey):
            pq_key = private_key.pq_key
            CombinedKeyFactory._validate_key_export_single(pq_key, private_key_bytes, key_type)
        else:
            raise TypeError(f"Unsupported key type: {type(private_key)}. Only PQ keys and hybrid keys are supported.")

    @staticmethod
    def get_pq_and_trad_name_form_hybrid_name(hybrid_name: str) -> Tuple[str, str]:
        """Get the PQ and traditional name for hybrid keys name (e.g., Composite, or Chempat).

        :param hybrid_name: The hybrid algorithm name to parse.
        :return: Tuple of (pq_name, trad_name).
        :raises ValueError: If the algorithm name format is not recognized.
        """
        alg = hybrid_name.lower()

        # Determine the prefix based on the algorithm name
        if alg.startswith("chempat-"):
            prefix = "chempat-"
        elif alg.startswith(f"composite-sig-{COMPOSITE_SIG_VERSION}-"):
            prefix = f"composite-sig-{COMPOSITE_SIG_VERSION}-"
        elif alg.startswith("composite-sig-"):
            prefix = "composite-sig-"
        elif alg.startswith(f"composite-kem-{COMPOSITE_KEM_VERSION}-"):
            prefix = f"composite-kem-{COMPOSITE_KEM_VERSION}-"
        elif alg.startswith(f"composite-kem{COMPOSITE_KEM_VERSION}-"):
            prefix = f"composite-kem{COMPOSITE_KEM_VERSION}-"
        elif alg.startswith("composite-dhkem-"):
            prefix = "composite-dhkem-"
        elif alg.startswith("composite-kem-"):
            prefix = "composite-kem-"
        else:
            raise NotImplementedError(f"Unsupported hybrid algorithm name format: {hybrid_name}")

        # Extract PQ algorithm name
        pq_name = PQKeyFactory.get_pq_alg_name(algorithm=alg)

        # Remove prefix and PQ name to get traditional algorithm name
        trad_name = alg.replace(prefix, "", 1).replace(pq_name + "-", "", 1)
        return pq_name, trad_name

    @staticmethod
    def _load_composite_sig_key(
        algorithm: str, private_key_bytes: bytes, public_key_bytes: Optional[bytes] = None
    ) -> HybridPrivateKey:
        """Load a composite signature key from the given bytes."""
        private_key = CombinedKeyFactory._load_composite_sig_from_private_bytes(algorithm, private_key_bytes)
        public_key = None
        if public_key_bytes is not None:
            try:
                public_key = CombinedKeyFactory._load_composite_sig_from_public_bytes(algorithm, public_key_bytes)
            except InvalidKeyData as e:
                msg = f"Failed to load composite signature public key: {e} from `OneAsymmetricKey`"
                raise InvalidKeyData(msg) from e

        if public_key is not None:
            if private_key.public_key() != public_key:
                raise MismatchingKey("The composite signature public key does not match the private key.")

        return private_key

    @staticmethod
    def _load_composite_sig_from_private_bytes(algorithm: str, private_key: bytes) -> HybridPrivateKey:
        """Load a composite signature key from private bytes."""
        pq_name, trad_name = CombinedKeyFactory.get_pq_and_trad_name_form_hybrid_name(algorithm)
        seed_size = 32
        pq_bytes, trad_bytes = private_key[:seed_size], private_key[seed_size:]
        pq_key = MLDSAPrivateKey.from_private_bytes(pq_bytes, name=pq_name)

        trad_key = CombinedKeyFactory._load_trad_composite_private_key(
            trad_name=trad_name, trad_key_bytes=trad_bytes, prefix="Sig v13"
        )

        use_pss = trad_name.endswith("-pss")
        private_key_obj = CompositeSigPrivateKey(
            pq_key=pq_key,
            trad_key=trad_key,  # type: ignore
        )

        try:
            private_key_obj.get_oid(use_pss=use_pss)
        except InvalidKeyCombination as e:
            msg = f"Invalid composite signature key combination: {e}"
            raise InvalidKeyCombination(msg) from e

        return private_key_obj

    @staticmethod
    def _try_load_ec_private_from_asn1(
        trad_key_bytes: bytes, curve_name: Optional[str] = None
    ) -> ec.EllipticCurvePrivateKey:
        """Try to load an ECDSA private key from the given bytes."""
        if curve_name is not None:
            curve = CURVE_NAMES_TO_INSTANCES.get(curve_name)
            if curve is None:
                raise ValueError(f"Unsupported ECDSA curve: {curve_name}")

        _, rest = try_decode_pyasn1(trad_key_bytes, rfc5915.ECPrivateKey())
        if rest:
            msg = f"Unexpected ECDSA private key data: {rest.hex()}"
            raise InvalidKeyData(msg)

        trad_key = serialization.load_der_private_key(trad_key_bytes, password=None)
        if not isinstance(trad_key, ec.EllipticCurvePrivateKey):
            raise InvalidKeyData(f"Expected ECDSA private key for, got: {type(trad_key)}")

        if curve_name and trad_key.curve.name.lower() != curve_name:
            raise InvalidKeyData(
                f"Expected ECDSA curve name {curve_name}, but got {trad_key.curve.name.lower()} for the key."
            )

        return trad_key

    @staticmethod
    def _load_trad_raw_key(
        name: str, trad_key_bytes: bytes
    ) -> Union[Ed448PrivateKey, Ed25519PrivateKey, X25519PrivateKey, X448PrivateKey]:
        """Load a traditional raw key from the given bytes.

        :param name: The name of the algorithm, e.g., "rsa2048-pss", "ecdsa-p256", "ed25519".
        :param trad_key_bytes: The traditional key bytes for RSA, ECDH, ECDSA, or EdDSA keys.
        :return: The loaded traditional private key.
        """
        if name == "ed448":
            return Ed448PrivateKey.from_private_bytes(trad_key_bytes)
        if name == "ed25519":
            return Ed25519PrivateKey.from_private_bytes(trad_key_bytes)
        if name == "x25519":
            return X25519PrivateKey.from_private_bytes(trad_key_bytes)
        if name == "x448":
            return X448PrivateKey.from_private_bytes(trad_key_bytes)

        raise ValueError(f"Unsupported traditional key type: {name}. Expected EdDSA or ECDH key.")

    @staticmethod
    def _load_trad_composite_private_key(
        trad_name: str, trad_key_bytes: bytes, prefix: str = "Sig v13"
    ) -> Union[
        RSAPrivateKey, Ed25519PrivateKey, Ed448PrivateKey, X25519PrivateKey, X448PrivateKey, ec.EllipticCurvePrivateKey
    ]:
        """Load a composite signature key from the given bytes.

        :param trad_name: The name of the algorithm, e.g., "rsa2048-pss".
        :param trad_key_bytes: The traditional key bytes for RSA, ECDH, ECDSA, or EdDSA keys.
        :param prefix: The prefix for the algorithm, e.g., "Sig v13".
        """
        try:
            if trad_name.startswith("ecdsa") or trad_name.startswith("ecdh"):
                return CombinedKeyFactory._try_load_ec_private_from_asn1(
                    trad_key_bytes, curve_name=trad_name.replace("ecdsa-", "").replace("ecdh-", "")
                )
            if trad_name in ["ed448", "ed25519", "x25519", "x448"]:
                return CombinedKeyFactory._load_trad_raw_key(name=trad_name, trad_key_bytes=trad_key_bytes)

            if trad_name.startswith("rsa"):
                trad_name = trad_name.replace("-pss", "")
            else:
                raise ValueError(
                    f"Unsupported traditional key type: {trad_name}. Expected RSA, ECDH, ECDSA, or EdDSA key."
                )

            _, rest = try_decode_pyasn1(trad_key_bytes, rfc8017.RSAPrivateKey())
            if rest:
                msg = (
                    f"Found trailing data for composite {prefix} traditional "
                    f"private key data. For {trad_name}: {rest.hex()}"
                )
                raise InvalidKeyData(msg)

            trad_key = serialization.load_der_private_key(trad_key_bytes, password=None)

            if not isinstance(trad_key, RSAPrivateKey):
                raise InvalidKeyData(f"Expected RSA private key for {trad_name}, got: {type(trad_key)}")

            num = int(trad_name.replace("rsa", ""))
            if num != trad_key.key_size:
                raise InvalidKeyData(f"Expected RSA key size {num}, but got {trad_key.key_size} for {trad_name}.")

            return trad_key
        except BadAsn1Data as e:
            msg = f"Failed to load traditional Composite {prefix} private key: {trad_name}. {e.message}"
            raise InvalidKeyData(msg) from e
        except ValueError as e:
            msg = f"Failed to load traditional Composite {prefix} private key: {trad_name}. {e}"
            raise InvalidKeyData(msg) from e

    @staticmethod
    def _load_composite_sig_from_public_bytes(algorithm: str, public_key_bytes: bytes) -> HybridPublicKey:
        """Load a composite signature public key from public bytes."""
        pq_name, trad_name = CombinedKeyFactory.get_pq_and_trad_name_form_hybrid_name(algorithm)
        try:
            pq_key, rest = PQKeyFactory.from_public_bytes(pq_name, public_key_bytes, allow_rest=True)
        except ValueError as e:
            raise InvalidKeyData(f"Failed to load public key for {algorithm}: {e}") from e

        try:
            if trad_name == "ed448":
                trad_key = Ed448PublicKey.from_public_bytes(rest)
            elif trad_name == "ed25519":
                trad_key = Ed25519PublicKey.from_public_bytes(rest)
            elif trad_name.startswith("ecdsa-"):
                trad_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    CURVE_NAMES_TO_INSTANCES[trad_name.replace("ecdsa-", "")],
                    rest,
                )
            else:
                _, rest_dec = decoder.decode(rest, asn1Spec=rfc3370.RSAPublicKey())
                if rest_dec:
                    raise InvalidKeyData(
                        f"Unexpected composite signature traditional private key data for {algorithm}: {rest.hex()}"
                    )
                trad_key = serialization.load_der_public_key(rest)
        except ValueError as e:
            raise InvalidKeyData(f"Failed to load public key for {algorithm}: {e}") from e

        if not isinstance(pq_key, MLDSAPublicKey):
            raise InvalidKeyData(f"Expected ML-DSA public key for {algorithm}, got: {type(pq_key)}")

        use_pss = trad_name.endswith("-pss") if trad_name.startswith("rsa") else None
        public_key = CompositeSigPublicKey(
            pq_key=pq_key,
            trad_key=trad_key,  # type: ignore[assignment]
        )
        _ = public_key.get_oid(use_pss=use_pss or trad_name.startswith("rsa"))
        return public_key


def _load_traditional_ecc_private_key(name: str, private_data: bytes, curve: Optional[str] = None):
    """Load a traditional private key from the given private key data."""
    if name in ["x25519", "x448", "ecdh"]:
        tmp_key = DHKEMPrivateKey.from_private_bytes(name, private_data, curve=curve)
        return tmp_key._private_key
    if name == "ed25519":
        return Ed25519PrivateKey.from_private_bytes(private_data)
    if name == "ed448":
        return Ed448PrivateKey.from_private_bytes(private_data)

    return serialization.load_der_private_key(private_data, password=None)
