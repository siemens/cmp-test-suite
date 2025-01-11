# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Key factory to create all supported keys."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc5280, rfc5958
from resources.oid_mapping import get_curve_instance
from resources.oidutils import CMS_COMPOSITE_OID_2_NAME, PQ_OID_2_NAME, XWING_OID_STR


from pq_logic.composite_factory import CompositeKeyFactory


from pq_logic.hybrid_structures import (
    CompositeSignaturePublicKeyAsn1,
)
from pq_logic.keys.comp_sig_cms03 import (
    CompositeSigCMSPublicKey,
)
from pq_logic.keys.composite_kem_pki import parse_public_keys
from pq_logic.keys.kem_keys import MLKEMPublicKey
from pq_logic.keys.sig_keys import MLDSAPrivateKey, MLDSAPublicKey
from pq_logic.keys.xwing import XWingPrivateKey, XWingPublicKey
from pq_logic.pq_key_factory import PQKeyFactory
from pq_logic.tmp_oids import COMPOSITE_KEM_OID_2_NAME
from pq_logic.trad_key_factory import generate_trad_key


# TODO update for Chempat and other Hybrid-KEM keys.
class CombinedKeyFactory:
    """
    Factory for creating all known key types, combining traditional, post-quantum,
    and composite keys.
    """

    @staticmethod
    def generate_key(algorithm: str, **kwargs):
        """Generate a key based on the provided key type, including composite CMS keys.

        :param algorithm: The type of key to generate (e.g., "rsa", "ml-kem-768", "composite", "composite_cms").
        :param kwargs: Additional parameters required by the specific key generator.
        :return: Generated key object.
        :raises ValueError: If the key type is not supported.
        """
        if algorithm in ["rsa", "ecdsa", "ed25519", "ed448"]:
            return generate_trad_key(algorithm, **kwargs)

        if algorithm == "xwing":
            return XWingPrivateKey.generate()
        elif PQKeyFactory.may_be_pq_alg(algorithm=algorithm):
            return PQKeyFactory.generate_pq_key(algorithm=algorithm)
        elif algorithm == "composite-sig":
            return CompositeKeyFactory.generate_comp_sig_key(**kwargs)
        else:
            options = "".join(CombinedKeyFactory.list_supported_keys())
            raise ValueError(f"Unsupported key type: {algorithm} Supported are {options}")

    @staticmethod
    def load_public_key_from_spki(spki: rfc5280.SubjectPublicKeyInfo):
        """Load a public key from an SPKI structure."""
        oid = spki["algorithm"]["algorithm"]

        if oid in CMS_COMPOSITE_OID_2_NAME:
            return CompositeSigCMSPublicKey.from_spki(spki)

        if str(oid) in COMPOSITE_KEM_OID_2_NAME:
            return CombinedKeyFactory.load_composite_kem_key(spki)

        if oid in PQ_OID_2_NAME:
            return PQKeyFactory.load_public_key_from_spki(spki=spki)

        if str(oid) == XWING_OID_STR:
            subject_public_key = spki["subjectPublicKey"].asOctets()
            return XWingPublicKey.from_public_bytes(subject_public_key)


        return serialization.load_der_public_key(encoder.encode(spki))

    @staticmethod
    def load_composite_kem_key(spki: rfc5280.SubjectPublicKeyInfo):
        """Load a composite KEM public key from an SPKI structure.

        :param spki: rfc5280.SubjectPublicKeyInfo structure.
        :return: Instance of the appropriate CompositeKEMPublicKey subclass.
        """
        oid = spki["algorithm"]["algorithm"]
        alg_name = COMPOSITE_KEM_OID_2_NAME[str(oid)]

        obj, rest = decoder.decode(spki["subjectPublicKey"].asOctets(), CompositeSignaturePublicKeyAsn1())
        if rest != b"":
            raise ValueError("Extra data after decoding public key")

        pq_pub_bytes = obj[0].asOctets()
        trad_pub_bytes = obj[1].asOctets()

        if "id_MLKEM768" in alg_name:
            name = "ml-kem-768"
        else:
            name = "ml-kem-512"

        pq_pub = MLKEMPublicKey(
            public_key=pq_pub_bytes,
            kem_alg=name.upper(),
        )

        trad_key = serialization.load_der_public_key(trad_pub_bytes)
        # TODO fix for two SPKIs.
        return parse_public_keys(pq_pub, trad_key)

    @staticmethod
    def load_public_key_from_file(key_type: str, path: str):
        """Load a public key from a file"""
        raise NotImplementedError()

    @staticmethod
    def list_supported_keys():
        """List all supported key types by this factory.

        :return: List of supported key types.
        """
        # TODO fix the list of supported keys!
        return [
            "rsa",
            "ecdsa",
            "ed25519",
            "ed448",
            "ml-kem-512",
            "ml-kem-768",
            "ml-kem-1024",
            "ml-dsa-44",
            "ml-dsa-65",
            "ml-dsa-87",
            "slh-dsa",
            "composite",
            "composite_cms",
            "xwing",
        ]

    @staticmethod
    def load_key_from_one_asym_key(one_asym_key: rfc5958.OneAsymmetricKey):
        """Load a private key from a OneAsymmetricKey structure.

        :param one_asym_key: The OneAsymmetricKey structure.
        :return: The loaded private key.
        """
        from pq_logic.key_pyasn1_utils import parse_key_from_one_asym_key

        der_data = encoder.encode(one_asym_key)
        return parse_key_from_one_asym_key(der_data)

