"""Abstract factory class for creating keys, to have a common interface for different key types."""

from abc import ABC, abstractmethod
from typing import Optional

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5280, rfc5958

from resources.exceptions import InvalidKeyData, MismatchingKey
from resources.typingutils import PrivateKey, PublicKey


class AbstractKeyFactory(ABC):
    """Abstract factory class for creating keys."""

    @staticmethod
    def _get_alg_family(algs: list, alg: str) -> list:
        """Get a list of algorithms that start with the specified prefix.

        :param algs: List of all supported algorithms.
        :param alg: The algorithm prefix to filter by.
        :return: List of algorithms that start with the specified prefix.
        """
        return [a for a in algs if a.startswith(alg)]

    @staticmethod
    @abstractmethod
    def supported_algorithms() -> list:
        """Return a list of supported algorithms.

        :return: List of all supported algorithm names.
        """

    @staticmethod
    @abstractmethod
    def get_supported_keys():
        """Return a list of supported key types (names).

        :return: List of supported key types (e.g., "rsa", "ecdsa", "xmss", etc.).
        """

    @staticmethod
    @abstractmethod
    def generate_key_by_name(
        algorithm: str,
    ) -> PrivateKey:
        """Generate a key by its name (e.g., "rsa2048", "ecdsa-secp256r1", "xmssmt-sha2_20/2_256").

        :param algorithm: The name of the algorithm to generate the key for.
        :return: The generated private key object.
        """

    @staticmethod
    @abstractmethod
    def load_public_key_from_spki(spki: rfc5280.SubjectPublicKeyInfo) -> PublicKey:
        """Load a public key from a `SubjectPublicKeyInfo` structure.

        :param spki: SubjectPublicKeyInfo object.
        :return: Public key object.
        """

    @staticmethod
    def _compare_loaded_public_key(
        private_key: PrivateKey, alg_id: rfc5280.AlgorithmIdentifier, public_key: bytes
    ) -> None:
        """Compare the loaded public key with the public key of the private key.

        :param private_key: The public key object to compare.
        :param public_key: The public key bytes to compare against.
        """
        spki = rfc5280.SubjectPublicKeyInfo()
        spki["algorithm"] = alg_id
        spki["subjectPublicKey"] = public_key
        public_key = AbstractKeyFactory.load_public_key_from_spki(spki)
        if public_key != private_key.public_key():
            msg = f"Loaded public key does not match the private key. Got algorithm: {private_key.name}"
            raise MismatchingKey(msg)

    @staticmethod
    def load_private_key_from_one_asym_key(one_asym_key: rfc5958.OneAsymmetricKey) -> PrivateKey:
        """Load a private key from a `OneAsymmetricKey`.

        :param one_asym_key: The OneAsymmetricKey structure containing the private key.
        :return: The private key object.
        """
        version = one_asym_key["version"]
        if int(version) not in (0, 1):
            raise InvalidKeyData("Unsupported PKCS#8 version: {}".format(version))

        if one_asym_key["publicKey"].isValue and version == 0:
            raise InvalidKeyData("Public key is not allowed in PKCS#8 version 0.")

        private_key_bytes = one_asym_key["privateKey"].asOctets()
        public_key_bytes = one_asym_key["publicKey"].asOctets() if one_asym_key["publicKey"].isValue else None
        alg_id = one_asym_key["privateKeyAlgorithm"]["algorithm"]
        private_key = AbstractKeyFactory._load_private_key_from_pkcs8(alg_id, private_key_bytes, public_key_bytes)
        return private_key

    @staticmethod
    @abstractmethod
    def _load_private_key_from_pkcs8(
        alg_id: rfc5280.AlgorithmIdentifier,
        private_key_bytes: bytes,
        public_key_bytes: Optional[bytes] = None,
    ) -> PrivateKey:
        """Load a private key from raw PKCS#8 data.

        :param private_key_bytes: Raw bytes of the private key inside the PKCS#8 format.
        :return: Private key object.
        """

    @staticmethod
    def _export_public_key(
        public_key: PublicKey,
    ) -> bytes:
        """Export the public key in a format suitable for serialization.

        :param public_key: The public key object to export.
        :return: The public key bytes.
        """
        der_data = public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
        spki, _ = decoder.decode(der_data, rfc5280.SubjectPublicKeyInfo())
        return spki["subjectPublicKey"].asOctets()

    @staticmethod
    def _get_public_bytes(
        private_key: PrivateKey,
        public_key: Optional[PublicKey] = None,
        version: int = 1,
        include_public_key: Optional[bool] = None,
        mismatching_public_key: bool = False,
    ) -> Optional[bytes]:
        """Get the private and public key bytes from a private key object.

        :param private_key: The private key object.
        :param version: The version of the key format. Defaults to `1`.
        :param include_public_key: Whether to include the public key in the output.
        :param mismatching_public_key: If True, the public key will not match the private key.
        :return: The public key bytes.
        """
        if mismatching_public_key:
            from resources.keyutils import generate_key

            new_key = generate_key(private_key.name).public_key()
            return AbstractKeyFactory._export_public_key(new_key)

        if include_public_key is None and version == 0 and public_key is not None:
            return None

        if include_public_key is None and version == 1:
            public_key = public_key or private_key.public_key()
            return AbstractKeyFactory._export_public_key(public_key)

        if include_public_key is False:
            return None

        if include_public_key:
            public_key = public_key or private_key.public_key()
            return AbstractKeyFactory._export_public_key(public_key)

        return None

    @staticmethod
    def _prepare_one_asym_key(
        private_key: bytes,
        version: int,
        alg_id: rfc5280.AlgorithmIdentifier,
        public_key: Optional[bytes] = None,
        add_public_trailing_data: bool = False,
        add_private_trailing_data: bool = False,
    ) -> rfc5958.OneAsymmetricKey:
        """Prepare a `OneAsymmetricKey` structure with the private key and optional public key.

        :param private_key: The private key object to prepare.
        :param version: The version of the key format.
        :param alg_id: The algorithm identifier for the private key.
        :param public_key: Optional public key bytes to include in the structure.
        :param add_public_trailing_data: If True, adds trailing data to the public key.
        :param add_private_trailing_data: If True, adds trailing data to the private key.
        :return: OneAsymmetricKey structure containing the private key.
        """
        one_asym_key = rfc5958.OneAsymmetricKey()
        one_asym_key["version"] = int(version)
        one_asym_key["privateKeyAlgorithm"] = alg_id

        if public_key is not None:
            if add_public_trailing_data:
                public_key += b"\x00" * 16
            one_asym_key["publicKey"] = public_key

        if add_private_trailing_data:
            private_key += b"\x00" * 16
        one_asym_key["privateKey"] = private_key
        return one_asym_key

    @staticmethod
    def _prepare_invalid_private_key(
        private_key: PrivateKey,
    ) -> bytes:
        """Prepare an invalid private key for testing purposes.

        :param private_key: The private key object to prepare.
        :return: Invalid private key bytes.
        """
        raise NotImplementedError("This method should be overridden by subclasses.")

    @staticmethod
    def save_private_key_to_one_asym_key(
        private_key: PrivateKey,
        version: int = 1,
        include_public_key: bool = True,
        mismatching_public_key: bool = False,
        add_public_trailing_data: bool = False,
        add_private_trailing_data: bool = False,
        alg_id: Optional[rfc5280.AlgorithmIdentifier] = None,
        invalid_private_key: bool = False,
    ) -> rfc5958.OneAsymmetricKey:
        """Save a private key to a `OneAsymmetricKey` structure.

        :param private_key: The private key object to save.
        :param version: The version of the key format. Defaults to `1`.
        :param include_public_key: Whether to include the public key in the output.
        :param mismatching_public_key: If True, the public key will not match the private key.
        :param add_public_trailing_data: If True, adds trailing data to the public key.
        :param add_private_trailing_data: If True, adds trailing data to the private key.
        :param alg_id: Optional algorithm identifier to use. If not provided, it will be derived from the private key.
        :param invalid_private_key: If True, the private key will be invalid. Defaults to `False`.
        :return: OneAsymmetricKey structure containing the private key.
        """
        public_key_bytes = AbstractKeyFactory._get_public_bytes(
            private_key,
            include_public_key=include_public_key,
            version=version,
            mismatching_public_key=mismatching_public_key,
        )

        der_private_key = private_key.private_bytes(
            encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
        )
        dec_private_key = decoder.decode(der_private_key, rfc5958.OneAsymmetricKey())[0]

        if invalid_private_key:
            private_key_bytes = AbstractKeyFactory._prepare_invalid_private_key(private_key)
        else:
            private_key_bytes = dec_private_key["privateKey"].asOctets()

        alg_id = alg_id or dec_private_key["privateKeyAlgorithm"]

        return AbstractKeyFactory._prepare_one_asym_key(
            private_key=private_key_bytes,
            version=version,
            alg_id=alg_id,
            public_key=public_key_bytes,
            add_public_trailing_data=add_public_trailing_data,
            add_private_trailing_data=add_private_trailing_data,
        )
