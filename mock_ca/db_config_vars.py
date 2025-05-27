# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Dataclasses for configuration variables used by the MockCA."""

from abc import ABC
from dataclasses import dataclass, field, fields
from typing import Optional, Union

from resources.data_objects import KARICertsAndKeys
from resources.typingutils import SignKey


@dataclass
class ConfigVal(ABC):
    """Base class for configuration values."""

    def to_dict(self) -> dict:
        """Convert the configuration to a dictionary."""
        out = {}
        for x in fields(self):
            out[x.name] = getattr(self, x.name)
        return out


@dataclass
class CertConfConfigVars(ConfigVal):
    """Configuration variables for the certificate confirmation handler.

    Attributes
    ----------
        enforce_same_alg: If the same `MAC` algorithm should be enforced. Defaults to `True`.
        must_be_protected: If the certificate confirmation message must be protected. Defaults to `True`.
        allow_auto_ed: If automatic hash algorithm selection is allowed, for EdDSA. Defaults to `True`.
        must_be_fresh_nonce: If a fresh `nonce` must be used, for the `certConf` message. Defaults to `True`.

    """

    enforce_same_alg: bool = True
    must_be_protected: bool = True
    allow_auto_ed: bool = True
    must_be_fresh_nonce: bool = True

    def to_dict(self) -> dict:
        """Convert the configuration variables to a dictionary."""
        return {
            "enforce_same_alg": self.enforce_same_alg,
            "must_be_protected": self.must_be_protected,
            "allow_auto_ed": self.allow_auto_ed,
            "must_be_fresh_nonce": self.must_be_fresh_nonce,
        }


@dataclass
class VerifyState(ConfigVal):
    """A simple class to store the verification state.

    Attributes:
        allow_only_authorized_certs: If only authorized certificates are allowed. Defaults to `False`.
        use_openssl: If OpenSSL should be used for verification. Defaults to `False`.
        algorithms: The algorithms to use. Defaults to "ecc+,rsa, pq, hybrid".
        curves: The curves to use. Defaults to "all".
        hash_alg: The hash algorithm to use. Defaults to "all".

    """

    allow_only_authorized_certs: bool = False
    use_openssl: bool = False
    algorithms: str = "ecc+,rsa, pq, hybrid"
    curves: str = "all"
    hash_alg: str = "all"


@dataclass
class TrustConfig(ConfigVal):
    """Configuration for the trust store.

    Attributes:
        mock_ca_trusted_dir: The directory containing the trusted CA certificates.
        Defaults to "data/mock_ca/trustanchors".
        trusted_ras_dir: The directory containing the trusted RA certificates, for `raVerified`
        and nested requests. Defaults to `None`.
        trusted_cas_dir: The directory containing the trusted CA certificates for
        Cross-Certification. Defaults to `None`.

    """

    mock_ca_trusted_dir: str = "data/mock_ca/trustanchors"
    trusted_ras_dir: Optional[str] = None
    trusted_cas_dir: Optional[str] = None


@dataclass
class ProtectionHandlerConfig(ConfigVal):
    """Configuration for the ProtectionHandler.

    Attributes:
        use_openssl: Whether to use OpenSSL for verification. Defaults to `True`.
        prot_alt_key: The alternative signing key to use for hybrid signatures. Defaults to `None`.
        include_alt_sig_key: Whether to include the alternative signing key in the PKIMessage. Defaults to `True`.
        kari_certs: The KARI certificates and keys to use for `DHBasedMac` protection. Defaults to `None`.
        Defaults to "data/mock_ca/trustanchors".
        enforce_lwcmp: Whether to enforce the use of LwCMP algorithm profile RFC9483. Defaults to `False`.

    """

    pre_shared_secret: Union[bytes, str] = b"SiemensIT"
    def_mac_alg: str = "password_based_mac"
    use_openssl: bool = True
    prot_alt_key: Optional[SignKey] = None
    include_alt_sig_key: bool = True
    kari_certs: Optional[KARICertsAndKeys] = None
    enforce_lwcmp: bool = False
    trusted_config: TrustConfig = field(default_factory=TrustConfig)

    def __post_init__(self):
        """Post-initialization to ensure the pre_shared_secret is in bytes."""
        if isinstance(self.trusted_config, dict):
            # If a dictionary is passed, convert it to TrustConfig
            self.trusted_config = TrustConfig(**self.trusted_config)

    @property
    def mock_ca_trusted_dir(self) -> str:
        """Get the directory containing the trusted CA certificates."""
        return self.trusted_config.mock_ca_trusted_dir

    @property
    def trusted_ras_dir(self) -> Optional[str]:
        """Get the directory containing the trusted RA certificates."""
        return self.trusted_config.trusted_ras_dir

    @property
    def trusted_cas_dir(self) -> Optional[str]:
        """Get the directory containing the trusted CA certificates for Cross-Certification."""
        return self.trusted_config.trusted_cas_dir

    def to_dict(self) -> dict:
        """Convert the configuration to a dictionary."""
        return {
            "pre_shared_secret": self.pre_shared_secret,
            "def_mac_alg": self.def_mac_alg,
            "use_openssl": self.use_openssl,
            "prot_alt_key": self.prot_alt_key,
            "include_alt_sig_key": self.include_alt_sig_key,
            "kari_certs": self.kari_certs,
            "enforce_lwcmp": self.enforce_lwcmp,
            **self.trusted_config.to_dict(),
        }
