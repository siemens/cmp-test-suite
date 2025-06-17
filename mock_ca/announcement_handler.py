# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""The AnnouncementHandler for the Mock CA."""

from typing import List, Optional, Union

from pyasn1_alt_modules import rfc9480

from resources.announcement import (
    build_cmp_cann_announcement,
    build_cmp_ckuann_message,
    build_cmp_rann_announcement,
)
from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import build_cmp_krp_message
from resources.convertutils import ensure_is_sign_key
from resources.keyutils import generate_key
from resources.prepareutils import prepare_general_name_from_name
from resources.typingutils import SignKey


class AnnouncementHandler:
    """The AnnouncementHandler class."""

    def __init__(
        self,
        ca_cert: rfc9480.CMPCertificate,
        ca_key: SignKey,
        new_key: Union[str, SignKey] = "ml-dsa-44",
        new_cert: Optional[rfc9480.CMPCertificate] = None,
    ):
        """Initialize the AnnouncementHandler.

        :param ca_cert: The CA certificate.
        :param ca_key: The CA key.
        :param new_key: The new key type or algorithm.
        :param new_cert: The new certificate.
        """
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        new_key = generate_key(new_key) if isinstance(new_key, str) else new_key  # type: ignore
        self.new_key = ensure_is_sign_key(new_key)
        self.new_cert = new_cert
        self.sender = "CN=Mock CA"

    def build_ckuann(self):
        """Build the `ckuann` message."""
        return build_cmp_ckuann_message(
            old_cert=self.ca_cert,
            old_key=self.ca_key,
            new_cert=self.new_cert,
            new_key=self.new_key,
        )

    def build_cert_request_announcement(self, cert: rfc9480.CMPCertificate) -> PKIMessageTMP:
        """Build the `certRequestAnn` message.

        :param cert: The certificate to announce.
        :return: The `certRequestAnn` PKIMessage.
        """
        recipient = prepare_general_name_from_name(
            cert,
            extract_subject=False,
        )
        return build_cmp_cann_announcement(
            cert=cert,
            sender=self.sender,
            recipient=recipient,
        )

    def build_rann_announcement(
        self,
        crl: rfc9480.CertificateList,
    ) -> PKIMessageTMP:
        """Build the `crlAnn` message.

        :param crl: The CRL to announce.
        :return: The `crlAnn` PKIMessage.
        """
        return build_cmp_rann_announcement(
            crl=crl,
            sender=self.sender,
        )

    def build_krp_announcement(
        self,
        ca_certs: Optional[List[rfc9480.CMPCertificate]] = None,
        key_cert_history: Optional[List[rfc9480.CMPCertificate]] = None,
        **kwargs,
    ) -> PKIMessageTMP:
        """Build the key recovery response (krp) message.

        :param ca_certs: The CA certificates to announce.
        :param key_cert_history: The key certificate history to announce.
        :param kwargs: Additional keyword arguments.
        :return: The `krp` PKIMessage.
        """
        return build_cmp_krp_message(
            ca_certs=ca_certs,
            key_cert_history=key_cert_history,
            sender=self.sender,
            **kwargs,
        )
