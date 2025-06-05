<!--
Add copywrite
-->

# Tags

## Core Protocol Tags
| Tag | Description |
|-----|-------------|
| cmp | Core Certificate Management Protocol tests |
| lwcmp | Lightweight CMP protocol variant tests |
| header | Tests focusing on PKIMessage header components |
| protection | Message protection mechanism tests |
| version | Protocol version compatibility tests |

## Message Type Tags
| Tag | Description |
|-----|-------------|
| cr | Certificate Request message tests |
| ir | Initial Registration message tests |
| kur | Key Update Request message tests |
| rr | Revocation Request message tests |
| ip | Initial Response message tests |
| cp | Certification Response message tests |
| kup | Key Update Response message tests |
| crr | Certificate Response message tests |
| general-message | General message handling tests |
| support-messages | Supporting message type tests |

## Cryptographic Operation Tags
| Tag | Description |
|-----|-------------|
| crypto | General cryptographic operation tests |
| rsa | RSA cryptography specific tests |
| ecc | Elliptic Curve Cryptography tests |
| pq | Post-Quantum cryptography tests |
| ml-dsa | Multi-Layer Digital Signature Algorithm tests |
| ml-kem | Multi-Layer Key Encapsulation Mechanism tests |
| hybrid-kem | Hybrid Key Encapsulation Mechanism tests |
| mac | Message Authentication Code tests |
| signature | Digital signature related tests |

## Certificate and Key Management Tags
| Tag | Description |
|-----|-------------|
| certTemplate | Certificate template handling tests |
| key-usage | Key usage extension tests |
| extended-key-usage | Extended key usage tests |
| basic-constraints | Basic constraints extension tests |
| san | Subject Alternative Name tests |
| ca-certs | CA certificate handling tests |
| csr | Certificate Signing Request tests |
| p10cr | PKCS#10 Certificate Request tests |

## Security and Protection Tags
| Tag | Description |
|-----|-------------|
| security | General security feature tests |
| protection | Message protection tests |
| protectionAlg | Protection algorithm tests |
| popo | Proof-of-Possession tests |
| sig-popo | Signature-based Proof-of-Possession tests |
| trust | Trust relationship tests |
| sec-awareness | Security awareness tests |

## Error Handling Tags
| Tag | Description |
|-----|-------------|
| bad-behaviour | Tests for handling incorrect behavior |
| badAlg | Invalid algorithm tests |
| badPOP | Invalid Proof-of-Possession tests |
| badCertTemplate | Invalid certificate template tests |
| negative | Negative test cases |
| rejection | Request rejection handling tests |
| notAuthorized | Unauthorized access tests |

## Configuration and Setup Tags
| Tag | Description |
|-----|-------------|
| setup | Test environment setup |
| config-dependent | Configuration-dependent tests |
| policy-dependent | Policy-dependent tests |
| minimal | Minimal configuration tests |
| advanced | Advanced configuration tests |

## Message Components Tags
| Tag | Description |
|-----|-------------|
| PKIBody | Tests for PKI message body handling |
| senderNonce | Sender nonce handling tests |
| recipNonce | Recipient nonce handling tests |
| transactionId | Transaction ID handling tests |
| regToken | Registration token tests |
| raVerified | RA verification tests |

## Special Feature Tags
| Tag | Description |
|-----|-------------|
| archive | Archival-related tests |
| batching | Message batching tests |
| nested | Nested message tests |
| publication | Certificate publication tests |
| revocation | Certificate revocation tests |
| revive | Certificate revival tests |
| time | Timestamp-related tests |

## RFC Compliance Tags
| Tag | Description |
|-----|-------------|
| rfc6712 | Tests for RFC 6712 compliance |
| rfc9483-header | Tests for RFC 9483 header compliance |
| rfc9483-validation | Tests for RFC 9483 validation compliance |

## Test Management Tags
| Tag | Description |
|-----|-------------|
| smoke | Basic functionality tests |
| deprecated | Tests for deprecated features |
| robot:skip-on-failure | Tests to skip on failure |
| strict | Strict compliance tests |
