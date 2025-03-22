<!--
SPDX-FileCopyrightText: Copyright 2024 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# Post-Quantum Cryptography Integration Documentation

### Table of Contents
1. [Design Decisions](#design-decisions)
2. [PQ Keys](#pq-keys)
    - [Adding a Key](#how-to-add-a-key)
3. [Hybrid Cryptography Key Design Overview](#hybrid-cryptography-key-design-overview)
4. [Supported Mechanisms](#supported-mechanisms)
    - [Traditional Mechanisms](#traditional)
    - [PQ Combined Mechanisms](#pq-combined)

---

### Glossary

- **OID**: Object Identifier, a standardized dot-notated string used to map objects such as algorithms.
- **KEM**: Key Encapsulation Mechanism, a method to securely transmit encryption keys.
- **MAC**: Message Authentication Code, a mechanism to ensure message integrity and authenticity.


#### Design Decisions
The design decisions follow closely the `cryptography` library for easier migration. This design ensures:
- Flexibility for users who may not wish to use `pyasn1` while still allowing PQ key usage.
- Simpler updates to existing workflows, such as creating a CSR (Certificate Signing Request).

#### Alternative Design Approach for Pre-hashing:

An alternative solution for the design of the Composite and the PQ-Keys would be
to use this approach:

```python
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import hashes

prehashed_algorithm = Prehashed(hashes.SHA256())
prehashed_algorithm._algorithm.name
```

This is the approach, which the `cryptography` library is
possible using, because the same can be done for `ECDSA`.

---

### PQ Keys
The implementation of PQ keys follows a specific set of design principles. Below are the current considerations:

- **Falcon**: If someone wants to set it up in pure python:
https://github.com/tprest/falcon.py (reason for not included: deprecated)
- **ML-DSA**: Does not support signing with context.
- **SLH-DSA**: Not yet supported, though OIDs are defined. Integration is planned for future versions.
- **FN-DSA**: Currently unstandardized and thus not considered. Updates will follow as the standard develops.
- **FrodoKem**: Uses OIDs defined by OQS.

#### How to Add a Key

To add a new key, follow these steps:

1. **Abstract Corresponding Class**:
    - For KEM, use the `PQKEMPrivateKey` class. To improve typing, consider adding a `PublicKey` class.
    - If `.public_bytes()` requires updates (e.g., for newer or unsupported versions), a RAW version can be used as an upper class.

2. **Example Implementation**:
   Define the new class within `sign_keys.py`. For instance, consider FN-DSA:

```python
class FNDSAPublicKey(PQSignaturePublicKey):
    def verify(self, data: bytes, signature: bytes, hash_alg: Optional[str] = None, ctx: Optional[bytes] = None):
        # Implement custom logic for verification
        pass

class FNDSAPrivateKey(PQSignaturePublicKey):
    def sign(self, data: bytes, hash_alg: Optional[str] = None, ctx: Optional[bytes] = None):
        # Implement custom logic for signing 
        pass

    def public_key(self) -> FNDSAPublicKey:
        return FNDSAPublicKey(self.name, self._raw_public_bytes)
```

3. **Default Encoding**:
   The default encoding of private keys has been changed to use `OneAsymmetricKey` in version 2.

4. **Add `name` Property**:
   The `name` property should support different versions of the key type, avoiding the need for a new type for every version.

---

### Hybrid Cryptography Key Design Overview

Hybrid cryptography combines traditional and post-quantum methods to enhance security. Below are key considerations:

1. **Hybrid KEM**:
    - Modern designs use EC private keys as ephemeral keys, which means these keys are not stored in the certificate.
    - The `KEMBasedMAC` class supports a structure **not** described in draft 4213bis-15 (e.g., an absent `infoValue`). This allows setting an OID to identify the hybrid method used.

2. **Custom OIDs**:
    - As Chempat does not define OIDs, custom ones are currently implemented in `customoids.py`.

---

### Supported Mechanisms

#### Traditional
The following mechanisms are supported using traditional cryptographic approaches:

- **DHKEM (ECDH)**: The ciphertext is a serialized public key.
- **DHKEM-RFC9180**: Utilizes HKDF for key derivation.
- **RSA-KEM**: Standard RSA-based key encapsulation mechanism.
- **RSA-OAEP-KEM**: Described in Composite KEM, using OAEP padding.

#### PQ Combined
The following post-quantum combined mechanisms are supported:

- **Chempat**: A hybrid cryptographic approach.
- **XWing**: Combines post-quantum KEM with traditional methods.
- **Composite KEM**: Merges traditional and PQ cryptography.
- **Composite KEM KMAC**: A variant of Composite KEM (now expired).

---


### Planned Updates
- Including FN-DSA, after the Standardization is finalized.
- Transition to standardized OIDs as they become available.
- Enhanced examples for integrating hybrid cryptography into existing workflows.

---

### Example Usage:

Please look at the `SLHDSAPrivate`, which is entirely from a different implementation.



