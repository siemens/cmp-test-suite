<!--
SPDX-FileCopyrightText: Copyright 2025 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

# Mock CA

> **Note:** *This mock CA is a simple tool to generate certificates for
> testing purposes. It is not a real CA and does not provide
> sufficient validation.*

## Overview

Mock CA is a simulated certificate authority designed for testing and
research purposes, particularly focusing on post-quantum (PQ) cryptography and hybrid certificate
issuance. The project enables the issuance, management, and revocation of certificates using a
combination of traditional and PQ cryptographic mechanisms.

As a Python/Flask-based component of the CMP Test Suite, MockCA (mainly) provides deterministic,
test-friendly responses to CMP requests. It is primarily used to:

- Run CMP and LwCMP tests without depending on a real CA backend.
- Exercise CMP features (including PQ and hybrid mechanisms) in a controlled environment.
- Provide fast iteration during test development.

### About the Mock CA

- The Mock-CA is currently only supported in the LwCMP fashion (one request at a time.)
- Supports the generation of certificates using various key types, including traditional and post-quantum keys and
  hybrid keys and mechanisms.



## Features

- **General Message Handling:** Supports CMP (Certificate Management Protocol) messages with functionalities like
    key updates, revocation passphrases, and encryption key pair type queries.
- **Certificate Request Processing:** Handles various certificate request types, including:
  - `ir` (initial registration)
  - `cr` (certificate request)
  - `p10cr` (PKCS#10 certificate request)
  - `kur` (key update request)
  - `ccr` (cross-certification request)
- **Challenge-Response Mechanism:** Implements a challenge-response system for authentication before issuing certificates,
  both the encrypted `Rand` and the encrypted certificate.
- **Hybrid Key and Certificate Support:** Enables the use of traditional, post-quantum, and hybrid key mechanisms such as:
  - ECDH (Elliptic Curve Diffie-Hellman)
  - X25519/X448 key exchange
  - Hybrid KEMs (Key Encapsulation Mechanisms)
- **Nested and Batch Processing:** Supports nested PKI messages and batch processing
  for multiple certificate requests (`ir`, `cr`, `p10cr`, `kur`, `ccr`).
- **Certificate Revocation Handling:** Manages certificate revocation lists (CRLs) and supports passphrase-based revocation.
- **Added Protection Requests:** Implements LwCMP (Lightweight CMP) protection mechanisms, including password-based MAC
  and hybrid protection.

### Missing Features

- Does not support **CRS** attributes, besides the one for extensions.
- Only supports **CA** `ccp` Cross-Certification Response.
- Does not support Announcement messages yet (Python logic is present).
- Does not support `krr` (key recovery request) messages and
  `krp` (key recovery response) messages (requires new state!)
- CMP is not yet supported (only **LwCMP**).


## Endpoints

The Mock CA exposes several HTTP endpoints. Unless noted otherwise, all POST
routes expect a DER-encoded CMP `PKIMessage` in the request body and return the
response as a DER-encoded `PKIMessage`.

The server listens on `127.0.0.1:5000` by default and exposes the following routes:

- **`/issuing`** (`POST`)
  – Handle standard CMP requests and return a `PKIMessage` with the issued certificate or an error.
- **`/chameleon`** (`POST`)
  – Processes requests for chameleon certificates.
- **`/sun-hybrid`** (`POST`)
  – Issues Sun‑Hybrid certificates using PQ and traditional keys.
- **`/multi-auth`** (`POST`)
  – Validate hybrid-protected requests using multiple certificates.
- **`/cert-discovery`** (`POST`)
  – Issues a certificate which includes the `url` of the secondary certificate.
- **`/related-cert`** (`POST`)
  – Issues a certificate related to an existing one.
- **`/catalyst-sig`** (`POST`)
  – Issues a certificate signed with a `Catalyst` alternative signature.
- **`/catalyst-issuing`** (`POST`)
  – Issues a certificate from a catalyst request with an alternative Proof-of-Possession (PoP) signature.
- **`/ocsp`** (`POST`)
  – Takes an OCSP request and returns the corresponding OCSP response.
- **`/crl`** (`GET`)
  – Returns the current certificate revocation list.
- **`/cert/<serial_number>`** (`GET`)
  – Retrieves the certificate with the specified serial number.
- **`/pubkey/<serial_number>`** (`GET`)
  – Returns the public key for the given certificate.
- **`/sig/<serial_number>`** (`GET`)
  – Returns the alternative signature for the specified Sun‑Hybrid certificate.

## Debug Error handler:

1. If the Exchange PKIMessage
   The `Exchange PKIMessage` keyword contains the error message is set there.
   Otherwise, the error message is set in the `PKIMessage` itself, it is advised to use the
   `PKIStatus Must Be` keyword to see the logged PKIStatusInfo, in human-readable format.

2. The Mock-CA runs in the `Debug` mode. But there are better not yet
   implemented methods, which are better for logging or debugging.

3. Some tests require a state and will fail, the second time, the tests are executed.

## Getting Started

To start using the Mock CA, ensure you have the necessary dependencies installed (e.g., Python version, OpenSSL, etc.).
Then follow the instructions in the [Start the CA](#start-the-ca) section below.

- The requirements are the same as for the CMP test cases.

## Example Usage

Examples are defined inside the [client.py](mock_ca/client.py) file.
If Python is not to be used, the OpenSSL command can be used instead:

```sh
OUTDIR="data/openssl_out"
mkdir -p "$OUTDIR"

# Generate key and CSR
openssl genpkey -algorithm RSA -out "$OUTDIR/new-private-key-rsa.pem" -pkeyopt rsa_keygen_bits:2048
openssl req -new -key "$OUTDIR/new-private-key-rsa.pem" -subj "/CN=Hans the Tester" -out "$OUTDIR/csr-rsa.pem"

# Send IR request with OpenSSL CMP; write outputs into $OUTDIR
openssl cmp -cmd ir \
  -server http://localhost:5000/issuing \
  -recipient "/CN=Hans the Tester" \
  -ref "CN=Hans the Tester" \
  -subject "/CN=Hans the Tester" \
  -csr "$OUTDIR/csr-rsa.pem" \
  -secret pass:SiemensIT \
  -popo 1 \
  -certout "$OUTDIR/result-cert.pem" \
  -newkey "$OUTDIR/new-private-key-rsa.pem" \
  -reqout "$OUTDIR/req-ir.pkimessage" \
  -unprotected_errors
```


### Start the CA

To start the CA, run the following command:

```sh
    make start-mock-ca
```

Alternative python command:

```sh
    python3 mock_ca/ca_handler.py
```

To test the CMP test cases, run the following command
in a second shell:

```sh
    make mock-ca-tests
```
