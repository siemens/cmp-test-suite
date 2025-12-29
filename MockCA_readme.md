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

### Mock CA Repository Structure

- **Implementation:** [`mock_ca/`](./mock_ca)
- **MockCA test suites:** [`tests_mock_ca/`](./tests_mock_ca)
- **MockCA test environment settings:** [`config/mock_ca.robot`](config/mock_ca.robot)
- **Test documentation (generated):** `doc/test-mock-ca.html` via `make docs`

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

## Prerequisites & Installation

### System Requirements

MockCA uses the same runtime dependencies as the CMP test suite.

- **Python:** Python 3.x (same as the CMP test suite).
- **Python packages:** Install the shared dependencies with:

```sh
  pip install -r requirements.txt
  ```

This includes **Flask** for the MockCA HTTP server.
- **Requires liboqs-python** for post-quantum and hybrid key support. Can be installed via with the
  [setup_pq.sh](scripts/setup_pq.sh) file.
- **OpenSSL** for the example CLI requests and for certificate validation helpers.
- **Optional:**
  - **Robot Framework** is included in [requirements.txt](requirements.txt) and is needed to run the test suites, but not the MockCA itself.

### Installation Steps

#### Install dependencies

From the repository root:

```sh
python3 -m venv venv-cmp-tests
source venv-cmp-tests/bin/activate
pip install -r requirements.txt
```

Verify the key runtime tools:

```sh
python3 --version
flask --version
```

If you plan to use OpenSSL for the example CMP requests:

```sh
openssl version
openssl cmp -help
```

To build the docker container, have a look at the **[Dockerfile.mockca](data/dockerfiles/Dockerfile.mockca)**.

## Running the Mock CA

### Configuration assumptions

> Note: Https is not supported yet, for the easiness of the test suite. This would be needed to be set
> up by the user himself.

The default configuration assumes:

- MockCA listens on `http://127.0.0.1:5000` by default.
- The CMP issuing endpoint is `http://127.0.0.1:5000/issuing`.
- The Robot Framework tests select MockCA via `--variable environment:mock_ca`, which loads
  `config/mock_ca.robot`.

These defaults are defined in `mock_ca/ca_handler.py` (host/port defaults) and `config/mock_ca.robot` (CMP URLs and
shared secret). Update the config or pass `--host`/`--port` as needed.

You can verify the default URLs in `config/mock_ca.robot`:

```robot
${PORT}    5000
${CA_BASE_URL}   http://127.0.0.1:${PORT}/
${CA_CMP_URL}    http://127.0.0.1:${PORT}/issuing
```

#### Request routing

All CMP requests are sent to `${CA_CMP_URL}` (default `/issuing`).
Specialized endpoints used by certain tests are configured via the suffix variables in
`config/mock_ca.robot` (for example `${SUN_HYBRID_SUFFIX}`, `${CHAMELEON_SUFFIX}`, `${CATALYST_ISSUING}`).

### Start the CA

To start the CA, run the following command:

```sh
    make start-mock-ca
```

Alternative python command:

```sh
    python3 mock_ca/ca_handler.py --port 5000
```

To test the CMP test cases, run the following command
in a second shell:

```sh
    make test env=mock_ca
```

#### Expected output

You should see Flask startup output similar to:

- Serving Flask app 'mock_ca.ca_handler'
- Debug mode: on
- Running on <http://127.0.0.1:5000>

### Verify MockCA is running

The simplest verification is checking the CRL endpoint:

```sh
curl -v http://127.0.0.1:5000/crl -o /tmp/mockca.crl
```

A `200 OK` response and a non-empty `/tmp/mockca.crl` confirm the server is responding.

To run an example CMP request against the MockCA, see the
[OpenSSL Example Usage](#openssl-cli) section below or have a look at the example script: [client.py](mock_ca/client.py).

### Required configuration changes

The test suite selects MockCA by passing the environment variable `environment:mock_ca`, which loads
`config/mock_ca.robot`. You typically do **not** need to edit any files to use the default MockCA settings.

Key variables in `config/mock_ca.robot` include:

- `${CA_BASE_URL}` and `${CA_CMP_URL}` — base and issuing CMP endpoints.
- `${PRESHARED_SECRET}` — shared secret for MAC-based protection (`SiemensIT` by default).
- `${LWCMP}` — enables LwCMP mode.

### Key material and certificates

MockCA uses local test keys and certificates referenced in `config/mock_ca.robot` (for example
`data/mock_ca/device_cert_ecdsa_cert_chain.pem`, `data/keys/private-key-ecdsa.pem`, and other files
under `data/`). No external CA material is required for the default configuration.

If you update any paths in `config/mock_ca.robot`, ensure the referenced files exist.

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

## Example Usage

### OpenSSL CMP Request Example

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

### Robot Framework Test

```sh
robot --pythonpath=./ --exclude verbose-tests --outputdir=reports --variable environment:mock_ca tests
```

To only run the MockCA tests. Those tests are supposed to be experimental and supposed to help with new features.
Which are located in `tests_mock_ca/`, use this command:

```sh
robot --pythonpath=./ --exclude verbose-tests --outputdir=reports --variable environment:mock_ca tests_mock_ca
```

#### End-to-end usage example

1. Install dependencies:

   ```sh
   python3 -m venv venv-cmp-tests
   source venv-cmp-tests/bin/activate
   pip install -r requirements.txt
   ```

2. Start MockCA:

   ```sh
   make start-mock-ca
   ```

3. In a new shell, run a MockCA test case:

   ```sh
   robot --pythonpath=./ --outputdir=reports --variable environment:mock_ca tests_mock_ca
   ```

4. Review the output report:
   - `reports/report.html`
   - `reports/log.html`

## Troubleshooting & Debugging

- **Checking for errors:**
  - When using the `Exchange PKIMessage` keyword, any error message is typically returned there.
  - If inspecting the `PKIMessage` directly, use the `PKIStatus Must Be` keyword to view the `PKIStatusInfo`
    in a human-readable format.
- **Logging:**
  - The Mock-CA runs in `Debug` mode by default. However, more advanced logging and debugging methods are planned
    but not yet implemented.
- **Stateful tests failing on re-run:** Some tests depend on state (e.g., issuance and revocation); re‑running the
   same test without resetting state can cause failures. **Restart** the MockCA to reset its in‑memory state.
- **`Connection refused`**: Mock CA is not running, or the host/port does not match `config/mock_ca.robot`.
- **`Address already in use`**: Another process is using port 5000. Stop it or start Mock CA on another port.
- **Unexpected 404 responses:** Confirm the request is sent to `/issuing` or the configured endpoint suffix.
   The list of supported endpoints is documented above.
