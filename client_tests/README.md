<!--
SPDX-FileCopyrightText: Copyright 2025 Siemens AG

SPDX-License-Identifier: Apache-2.0
-->

This folder contains an experimental draft for test cases of client-side
CMP implementations.

- `cmp_tests_jinja.robot`: Main test suite for client-side components.
- `certs`: Contains all required certificates for testing.
- `cmp_client.py`: Defines the commands for CMP clients.


## Running Tests

1. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
2. Start CA server:
   ```bash
   python3 mock_ca/ca_handler.py 
   ```
3. Run tests:
   ```bash
   cd client_tests
   robot cmp_tests_jinja.robot
   ```
## Add Custom Client
1. Define your cmp commands in the test suit: Default is Openssl:
```bash
    ${CMP_CLIENT}    openssl
    ${INITIATION_REQUEST}      ir
    ${CERTIFICATION_REQUEST}   p10cr
    ${KEY_UPDATE_REQUEST}      kur
    ${REVOCATION_REQUEST}      rr
```
2. Define all available CLI commands for your cmp client in "cmp_client.py" using jinja, example of openssl:
```python
openssl = """
    openssl cmp
    -cmd {{ cmd }}
    -server {{ server }}
    -subject {{ subject }}
    -secret {{ secret }}
    -ref {{ ref | default('NULL-DN') }}
    {% if recipient %}-recipient {{ recipient }}{% endif %}
    {% if csr %}-csr {{ csr }}{% endif %}
    {% if newkey %}-newkey {{ newkey }}{% endif %}
    {% if certout %}-certout {{ certout }}{% endif %}
    {% if unprotected_requests %}-unprotected_requests{% endif %}
    """
```
