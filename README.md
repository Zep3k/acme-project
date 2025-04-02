# ACME Project – Network Security AS 2024

This repository contains my implementation of an ACME client as part of the Network Security AS 2024 course at ETH Zurich. The project explores automating the digital certificate issuance process using the ACME protocol (RFC 8555).

## Overview

The ACME protocol automates the process of obtaining digital certificates from a Certificate Authority (CA). In this project, I built an ACME client that:

- **Generates a Certificate Signing Request (CSR):** For a given domain (e.g., `my-server.ch`), using a generated key pair.
- **Places a Certificate Order:** Communicates with the ACME server to initiate the certificate issuance process.
- **Validates Challenges:** Retrieves and validates challenges (HTTP-01 or DNS-01) to prove domain ownership.
- **Submits the CSR:** Sends the validated CSR to receive the certificate.
- **Implements JOSE Cryptography:** Handles the cryptographic operations required by the ACME protocol.

## Key Features

- **Automated Certificate Order:** From order placement to certificate download.
- **Challenge Validation:** Supports both HTTP-01 and DNS-01 challenge types.
- **Secure Communication:** Uses JOSE standards for cryptographic operations.
- **Continuous Integration (CI):** Automated tests run with every push to ensure functionality.

## Project Structure

- **`src/`** – Source code for the ACME client.
- **`docs/`** – Documentation and additional resources (including the presentation slides).
- **`tests/`** – Automated tests for the project..
