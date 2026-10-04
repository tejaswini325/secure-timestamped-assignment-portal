# Secure Timestamped Assignment Submission and Verification Portal

A post-quantum secure assignment submission and verification portal that provides encrypted file storage, cryptographic integrity verification, digitally signed submission receipts, role-based access control, secure timestamps, and tamper detection.

## Features

- Student, Faculty, and Admin dashboards
- Secure authentication and Role-Based Access Control (RBAC)
- Assignment creation and submission
- SHA-256 file integrity verification
- ML-KEM-768 post-quantum key encapsulation
- HKDF-SHA256 key derivation
- AES-256-GCM file encryption
- ML-DSA-65 post-quantum digital signatures
- Cryptographically signed submission receipts
- Server-generated submission timestamps
- Hash-chained submission receipts
- Receipt and file verification
- Tamper simulation and integrity auditing
- Post-quantum key management and key rotation
- Audit logging
- HTTPS/TLS support

## Security Architecture

```text
Student
   |
   v
Authentication + RBAC
   |
   v
Assignment Upload
   |
   +--------------------+
   |                    |
   v                    v
SHA-256             ML-KEM-768
File Hash           Key Encapsulation
                        |
                        v
                   Shared Secret
                        |
                        v
                  HKDF-SHA256
                        |
                        v
                 AES-256-GCM
                        |
                        v
                 Encrypted File
   |
   v
Submission Receipt
   |
   v
ML-DSA-65 Digital Signature
   |
   v
Hash-Chained Receipt
   |
   v
Secure Database
   |
   +-------------+-------------+
   |             |             |
   v             v             v
Student       Faculty        Admin
Dashboard     Dashboard      Dashboard
