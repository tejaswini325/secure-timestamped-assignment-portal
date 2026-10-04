# Secure Timestamped Assignment Submission Portal — Post-Quantum Edition
26ECAC402 · Cryptography and Network Security · Review 2

## Run (2 minutes)
```bash
pip install -r requirements.txt
python seed_demo.py        # optional: fills dashboard with demo data
python app.py              # http://127.0.0.1:5000   (TLS=1 python app.py for https, self-signed)
python test_flow.py        # 14 end-to-end tests (submit, verify, forge, tamper, replay, access control)
```
Logins: `student1/2/3` → `Student@123` · faculty `prof1` → `Faculty@123`

## Review comments → what was done
| Comment | Implementation |
|---|---|
| Use post-quantum cryptography | Receipts signed with **ML-DSA-65** (FIPS 204, was RSA). Per-file key from **ML-KEM-768** (FIPS 203) → HKDF-SHA256 → **AES-256-GCM**. SHA-256 for integrity. |
| Show implementation with dashboard | Student dashboard (upload, history, receipts, pipeline timings) + faculty dashboard (stats, charts, key info, audit log, integrity audit, tamper demo). |

## Crypto flow (per submission)
1. SHA-256 of file → 2. ML-KEM-768 encapsulate → shared secret → HKDF → AES key
3. AES-256-GCM encrypt (AAD = student|assignment|submission id) → stored as `.enc`
4. Receipt `{student, file, sha256, timestamp, deadline, late, prev_receipt_hash}` signed with ML-DSA-65
5. Receipts are hash-chained (each embeds the previous receipt hash) → log can't be reordered/trimmed.

Files: `pqc_crypto.py` (all crypto) · `app.py` (Flask, DB, routes) · `templates/` · `verify_receipt.py` (offline verifier) · `test_flow.py`

## Live demo script (5 min)
1. Log in `student1` → upload a file to Assignment 1 → show receipt page (4-step pipeline with sizes/timings).
2. Upload to Assignment 2 (deadline passed) → receipt shows **LATE**, inside the signed payload.
3. `/verify` (no login) → paste receipt + original file → all green. Edit one char of the timestamp/hash → **INVALID**.
4. Log in `prof1` → dashboard → **Run integrity audit** (all ✔).
5. Click **Simulate tamper** on a row → audit flags "file tampered" (GCM tag fails); **Restore** → green again.
6. Offline: `curl localhost:5000/api/pubkey > server_pubkey.json` then `python verify_receipt.py receipt.json original.pdf`.

## Security notes (for viva)
- Why PQC: RSA/ECDSA fall to Shor's algorithm; ML-DSA/ML-KEM are lattice-based (NIST FIPS 204/203). AES-256 & SHA-256 remain quantum-safe (Grover halves strength → 128-bit).
- Passwords: scrypt + per-user salt; login throttling (5 fails / 5 min); CSRF tokens; per-student access control on receipts.
- Non-repudiation: only the server holds the ML-DSA secret key; timestamp is inside the signed payload.
- Limitations (state honestly): server clock is trusted (production: RFC 3161 TSA); server holds KEM secret key on disk (production: HSM/KMS); TLS itself uses the OpenSSL/Werkzeug default, PQ protection is at the application layer.
