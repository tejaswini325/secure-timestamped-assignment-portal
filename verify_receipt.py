"""Offline receipt verifier - needs only the server's public key, no access to the server.
Usage: python verify_receipt.py receipt.json [original_file] [--pubkey server_pubkey.json]
Get the key with:  curl http://127.0.0.1:5000/api/pubkey > server_pubkey.json
"""
import sys, json, base64, hashlib
from pqcrypto.sign import ml_dsa_65 as DSA

args = [a for a in sys.argv[1:] if not a.startswith("--")]
pkfile = sys.argv[sys.argv.index("--pubkey") + 1] if "--pubkey" in sys.argv else "server_pubkey.json"
if "--pubkey" in sys.argv: args.remove(pkfile)
if not args: sys.exit(__doc__)
bundle = json.load(open(args[0])); pk = json.load(open(pkfile))
payload, sig = bundle["payload"], base64.b64decode(bundle["signature"])
if pk.get("kid") != payload.get("dsa_kid"):
    sys.exit(f"[!] receipt was signed with key #{payload.get('dsa_kid')} - fetch it: curl 'http://127.0.0.1:5000/api/pubkey?kid={payload.get('dsa_kid')}' > server_pubkey.json")
msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
try:
    DSA.verify(base64.b64decode(pk["public_key"]), msg, sig, context=pk["context"].encode())
    print("[OK]   ML-DSA-65 signature valid - issued by the server at", payload["timestamp"])
except Exception:
    sys.exit("[FAIL] signature invalid - receipt forged or altered")
if len(args) > 1:
    h = hashlib.sha256(open(args[1], "rb").read()).hexdigest()
    print("[OK]  " if h == payload["sha256"] else "[FAIL]", "file SHA-256", "matches receipt" if h == payload["sha256"] else "does NOT match receipt")
