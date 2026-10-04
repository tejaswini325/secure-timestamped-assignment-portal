"""Cryptography + key management (Members 2 & 3).
 - ML-KEM-768 (FIPS 203) -> HKDF-SHA256 -> AES-256-GCM : confidentiality of stored files
 - SHA-256                                               : integrity
 - ML-DSA-65 (FIPS 204)                                  : post-quantum digital signature on receipts
 - Versioned keyring; secret keys are AES-GCM-sealed at rest under a master key; rotation keeps old keys for verification.
"""
import os, json, time, hashlib, threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from pqcrypto.kem import ml_kem_768 as KEM
from pqcrypto.sign import ml_dsa_65 as DSA

KEY_DIR = os.environ.get("PORTAL_KEYS", os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys"))
CTX = b"TSASP-receipt-v1"                       # domain separation for signatures
ALGS = {"kem": "ML-KEM-768", "sig": "ML-DSA-65", "aead": "AES-256-GCM", "hash": "SHA-256", "kdf": "HKDF-SHA256"}
MOD = {"kem": KEM, "dsa": DSA}
_lock = threading.Lock(); _cache = {}

def _p(n): return os.path.join(KEY_DIR, n)
def _write(n, b):
    with open(_p(n), "wb") as f: f.write(b)
    os.chmod(_p(n), 0o600)

# ---- master key (protects secret keys at rest) --------------------------------------------------
def _master():
    h = os.environ.get("MASTER_KEY_HEX")
    if h: return bytes.fromhex(h)
    os.makedirs(KEY_DIR, exist_ok=True)
    if not os.path.exists(_p("master.key")): _write("master.key", os.urandom(32))
    return open(_p("master.key"), "rb").read()
def _seal(b): n = os.urandom(12); return n + AESGCM(_master()).encrypt(n, b, b"tsasp-key-at-rest")
def _open(b): return AESGCM(_master()).decrypt(b[:12], b[12:], b"tsasp-key-at-rest")

# ---- keyring ------------------------------------------------------------------------------------
def _gen(kind, kid):
    pk, sk = MOD[kind].keygen(); _write(f"{kind}-{kid}.pk", pk); _write(f"{kind}-{kid}.sk", _seal(sk))

def state():
    with _lock:
        os.makedirs(KEY_DIR, exist_ok=True)
        if not os.path.exists(_p("active.json")):
            _gen("kem", 1); _gen("dsa", 1); _write("active.json", json.dumps({"kem": 1, "dsa": 1}).encode())
        return json.load(open(_p("active.json")))

def active(kind): return state()[kind]
def pk(kind, kid): return open(_p(f"{kind}-{kid}.pk"), "rb").read()
def _sk(kind, kid):
    k = (kind, kid)
    if k not in _cache: _cache[k] = _open(open(_p(f"{kind}-{kid}.sk"), "rb").read())
    return _cache[k]

def rotate():
    """New ML-KEM + ML-DSA keypairs become active. Old ones stay (to decrypt old files / verify old receipts)."""
    st = state()
    with _lock:
        st = {k: v + 1 for k, v in st.items()}
        for kind, kid in st.items(): _gen(kind, kid)
        _write("active.json", json.dumps(st).encode())
    return st

def keyring():
    st = state(); out = []
    for kind in ("dsa", "kem"):
        for kid in range(st[kind], 0, -1):
            b = pk(kind, kid)
            out.append(dict(kind=kind, kid=kid, alg=ALGS["sig" if kind == "dsa" else "kem"], size=len(b),
                            fp=fingerprint(b), active=kid == st[kind]))
    return out

# ---- primitives ---------------------------------------------------------------------------------
def sha256_hex(b): return hashlib.sha256(b).hexdigest()
def fingerprint(b): return hashlib.sha256(b).hexdigest()[:32]
def canonical(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
def _aes_key(shared): return HKDF(hashes.SHA256(), 32, None, b"tsasp-file-key-v1").derive(shared)

def encrypt_file(data, aad):
    kid = active("kem"); t0 = time.perf_counter()
    kem_ct, shared = KEM.encaps(pk("kem", kid)); t1 = time.perf_counter()
    nonce = os.urandom(12); ct = AESGCM(_aes_key(shared)).encrypt(nonce, data, aad); t2 = time.perf_counter()
    return dict(kem_kid=kid, kem_ct=kem_ct, nonce=nonce, ct=ct, kem_ms=(t1 - t0) * 1e3, aes_ms=(t2 - t1) * 1e3)

def decrypt_file(kem_kid, kem_ct, nonce, ct, aad):
    shared = KEM.decaps(_sk("kem", kem_kid), kem_ct)
    return AESGCM(_aes_key(shared)).decrypt(nonce, ct, aad)          # InvalidTag if tampered

def sign(payload):
    t0 = time.perf_counter(); sig = DSA.sign(_sk("dsa", payload["dsa_kid"]), canonical(payload), context=CTX)
    return sig, (time.perf_counter() - t0) * 1e3

def verify(payload, sig, public_key=None):
    try:
        DSA.verify(public_key or pk("dsa", int(payload["dsa_kid"])), canonical(payload), sig, context=CTX); return True
    except Exception: return False
