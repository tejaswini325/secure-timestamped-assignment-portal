"""Secure Timestamped Assignment Submission & Verification Portal - post-quantum edition (Member 4: backend + integration)
Run:  python app.py      ->  http://127.0.0.1:5000        (TLS=1 python app.py  ->  https, self-signed)
"""
import os, io, json, time, uuid, hmac, base64, sqlite3, secrets, threading, ssl
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import (Flask, request, session, redirect, url_for, render_template, flash, jsonify, send_file, abort, g)
from werkzeug.utils import secure_filename
import pqc_crypto as pc
import rbac

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("PORTAL_DB", os.path.join(BASE, "portal.db"))
STORE = os.environ.get("PORTAL_STORE", os.path.join(BASE, "storage"))
DEMO = os.environ.get("DEMO_TOOLS", "1") == "1"
LOCK = threading.Lock()          # serialises submissions so the receipt hash-chain stays ordered
FAILS = {}                       # username -> [timestamps]  (login throttling)
TSFMT = "%Y-%m-%dT%H:%M:%S.%fZ"

app = Flask(__name__)
app.config.update(MAX_CONTENT_LENGTH=16 * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
os.makedirs(pc.KEY_DIR, exist_ok=True)
_sk = os.path.join(pc.KEY_DIR, "session.key")
if not os.path.exists(_sk):
    open(_sk, "wb").write(secrets.token_bytes(32)); os.chmod(_sk, 0o600)
app.secret_key = open(_sk, "rb").read()

# ------------------------------------------------------------------ helpers
def now(): return datetime.now(timezone.utc)
def iso(d): return d.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
def b64(b): return base64.b64encode(b).decode()
def unb64(s): return base64.b64decode(s)

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10); g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def _close(_):
    d = g.pop("db", None)
    if d: d.close()

def log(event, actor, detail="", ms=None):
    db().execute("INSERT INTO audit(ts,actor,event,detail,ms) VALUES(?,?,?,?,?)", (iso(now()), actor, event, detail, ms)); db().commit()

def init_db():
    os.makedirs(STORE, exist_ok=True); pc.state()
    c = sqlite3.connect(DB_PATH)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, name TEXT, role TEXT, pw TEXT, active INT DEFAULT 1, created TEXT);
    CREATE TABLE IF NOT EXISTS courses(id INTEGER PRIMARY KEY, code TEXT UNIQUE, name TEXT, faculty_id INT);
    CREATE TABLE IF NOT EXISTS enrollments(user_id INT, course_id INT, PRIMARY KEY(user_id, course_id));
    CREATE TABLE IF NOT EXISTS assignments(id INTEGER PRIMARY KEY, course_id INT, title TEXT, deadline TEXT, created_by INT);
    CREATE TABLE IF NOT EXISTS acl(role TEXT, perm TEXT, allowed INT, PRIMARY KEY(role, perm));
    CREATE TABLE IF NOT EXISTS submissions(
        seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE, user_id INT, assignment_id INT, filename TEXT, size INT, sha256 TEXT,
        submitted_at TEXT, late INT, enc_path TEXT, kem_kid INT, kem_ct BLOB, nonce BLOB, receipt TEXT, signature BLOB,
        receipt_hash TEXT, prev_hash TEXT, timings TEXT);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT, actor TEXT, event TEXT, detail TEXT, ms REAL);
    """)
    rbac.seed_acl(c)
    if os.environ.get("SEED_DEMO", "1") == "1" and not c.execute("SELECT 1 FROM users").fetchone():
        t = iso(now())
        for u, n, r, p in [("admin1", "Portal Admin", "admin", "Admin@1234"), ("prof1", "Prof. Sadaf Mujawar", "faculty", "Faculty@123"),
                           ("prof2", "Prof. R. Patil", "faculty", "Faculty@123"), ("rakshita", "Rakshita", "student", "Student@123"),
                           ("tejaswini", "Tejaswini", "student", "Student@123"), ("manjula", "Manjula", "student", "Student@123"),
                           ("sinchana", "Sinchana", "student", "Student@123")]:
            c.execute("INSERT INTO users(username,name,role,pw,created) VALUES(?,?,?,?,?)", (u, n, r, rbac.hash_pw(p), t))
        uid = lambda u: c.execute("SELECT id FROM users WHERE username=?", (u,)).fetchone()[0]
        c.execute("INSERT INTO courses(code,name,faculty_id) VALUES('26ECAC402','Cryptography and Network Security',?)", (uid("prof1"),))
        c.execute("INSERT INTO courses(code,name,faculty_id) VALUES('22CSC301','Operating Systems',?)", (uid("prof2"),))
        for u in ("rakshita", "tejaswini", "manjula", "sinchana"): c.execute("INSERT INTO enrollments VALUES(?,1)", (uid(u),))
        for u in ("rakshita", "tejaswini"): c.execute("INSERT INTO enrollments VALUES(?,2)", (uid(u),))
        for cid, ti, d, by in [(1, "Assignment 1 - Hash functions & MACs", now() + timedelta(days=7), "prof1"),
                               (1, "Assignment 2 - Symmetric ciphers (deadline passed)", now() - timedelta(days=1), "prof1"),
                               (2, "Assignment 1 - Process scheduling", now() + timedelta(days=5), "prof2")]:
            c.execute("INSERT INTO assignments(course_id,title,deadline,created_by) VALUES(?,?,?,?)", (cid, ti, iso(d), uid(by)))
    c.commit(); c.close()

@app.before_request
def load_user():
    g.user = None
    if "uid" in session:
        u = db().execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
        if u and u["active"]: g.user = u
        else: session.clear()
    if "csrf" not in session: session["csrf"] = secrets.token_hex(16)
    if request.method == "POST" and request.endpoint not in ("api_verify", "login", "register"):
        tok = request.headers.get("X-CSRF-Token") or request.form.get("csrf")
        if not tok or not hmac.compare_digest(tok, session["csrf"]): abort(400, "CSRF check failed")

@app.after_request
def headers(r):
    r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Cache-Control": "no-store",
                      "Referrer-Policy": "no-referrer"})
    if request.is_secure: r.headers["Strict-Transport-Security"] = "max-age=31536000"
    return r

def can(perm): return bool(g.user) and rbac.can(db(), g.user["role"], perm)

def need(*perms):
    """Login + permission check against the Access Control Matrix (any of perms)."""
    def deco(fn):
        @wraps(fn)
        def w(*a, **k):
            if not g.user: return redirect(url_for("login"))
            if perms and not any(can(p) for p in perms):
                log("access_denied", g.user["username"], request.path); abort(403)
            return fn(*a, **k)
        return w
    return deco

@app.context_processor
def inject():
    return dict(me=g.get("user"), csrf=session.get("csrf"), algs=pc.ALGS, can=can, demo=DEMO)

def receipt_bundle(row): return {"payload": json.loads(row["receipt"]), "signature": b64(row["signature"]), "alg": pc.ALGS["sig"]}
def aad(r): return f"{r['user_id']}|{r['assignment_id']}|{r['id']}".encode()

# ------------------------------------------------------------------ auth (Authentication layer)
@app.route("/")
def index(): return redirect(url_for("dashboard") if g.user else url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip().lower(); p = request.form.get("password", "")
        recent = [t for t in FAILS.get(u, []) if time.time() - t < 300]
        if len(recent) >= 5:
            flash("Too many failed attempts. Try again in 5 minutes.", "err"); return render_template("login.html"), 429
        row = db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if row and row["active"] and rbac.check_pw(p, row["pw"]):
            session.clear(); session.update(uid=row["id"], csrf=secrets.token_hex(16))
            g.user = row; log("login", u); return redirect(url_for("dashboard"))
        FAILS[u] = recent + [time.time()]; log("login_fail", u or "?")
        flash("Invalid credentials (or account disabled).", "err")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username", "").strip().lower(); n = request.form.get("name", "").strip(); p = request.form.get("password", "")
        if not (3 <= len(u) <= 32 and u.replace("_", "").replace(".", "").isalnum()) or not n:
            flash("Username: 3-32 letters/digits/._  and a name are required.", "err")
        elif rbac.pw_problem(p): flash(rbac.pw_problem(p), "err")
        elif db().execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone(): flash("Username already taken.", "err")
        else:
            db().execute("INSERT INTO users(username,name,role,pw,created) VALUES(?,?,'student',?,?)", (u, n, rbac.hash_pw(p), iso(now()))); db().commit()
            log("register", u); flash("Account created - please sign in.", "ok"); return redirect(url_for("login"))
    return render_template("register.html")

@app.post("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

# ------------------------------------------------------------------ dashboards (one per role)
def timing_stats(rows):
    tim = [json.loads(r["timings"]) for r in rows if r["timings"]]
    avg = lambda k: round(sum(t[k] for t in tim) / len(tim), 2) if tim else 0
    a = dict(hash=avg("hash_ms"), kem=avg("kem_ms"), aes=avg("aes_ms"), sign=avg("sign_ms"))
    return a, round(sum(a.values()), 2)

SUBQ = """SELECT s.*, a.title, a.deadline, c.code, c.name course_name, c.faculty_id, u.username, u.name student
          FROM submissions s JOIN assignments a ON a.id=s.assignment_id JOIN courses c ON c.id=a.course_id JOIN users u ON u.id=s.user_id"""

@app.route("/dashboard")
@need()
def dashboard():
    d, me = db(), g.user
    if me["role"] == "student":
        courses = d.execute("SELECT c.* FROM courses c JOIN enrollments e ON e.course_id=c.id WHERE e.user_id=?", (me["id"],)).fetchall()
        asg = d.execute("""SELECT a.*, c.code, (SELECT COUNT(*) FROM submissions s WHERE s.assignment_id=a.id AND s.user_id=?) done
                           FROM assignments a JOIN courses c ON c.id=a.course_id JOIN enrollments e ON e.course_id=c.id
                           WHERE e.user_id=? ORDER BY a.deadline""", (me["id"], me["id"])).fetchall()
        subs = d.execute(SUBQ + " WHERE s.user_id=? ORDER BY s.seq DESC", (me["id"],)).fetchall()
        return render_template("student.html", courses=courses, asg=asg, subs=subs, now=iso(now()))
    if me["role"] == "faculty":
        courses = d.execute("SELECT * FROM courses WHERE faculty_id=?", (me["id"],)).fetchall()
        rows = d.execute(SUBQ + " WHERE c.faculty_id=? ORDER BY s.seq DESC", (me["id"],)).fetchall()
        asg = d.execute("""SELECT a.*, c.code, (SELECT COUNT(*) FROM submissions s WHERE s.assignment_id=a.id) n,
                           (SELECT COUNT(*) FROM submissions s WHERE s.assignment_id=a.id AND s.late=1) late,
                           (SELECT COUNT(*) FROM enrollments e WHERE e.course_id=c.id) enrolled
                           FROM assignments a JOIN courses c ON c.id=a.course_id WHERE c.faculty_id=? ORDER BY a.deadline DESC""", (me["id"],)).fetchall()
        avg, tot = timing_stats(rows)
        return render_template("faculty.html", courses=courses, rows=rows, asg=asg, avg=avg, tot=tot)
    # admin
    rows = d.execute(SUBQ + " ORDER BY s.seq DESC").fetchall()
    users = d.execute("""SELECT u.*, (SELECT COUNT(*) FROM submissions s WHERE s.user_id=u.id) subs FROM users u ORDER BY u.role, u.username""").fetchall()
    courses = d.execute("""SELECT c.*, f.name faculty, (SELECT COUNT(*) FROM enrollments e WHERE e.course_id=c.id) enrolled,
                           (SELECT COUNT(*) FROM assignments a WHERE a.course_id=c.id) n_asg
                           FROM courses c LEFT JOIN users f ON f.id=c.faculty_id""").fetchall()
    faculty = [u for u in users if u["role"] == "faculty"]
    logs = d.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 30").fetchall()
    avg, tot = timing_stats(rows)
    by_course = d.execute("""SELECT c.code, COUNT(s.id) n, COALESCE(SUM(s.late),0) late FROM courses c LEFT JOIN assignments a ON a.course_id=c.id
                             LEFT JOIN submissions s ON s.assignment_id=a.id GROUP BY c.id""").fetchall()
    stats = dict(total=len(rows), late=sum(r["late"] for r in rows), users=len(users), tot=tot, avg=avg,
                 events=d.execute("SELECT COUNT(*) FROM audit WHERE event IN ('login_fail','access_denied','tamper_demo')").fetchone()[0])
    return render_template("admin.html", rows=rows, users=users, courses=courses, faculty=faculty, logs=logs, stats=stats, by_course=by_course,
                           matrix=rbac.matrix(d), perms=rbac.PERMS, roles=rbac.ROLES, locked=rbac.LOCKED, keyring=pc.keyring())

# ------------------------------------------------------------------ student: join course + submit (FR1-FR4)
@app.post("/courses/join")
@need("submission.create")
def join_course():
    c = db().execute("SELECT * FROM courses WHERE code=?", (request.form.get("code", "").strip().upper(),)).fetchone()
    if not c: flash("No course with that code.", "err")
    else:
        db().execute("INSERT OR IGNORE INTO enrollments VALUES(?,?)", (g.user["id"], c["id"])); db().commit()
        log("enroll", g.user["username"], c["code"]); flash(f"Enrolled in {c['code']}.", "ok")
    return redirect(url_for("dashboard"))

@app.post("/submit")
@need("submission.create")
def submit():
    f = request.files.get("file")
    try: aid = int(request.form.get("assignment_id", ""))
    except ValueError: abort(400)
    d, me = db(), g.user
    asg = d.execute("""SELECT a.*, c.code FROM assignments a JOIN courses c ON c.id=a.course_id
                       JOIN enrollments e ON e.course_id=c.id AND e.user_id=? WHERE a.id=?""", (me["id"], aid)).fetchone()
    if not asg: log("access_denied", me["username"], f"submit assignment {aid}"); abort(403)
    if not f or not f.filename: flash("Choose a file.", "err"); return redirect(url_for("dashboard"))
    data = f.read()
    if not data: flash("Empty file rejected.", "err"); return redirect(url_for("dashboard"))
    name = secure_filename(f.filename) or "submission.bin"
    with LOCK:
        T = {}
        t0 = time.perf_counter(); digest = pc.sha256_hex(data); T["hash_ms"] = (time.perf_counter() - t0) * 1e3            # FR2
        if d.execute("SELECT 1 FROM submissions WHERE user_id=? AND assignment_id=? AND sha256=?", (me["id"], aid, digest)).fetchone():
            flash("Duplicate: this exact file was already submitted for this assignment.", "err"); return redirect(url_for("dashboard"))
        sid = uuid.uuid4().hex; ts = now()
        enc = pc.encrypt_file(data, f"{me['id']}|{aid}|{sid}".encode())                                                    # FR3
        T["kem_ms"], T["aes_ms"] = enc["kem_ms"], enc["aes_ms"]
        path = os.path.join(STORE, sid + ".enc"); open(path, "wb").write(enc["ct"])
        last = d.execute("SELECT receipt_hash FROM submissions ORDER BY seq DESC LIMIT 1").fetchone()
        prev = last["receipt_hash"] if last else "0" * 64
        late = int(ts > datetime.strptime(asg["deadline"], TSFMT).replace(tzinfo=timezone.utc))
        payload = dict(v=2, submission_id=sid, username=me["username"], student=me["name"], student_id=me["id"], course=asg["code"],
                       assignment_id=aid, assignment=asg["title"], filename=name, size=len(data), sha256=digest, timestamp=iso(ts),
                       ts_source="server-clock", deadline=asg["deadline"], late=bool(late), prev_receipt_hash=prev, algs=pc.ALGS,
                       dsa_kid=pc.active("dsa"), kem_kid=enc["kem_kid"])
        sig, T["sign_ms"] = pc.sign(payload)                                                                                # FR4
        rh = pc.sha256_hex(pc.canonical(payload) + sig)
        T.update(kem_ct_bytes=len(enc["kem_ct"]), sig_bytes=len(sig), enc_bytes=len(enc["ct"]))
        d.execute("""INSERT INTO submissions(id,user_id,assignment_id,filename,size,sha256,submitted_at,late,enc_path,kem_kid,kem_ct,nonce,
                     receipt,signature,receipt_hash,prev_hash,timings) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (sid, me["id"], aid, name, len(data), digest, payload["timestamp"], late, path, enc["kem_kid"], enc["kem_ct"], enc["nonce"],
                   json.dumps(payload), sig, rh, prev, json.dumps(T)))
        d.commit()
    log("submit", me["username"], f"{asg['code']} {name} sha256={digest[:12]}.. late={bool(late)}", sum(T[k] for k in ("hash_ms", "kem_ms", "aes_ms", "sign_ms")))
    flash("Submission accepted - signed receipt issued." + (" (marked LATE)" if late else ""), "ok")
    return redirect(url_for("receipt_page", sid=sid))

# ------------------------------------------------------------------ receipts (access checked per record)
def get_sub(sid, download=False):
    row = db().execute(SUBQ + " WHERE s.id=?", (sid,)).fetchone()
    if not row: abort(404)
    me = g.user
    ok = ((me["role"] == "student" and row["user_id"] == me["id"] and can("submission.view_own") and not download) or
          (row["faculty_id"] == me["id"] and (can("submission.download") if download else can("submission.view_course"))) or
          (can("submission.view_all") and not download))
    if not ok: log("access_denied", me["username"], f"{'download' if download else 'view'} {sid[:8]}"); abort(403)
    return row

@app.route("/receipt/<sid>")
@need()
def receipt_page(sid):
    row = get_sub(sid)
    return render_template("receipt.html", s=row, T=json.loads(row["timings"]), bundle=json.dumps(receipt_bundle(row), indent=2), payload=json.loads(row["receipt"]))

@app.route("/receipt/<sid>.json")
@need()
def receipt_download(sid):
    row = get_sub(sid)
    return send_file(io.BytesIO(json.dumps(receipt_bundle(row), indent=2).encode()), mimetype="application/json", as_attachment=True, download_name=f"receipt_{sid[:8]}.json")

# ------------------------------------------------------------------ verification (FR6) - public
def check_row(row, prev_hash):
    payload, sig = json.loads(row["receipt"]), bytes(row["signature"])
    sig_ok = pc.verify(payload, sig)
    chain_ok = payload["prev_receipt_hash"] == prev_hash and row["receipt_hash"] == pc.sha256_hex(pc.canonical(payload) + sig)
    try: file_ok = pc.sha256_hex(pc.decrypt_file(row["kem_kid"], row["kem_ct"], row["nonce"], open(row["enc_path"], "rb").read(), aad(row))) == payload["sha256"]
    except Exception: file_ok = False
    return dict(sig=sig_ok, chain=chain_ok, file=file_ok, ok=sig_ok and chain_ok and file_ok)

def verify_bundle(bundle, file_bytes=None):
    checks = []
    add = lambda n, ok, det="": checks.append(dict(name=n, ok=ok, detail=det))
    try: payload, sig = bundle["payload"], unb64(bundle["signature"])
    except Exception: return [dict(name="Receipt format", ok=False, detail="Not a valid receipt file")]
    add(f"ML-DSA-65 signature valid (server key #{payload.get('dsa_kid')})", pc.verify(payload, sig), "Receipt was issued by this server and has not been altered")
    row = db().execute("SELECT * FROM submissions WHERE id=?", (payload.get("submission_id"),)).fetchone()
    if not row: add("Receipt exists in server log", False, "No record of this submission id")
    else:
        add("Receipt exists in server log", row["receipt_hash"] == pc.sha256_hex(pc.canonical(payload) + sig), f"Submission #{row['seq']} recorded at {row['submitted_at']}")
        prev = db().execute("SELECT receipt_hash FROM submissions WHERE seq<? ORDER BY seq DESC LIMIT 1", (row["seq"],)).fetchone()
        add("Hash-chain link to previous receipt", payload.get("prev_receipt_hash") == (prev["receipt_hash"] if prev else "0" * 64), "Log cannot be reordered or have entries silently removed")
        try:
            plain = pc.decrypt_file(row["kem_kid"], row["kem_ct"], row["nonce"], open(row["enc_path"], "rb").read(), aad(row))
            add("Stored file decrypts (ML-KEM + AES-GCM) and matches signed hash", pc.sha256_hex(plain) == payload["sha256"], "Encrypted copy on server is intact")
        except Exception:
            add("Stored file decrypts (ML-KEM + AES-GCM) and matches signed hash", False, "Authentication tag failed - stored ciphertext was modified")
    if file_bytes is not None:
        add("Uploaded file SHA-256 matches receipt", pc.sha256_hex(file_bytes) == payload.get("sha256"), "The file you supplied is byte-identical to what was submitted")
    return checks

@app.route("/verify", methods=["GET", "POST"])
def verify_page():
    res = None
    if request.method == "POST":
        try:
            rf = request.files.get("receipt"); txt = rf.read().decode() if rf and rf.filename else request.form.get("receipt_text", "")
            fb = request.files.get("file"); fb = fb.read() if fb and fb.filename else None
            res = verify_bundle(json.loads(txt), fb)
        except Exception: res = [dict(name="Receipt format", ok=False, detail="Could not parse receipt JSON")]
        log("verify", g.user["username"] if g.user else "public", "PASS" if all(c["ok"] for c in res) else "FAIL")
    return render_template("verify.html", res=res)

@app.post("/api/verify")
def api_verify():
    try: res = verify_bundle(request.get_json(force=True))
    except Exception: return jsonify(valid=False, error="bad request"), 400
    return jsonify(valid=all(c["ok"] for c in res), checks=res)

@app.get("/api/pubkey")
def api_pubkey():
    kid = request.args.get("kid", type=int) or pc.active("dsa")
    try: k = pc.pk("dsa", kid)
    except FileNotFoundError: abort(404)
    return jsonify(alg=pc.ALGS["sig"], kid=kid, public_key=b64(k), fingerprint=pc.fingerprint(k), context=pc.CTX.decode())

# ------------------------------------------------------------------ audit / verify (scoped) / tamper demo
@app.post("/audit")
@need("submission.verify", "audit.view")
def run_audit():
    full = can("audit.view"); t0 = time.perf_counter(); out, prev, all_ok = {}, "0" * 64, True
    for r in db().execute(SUBQ + " ORDER BY s.seq").fetchall():
        res = check_row(r, prev); prev = r["receipt_hash"]
        if full or r["faculty_id"] == g.user["id"]:
            out[r["id"]] = res; all_ok &= res["ok"]
    ms = (time.perf_counter() - t0) * 1e3
    log("audit", g.user["username"], f"{len(out)} receipts - {'ALL OK' if all_ok else 'TAMPERING DETECTED'}", ms)
    return jsonify(ok=all_ok, results=out, ms=round(ms, 1))

def _own_sub(sid):
    r = db().execute(SUBQ + " WHERE s.id=?", (sid,)).fetchone() or abort(404)
    if r["faculty_id"] != g.user["id"]: abort(403)
    return r

@app.post("/tamper/<sid>")
@need("demo.tamper")
def tamper(sid):
    if not DEMO: abort(404)
    p = _own_sub(sid)["enc_path"]
    if not os.path.exists(p + ".bak"): open(p + ".bak", "wb").write(open(p, "rb").read())
    b = bytearray(open(p, "rb").read()); b[len(b) // 2] ^= 1; open(p, "wb").write(bytes(b))
    log("tamper_demo", g.user["username"], sid[:8]); return jsonify(ok=True)

@app.post("/restore/<sid>")
@need("demo.tamper")
def restore(sid):
    if not DEMO: abort(404)
    p = _own_sub(sid)["enc_path"]
    if os.path.exists(p + ".bak"): os.replace(p + ".bak", p)
    log("restore", g.user["username"], sid[:8]); return jsonify(ok=True)

@app.route("/download/<sid>")
@need("submission.download")
def download(sid):
    r = get_sub(sid, download=True)
    try: plain = pc.decrypt_file(r["kem_kid"], r["kem_ct"], r["nonce"], open(r["enc_path"], "rb").read(), aad(r))
    except Exception: abort(409, "Stored file failed authentication - it has been tampered with.")
    log("download", g.user["username"], f"{r['code']} {r['filename']} by {r['username']}")
    return send_file(io.BytesIO(plain), as_attachment=True, download_name=r["filename"])

# ------------------------------------------------------------------ faculty: create assignment
def local_to_utc(val, tzmin):
    return datetime.strptime(val, "%Y-%m-%dT%H:%M").replace(tzinfo=timezone.utc) + timedelta(minutes=int(tzmin))

@app.post("/assignments/create")
@need("assignment.create")
def create_assignment():
    c = db().execute("SELECT * FROM courses WHERE id=? AND faculty_id=?", (request.form.get("course_id", type=int), g.user["id"])).fetchone()
    title = request.form.get("title", "").strip()
    try: dl = local_to_utc(request.form["deadline"], request.form.get("tz", 0))
    except Exception: dl = None
    if not c or not title or not dl: flash("Pick your course, a title and a valid deadline.", "err")
    else:
        db().execute("INSERT INTO assignments(course_id,title,deadline,created_by) VALUES(?,?,?,?)", (c["id"], title[:120], iso(dl), g.user["id"])); db().commit()
        log("assignment_create", g.user["username"], f"{c['code']} {title[:40]}"); flash("Assignment created.", "ok")
    return redirect(url_for("dashboard"))

# ------------------------------------------------------------------ admin module
@app.post("/admin/user/create")
@need("user.manage")
def admin_user_create():
    f = request.form; u = f.get("username", "").strip().lower(); role = f.get("role")
    if role not in rbac.ROLES or not u or not f.get("name", "").strip() or rbac.pw_problem(f.get("password", "")): flash("Invalid user details (password: 8+ chars, upper, lower, digit).", "err")
    elif db().execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone(): flash("Username already exists.", "err")
    else:
        db().execute("INSERT INTO users(username,name,role,pw,created) VALUES(?,?,?,?,?)", (u, f["name"].strip(), role, rbac.hash_pw(f["password"]), iso(now()))); db().commit()
        log("user_create", g.user["username"], f"{u} as {role}"); flash(f"User {u} created.", "ok")
    return redirect(url_for("dashboard") + "#users")

@app.post("/admin/user/<int:uid>")
@need("user.manage")
def admin_user_update(uid):
    if uid == g.user["id"]: flash("You cannot change your own role or status.", "err"); return redirect(url_for("dashboard") + "#users")
    u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() or abort(404)
    role = request.form.get("role", u["role"]); active = int(request.form.get("active", u["active"]))
    if role not in rbac.ROLES: abort(400)
    db().execute("UPDATE users SET role=?, active=? WHERE id=?", (role, active, uid)); db().commit()
    log("user_update", g.user["username"], f"{u['username']} role={role} active={active}"); flash(f"Updated {u['username']}.", "ok")
    return redirect(url_for("dashboard") + "#users")

@app.post("/admin/course/create")
@need("course.manage")
def admin_course_create():
    f = request.form; code = f.get("code", "").strip().upper(); name = f.get("name", "").strip()
    fac = db().execute("SELECT id FROM users WHERE id=? AND role='faculty'", (f.get("faculty_id", type=int),)).fetchone()
    if not code or not name or not fac: flash("Course code, name and a faculty member are required.", "err")
    elif db().execute("SELECT 1 FROM courses WHERE code=?", (code,)).fetchone(): flash("Course code already exists.", "err")
    else:
        db().execute("INSERT INTO courses(code,name,faculty_id) VALUES(?,?,?)", (code, name, fac["id"])); db().commit()
        log("course_create", g.user["username"], code); flash(f"Course {code} created.", "ok")
    return redirect(url_for("dashboard") + "#courses")

@app.post("/admin/acl")
@need("acl.manage")
def admin_acl():
    role, perm, allowed = request.form.get("role"), request.form.get("perm"), int(request.form.get("allowed", 0))
    if role not in rbac.ROLES or perm not in rbac.PERMS or ((role, perm) in rbac.LOCKED and not allowed): return jsonify(ok=False), 400
    db().execute("UPDATE acl SET allowed=? WHERE role=? AND perm=?", (allowed, role, perm)); db().commit()
    log("acl_change", g.user["username"], f"{role}:{perm}={'allow' if allowed else 'deny'}"); return jsonify(ok=True)

@app.post("/admin/keys/rotate")
@need("keys.manage")
def admin_rotate():
    st = pc.rotate(); log("key_rotate", g.user["username"], f"ML-DSA #{st['dsa']}, ML-KEM #{st['kem']} now active")
    flash(f"New ML-DSA-65 key #{st['dsa']} and ML-KEM-768 key #{st['kem']} are active. Old keys kept for verification/decryption.", "ok")
    return redirect(url_for("dashboard") + "#keys")

def tls_context():
    """Self-signed TLS 1.3 for the demo. If OpenSSL >= 3.5, prefer the hybrid post-quantum group X25519MLKEM768."""
    import datetime as dt
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    cert, key = os.path.join(pc.KEY_DIR, "tls.crt"), os.path.join(pc.KEY_DIR, "tls.key")
    if not os.path.exists(cert):
        k = ec.generate_private_key(ec.SECP256R1()); n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(dt.datetime.now(dt.timezone.utc)).not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365))
             .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False).sign(k, hashes.SHA256()))
        open(cert, "wb").write(c.public_bytes(serialization.Encoding.PEM))
        open(key, "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); os.chmod(key, 0o600)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version = ssl.TLSVersion.TLSv1_3; ctx.load_cert_chain(cert, key)
    try: ctx.set_ecdh_curve("X25519MLKEM768"); print("[TLS] hybrid post-quantum key exchange X25519MLKEM768 enabled")
    except Exception: print(f"[TLS] TLS 1.3 enabled ({ssl.OPENSSL_VERSION}); hybrid PQ groups need OpenSSL >= 3.5")
    return ctx

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), ssl_context=tls_context() if os.environ.get("TLS") == "1" else None)
