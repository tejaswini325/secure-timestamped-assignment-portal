"""End-to-end tests: auth, RBAC, submit, receipt, verify, forge, tamper, replay, key rotation."""
import os, io, json, tempfile
tmp = tempfile.mkdtemp()
os.environ.update(PORTAL_DB=tmp + "/t.db", PORTAL_STORE=tmp + "/st", PORTAL_KEYS=tmp + "/keys")
import app as A
A.init_db()
ok = lambda m: print("PASS", m)

def client(u=None, p=None):
    c = A.app.test_client(); c.get("/login")
    if u: c.post("/login", data={"username": u, "password": p})
    return c
def tok(c):
    with c.session_transaction() as s: return s["csrf"]
def up(c, aid, data, name="a.txt"):
    return c.post("/submit", data={"csrf": tok(c), "assignment_id": aid, "file": (io.BytesIO(data), name)}, content_type="multipart/form-data")
def post(c, url, **d): return c.post(url, data={"csrf": tok(c), **d})
def verify_page(c, b, f=None):
    d = {"receipt_text": json.dumps(b), "csrf": tok(c)}
    if f is not None: d["file"] = (io.BytesIO(f), "x")
    return c.post("/verify", data=d, content_type="multipart/form-data").data.decode()

# ---- authentication & registration
assert b"Invalid" in A.app.test_client().post("/login", data={"username": "tejaswini", "password": "bad"}).data
c = client(); r = c.post("/register", data={"name": "New Kid", "username": "newkid", "password": "weak"}); assert b"Password needs" in r.data
c.post("/register", data={"name": "New Kid", "username": "newkid", "password": "Str0ngPass1"}); assert client("newkid", "Str0ngPass1").get("/dashboard").status_code == 200; ok("registration + password policy + login")
assert client().get("/dashboard").status_code == 302; ok("dashboard requires login")

# ---- submit / receipt
S = client("tejaswini", "Student@123"); data = b"My CNS assignment " * 500
r = up(S, 1, data); assert r.status_code == 302; sid = r.location.split("/")[-1]
bundle = json.loads(S.get(f"/receipt/{sid}.json").data); p = bundle["payload"]
assert p["course"] == "26ECAC402" and p["late"] is False and p["ts_source"] == "server-clock" and p["dsa_kid"] == 1; ok("submission + signed receipt")
V = client()
assert "✔ VALID" in verify_page(V, bundle, data); ok("public verify: receipt + original file")
assert "✘ INVALID" in verify_page(V, bundle, data + b"!"); ok("altered file detected")
f = json.loads(json.dumps(bundle)); f["payload"]["timestamp"] = "2020-01-01T00:00:00.000Z"; assert "✘ INVALID" in verify_page(V, f, data); ok("forged timestamp detected")
f = json.loads(json.dumps(bundle)); f["payload"]["sha256"] = "0" * 64; assert "✘ INVALID" in verify_page(V, f); ok("forged hash detected")
assert V.post("/api/verify", json=bundle).json["valid"]; ok("/api/verify")
assert b"Duplicate" in S.post("/submit", data={"csrf": tok(S), "assignment_id": 1, "file": (io.BytesIO(data), "a.txt")}, content_type="multipart/form-data", follow_redirects=True).data; ok("duplicate submission rejected")
lr = up(S, 2, b"late one"); assert json.loads(S.get(lr.location + ".json").data)["payload"]["late"] is True; ok("late flagged inside signed receipt")
assert up(S, 3, b"os work").status_code == 302; ok("student enrolled in 2nd course can submit there")
assert up(client("manjula", "Student@123"), 3, b"x").status_code == 403; ok("student NOT enrolled cannot submit to that course")
assert S.post("/submit", data={"assignment_id": 1}).status_code == 400; ok("CSRF enforced")

# ---- RBAC
S2 = client("manjula", "Student@123")
assert S2.get(f"/receipt/{sid}.json").status_code == 403; ok("other student cannot read receipt")
assert S.get("/audit").status_code == 405 and S.post("/audit", headers={"X-CSRF-Token": tok(S)}).status_code == 403; ok("student cannot run audit")
assert S.get(f"/download/{sid}").status_code == 403; ok("student cannot download")
F1, F2, AD = client("prof1", "Faculty@123"), client("prof2", "Faculty@123"), client("admin1", "Admin@1234")
assert F1.get("/dashboard").status_code == 200 and b"Faculty dashboard" in F1.get("/dashboard").data
assert F2.get(f"/receipt/{sid}").status_code == 403 and F2.get(f"/download/{sid}").status_code == 403; ok("faculty of another course blocked")
assert F1.get(f"/download/{sid}").data == data; ok("course faculty can decrypt + download")
assert AD.get(f"/receipt/{sid}").status_code == 200 and AD.get(f"/download/{sid}").status_code == 403; ok("admin sees metadata but cannot decrypt files")
assert F1.get("/admin/acl").status_code == 405 and post(F1, "/admin/acl", role="faculty", perm="user.manage", allowed=1).status_code == 403; ok("faculty cannot reach admin functions")

# ---- faculty creates assignment; admin creates course/user
r = post(F1, "/assignments/create", course_id=1, title="Assignment 3 - PKI", deadline="2030-01-01T10:00", tz=-330); assert r.status_code == 302
a = A.sqlite3.connect(A.DB_PATH).execute("SELECT deadline FROM assignments WHERE title LIKE '%PKI%'").fetchone()[0]; assert a.startswith("2030-01-01T04:30"); ok("faculty creates assignment (local IST -> UTC)")
assert post(F1, "/assignments/create", course_id=2, title="hack", deadline="2030-01-01T10:00").status_code == 302 and not A.sqlite3.connect(A.DB_PATH).execute("SELECT 1 FROM assignments WHERE title='hack'").fetchone(); ok("faculty cannot create in someone else's course")
post(AD, "/admin/user/create", username="prof3", name="Prof Three", password="Faculty@123", role="faculty"); assert client("prof3", "Faculty@123").get("/dashboard").status_code == 200; ok("admin creates user")
fid = A.sqlite3.connect(A.DB_PATH).execute("SELECT id FROM users WHERE username='prof3'").fetchone()[0]
post(AD, "/admin/course/create", code="cs500", name="Networks", faculty_id=fid); assert A.sqlite3.connect(A.DB_PATH).execute("SELECT 1 FROM courses WHERE code='CS500'").fetchone(); ok("admin creates course")
sid_u = A.sqlite3.connect(A.DB_PATH).execute("SELECT id FROM users WHERE username='newkid'").fetchone()[0]
post(AD, f"/admin/user/{sid_u}", role="student", active=0); assert client("newkid", "Str0ngPass1").get("/dashboard").status_code == 302; ok("admin disables user -> cannot log in")
assert post(AD, "/admin/acl", role="admin", perm="acl.manage", allowed=0).status_code == 400; ok("admin lock-out prevented")
post(AD, "/admin/acl", role="faculty", perm="submission.download", allowed=0); assert F1.get(f"/download/{sid}").status_code == 403; ok("ACL matrix change takes effect immediately")
post(AD, "/admin/acl", role="faculty", perm="submission.download", allowed=1); assert F1.get(f"/download/{sid}").status_code == 200

# ---- audit + tamper
assert F1.post("/audit", headers={"X-CSRF-Token": tok(F1)}).json["ok"] and AD.post("/audit", headers={"X-CSRF-Token": tok(AD)}).json["ok"]; ok("audit clean (faculty scoped + admin full)")
H = {"X-CSRF-Token": tok(F1)}; F1.post(f"/tamper/{sid}", headers=H)
a = F1.post("/audit", headers=H).json; assert not a["ok"] and not a["results"][sid]["file"]; ok("tampering with stored file detected")
assert F1.get(f"/download/{sid}").status_code == 409 and "✘ INVALID" in verify_page(V, bundle, data); ok("download refused + verify fails on tampered storage")
assert F2.post(f"/restore/{sid}", headers={"X-CSRF-Token": tok(F2)}).status_code == 403; ok("other faculty cannot touch tamper tools")
F1.post(f"/restore/{sid}", headers=H); assert F1.post("/audit", headers=H).json["ok"]; ok("restore ok")

# ---- key rotation keeps old data verifiable
post(AD, "/admin/keys/rotate"); import pqc_crypto as pc; assert pc.state() == {"kem": 2, "dsa": 2}
r = up(client("sinchana", "Student@123"), 1, b"after rotation"); b2 = json.loads(client("sinchana", "Student@123").get(r.location + ".json").data); assert b2["payload"]["dsa_kid"] == 2
assert V.post("/api/verify", json=bundle).json["valid"] and V.post("/api/verify", json=b2).json["valid"]; ok("key rotation: old + new receipts verify")
assert F1.get(f"/download/{sid}").data == data and AD.post("/audit", headers={"X-CSRF-Token": tok(AD)}).json["ok"]; ok("key rotation: old files still decrypt")
assert V.get("/api/pubkey?kid=1").json["kid"] == 1 and V.get("/api/pubkey").json["kid"] == 2; ok("public keys served per key id")
# secret keys are sealed at rest
assert len(open(tmp + "/keys/dsa-1.sk", "rb").read()) == 4032 + 12 + 16; ok("secret keys sealed at rest (AES-GCM)")
print("\nALL TESTS PASSED")
