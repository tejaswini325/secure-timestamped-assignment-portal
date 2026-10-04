"""Authentication helpers + Role-Based Access Control with an editable Access Control Matrix (Member 1)."""
import os, hmac, hashlib, re

PERMS = {
    "assignment.view":        "View available assignments",
    "submission.create":      "Upload an assignment",
    "submission.view_own":    "View own submissions & receipts",
    "assignment.create":      "Create assignment & set deadline",
    "submission.view_course": "View submissions of own courses",
    "submission.download":    "Decrypt & download submissions (own courses)",
    "submission.verify":      "Verify integrity & signature (own courses)",
    "submission.view_all":    "Monitor all submission records (metadata only)",
    "user.manage":            "Manage users & roles",
    "course.manage":          "Manage courses",
    "acl.manage":             "Manage access permissions",
    "audit.view":             "View audit log / run full audit",
    "keys.manage":            "View & rotate cryptographic keys",
    "demo.tamper":            "Tamper simulation (demo)",
}
ROLES = ("student", "faculty", "admin")
DEFAULT = {
    "student": ["assignment.view", "submission.create", "submission.view_own"],
    "faculty": ["assignment.view", "assignment.create", "submission.view_course", "submission.download",
                "submission.verify", "demo.tamper"],
    "admin":   ["submission.view_all", "user.manage", "course.manage", "acl.manage", "audit.view", "keys.manage"],
}
LOCKED = {("admin", "acl.manage"), ("admin", "user.manage")}       # prevents admin lock-out

def seed_acl(c):
    for r in ROLES:
        for p in PERMS:
            c.execute("INSERT OR IGNORE INTO acl(role,perm,allowed) VALUES(?,?,?)", (r, p, int(p in DEFAULT[r])))

def can(db, role, perm):
    r = db.execute("SELECT allowed FROM acl WHERE role=? AND perm=?", (role, perm)).fetchone()
    return bool(r and r["allowed"])

def matrix(db):
    return {r: {p: can(db, r, p) for p in PERMS} for r in ROLES}

# ---- passwords (scrypt + per-user salt) ---------------------------------------------------------
def hash_pw(pw, salt=None):
    salt = salt or os.urandom(16)
    return salt.hex() + "$" + hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1).hex()
def check_pw(pw, stored):
    salt, h = stored.split("$")
    return hmac.compare_digest(hash_pw(pw, bytes.fromhex(salt)).split("$")[1], h)
def pw_problem(pw):
    if len(pw) < 8 or not re.search(r"[A-Z]", pw) or not re.search(r"[a-z]", pw) or not re.search(r"\d", pw):
        return "Password needs 8+ characters with upper-case, lower-case and a digit."
