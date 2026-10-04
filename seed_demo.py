"""Fills the portal with demo submissions so the dashboards aren't empty:  python seed_demo.py
(init_db already creates demo users/courses/assignments; see README for logins)"""
import io, app as A
A.init_db()
plan = [("rakshita", 1, "rakshita_hashing.txt", b"SHA-256 lab report. " * 300), ("tejaswini", 1, "tejaswini_hashing.pdf", b"%PDF-1.4 hash notes " * 900),
        ("manjula", 1, "manjula_hashing.docx", b"PK hashing answers " * 1500), ("tejaswini", 2, "tejaswini_ciphers.txt", b"AES modes writeup " * 400),
        ("sinchana", 2, "sinchana_ciphers.txt", b"Feistel vs SPN " * 700), ("rakshita", 3, "rakshita_scheduling.txt", b"Round robin gantt " * 500)]
for u, aid, name, data in plan:
    c = A.app.test_client(); c.post("/login", data={"username": u, "password": "Student@123"})
    with c.session_transaction() as s: t = s["csrf"]
    r = c.post("/submit", data={"csrf": t, "assignment_id": aid, "file": (io.BytesIO(data), name)}, content_type="multipart/form-data")
    print(u, name, "->", r.status_code)
