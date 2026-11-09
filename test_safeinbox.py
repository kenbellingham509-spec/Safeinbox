"""Run with:  python -m pytest -q   (or)   python test_safeinbox.py"""
import os, re, tempfile

os.environ["SAFEINBOX_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")
import detector
import app as appmod

appmod.app.config["TESTING"] = True


def csrf(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def test_detector_samples():
    S = detector.SAMPLES
    run = lambda k: detector.analyze(S[k]["sender"], S[k]["subject"], S[k]["body"], attachments=S[k]["attachments"])
    for k in ("mtn_phish", "lottery", "invoice_malware", "ura_fake"):
        assert run(k)["verdict"] == "dangerous", k
    for k in ("legit_meeting", "legit_newsletter"):
        assert run(k)["verdict"] == "safe", k


def test_lookalike_and_negation():
    assert detector._lookalike("paypa1.com")
    assert detector._lookalike("stanbicbamk.co.ug")
    assert detector._lookalike("mtn.co.ug") is None
    r = detector.analyze("a@b.com", "Hi", "We will never ask for your PIN or password by email.")
    assert r["verdict"] == "safe"


def test_highlight_escapes_html():
    out = detector.highlight_html("<script>alert(1)</script> urgent", ["urgent"])
    assert "<script>" not in out and "<mark>urgent</mark>" in out


def test_pages_and_flow():
    c = appmod.app.test_client()
    for path in ("/", "/services", "/pricing", "/blog", "/contact", "/scan", "/login", "/register",
                 "/blog/10-ways-to-spot-a-spam-email"):
        assert c.get(path).status_code == 200, path
    assert c.get("/dashboard").status_code == 302          # login required
    assert c.get("/nope").status_code == 404
    assert c.post("/login", data={"email": "x"}).status_code == 400   # CSRF enforced

    t = csrf(c)
    r = c.post("/login", data={"csrf": t, "email": "demo@safeinbox.ug", "password": "demo1234"})
    assert r.status_code == 302
    for path in ("/dashboard", "/history", "/history?verdict=dangerous&q=urgent", "/report"):
        assert c.get(path).status_code == 200, path

    t = csrf(c, "/scan")
    s = detector.SAMPLES["mtn_phish"]
    r = c.post("/scan", data={"csrf": t, **{k: s[k] for k in ("sender", "subject", "body", "attachments")}})
    assert r.status_code == 200 and "dangerous" in r.get_data(as_text=True)
    sid = int(re.search(r"/scan/(\d+)", r.get_data(as_text=True)).group(1))
    assert c.get(f"/scan/{sid}").status_code == 200
    assert c.post(f"/scan/{sid}/feedback", data={"csrf": t, "feedback": "correct"}).status_code == 302
    assert c.post(f"/scan/{sid}/delete", data={"csrf": t}).status_code == 302
    assert c.get(f"/scan/{sid}").status_code == 404


def test_isolation_between_users():
    a, b = appmod.app.test_client(), appmod.app.test_client()
    t = csrf(b, "/register")
    b.post("/register", data={"csrf": t, "name": "Bob", "email": "bob@example.com", "password": "password123"})
    assert b.get("/dashboard").status_code == 200
    ta = csrf(a)
    a.post("/login", data={"csrf": ta, "email": "demo@safeinbox.ug", "password": "demo1234"})
    some = appmod.db.connect().execute("SELECT id FROM scans WHERE user_id=(SELECT id FROM users WHERE email='demo@safeinbox.ug') LIMIT 1").fetchone()["id"]
    assert b.get(f"/scan/{some}").status_code == 404       # cannot see another user's scan


def test_api_and_contact():
    c = appmod.app.test_client()
    r = c.post("/api/scan", json={"subject": "URGENT verify your password now", "body": "Click here http://bit.ly/x"})
    assert r.status_code == 200 and r.json["verdict"] in ("suspicious", "dangerous")
    assert c.post("/api/scan", json={}).status_code == 400
    t = csrf(c, "/contact")
    assert c.post("/contact", data={"csrf": t, "name": "A", "email": "a@b.co", "message": "hi"}).status_code == 302
    assert appmod.db.connect().execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 1


if __name__ == "__main__":
    import sys, pytest
    sys.exit(pytest.main([__file__, "-q"]))
