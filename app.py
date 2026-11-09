"""SafeInbox Security Solutions - Flask web app.

Run:  python app.py      then open http://127.0.0.1:5000
Demo login:  demo@safeinbox.ug / demo1234
"""
import json
import os
import re
import secrets
from collections import Counter
from datetime import date, datetime, timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import db
import detector

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def _secret_key():
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    path = os.path.abspath(os.path.join(db.BASE_DIR, "instance", ".secret_key"))
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w") as fh:
            fh.write(secrets.token_hex(32))
    with open(path) as fh:
        return fh.read().strip()


app.secret_key = _secret_key()
WHATSAPP_NUMBER = os.environ.get("WHATSAPP_NUMBER", "256748742871")
db.init_db()

EMAIL_OK = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ------------------------------------------------------------------ plumbing
def get_db():
    if "db" not in g:
        g.db = db.connect()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    con = g.pop("db", None)
    if con:
        con.close()


@app.before_request
def load_user_and_csrf():
    g.user = None
    if session.get("uid"):
        g.user = get_db().execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
        if g.user is None:
            session.clear()
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    if request.method == "POST" and not request.path.startswith("/api/"):
        if not secrets.compare_digest(request.form.get("csrf", ""), session["csrf"]):
            abort(400, "Your session expired. Please go back, refresh the page and try again.")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


@app.context_processor
def inject():
    return {"csrf_token": session.get("csrf", ""), "user": g.get("user"), "whatsapp": WHATSAPP_NUMBER,
            "industries": db.INDUSTRIES, "year": date.today().year}


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if g.user is None:
            flash("Please log in to continue.", "info")
            return redirect(url_for("login", next=request.path))
        return fn(*a, **kw)
    return wrapper


@app.template_filter("ago")
def ago(value):
    try:
        dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return value or ""
    diff = datetime.now() - dt
    s = int(diff.total_seconds())
    if s < 60:
        return "just now"
    if s < 3600:
        return f"{s // 60} min ago"
    if s < 86400:
        return f"{s // 3600} h ago"
    if s < 86400 * 7:
        return f"{s // 86400} d ago"
    return dt.strftime("%d %b %Y")


@app.template_filter("fromjson")
def fromjson(value):
    try:
        return json.loads(value or "[]")
    except ValueError:
        return []


@app.template_filter("pretty_date")
def pretty_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime("%d %B %Y")
    except (TypeError, ValueError):
        return value or ""


# ------------------------------------------------------------------ public pages
@app.route("/")
def index():
    posts = get_db().execute("SELECT * FROM posts ORDER BY id LIMIT 3").fetchall()
    return render_template("index.html", posts=posts)


@app.route("/pricing")
def pricing():
    return render_template("pricing.html")


@app.route("/services")
def services():
    return render_template("services.html")


@app.route("/blog")
def blog():
    posts = get_db().execute("SELECT * FROM posts ORDER BY id").fetchall()
    return render_template("blog.html", posts=posts)


@app.route("/blog/<slug>")
def post(slug):
    p = get_db().execute("SELECT * FROM posts WHERE slug=?", (slug,)).fetchone()
    if not p:
        abort(404)
    more = get_db().execute("SELECT * FROM posts WHERE slug<>? ORDER BY id LIMIT 2", (slug,)).fetchall()
    return render_template("post.html", p=p, more=more)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:100]
        email = request.form.get("email", "").strip()[:150]
        topic = request.form.get("topic", "General")[:40]
        msg = request.form.get("message", "").strip()[:3000]
        if not name or not msg or not EMAIL_OK.match(email):
            flash("Please fill in your name, a valid email and a message.", "error")
            return render_template("contact.html", form=request.form), 400
        get_db().execute("INSERT INTO messages (name,email,topic,message) VALUES (?,?,?,?)", (name, email, topic, msg))
        get_db().commit()
        flash("Thank you! We received your message and will reply within one working day.", "success")
        return redirect(url_for("contact"))
    return render_template("contact.html", form={})


# ------------------------------------------------------------------ scanner
def _scan_inputs(src):
    return {
        "sender": (src.get("sender") or "")[:300],
        "reply_to": (src.get("reply_to") or "")[:300],
        "subject": (src.get("subject") or "")[:500],
        "body": (src.get("body") or "")[:20000],
        "attachments": (src.get("attachments") or "")[:500],
    }


@app.route("/scan", methods=["GET", "POST"])
def scan():
    result, data, scan_id = None, {}, None
    if request.method == "POST":
        data = _scan_inputs(request.form)
        if not (data["body"].strip() or data["subject"].strip()):
            flash("Paste the email's subject or message first.", "error")
        else:
            result = detector.analyze(**data)
            if g.user:
                scan_id = db.save_scan(get_db(), g.user["id"], data, result)
                get_db().commit()
    return render_template("scan.html", result=result, data=data, scan_id=scan_id, samples=detector.SAMPLES,
                           body_html=detector.highlight_html(data.get("body"), result["highlights"]) if result else "")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    payload = request.get_json(silent=True) or {}
    data = _scan_inputs(payload)
    if not (data["body"].strip() or data["subject"].strip()):
        return jsonify(error="Provide at least 'subject' or 'body'."), 400
    r = detector.analyze(**data)
    return jsonify(score=r["score"], verdict=r["verdict"], headline=r["headline"],
                   findings=[{k: f[k] for k in ("title", "detail", "severity", "category")} for f in r["findings"]],
                   advice=r["advice"])


@app.route("/sample/<key>")
def sample(key):
    s = detector.SAMPLES.get(key)
    return jsonify(s) if s else abort(404)


# ------------------------------------------------------------------ dashboard
def _recent(con, uid, days):
    since = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    return con.execute("SELECT * FROM scans WHERE user_id=? AND created_at>=? ORDER BY created_at DESC",
                       (uid, since)).fetchall()


def _risk(rows):
    total = len(rows)
    if total == 0:
        return {"level": "Unknown", "meter": 0, "note": "Scan some emails to see your risk level."}
    dang = sum(r["verdict"] == "dangerous" for r in rows)
    threat_rate = sum(r["verdict"] != "safe" for r in rows) / total
    meter = min(100, round(sum(r["score"] for r in rows) / total * 1.4))
    if dang >= 6 or threat_rate > 0.55:
        level, note = "High", "You are receiving many dangerous emails. Follow this week's tips and never click links in them."
    elif dang >= 2 or threat_rate > 0.3:
        level, note = "Medium", "Some risky emails are reaching you. Stay alert and keep scanning anything unusual."
    else:
        level, note = "Low", "Looking good. Keep scanning suspicious emails and stay alert."
    return {"level": level, "meter": meter, "note": note}


def _categories(rows):
    c = Counter()
    for r in rows:
        if r["verdict"] == "safe":
            continue
        for cat in {f["category"] for f in json.loads(r["findings_json"])}:
            c[cat] += 1
    return c.most_common(6)


def _tips(con, industry, n=3):
    rows = con.execute("SELECT text FROM tips WHERE industry IN (?, 'general') ORDER BY (industry=?) DESC, id", (industry, industry)).fetchall()
    texts = [r["text"] for r in rows]
    # rotate weekly so the tips feel fresh but stay stable within a week
    k = date.today().isocalendar()[1] % max(1, len(texts))
    texts = texts[k:] + texts[:k]
    return texts[:n]


@app.route("/dashboard")
@login_required
def dashboard():
    con, uid = get_db(), g.user["id"]
    rows = _recent(con, uid, 30)
    counts = Counter(r["verdict"] for r in rows)
    # last 14 days stacked bars
    today = date.today()
    days = [(today - timedelta(days=i)) for i in range(13, -1, -1)]
    per_day = {d.isoformat(): Counter() for d in days}
    for r in rows:
        d = r["created_at"][:10]
        if d in per_day:
            per_day[d][r["verdict"]] += 1
    mx = max([sum(c.values()) for c in per_day.values()] + [1])
    bars = [{"label": d.strftime("%d %b"), "short": d.strftime("%a")[0], "safe": per_day[d.isoformat()]["safe"],
             "suspicious": per_day[d.isoformat()]["suspicious"], "dangerous": per_day[d.isoformat()]["dangerous"],
             "total": sum(per_day[d.isoformat()].values())} for d in days]
    total = len(rows)
    pct = {k: (round(counts[k] * 100 / total) if total else 0) for k in ("safe", "suspicious", "dangerous")}
    return render_template("dashboard.html", total=total, counts=counts, pct=pct, bars=bars, mx=mx,
                           risk=_risk(rows), cats=_categories(rows), recent=rows[:6],
                           tips=_tips(con, g.user["industry"], 2),
                           blocked=counts["dangerous"] + counts["suspicious"])


@app.route("/history")
@login_required
def history():
    verdict = request.args.get("verdict", "")
    q = request.args.get("q", "").strip()
    page = max(1, request.args.get("page", 1, type=int))
    per = 10
    sql, args = "FROM scans WHERE user_id=?", [g.user["id"]]
    if verdict in ("safe", "suspicious", "dangerous"):
        sql += " AND verdict=?"
        args.append(verdict)
    if q:
        sql += " AND (subject LIKE ? OR sender LIKE ? OR body LIKE ?)"
        args += [f"%{q}%"] * 3
    total = get_db().execute("SELECT COUNT(*) " + sql, args).fetchone()[0]
    rows = get_db().execute("SELECT * " + sql + " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                            args + [per, (page - 1) * per]).fetchall()
    return render_template("history.html", rows=rows, verdict=verdict, q=q, page=page,
                           pages=max(1, -(-total // per)), total=total)


def _own_scan(scan_id):
    row = get_db().execute("SELECT * FROM scans WHERE id=? AND user_id=?", (scan_id, g.user["id"])).fetchone()
    if not row:
        abort(404)
    return row


@app.route("/scan/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    row = _own_scan(scan_id)
    findings = json.loads(row["findings_json"])
    result = {"score": row["score"], "verdict": row["verdict"], "findings": findings,
              "headline": detector._headline(row["verdict"], findings), "advice": detector._advice(row["verdict"]),
              "highlights": json.loads(row["highlights_json"])}
    return render_template("scan_detail.html", s=row, result=result,
                           body_html=detector.highlight_html(row["body"], result["highlights"]))


@app.route("/scan/<int:scan_id>/feedback", methods=["POST"])
@login_required
def scan_feedback(scan_id):
    _own_scan(scan_id)
    fb = request.form.get("feedback")
    if fb in ("correct", "wrong"):
        get_db().execute("UPDATE scans SET feedback=? WHERE id=?", (fb, scan_id))
        get_db().commit()
        flash("Thanks! Your feedback helps us improve." if fb == "correct" else
              "Thanks for telling us. We will review this result.", "success")
    return redirect(request.referrer or url_for("scan_detail", scan_id=scan_id))


@app.route("/scan/<int:scan_id>/delete", methods=["POST"])
@login_required
def scan_delete(scan_id):
    _own_scan(scan_id)
    get_db().execute("DELETE FROM scans WHERE id=?", (scan_id,))
    get_db().commit()
    flash("Scan deleted.", "success")
    return redirect(url_for("history"))


@app.route("/report")
@login_required
def report():
    con, uid = get_db(), g.user["id"]
    week = _recent(con, uid, 7)
    prev_since = (datetime.now() - timedelta(days=14)).strftime("%Y-%m-%d %H:%M:%S")
    week_since = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    prev = con.execute("SELECT COUNT(*) FROM scans WHERE user_id=? AND created_at>=? AND created_at<? AND verdict<>'safe'",
                       (uid, prev_since, week_since)).fetchone()[0]
    counts = Counter(r["verdict"] for r in week)
    threats = counts["dangerous"] + counts["suspicious"]
    cats = _categories(week)
    top = [r for r in week if r["verdict"] == "dangerous"][:5]
    if not week:
        summary = "You did not scan any emails this week. Paste anything suspicious into the scanner and we will explain it."
    else:
        summary = (f"This week you checked {len(week)} email{'s' if len(week) != 1 else ''}. "
                   f"{counts['dangerous']} {'was' if counts['dangerous'] == 1 else 'were'} dangerous and "
                   f"{counts['suspicious']} looked suspicious. ")
        if cats:
            summary += f"The most common warning sign was <strong>{cats[0][0].lower()}</strong>. "
        if threats > prev:
            summary += "That is more threats than last week, so please stay extra careful."
        elif threats < prev:
            summary += "That is fewer threats than last week. Well done!"
        else:
            summary += "That is about the same as last week."
    return render_template("report.html", week=week, counts=counts, cats=cats, top=top, summary=summary,
                           risk=_risk(week), tips=_tips(con, g.user["industry"], 3), prev=prev, threats=threats,
                           start=(date.today() - timedelta(days=6)), end=date.today())


# ------------------------------------------------------------------ accounts
@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        f = request.form
        name, email, pw = f.get("name", "").strip()[:100], f.get("email", "").strip().lower()[:150], f.get("password", "")
        industry = f.get("industry") if f.get("industry") in db.INDUSTRIES else "general"
        err = None
        if not name:
            err = "Please enter your name."
        elif not EMAIL_OK.match(email):
            err = "Please enter a valid email address."
        elif len(pw) < 8:
            err = "Password must be at least 8 characters."
        elif get_db().execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            err = "An account with that email already exists. Try logging in."
        if err:
            flash(err, "error")
            return render_template("register.html", form=f), 400
        cur = get_db().execute("INSERT INTO users (name,email,password_hash,business,industry) VALUES (?,?,?,?,?)",
                               (name, email, generate_password_hash(pw), f.get("business", "").strip()[:120], industry))
        get_db().commit()
        session.clear()
        session["uid"] = cur.lastrowid
        flash(f"Welcome to SafeInbox, {name.split()[0]}!", "success")
        return redirect(url_for("scan"))
    return render_template("register.html", form={})


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        u = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if u and check_password_hash(u["password_hash"], request.form.get("password", "")):
            session.clear()
            session["uid"] = u["id"]
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))
        flash("Incorrect email or password.", "error")
        return render_template("login.html", email=email), 401
    return render_template("login.html", email="")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, msg="We could not find that page."), 404


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, msg=getattr(e, "description", "Bad request.")), 400


@app.errorhandler(413)
def too_big(_e):
    return render_template("error.html", code=413, msg="That email is too large to scan."), 413


if _name_ == "_main_":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
