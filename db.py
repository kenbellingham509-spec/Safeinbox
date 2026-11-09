"""SafeInbox database layer (SQLite). Creates the schema and seeds demo data."""
import json
import os
import random
import sqlite3
from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash

import detector

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SAFEINBOX_DB", os.path.join(BASE_DIR, "instance", "safeinbox.db"))
DB_PATH = os.path.abspath(DB_PATH)

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    business      TEXT DEFAULT '',
    industry      TEXT NOT NULL DEFAULT 'general',
    plan          TEXT NOT NULL DEFAULT 'free',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sender        TEXT DEFAULT '',
    reply_to      TEXT DEFAULT '',
    subject       TEXT DEFAULT '',
    body          TEXT DEFAULT '',
    attachments   TEXT DEFAULT '',
    score         INTEGER NOT NULL,
    verdict       TEXT NOT NULL CHECK (verdict IN ('safe','suspicious','dangerous')),
    findings_json TEXT NOT NULL DEFAULT '[]',
    highlights_json TEXT NOT NULL DEFAULT '[]',
    feedback      TEXT CHECK (feedback IN ('correct','wrong') OR feedback IS NULL),
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scans_user_date ON scans(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(user_id, verdict);

CREATE TABLE IF NOT EXISTS posts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    slug       TEXT NOT NULL UNIQUE,
    title      TEXT NOT NULL,
    excerpt    TEXT NOT NULL,
    body_html  TEXT NOT NULL,
    category   TEXT NOT NULL DEFAULT 'Tips',
    read_mins  INTEGER NOT NULL DEFAULT 3,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tips (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    industry TEXT NOT NULL,
    text     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    email      TEXT NOT NULL,
    topic      TEXT DEFAULT 'General',
    message    TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

INDUSTRIES = {
    "general": "General / Other",
    "retail": "Retail & shops",
    "education": "Student / Education",
    "finance": "Finance & SACCOs",
    "agri": "Agribusiness",
    "tech": "Startup / Tech",
    "ngo": "NGO / Non-profit",
}

TIPS = [
    ("general", "Hover over a link before you click it. If the web address does not match the company, do not click."),
    ("general", "No bank, MTN or Airtel agent will ever ask for your PIN or OTP by email. Never share it."),
    ("general", "Turn on two-step verification for your email today. It stops most account takeovers."),
    ("retail", "Fake supplier invoices are common in retail. Call your supplier on a known number before paying a changed account."),
    ("retail", "Be careful with 'customer complaint' attachments. Scammers use them to install malware on shop computers."),
    ("education", "Scholarship and internship offers that ask for a 'processing fee' are scams. Real ones are free."),
    ("education", "Check that exam, portal or fee emails come from your university's real domain (for example .ac.ug)."),
    ("finance", "Treat any request to change payment details or release funds as high risk. Confirm by phone with a second person."),
    ("finance", "Members' data is valuable. Use separate passwords for email and your core banking tools."),
    ("agri", "Fake buyer emails offering large export orders often ask for 'inspection fees' first. Verify the buyer independently."),
    ("agri", "Agro-input discount offers sent by email should be checked directly with the supplier before paying."),
    ("tech", "Fake 'security alerts' from cloud or hosting providers aim to steal admin logins. Go to the dashboard by typing the address yourself."),
    ("tech", "Use a password manager. It will not auto-fill on look-alike sites, which is an instant phishing alarm."),
    ("ngo", "Donor and grant emails are a favourite lure. Confirm new bank details with the donor through a known contact."),
    ("ngo", "Be careful with 'urgent' requests that appear to come from your director. Call them to confirm."),
]

POSTS = [
    ("10-ways-to-spot-a-spam-email", "10 Ways to Spot a Spam Email", "Tips", 4,
     "A quick checklist anyone can use before clicking.",
     """<p>Spam and phishing emails are getting smarter, but they still leave clues. Use this checklist before you click anything.</p>
<ol>
<li><strong>Check the sender's real address.</strong> The name can say 'MTN Support' while the address ends in <code>.xyz</code>.</li>
<li><strong>Look for urgency.</strong> 'Act within 24 hours' is designed to stop you thinking.</li>
<li><strong>Be wary of generic greetings.</strong> 'Dear customer' means a mass mailing.</li>
<li><strong>Hover over links.</strong> The destination should match the company you expect.</li>
<li><strong>Never share a PIN, OTP or password.</strong> No real provider asks for these by email.</li>
<li><strong>Watch for money requests.</strong> Mobile money, gift cards, 'processing fees' and crypto are red flags.</li>
<li><strong>Be suspicious of prizes.</strong> You cannot win a lottery you never entered.</li>
<li><strong>Check attachments.</strong> Files ending in .exe, .scr or double extensions such as <code>invoice.pdf.exe</code> are dangerous.</li>
<li><strong>Notice odd wording and formatting.</strong> Strange capitals, many exclamation marks and huge sums of money are common in scams.</li>
<li><strong>When in doubt, ask.</strong> Paste it into SafeInbox or message our WhatsApp support before you act.</li>
</ol>"""),
    ("mobile-money-email-scams-uganda", "Mobile Money Email Scams: What Ugandans Should Know", "Awareness", 4,
     "How fraudsters mix email, SMS and calls to empty mobile money wallets.",
     """<p>Fraudsters know that many Ugandans use mobile money daily. A common trick is an email that looks like it came from your provider, claiming your account is 'suspended'.</p>
<p><strong>What they want:</strong> your PIN, your OTP, or for you to log in on a fake page that copies the real one.</p>
<p><strong>What to do:</strong> ignore the email, open your provider's app or dial the official code yourself, and report the message. Providers will never ask for your PIN.</p>
<p>If you already shared your PIN, call your provider's customer care immediately and change it.</p>"""),
    ("protecting-your-small-business-email", "Protecting Your Small Business Email in 5 Steps", "Business", 5,
     "Simple, low-cost steps that stop most email attacks.",
     """<p>You do not need an IT department to be safe. Start here:</p>
<ol>
<li>Turn on two-step verification for every staff email account.</li>
<li>Use a different strong password for email than for anything else.</li>
<li>Agree a rule: any change of bank details must be confirmed by phone.</li>
<li>Train staff to pause before clicking. Share one tip each week.</li>
<li>Scan anything suspicious with SafeInbox before opening it.</li>
</ol>"""),
    ("what-is-phishing", "What Is Phishing? A Plain-English Guide", "Basics", 3,
     "No jargon. Just what phishing is and how to avoid it.",
     """<p>Phishing is when a criminal pretends to be someone you trust, such as a bank, a boss or a delivery company, to trick you into giving away information or money.</p>
<p>The email usually contains a link to a fake website. When you type your password, the criminal receives it.</p>
<p><strong>Golden rule:</strong> never log in through a link in an email. Type the website address yourself or use the official app.</p>"""),
]

DEMO_EMAIL = "demo@safeinbox.ug"
DEMO_PASSWORD = "demo1234"


def connect(path=None):
    path = os.path.abspath(path or DB_PATH)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def save_scan(con, user_id, data, result, when=None):
    when = when or datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # local time, matches the app's date maths
    cur = con.execute(
        """INSERT INTO scans (user_id, sender, reply_to, subject, body, attachments, score, verdict,
                              findings_json, highlights_json, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,COALESCE(?, datetime('now')))""",
        (user_id, data.get("sender", ""), data.get("reply_to", ""), data.get("subject", ""),
         data.get("body", ""), data.get("attachments", ""), result["score"], result["verdict"],
         json.dumps(result["findings"]), json.dumps(result["highlights"]), when))
    return cur.lastrowid


def init_db(seed=True):
    con = connect()
    con.executescript(SCHEMA)
    if seed and con.execute("SELECT COUNT(*) FROM posts").fetchone()[0] == 0:
        for slug, title, cat, mins, excerpt, html in POSTS:
            con.execute("INSERT INTO posts (slug,title,category,read_mins,excerpt,body_html) VALUES (?,?,?,?,?,?)",
                        (slug, title, cat, mins, excerpt, html))
        con.executemany("INSERT INTO tips (industry, text) VALUES (?,?)", TIPS)
    if seed and con.execute("SELECT COUNT(*) FROM users WHERE email=?", (DEMO_EMAIL,)).fetchone()[0] == 0:
        seed_demo(con)
    con.commit()
    con.close()


def seed_demo(con):
    """A demo account with a realistic month of scan history."""
    cur = con.execute(
        "INSERT INTO users (name,email,password_hash,business,industry,plan) VALUES (?,?,?,?,?,?)",
        ("Grace Namuli", DEMO_EMAIL, generate_password_hash(DEMO_PASSWORD), "Namuli Fresh Foods", "retail", "business"))
    uid = cur.lastrowid
    rng = random.Random(7)
    keys = list(detector.SAMPLES)
    weights = [2, 1, 1, 1, 2, 2, 12, 9]  # mostly genuine mail, some threats
    now = datetime.now()
    for _ in range(38):
        key = rng.choices(keys, weights)[0]
        s = detector.SAMPLES[key]
        res = detector.analyze(s["sender"], s["subject"], s["body"], attachments=s["attachments"])
        when = (now - timedelta(days=rng.random() * 27, hours=rng.random() * 10)).strftime("%Y-%m-%d %H:%M:%S")
        save_scan(con, uid, s, res, when)
    con.execute("UPDATE scans SET feedback='correct' WHERE id % 4 = 0 AND user_id=?", (uid,))
