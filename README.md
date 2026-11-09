# SafeInbox Security Solutions 🛡️✉️
**Secure Your Inbox. Protect Your Future.**

AI-powered email security for small businesses, students and startups in Uganda. SafeInbox uses a navy
and sky-blue visual identity with a shield, envelope and checkmark logo.

## What it does
| Feature (from the proposal) | Where |
|---|---|
| AI spam & phishing detection with **plain-English reasons** | `/scan`, `detector.py` |
| Simple **dashboard** showing risk level | `/dashboard` |
| **Weekly summary** of flagged threats (printable) | `/report` |
| **Personalised tips** by industry | dashboard + report (`tips` table) |
| Website pages: Home, Services, Pricing, Blog, Contact | `/`, `/services`, `/pricing`, `/blog`, `/contact` |
| "10 Ways to Spot a Spam Email" guide | `/blog/10-ways-to-spot-a-spam-email` |
| 24/7 **WhatsApp** support button | floating button + footer |
| Accounts, scan history, search, feedback | `/register`, `/login`, `/history` |
| JSON API | `POST /api/scan` |

### How the "AI" works
`detector.py` is an **explainable** scoring engine: 30+ signals (urgency, credential/PIN requests, mobile-money & gift-card
requests, prize/inheritance bait, look-alike domains such as `mtn-momo-secure.xyz`, link text that hides its real
destination, raw-IP and shortened links, double-extension attachments like `invoice.pdf.exe`, mismatched reply-to, ...).
Each signal has a weight and a plain-English explanation; weights are combined into a 0–100 risk score
(`safe` < 30 ≤ `suspicious` < 60 ≤ `dangerous`). It understands negation, so "we will never ask for your PIN" is not flagged.
It is Uganda-aware (MTN, Airtel, URA, NSSF, Stanbic, Centenary, ...).

## Database (SQLite, auto-created at `instance/safeinbox.db`)
`users` · `scans` (score, verdict, findings JSON, user feedback) · `posts` (blog) · `tips` (by industry) · `messages` (contact form).
Indexed on `(user_id, created_at)` and `(user_id, verdict)`; scans are private per user. First run seeds a demo account,
blog posts, tips and ~38 sample scans so the dashboard is alive immediately.

## Run it
```bash
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5000
```
Demo login: **demo@safeinbox.ug / demo1234**

Optional environment variables: `SECRET_KEY`, `WHATSAPP_NUMBER` (e.g. `2567XXXXXXXX`), `PORT`, `SAFEINBOX_DB`.
To reset the data, delete the `instance/` folder.

## Tests
```bash
pip install pytest && python -m pytest -q
```

## Security notes
Passwords hashed (Werkzeug), CSRF tokens on all forms, HttpOnly/SameSite cookies, parameterised SQL, output escaped
(email text is HTML-escaped before highlighting), per-user data isolation, size limits on input.
For production use a real WSGI server (e.g. `gunicorn app:app`) over HTTPS and set `SECRET_KEY`.

## Project structure
```
app.py          routes, dashboard & report logic
detector.py     explainable detection engine + sample emails
db.py           SQLite schema, seed data
templates/      Jinja pages     static/  CSS, JS, logo
test_safeinbox.py
```
> Prices are illustrative; the scanner gives guidance, not a guarantee.
