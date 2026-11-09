"""SafeInbox detection engine.

An explainable email-threat scorer. Every point of risk comes from a named
signal with a plain-English explanation, so the dashboard can show *why* an
email was flagged (the core promise of SafeInbox).

No external dependencies.
"""
import re
from html import escape
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Knowledge base (Uganda-aware)
# --------------------------------------------------------------------------
BRANDS = {
    # brand keyword -> legitimate domains
    "mtn": ["mtn.co.ug", "mtn.com"],
    "airtel": ["airtel.co.ug", "airtel.com"],
    "stanbic": ["stanbicbank.co.ug", "stanbic.com"],
    "centenary": ["centenarybank.co.ug"],
    "equity": ["equitybank.co.ug", "equitybankgroup.com"],
    "absa": ["absa.co.ug", "absa.africa"],
    "dfcu": ["dfcugroup.com"],
    "uganda revenue authority": ["ura.go.ug"],
    "ura": ["ura.go.ug"],
    "nssf": ["nssfug.org"],
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"],
    "facebook": ["facebook.com", "facebookmail.com", "meta.com"],
    "netflix": ["netflix.com"],
    "dhl": ["dhl.com"],
    "whatsapp": ["whatsapp.com"],
}
FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me",
            "protonmail.com", "mail.com", "aol.com", "icloud.com", "yandex.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly",
              "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "buff.ly"}
RISKY_TLDS = {"xyz", "top", "click", "link", "tk", "ml", "ga", "cf", "gq", "icu",
              "work", "support", "rest", "buzz", "cam", "monster", "zip", "mov"}
DANGEROUS_EXT = {"exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "wsf",
                 "jar", "msi", "apk", "iso", "lnk", "hta"}
MACRO_EXT = {"docm", "xlsm", "pptm", "xlsb", "zip", "rar", "7z"}

# (regex, weight 0..1, category, title, explanation)
PHRASE_SIGNALS = [
    (r"\b(urgent(ly)?|immediately|act now|right away|within (24|48) hours|"
     r"last (warning|notice|chance)|final notice|expires? (today|soon|in)|"
     r"as soon as possible|don'?t delay|failure to (comply|respond|act))\b",
     0.22, "Pressure tactics", "Creates false urgency",
     "Scammers rush you so you don't stop to think. Real organisations rarely demand action 'immediately'."),
    (r"\b(verify|confirm|validate|update|re-?activate|unlock|restore)\b.{0,40}"
     r"\b(account|password|identity|details|information|login|credentials|pin|wallet|profile)\b",
     0.34, "Credential theft", "Asks you to verify account details",
     "Legitimate companies do not ask you to 'verify' your password or PIN through email links."),
    (r"\b(password|passcode|one[- ]time (code|pin)|otp|pin number|mobile money pin|momo pin|"
     r"card number|cvv|security code|bank details|account number|national id|nin)\b",
     0.28, "Credential theft", "Requests sensitive personal information",
     "Passwords, PINs, OTP codes and card or ID numbers should never be sent by email."),
    (r"\b(suspended|locked|deactivated|disabled|restricted|compromised|unusual (activity|sign[- ]?in)|"
     r"unauthori[sz]ed (access|login|transaction)|will be (closed|terminated|blocked))\b",
     0.24, "Pressure tactics", "Threatens account suspension or lock-out",
     "Threats of closure are a classic phishing trick to make you click without thinking."),
    (r"\b(wire transfer|western union|moneygram|send (me )?(money|funds|payment)|"
     r"(mtn )?mobile money|airtel money|momo|gift cards?|itunes card|bitcoin|crypto(currency)?|"
     r"bank transfer|processing fee|release fee|clearance fee|advance fee)\b",
     0.26, "Money request", "Asks for money or unusual payment methods",
     "Requests for mobile money, gift cards, crypto or 'fees' are the most common fraud payment routes in Uganda."),
    (r"\b(you('ve| have)? (won|been selected|been chosen)|winner|lottery|jackpot|prize|"
     r"congratulations|claim your|free (iphone|gift|money|airtime|data)|"
     r"inheritance|beneficiary|next of kin|unclaimed funds|million (usd|dollars|shillings|ugx))\b",
     0.38, "Too good to be true", "Promises prizes, windfalls or inheritance",
     "Unexpected winnings and inheritances are advance-fee scams. If you never entered, you can't win."),
    (r"\b(dear (customer|user|client|friend|beneficiary|sir|madam|sir/madam|account holder|valued member)|"
     r"valued customer|to whom it may concern)\b",
     0.12, "Generic greeting", "Uses a generic greeting",
     "Real banks and service providers address you by name. 'Dear customer' suggests a mass mailing."),
    (r"\b(kindly|revert back|do the needful|your esteemed|reply (to|with) (this )?email)\b.{0,80}"
     r"\b(urgent|confidential|transfer|funds|business proposal)\b",
     0.2, "Scam wording", "Classic 'business proposal' scam wording",
     "Formal, unusual wording combined with confidential money talk matches advance-fee fraud patterns."),
    (r"\b(confidential|secret|do not (tell|share|inform)|keep (this )?(private|secret|between us))\b",
     0.16, "Pressure tactics", "Asks you to keep it secret",
     "Fraudsters isolate victims. Genuine organisations never ask you to hide a request from colleagues."),
    (r"\b(click (here|below|the link|this link)|follow (the|this) link|log ?in (here|below|now)|"
     r"open the attachment|download (the )?(attached|file|invoice|document))\b",
     0.14, "Call to action", "Pushes you to click a link or open a file",
     "Be careful when an email's main goal is to get you to click or download something."),
    (r"\b(invoice|payment (advice|receipt|confirmation)|remittance|purchase order|shipping (document|notice)|"
     r"delivery (failed|notification)|parcel|package (is )?(waiting|held|on hold))\b",
     0.1, "Lure", "Uses a common business-document lure",
     "Fake invoices and parcel notices are popular ways to make you open malicious links or files."),
]

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'\)\]]+)""")
ANCHOR_RE = re.compile(r"""(?is)<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""")
EMAIL_RE = re.compile(r"""([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})""")
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "$": "s"})


def _domain_of(url):
    if not re.match(r"(?i)^[a-z]+://", url):
        url = "http://" + url
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        host = ""
    return host


def _root(domain):
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "go", "ac", "or", "ne", "org", "gov"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


NEGATION_RE = re.compile(r"(never|do not|don'?t|will not|won'?t|would not|not)\s+(ever\s+)?(ask|request|send|share|email|call|text)[^.!?\n]*$", re.I)


def _negated(text, start):
    """True if the match sits in a sentence like 'we will never ask for your PIN'."""
    window = text[max(0, start - 70):start + 40]
    before = re.split(r"[.!?\n]", text[max(0, start - 70):start])[-1]
    return bool(NEGATION_RE.search(before + " "))


def _bn(brand):
    return brand.upper() if len(brand) <= 4 else brand.title()


def _levenshtein(a, b):
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _normalise_label(label):
    return label.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")


def _lookalike(domain):
    """Return (brand, legit_domain) if `domain` imitates a known brand domain."""
    root = _root(domain)
    if any(root == d for ds in BRANDS.values() for d in ds):
        return None
    label = root.split(".")[0]
    tokens = [t for t in re.split(r"[-.]", domain.rsplit(".", 1)[0]) if t]
    norm = _normalise_label(label)
    for brand, doms in BRANDS.items():
        for legit in doms:
            ll = legit.split(".")[0]
            if len(ll) >= 4:
                if norm == ll and label != ll:                      # paypa1.com, rnicrosoft.com
                    return brand, legit
                if len(ll) >= 5 and _levenshtein(label, ll) == 1:   # stanbicbamk.co.ug
                    return brand, legit
            # brand used as a whole word in the domain: mtn-momo-secure.xyz, paypal.verify.top
            if brand in tokens or ll in tokens or _normalise_label(ll) in [_normalise_label(t) for t in tokens if len(t) > 3]:
                if len(ll) >= 3:
                    return brand, legit
    return None


# --------------------------------------------------------------------------
# Main analysis
# --------------------------------------------------------------------------
def analyze(sender="", subject="", body="", reply_to="", attachments=""):
    """Analyse an email. Returns a dict with score, verdict, findings, highlights."""
    sender, subject, body = (sender or "").strip(), (subject or "").strip(), (body or "")
    reply_to, attachments = (reply_to or "").strip(), (attachments or "").strip()
    text = f"{subject}\n{body}"
    findings, highlights = [], []

    def add(weight, category, title, detail, evidence=None):
        findings.append({"weight": round(weight, 2), "category": category, "title": title,
                         "detail": detail, "evidence": evidence})

    # --- 1. Wording signals ------------------------------------------------
    for rx, weight, cat, title, detail in PHRASE_SIGNALS:
        matches = [m for m in re.finditer(rx, text, re.I | re.S) if not _negated(text, m.start())]
        if matches:
            ev = [m.group(0).strip() for m in matches][:3]
            bump = min(0.08, 0.03 * (len(matches) - 1))
            add(min(weight + bump, 0.6), cat, title, detail, ev[0] if len(ev[0]) < 90 else ev[0][:87] + "…")
            highlights += [e for e in ev if len(e) < 90]

    # --- 2. Style signals ---------------------------------------------------
    letters = [c for c in text if c.isalpha()]
    if len(letters) > 25:
        caps = sum(c.isupper() for c in letters) / len(letters)
        if caps > 0.35:
            add(0.12, "Style", "Excessive CAPITAL LETTERS", "Shouting in capitals is common in spam and scam messages.")
    if text.count("!") >= 4:
        add(0.08, "Style", "Too many exclamation marks", "Professional emails rarely use several exclamation marks.")
    if re.search(r"[A-Z][a-z]+\s{2,}[a-z]|\$\s?\d{1,3}(,\d{3}){2,}|\bUSD\s?\d{1,3}(,\d{3}){2,}", text):
        add(0.1, "Style", "Unusual formatting or very large sums", "Odd spacing and millions of dollars are typical of scam templates.")

    # --- 3. Sender checks ----------------------------------------------------
    sm = EMAIL_RE.search(sender)
    s_domain = sm.group(2).lower() if sm else ""
    s_name = re.sub(r"<.*?>|[\"']", "", sender).strip().lower() if sender else ""
    if sender and not sm:
        add(0.12, "Sender", "Sender address is missing or malformed", "A valid sender address is expected. Check who really sent it.")
    if s_domain:
        look = _lookalike(s_domain)
        if look:
            add(0.5, "Impersonation", f"Sender domain imitates {_bn(look[0])}",
                f"'{s_domain}' looks like '{look[1]}' but is not the real domain. This is called a look-alike domain.", s_domain)
        else:
            for brand, doms in BRANDS.items():
                if re.search(r"\b" + re.escape(brand) + r"\b", s_name) and _root(s_domain) not in doms:
                    add(0.4, "Impersonation", f"Claims to be {_bn(brand)} but sent from {s_domain}",
                        f"The display name says {_bn(brand)}, yet the real address belongs to a different domain.", sender[:80])
                    break
        tld = s_domain.rsplit(".", 1)[-1]
        if tld in RISKY_TLDS:
            add(0.2, "Sender", f"Sender uses a risky domain ending (.{tld})",
                "Cheap domain endings like .xyz or .top are heavily used by scammers.", s_domain)
        if s_domain in FREEMAIL and re.search(r"\b(bank|support|security|billing|helpdesk|service|official|"
                                              r"revenue|authority|payroll|hr|ceo|director)\b", s_name):
            add(0.3, "Impersonation", "Official-sounding name on a free email address",
                "Banks and authorities do not email from Gmail, Yahoo or Outlook addresses.", sender[:80])
        if re.search(r"\d{4,}", s_domain.split(".")[0]) or s_domain.count("-") >= 2:
            add(0.12, "Sender", "Sender domain looks auto-generated", "Random numbers and many hyphens in a domain are suspicious.", s_domain)
    if reply_to:
        rm = EMAIL_RE.search(reply_to)
        if rm and s_domain and _root(rm.group(2).lower()) != _root(s_domain):
            add(0.32, "Sender", "Replies go to a different address",
                f"Replies would go to '{rm.group(2).lower()}', not '{s_domain}'. Scammers use this to steal your response.", reply_to)

    # --- 4. Link checks ------------------------------------------------------
    urls, seen = [], set()
    for m in URL_RE.finditer(body):
        u = m.group(1).rstrip(".,;:!?")
        if u not in seen:
            seen.add(u)
            urls.append(u)
    for href, label in ANCHOR_RE.findall(body):
        if href not in seen:
            seen.add(href)
            urls.append(href)
        shown = URL_RE.search(re.sub(r"<[^>]+>", "", label))
        if shown and _root(_domain_of(shown.group(1))) != _root(_domain_of(href)):
            add(0.45, "Links", "Link text hides a different destination",
                f"The link says '{shown.group(1)[:40]}' but really goes to '{_domain_of(href)}'.", href[:80])
    flagged_link = False
    for u in urls[:12]:
        d = _domain_of(u)
        if not d:
            continue
        ev = u if len(u) < 70 else u[:67] + "…"
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", d):
            add(0.5, "Links", "Link points to a raw IP address", "Real companies use names, not numbers, in their links.", ev)
            flagged_link = True
        elif _root(d) in SHORTENERS or d in SHORTENERS:
            add(0.25, "Links", "Shortened link hides the destination", "You cannot see where this link really leads before clicking.", ev)
            flagged_link = True
        elif d.startswith("xn--") or ".xn--" in d:
            add(0.4, "Links", "Link uses disguised (punycode) characters", "Foreign look-alike letters can make a fake site look real.", ev)
            flagged_link = True
        else:
            look = _lookalike(d)
            if look:
                add(0.5, "Impersonation", f"Link imitates {_bn(look[0])}",
                    f"'{d}' is not '{look[1]}'. It is built to look like it.", ev)
                flagged_link = True
            elif d.rsplit(".", 1)[-1] in RISKY_TLDS:
                add(0.25, "Links", f"Link uses a risky domain ending (.{d.rsplit('.', 1)[-1]})", "Scammers favour cheap domain endings.", ev)
                flagged_link = True
            elif d.count(".") >= 4:
                add(0.18, "Links", "Link has an unusually long web address", "Many sub-domains are used to bury the real site name.", ev)
                flagged_link = True
        if "@" in u.split("//", 1)[-1].split("/", 1)[0]:
            add(0.4, "Links", "Link contains an '@' trick", "Everything before '@' is ignored by browsers; it disguises the real site.", ev)
            flagged_link = True
        if u.lower().startswith("http://") and not flagged_link and re.search(r"login|verify|secure|account|bank|pay", u, re.I):
            add(0.15, "Links", "Login-style link is not encrypted (http)", "Sensitive pages should always use https.", ev)
    if len(urls) >= 5:
        add(0.08, "Links", "Contains many links", "Messages stuffed with links are often promotional or malicious.")

    # --- 5. Attachments --------------------------------------------------------
    for name in [a.strip().lower() for a in re.split(r"[,\n;]", attachments) if a.strip()]:
        parts = name.split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        if len(parts) >= 3 and ext in DANGEROUS_EXT | MACRO_EXT:
            add(0.6, "Attachment", f"Disguised file: {name}", "A double extension (like invoice.pdf.exe) hides a program inside a harmless-looking name.", name)
        elif ext in DANGEROUS_EXT:
            add(0.6, "Attachment", f"Dangerous file type (.{ext})", "Programs and scripts attached to email can install malware.", name)
        elif ext in MACRO_EXT:
            add(0.3, "Attachment", f"Risky attachment type (.{ext})", "Macro-enabled files and archives are commonly used to deliver malware.", name)

    # --- 6. Brand + money/credentials context bonus ---------------------------------
    low = text.lower()
    named = [b for b in BRANDS if len(b) > 3 and b in low]
    cats = {f["category"] for f in findings}
    if named and ("Credential theft" in cats or "Money request" in cats) and not any(f["category"] == "Impersonation" for f in findings):
        add(0.12, "Impersonation", f"Mentions {_bn(named[0])} while asking for credentials or money",
            "Check this with the organisation directly using the number on their official website.")

    # --- Score -----------------------------------------------------------------
    p = 1.0
    for f in findings:
        p *= (1 - f["weight"])
    score = round((1 - p) * 100)
    cats = {f["category"] for f in findings}
    if {"Credential theft", "Pressure tactics"} <= cats and ("Links" in cats or "Impersonation" in cats):
        score = max(score, 80)  # textbook phishing combo
    score = min(score, 99)
    if not findings:
        score = 2
    verdict = "dangerous" if score >= 60 else "suspicious" if score >= 30 else "safe"
    findings.sort(key=lambda f: -f["weight"])
    for f in findings:
        f["severity"] = "high" if f["weight"] >= 0.4 else "medium" if f["weight"] >= 0.2 else "low"

    return {
        "score": score,
        "verdict": verdict,
        "findings": findings,
        "highlights": sorted(set(highlights), key=len, reverse=True),
        "links": urls[:12],
        "headline": _headline(verdict, findings),
        "advice": _advice(verdict),
        "categories": sorted({f["category"] for f in findings}),
    }


def _headline(verdict, findings):
    if verdict == "safe":
        return "No major warning signs found."
    top = "; ".join(dict.fromkeys(f["title"] for f in findings[:3]))
    lead = "This looks like a scam" if verdict == "dangerous" else "This email looks suspicious"
    return f"{lead}. Main reasons: {top}."


def _advice(verdict):
    return {
        "dangerous": ["Do not click any links or open attachments.",
                      "Do not reply or share any password, PIN, OTP or money.",
                      "Delete it, or forward it to SafeInbox support on WhatsApp for a human check.",
                      "If you already clicked or paid, change your passwords now and call your bank or mobile money provider."],
        "suspicious": ["Do not click links yet. Type the company's website address yourself instead.",
                       "Contact the sender using a phone number you already trust.",
                       "Ask SafeInbox support if you are unsure."],
        "safe": ["Looks fine, but stay alert. No scanner is perfect.",
                 "Never share passwords or PINs by email, even if a message seems genuine."],
    }[verdict]


def highlight_html(text, phrases):
    """Escape `text` and wrap each flagged phrase in <mark>. Safe to render with |safe."""
    out = escape(text or "")
    for ph in phrases or []:
        ep = escape(ph)
        out = re.sub(re.escape(ep), lambda m: f"<mark>{m.group(0)}</mark>", out, flags=re.I)
    return out.replace("\n", "<br>")


# --------------------------------------------------------------------------
# Demo samples (also used to seed the dashboard)
# --------------------------------------------------------------------------
SAMPLES = {
    "mtn_phish": {
        "label": "Fake MTN MoMo alert",
        "sender": "MTN MoMo Support <support@mtn-momo-secure.xyz>",
        "subject": "URGENT: Your Mobile Money account has been suspended",
        "body": "Dear customer,\n\nWe detected unusual activity on your MTN Mobile Money account. Your account will be "
                "closed within 24 hours unless you verify your account details and PIN.\n\n"
                "Click here to restore access: http://mtn-momo-secure.xyz/verify-login\n\nMTN Uganda Security Team",
        "attachments": "",
    },
    "lottery": {
        "label": "Lottery / inheritance scam",
        "sender": "Barrister James Okello <jokello.legal2024@gmail.com>",
        "subject": "CONGRATULATIONS!!! You have been selected as beneficiary",
        "body": "Dear Beneficiary,\n\nYou have been chosen as next of kin to unclaimed funds of USD 8,500,000. "
                "To release the funds you must pay a small processing fee through mobile money. "
                "This matter is strictly confidential, do not tell anyone!!!\n\nReply to this email immediately.",
        "attachments": "",
    },
    "invoice_malware": {
        "label": "Malicious invoice attachment",
        "sender": "Accounts <billing@dhl-delivery-notice.top>",
        "subject": "Invoice and shipping documents - parcel on hold",
        "body": "Hello,\n\nYour parcel is on hold. Please download the attached invoice and open the attachment "
                "to confirm delivery. Track here: http://192.168.44.12/track?id=88231",
        "attachments": "Invoice_88231.pdf.exe",
    },
    "ura_fake": {
        "label": "Fake URA tax notice",
        "sender": "URA Notices <notices@ura-go-ug.com>",
        "subject": "Final notice: confirm your TIN details",
        "body": "Dear taxpayer, your Uganda Revenue Authority profile is restricted. You must update your "
                "account information and bank details immediately to avoid penalties. "
                '<a href="http://ura-refunds.click/login">https://www.ura.go.ug/portal</a>',
        "attachments": "",
    },
    "supplier_change": {
        "label": "Supplier bank-detail change",
        "sender": "Accounts <accounts@freshsupplies-ug.com>",
        "subject": "Updated bank details for your next payment",
        "body": "Hello,\n\nPlease note our bank account has changed. Kindly confirm the new account details "
                "before you make your next payment. The invoice is attached for your records. "
                "Reply to this email to confirm.",
        "attachments": "",
    },
    "short_link": {
        "label": "Odd shortened link",
        "sender": "Promo Team <offers@market-deals.co.ug>",
        "subject": "Your delivery is waiting",
        "body": "Hi, your package is waiting for you. Please follow this link to confirm delivery: https://bit.ly/3xYz9Qa",
        "attachments": "",
    },
    "legit_meeting": {
        "label": "Genuine team email",
        "sender": "Sarah Nakato <sarah@kampalabakery.co.ug>",
        "subject": "Meeting notes from Tuesday",
        "body": "Hi team,\n\nThanks for joining on Tuesday. Notes are in the shared folder. "
                "Please send me your sales figures for October by Friday so we can plan the next order.\n\nBest,\nSarah",
        "attachments": "",
    },
    "legit_newsletter": {
        "label": "Genuine newsletter",
        "sender": "Stanbic Bank <alerts@stanbicbank.co.ug>",
        "subject": "Your October statement is ready",
        "body": "Hello Grace,\n\nYour monthly statement is now available in the Stanbic app. "
                "We will never ask for your PIN or password by email. Visit https://www.stanbicbank.co.ug anytime.",
        "attachments": "",
    },
}
