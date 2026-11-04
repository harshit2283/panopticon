#!/usr/bin/env python3
"""Deterministic labelled corpus for scoring panopticon's PII detection.

    python3 tests/pii/gen_corpus.py [--seed 20261104] [--n 5000] [--out tests/pii/corpus.jsonl]

Each line is one payload as one agent field would carry it:

    {"id": 7, "kind": "json", "field": "request_text", "header": null,
     "text": "...", "labels": [{"type": "EMAIL", "start": 9, "end": 26}]}

- field: which L7Message field the scorer puts the text in: "path" (scanned
  percent-decoded, like the agent does), "header" (value of header `header`),
  "request_text" (request body, Redis args) or "payload_text" (response
  body, SQL text, log lines).
- labels: byte spans in the text the agent scans (the percent-decoded form
  for "path"). Types: EMAIL PHONE CREDIT_CARD SSN AADHAAR PAN UPI GSTIN
  PASSPORT_IN IBAN IP_V4 JWT API_KEY AWS_KEY.

Policy decisions encoded here (see docs/BENCHMARKS.md, PII detection accuracy):
- every IPv4 address is labelled IP_V4: client addresses are personal data
  under GDPR and India's DPDP Act, and a passive observer cannot tell a
  client address from an infrastructure one;
- emails at example.com / example.org are real emails (test accounts use
  them and the capture oracles rely on them);
- names and street addresses are not generated: only the optional ML path
  could find them, and it is not in the default build.

Hard negatives (look like PII, are not): order and transaction IDs, UUIDs,
ISO timestamps, Unix epochs (s and ms), 12-digit numbers failing Verhoeff,
16-digit numbers failing Luhn, version strings and user agents, OIDs,
prices, SKUs, base64 blobs, hex hashes, retina asset names (logo@2x.png),
npm specs (lodash@4.17.21), PAN/GSTIN/IBAN look-alikes failing their checks,
passport-shaped codes without context.
"""
import argparse
import base64
import json
import random
import string
import urllib.parse

# ---------------------------------------------------------------- checksums

_VD = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VP = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]
_VINV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_ok(num):
    c = 0
    for i, d in enumerate(reversed(num)):
        c = _VD[c][_VP[i % 8][int(d)]]
    return c == 0


def verhoeff_digit(num):
    c = 0
    for i, d in enumerate(reversed(num)):
        c = _VD[c][_VP[(i + 1) % 8][int(d)]]
    return str(_VINV[c])


def luhn_ok(num):
    s = 0
    for i, d in enumerate(reversed(num)):
        d = int(d)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        s += d
    return s % 10 == 0


def luhn_digit(partial):
    for d in "0123456789":
        if luhn_ok(partial + d):
            return d


GST_CHARS = string.digits + string.ascii_uppercase


def gstin_check(first14):
    s = 0
    for i, ch in enumerate(first14):
        p = GST_CHARS.index(ch) * (2 if i % 2 else 1)
        s += p // 36 + p % 36
    return GST_CHARS[(36 - s % 36) % 36]


def iban_check(country, bban):
    digits = "".join(str(int(ch, 36)) for ch in bban + country + "00")
    return "%02d" % (98 - int(digits) % 97)


def iban_ok(iban):
    s = iban[4:] + iban[:4]
    return int("".join(str(int(ch, 36)) for ch in s)) % 97 == 1


# ---------------------------------------------------------------- values


class Gen:
    def __init__(self, seed):
        self.r = random.Random(seed)

    def digits(self, n, first="0123456789"):
        return self.r.choice(first) + "".join(self.r.choice(string.digits) for _ in range(n - 1))

    def alnum(self, n, chars=string.ascii_letters + string.digits):
        return "".join(self.r.choice(chars) for _ in range(n))

    def pick(self, seq):
        return self.r.choice(seq)

    # ---- positives

    FIRST = ["aarav", "priya", "rahul", "ananya", "vikram", "sneha", "arjun", "kavya", "rohan",
             "meera", "john", "emma", "liam", "olivia", "noah", "sofia", "wei", "fatima", "carlos", "yuki"]
    LAST = ["sharma", "patel", "iyer", "reddy", "nair", "gupta", "singh", "das", "smith", "garcia",
            "mueller", "tanaka", "khan", "silva", "brown", "kumar", "joshi", "mehta"]
    DOMAINS = ["gmail.com", "yahoo.co.in", "outlook.com", "rediffmail.com", "hotmail.com",
               "acme-corp.io", "mail.example.com", "example.com", "example.org", "proton.me",
               "infosys.com", "company.co.uk", "uni-heidelberg.de", "startup.in"]

    def email(self):
        f, l = self.pick(self.FIRST), self.pick(self.LAST)
        local = self.pick([f"{f}.{l}", f"{f}{self.digits(2)}", f"{f[0]}{l}", f"{f}_{l}",
                           f"{f}+orders", f"{l}.{f}{self.digits(4)}"])
        return local + "@" + self.pick(self.DOMAINS)

    def phone_in(self, bare_ok):
        n = self.digits(10, "6789")
        forms = [f"+91 {n[:5]} {n[5:]}", f"+91-{n}", f"+91{n}", f"0{n}", f"+91 {n}"]
        if bare_ok:
            forms += [n, n, n]
        return self.pick(forms)

    def phone_us(self):
        a, b, c = self.digits(3, "23456789"), self.digits(3, "23456789"), self.digits(4)
        return self.pick([f"({a}) {b}-{c}", f"{a}-{b}-{c}", f"+1 {a} {b} {c}", f"{a}.{b}.{c}",
                          f"+1-{a}-{b}-{c}", f"+1 ({a}) {b}-{c}"])

    def phone_intl(self):
        return self.pick([
            f"+44 20 {self.digits(4)} {self.digits(4)}", f"+44 7{self.digits(3)} {self.digits(6)}",
            f"+49 30 {self.digits(7)}", f"+33 1 {self.digits(2)} {self.digits(2)} {self.digits(2)} {self.digits(2)}",
            f"+65 {self.digits(4, '689')} {self.digits(4)}", f"+61 2 {self.digits(4)} {self.digits(4)}",
            f"+971 50 {self.digits(3)} {self.digits(4)}", f"+81 3-{self.digits(4)}-{self.digits(4)}"])

    def phone(self, bare_ok=False):
        k = self.r.random()
        if k < 0.5:
            return self.phone_in(bare_ok)
        if k < 0.8:
            return self.phone_us()
        return self.phone_intl()

    def card(self):
        brand = self.pick(["visa", "visa", "mc", "mc2", "amex", "rupay", "discover"])
        if brand == "amex":
            p = self.pick(["34", "37"]) + self.digits(12)
            n = p + luhn_digit(p)
            return self.pick([n, f"{n[:4]} {n[4:10]} {n[10:]}", f"{n[:4]}-{n[4:10]}-{n[10:]}"])
        prefix = {"visa": "4", "mc": self.pick(["51", "52", "53", "54", "55"]),
                  "mc2": str(self.r.randint(2221, 2720)), "rupay": self.pick(["60", "65", "81", "508"]),
                  "discover": "6011"}[brand]
        p = prefix + self.digits(15 - len(prefix))
        n = p + luhn_digit(p)
        return self.pick([n, n, " ".join(n[i:i + 4] for i in range(0, 16, 4)),
                          "-".join(n[i:i + 4] for i in range(0, 16, 4))])

    def ssn(self):
        area = self.pick([self.r.randint(1, 665), self.r.randint(667, 899)])
        return f"{area:03d}-{self.r.randint(1, 99):02d}-{self.r.randint(1, 9999):04d}"

    def aadhaar(self):
        p = self.digits(11, "23456789")
        n = p + verhoeff_digit(p)
        return self.pick([f"{n[:4]} {n[4:8]} {n[8:]}", f"{n[:4]} {n[4:8]} {n[8:]}", n,
                          f"{n[:4]}-{n[4:8]}-{n[8:]}"])

    def pan(self, holder=None):
        up = string.ascii_uppercase
        return (self.alnum(3, up) + (holder or self.pick("PPPPCHFATBLJG")) + self.alnum(1, up)
                + self.digits(4) + self.alnum(1, up))

    UPI_HANDLES = ["okaxis", "oksbi", "okhdfcbank", "okicici", "ybl", "ibl", "axl", "paytm", "upi",
                   "apl", "yapl", "ptyes", "ptsbi", "icici", "hdfcbank", "sbi", "axisbank", "kotak",
                   "fbl", "rapl", "freecharge", "jupiteraxis", "slc", "abfspay"]

    def upi(self):
        f, l = self.pick(self.FIRST), self.pick(self.LAST)
        local = self.pick([f"{f}.{l}", f"{f}{self.digits(3)}", self.digits(10, "6789"), f"{f}{l}"])
        return local + "@" + self.pick(self.UPI_HANDLES)

    def gstin(self):
        first = "%02d" % self.r.randint(1, 37) + self.pan(self.pick("CCFPPATH")) \
            + self.pick("123456789") + "Z"
        return first + gstin_check(first)

    def passport_in(self):
        return self.pick("ABCDEFGHJKLMNPRSTUVWY") + self.digits(1, "123456789") + self.digits(5) \
            + self.digits(1, "123456789")

    def iban(self):
        c = self.pick(["DE", "GB", "FR", "NL", "ES", "IT"])
        bban = {"DE": lambda: self.digits(18),
                "GB": lambda: self.alnum(4, string.ascii_uppercase) + self.digits(14),
                "FR": lambda: self.digits(23),
                "NL": lambda: self.alnum(4, string.ascii_uppercase) + self.digits(10),
                "ES": lambda: self.digits(20),
                "IT": lambda: self.alnum(1, string.ascii_uppercase) + self.digits(22)}[c]()
        iban = c + iban_check(c, bban) + bban
        if self.r.random() < 0.4:
            return " ".join(iban[i:i + 4] for i in range(0, len(iban), 4))
        return iban

    def ipv4(self):
        return self.pick([
            f"{self.r.randint(1, 223)}.{self.r.randint(0, 255)}.{self.r.randint(0, 255)}.{self.r.randint(1, 254)}",
            f"10.{self.r.randint(0, 255)}.{self.r.randint(0, 255)}.{self.r.randint(1, 254)}",
            f"192.168.{self.r.randint(0, 255)}.{self.r.randint(1, 254)}",
            f"203.0.113.{self.r.randint(1, 254)}"])

    def b64url(self, raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    def jwt(self):
        h = self.b64url(json.dumps({"alg": self.pick(["HS256", "RS256"]), "typ": "JWT"}).encode())
        p = self.b64url(json.dumps({"sub": self.digits(8), "iat": int(self.digits(10, "1")),
                                    "scope": self.pick(["read", "orders:write", "admin"])}).encode())
        return f"{h}.{p}.{self.alnum(43, string.ascii_letters + string.digits + '-_')}"

    def api_key_value(self):
        return self.pick([self.alnum(32), "sk_" + self.alnum(28), self.alnum(40, string.hexdigits.lower())])

    def aws_key(self):
        return self.pick(["AKIA", "ASIA"]) + self.alnum(16, string.ascii_uppercase + string.digits)

    # ---- hard negatives (each must NOT be PII)

    def uuid(self):
        h = "".join(self.r.choice("0123456789abcdef") for _ in range(32))
        return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-{self.pick('89ab')}{h[17:20]}-{h[20:]}"

    def iso_ts(self):
        return (f"2024-{self.r.randint(1, 12):02d}-{self.r.randint(1, 28):02d}T{self.r.randint(0, 23):02d}:"
                f"{self.r.randint(0, 59):02d}:{self.r.randint(0, 59):02d}"
                + self.pick(["Z", ".123Z", "+05:30", "+00:00", ".482913Z"]))

    def epoch(self):
        s = str(self.r.randint(1600000000, 1790000000))
        return self.pick([s, s + self.digits(3)])

    def order_id(self):
        return self.pick([f"ORD-2024-{self.digits(6)}", f"#{self.digits(9, '123456789')}",
                          f"INV/2024/{self.digits(5)}", f"PO{self.digits(8)}",
                          self.digits(10, "123456789"), f"ord_{self.alnum(14)}"])

    def bad_verhoeff12(self):
        while True:
            n = self.digits(12, "123456789")
            if not verhoeff_ok(n):
                return self.pick([n, f"{n[:4]} {n[4:8]} {n[8:]}"])

    def bad_luhn16(self):
        while True:
            n = self.pick(["4", "5", "6", "1", "9"]) + self.digits(15)
            if not luhn_ok(n):
                return self.pick([n, " ".join(n[i:i + 4] for i in range(0, 16, 4))])

    def version(self):
        return self.pick([f"{self.r.randint(0, 9)}.{self.r.randint(0, 30)}.{self.r.randint(0, 99)}",
                          f"v{self.r.randint(1, 5)}.{self.r.randint(0, 20)}.{self.r.randint(0, 9)}-rc.{self.r.randint(1, 5)}",
                          f"10.0.{self.r.randint(17000, 22631)}.{self.r.randint(1000, 4000)}",
                          f"1.3.6.1.4.1.{self.r.randint(300, 60000)}.{self.r.randint(1, 9)}"])

    def user_agent(self):
        return self.pick([
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{self.r.randint(110, 131)}.0.{self.r.randint(5000, 6999)}.{self.r.randint(10, 250)} Safari/537.36",
            f"okhttp/4.{self.r.randint(9, 12)}.{self.r.randint(0, 3)}",
            f"python-requests/2.{self.r.randint(25, 32)}.{self.r.randint(0, 3)}",
            f"Go-http-client/{self.pick(['1.1', '2.0'])}",
            f"PhonePe/{self.r.randint(20, 24)}.{self.r.randint(1, 12)}.{self.r.randint(1, 30)} (Android 14)"])

    def price(self):
        return self.pick([f"{self.r.randint(1, 99999)}.{self.r.randint(0, 99):02d}",
                          f"₹{self.r.randint(1, 999)},{self.r.randint(0, 999):03d}",
                          f"${self.r.randint(1, 999)}.{self.r.randint(0, 99):02d}",
                          str(self.r.randint(100, 9999999))])

    def sku(self):
        return self.pick([f"SKU-{self.digits(5)}-BLK-{self.pick(['S', 'M', 'L', 'XL'])}",
                          f"HX-{self.digits(4)}-{self.digits(4)}", f"{self.digits(4)}-{self.digits(3)}-{self.digits(3)}",
                          f"MDL-{self.digits(3)}-{self.digits(3)}-{self.digits(5)}",
                          f"PRD{self.alnum(2, string.ascii_uppercase)}{self.digits(4)}{self.alnum(1, string.ascii_uppercase)}"])

    def b64blob(self):
        return base64.b64encode(bytes(self.r.getrandbits(8) for _ in range(self.r.randint(24, 120)))).decode()

    def hexhash(self):
        return "".join(self.r.choice("0123456789abcdef") for _ in range(self.pick([32, 40, 64])))

    def fake_email(self):
        return self.pick([f"logo@{self.r.randint(2, 3)}x.png", f"icon-{self.alnum(4).lower()}@2x.webp",
                          f"lodash@4.17.{self.r.randint(10, 21)}", f"react@18.{self.r.randint(0, 3)}.0",
                          "@types/node", f"hero@3x.jpg"])

    def fake_pan(self):
        up = string.ascii_uppercase
        return self.alnum(3, up) + self.pick("DEIKMNOQRSUVWXYZ") + self.alnum(1, up) + self.digits(4) \
            + self.alnum(1, up)

    def fake_gstin(self):
        while True:
            first = "%02d" % self.r.randint(1, 37) + self.pan() + self.pick("123456789") + "Z"
            c = self.pick(GST_CHARS)
            if c != gstin_check(first):
                return first + c

    def fake_iban(self):
        while True:
            c = self.pick(["DE", "GB", "FR"])
            s = c + self.digits(2) + self.digits(18)
            if not iban_ok(s):
                return s

    def fake_passport(self):
        return self.passport_in()  # same shape, but placed with no passport context

    def negative(self):
        return self.pick([self.uuid, self.iso_ts, self.epoch, self.order_id, self.bad_verhoeff12,
                          self.bad_luhn16, self.version, self.price, self.sku, self.b64blob,
                          self.hexhash, self.fake_email, self.fake_pan, self.fake_gstin,
                          self.fake_iban, self.fake_passport])()


# ---------------------------------------------------------------- payloads

# (label, json key / form name, generator(g)) for positives; bare 10-digit
# phones only appear under a key that says "phone".
def positive_fields(g):
    return [
        ("EMAIL", g.pick(["email", "emailAddress", "customer_email", "contact", "user_email", "billing_email"]), g.email),
        ("PHONE", g.pick(["phone", "mobile", "mobile_no", "phoneNumber", "msisdn", "contact_number", "alt_phone"]), lambda: g.phone(bare_ok=True)),
        ("PHONE", g.pick(["shipping_contact", "tel", "support_line", "number"]), g.phone),
        ("CREDIT_CARD", g.pick(["card_number", "pan_card", "cc", "cardNumber", "number"]), g.card),
        ("SSN", g.pick(["ssn", "social", "tax_id", "taxpayer_id"]), g.ssn),
        ("AADHAAR", g.pick(["aadhaar", "aadhaar_no", "uid", "aadhaarNumber", "kyc_id"]), g.aadhaar),
        ("PAN", g.pick(["pan", "pan_no", "panNumber", "tax_pan"]), g.pan),
        ("UPI", g.pick(["upi", "vpa", "upi_id", "payee_vpa", "payer"]), g.upi),
        ("GSTIN", g.pick(["gstin", "gst_no", "gstNumber", "seller_gstin"]), g.gstin),
        ("PASSPORT_IN", g.pick(["passport", "passport_no", "passportNumber", "passport_number"]), g.passport_in),
        ("IBAN", g.pick(["iban", "account_iban", "beneficiary_iban", "payout_account"]), g.iban),
        ("IP_V4", g.pick(["ip", "client_ip", "remote_addr", "last_login_ip"]), g.ipv4),
        ("JWT", g.pick(["token", "id_token", "refresh_token", "jwt"]), g.jwt),
        ("AWS_KEY", g.pick(["aws_access_key_id", "accessKeyId", "key_id"]), g.aws_key),
    ]


def api_key_field(g):
    return g.pick(["api_key", "apiKey", "secret_key", "access_token", "secretKey", "api-key"]), g.api_key_value


NEG_KEYS = ["id", "order_id", "txn_id", "request_id", "trace_id", "created_at", "updated_at", "ts",
            "version", "sku", "amount", "price", "checksum", "etag", "image", "ref", "tracking_no",
            "build", "dependency", "code", "item_code", "ticket", "batch", "invoice", "oid"]


class Payload:
    """Text built from segments, with byte-span labels."""

    def __init__(self):
        self.parts, self.labels, self.pos = [], [], 0

    def add(self, s, label=None):
        b = len(s.encode())
        if label:
            self.labels.append({"type": label, "start": self.pos, "end": self.pos + b})
        self.parts.append(s)
        self.pos += b
        return self

    def text(self):
        return "".join(self.parts)


def pick_fields(g, dirty):
    """List of (key, value, label|None)."""
    out = []
    for _ in range(g.r.randint(2, 6)):
        k = g.pick(NEG_KEYS)
        out.append((k, g.negative(), None))
    if dirty:
        for _ in range(g.r.choice([1, 1, 1, 2, 2, 3])):
            if g.r.random() < 0.08:
                k, f = api_key_field(g)
                out.append((k, f(), "API_KEY"))
            else:
                label, k, f = g.pick(positive_fields(g))
                out.append((k, f(), label))
    g.r.shuffle(out)
    return out


def json_body(g, dirty):
    p = Payload().add("{")
    fields = pick_fields(g, dirty)
    for i, (k, v, lab) in enumerate(fields):
        if i:
            p.add(",")
        p.add(f'"{k}":"')
        if lab == "API_KEY":
            # the key name is part of what the detector needs; label the value
            p.add(v, lab)
        else:
            p.add(v, lab)
        p.add('"')
    if g.r.random() < 0.5:
        p.add(f',"status":"{g.pick(["active", "pending", "PAID", "shipped"])}","count":{g.r.randint(0, 500)}')
    return p.add("}")


def form_body(g, dirty):
    p = Payload()
    for i, (k, v, lab) in enumerate(pick_fields(g, dirty)):
        if i:
            p.add("&")
        p.add(f"{k}=")
        p.add(v, lab)
    return p


def query_path(g, dirty):
    p = Payload().add(g.pick(["/api/v1/users", "/checkout", "/v2/payments/verify", "/search", "/kyc/submit",
                              "/orders", "/track"]) + "?")
    for i, (k, v, lab) in enumerate(pick_fields(g, dirty)[:4]):
        if i:
            p.add("&")
        p.add(f"{k}=")
        p.add(v, lab)
    return p


def sql_text(g, dirty):
    fields = pick_fields(g, dirty)
    p = Payload()
    kind = g.r.random()
    if kind < 0.5:
        p.add(f"INSERT INTO {g.pick(['customers', 'orders', 'kyc_records', 'payments'])} (")
        p.add(", ".join(k for k, _, _ in fields) + ") VALUES (")
        for i, (_, v, lab) in enumerate(fields):
            if i:
                p.add(", ")
            p.add("'").add(v, lab).add("'")
        p.add(")")
    elif kind < 0.8:
        p.add(f"SELECT id, status FROM {g.pick(['users', 'orders', 'accounts'])} WHERE ")
        for i, (k, v, lab) in enumerate(fields[:3]):
            if i:
                p.add(" AND ")
            p.add(f"{k} = '").add(v, lab).add("'")
        p.add(f" LIMIT {g.r.randint(1, 100)}")
    else:
        p.add(f"UPDATE {g.pick(['users', 'profiles'])} SET ")
        for i, (k, v, lab) in enumerate(fields[:3]):
            if i:
                p.add(", ")
            p.add(f"{k} = '").add(v, lab).add("'")
        p.add(f" WHERE id = {g.r.randint(1, 10 ** 6)}")
    return p


def redis_args(g, dirty):
    # The Redis parser exports the key as path and the remaining args,
    # space-joined, as request_text: score the args.
    p = Payload()
    for i, (k, v, lab) in enumerate(pick_fields(g, dirty)):
        if i:
            p.add(" ")
        p.add(f"{k} ")
        p.add(v, lab)
    return p


LOG_TEMPLATES = [
    ("{lvl} payment.service request completed id={neg} latency_ms={ms} ", "user={val}"),
    ("{lvl} [kyc-worker] verifying document ref={neg} for customer ", "{val}"),
    ("{ts} {lvl} auth: login ok trace={neg} principal=", "{val}"),
    ("{lvl} notify: OTP sent to ", "{val} (attempt {n}) req={neg}"),
    ("{ts} {lvl} http: POST /v1/charge 201 {ms}ms ref={neg} from=", "{val}"),
    ("{lvl} payout queued batch={neg} to ", "{val} amount={price}"),
]


def log_line(g, dirty):
    p = Payload()
    pre, post = g.pick(LOG_TEMPLATES)
    fmt = dict(lvl=g.pick(["INFO", "WARN", "DEBUG", "ERROR"]), neg=g.negative(), ms=g.r.randint(1, 900),
               ts=g.iso_ts(), n=g.r.randint(1, 3), price=g.price())
    p.add(pre.format(**fmt))
    if dirty:
        label, _, f = g.pick(positive_fields(g))
        if label == "PASSPORT_IN":
            p.add("passport ")
        v_pre, v_post = post.split("{val}")
        p.add(v_pre.format(**fmt)).add(f(), label).add(v_post.format(**fmt))
    else:
        v = g.negative()
        p.add(post.replace("{val}", v).format(**fmt))
    if g.r.random() < 0.3:
        p.add(f" ua=\"{g.user_agent()}\"")
    return p


# Credential headers are masked wholesale by the agent; others are scanned.
def header(g, dirty):
    if dirty:
        name, mk = g.pick([
            ("X-Forwarded-For", lambda p: p.add(g.ipv4(), "IP_V4").add(", ").add(g.ipv4(), "IP_V4")),
            ("X-Real-IP", lambda p: p.add(g.ipv4(), "IP_V4")),
            ("X-User-Email", lambda p: p.add(g.email(), "EMAIL")),
            ("X-Customer-Phone", lambda p: p.add(g.phone(), "PHONE")),
            ("X-Customer-Mobile", lambda p: p.add(g.phone_in(True), "PHONE")),
            ("X-Upi-Vpa", lambda p: p.add(g.upi(), "UPI")),
            ("Authorization", lambda p: p.add("Bearer ").add(g.jwt(), "JWT")),
            ("X-Api-Key", lambda p: p.add(g.api_key_value(), "API_KEY")),
            ("Cookie", lambda p: p.add(f"sid={g.hexhash()}; user_email=").add(g.email(), "EMAIL")
             .add(f"; theme=dark")),
            ("Referer", lambda p: p.add("https://shop.example.in/account?email=").add(g.email(), "EMAIL")),
        ])
        p = Payload()
        mk(p)
        return name, p
    name, val = g.pick([
        ("User-Agent", g.user_agent), ("X-Request-Id", g.uuid), ("If-None-Match", lambda: f'W/"{g.hexhash()}"'),
        ("X-Trace-Id", g.hexhash), ("Date", lambda: "Tue, 05 Nov 2024 10:22:33 GMT"),
        ("X-Order-Ref", g.order_id), ("Content-Length", lambda: str(g.r.randint(0, 999999))),
        ("X-Client-Version", g.version), ("X-Timestamp", g.epoch), ("X-Idempotency-Key", g.uuid),
        ("X-Signature", g.b64blob), ("Authorization", lambda: "Basic " + g.b64blob()[:24]),
    ])
    return name, Payload().add(val())


KINDS = [  # (kind, field, builder, weight)
    ("json", "request_text", json_body, 18),
    ("json_resp", "payload_text", json_body, 12),
    ("form", "request_text", form_body, 10),
    ("query", "path", query_path, 15),
    ("header", "header", None, 15),
    ("sql", "payload_text", sql_text, 12),
    ("redis", "request_text", redis_args, 8),
    ("log", "payload_text", log_line, 10),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20261104)
    ap.add_argument("--n", type=int, default=5000)
    ap.add_argument("--dirty", type=float, default=0.3, help="share of payloads carrying PII")
    ap.add_argument("--out", default="tests/pii/corpus.jsonl")
    a = ap.parse_args()
    g = Gen(a.seed)
    weights = [k[3] for k in KINDS]
    with open(a.out, "w") as out:
        for i in range(a.n):
            kind, field, build, _ = g.r.choices(KINDS, weights)[0]
            dirty = g.r.random() < a.dirty
            hname = None
            if kind == "header":
                hname, p = header(g, dirty)
            else:
                p = build(g, dirty)
            scanned = p.text()
            text = scanned
            if field == "path":
                text = urllib.parse.quote(scanned, safe="/?=&-._~:,")
                assert urllib.parse.unquote_plus(text) == scanned
            assert len(scanned.encode()) < 4096, "keep payloads inside max_body_bytes"
            line = json.dumps({"id": i, "kind": kind, "field": field, "header": hname, "text": text,
                               "labels": p.labels}, ensure_ascii=False)
            # Synthetic AWS key IDs are written with a JSON \u escape so the
            # raw file never contains AKIA/ASIA and secret scanners (GitHub
            # push protection) don't flag the fixture. JSON parsing restores them.
            line = line.replace("AKIA", "AK\\u0049A").replace("ASIA", "AS\\u0049A")
            out.write(line + "\n")


if __name__ == "__main__":
    main()
