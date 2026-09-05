# MailShield MVP — SIH26106

AI-powered email threat detection & forensic intelligence dashboard.
Detects phishing/BEC emails, validates SPF/DKIM/DMARC, traces the earliest
external IP in the routing chain, geolocates it, and produces a fraud score
with a downloadable PDF forensic report.

This is a deliberately collapsed, single-process MVP (Streamlit only — no
Node/React/Docker) built for a fast demo. See the fuller three-tier design
in `ARCHITECTURE_FUTURE.md` (if you kept your original doc) as the
production roadmap.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Train the classifier (one-time, ~1 second)

```bash
python3 train_classifier.py
```

This creates `core/model.pkl`. Re-run it any time you edit
`data/training_data.csv`.

## Run the app

```bash
streamlit run app.py
```

Opens at http://localhost:8501

## What's inside

```
core/
  header_forensics.py   - parses .eml, extracts Received chain, SPF/DKIM/DMARC, anomalies
  scorer.py              - converts header anomalies into a 0-100 risk score
  classifier.py           - TF-IDF + LogisticRegression phishing/BEC text classifier
  geo_lookup.py           - IP geolocation with offline-safe fallback (demo-proof)
  fusion.py               - combines all signals into one final fraud score
data/
  sample_emails/*.eml    - 5 realistic test emails (2 phishing, 1 BEC, 2 legit)
  training_data.csv      - labeled text used to train the classifier
app.py                    - Streamlit dashboard (the demo UI)
train_classifier.py       - one-time training script
```

## Demo script (rehearse this)

1. Open the app, select `legitimate_invoice.eml` — show low score, all green.
2. Switch to `phishing_paypal.eml` — score jumps to ~76, show SPF/DKIM failures,
   the flagged hosting-IP location on the map, and top ML terms ("verify",
   "account", "click").
3. Click "Generate Forensic Report" — show the PDF downloads instantly.
4. Mention: this MVP proves the core detection + forensics logic; the full
   production architecture (multi-tier, case management, campaign graphs,
   evidence vault) is the next phase.

## Notes on design decisions (for judge Q&A)

- **Why TF-IDF + Logistic Regression, not a transformer model?** Trains in
  under a second on a laptop with no GPU, and its coefficients are directly
  explainable — we can show exactly which words influenced the score, which
  matters for forensic/legal credibility.
- **Why hardcoded geo fallback?** Live IP geolocation depends on internet
  access and a third-party API's uptime — neither should be allowed to break
  a live demo. The fallback data is real geolocation data for the sample
  IPs, just cached locally.
- **Why is "earliest external IP" not 100% reliable?** Sophisticated
  attackers can spoof or manipulate Received headers. We present this as a
  "probable origin, not definitive," and the fusion score never relies on
  it alone — it's one of three independent signals.
