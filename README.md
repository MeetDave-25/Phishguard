# PhishGuard

Scam/phishing checker for links, SMS/WhatsApp/email text and screenshots. Free, no API keys needed, privacy-first.

## Run locally
    pip install -r requirements.txt
    python app.py          # http://127.0.0.1:5000

## How it decides
1. **Rule engine** (explainable): lookalike/typosquat domains for 85+ brands, risky TLDs, free-hosting abuse, IDN homographs,
   OTP/KYC/lottery/digital-arrest phrases.
2. **ML hostname model** (offline, 1.4 MB): logistic regression on character n-grams, trained on real phishing data.
3. **Live blocklists**: OpenPhish feed, Cloudflare security DNS (1.1.1.2), optional Google Safe Browsing.
4. **Deep scan** (optional): domain age (RDAP) + TLS certificate. Only runs against public internet hosts (SSRF-guarded).
5. **Screenshots**: offline OCR (RapidOCR), then the same analysis.

## Accuracy
See [eval/REPORT.md](eval/REPORT.md): measured on held-out data, including limits. Reproduce / retrain:

    python eval/fetch_data.py     # downloads Phishing.Database, OpenPhish, Tranco
    python eval/train.py          # honest held-out metrics (add --final to retrain on all data before shipping)
    python eval/evaluate.py rules|ml|combined

Retrain monthly: phishing patterns drift.

## Deploy (free tier)
- **Render:** push to GitHub, then New > Blueprint (uses `render.yaml` + `Dockerfile`).
- **Docker anywhere:** `docker build -t phishguard . && docker run -p 8000:8000 phishguard`
- Behind a proxy set `PHISHGUARD_PROXY=1` (already set in the Dockerfile). Health check: `/healthz`.
- Built in: rate limiting, strict CSP + security headers, no request logging, no cookies, no third-party assets.

## Privacy
See `/privacy` (templates/privacy.html). Submissions are never stored or logged.

## Optional keys
| Feature | Env var |
|---|---|
| Google Safe Browsing | `GSB_API_KEY` |
| Claude AI second opinion | `ANTHROPIC_API_KEY` (UI toggle hidden without it) |

## Chrome extension
chrome://extensions -> Developer mode -> Load unpacked -> `extension/`. Talks only to 127.0.0.1:5000.

## Front-end
Editorial paper-and-ink design with a scroll-driven SVG story (`static/story.js` maps scroll position to a `--p` CSS variable; no libraries).
Fonts are self-hosted (SIL Open Font License): Instrument Serif, Inter, JetBrains Mono.

## Link inspection (on by default in the web UI)
`inspector.py` follows redirects and reads the destination page without running it: login/OTP/card forms posting to another
domain, Telegram/Discord exfiltration, brand impersonation, hidden iframes, obfuscated scripts. Hardened for hostile servers:
every hop must resolve to public IPs and we connect to the validated IP itself (no DNS-rebinding), ports 80/443/8080/8443 only,
6 redirects, 400 KB, 10 s. The destination sees the server's IP, never the user's.

## Tests
    python tests/test_inspector.py   # 33 checks incl. SSRF, slow-drip, false-positive regressions
    python tests/test_scoring.py     # 306 legitimate URL variants must not be flagged
See [eval/REPORT.md](eval/REPORT.md) for measured accuracy, limits, and bugs found.

## Languages
English, Hindi (`/hi/`), Gujarati (`/gu/`), Marathi (`/mr/`) and Spanish (`/es/`). Translations live in `translations/<code>.json`
(English is the source; a missing key falls back to English). The home page, checker, results, forms and thank-you page are
translated; the legal pages and About stay English (with a notice) because a wrong legal translation is worse than none.
Search engines get `hreflang` alternates and a multilingual sitemap. Indic fonts (Noto) are self-hosted and downloaded only when a
page uses those characters.

**Add a language:** add it to `LANGS` in `i18n.py`, copy `translations/en.json` to `translations/<code>.json` and translate the values
(keep `{placeholders}` and the few HTML tags), add scam phrases to `textrules_i18n.py`, add a font if the script needs one, then run
`python tests/test_i18n.py`. **Have native speakers review the translations**: they were written without one.

**Scam detection in other languages** (`textrules_i18n.py`): Hindi, Hinglish, Gujarati, Marathi, Spanish. Hand-tested only; there is no
labelled benchmark in these languages yet. **QR codes** in uploaded screenshots are decoded offline (`qrscan.py`) and their links are
analyzed ("quishing").

Tests: `python tests/test_i18n.py && python tests/test_multilang.py`
