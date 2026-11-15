# Going live: SEO, Google Analytics, Google Ads

Everything below is built in and tested (`python tests/test_site.py`, 173 checks). This page is what **you** still have to do,
because it needs your accounts, domain and decisions. Nothing here is legal advice.

## 1. Host it on HTTPS under your own domain
HTTPS itself is provided by your host (Render, Fly, Cloudflare, etc.). Set these environment variables:

| Variable | Value | Why |
|---|---|---|
| `PHISHGUARD_SITE_URL` | `https://yourdomain.com` | canonical links, share previews, sitemap use your real address |
| `PHISHGUARD_PROXY` | `1` | read the real client IP and HTTPS behind the host's proxy (already set in the Dockerfile) |
| `PHISHGUARD_FORCE_HTTPS` | `1` | 301-redirect any http:// request to https:// and add `upgrade-insecure-requests` |
| `PHISHGUARD_SECRET` | any long random string | signs form tokens; keep it identical across workers/restarts |

## 2. Google Search Console (free, recommended first)
1. Add your site at search.google.com/search-console, choose the **HTML tag** method.
2. Put the token (the part after `content=`) in `PHISHGUARD_GSC_TOKEN`. The tag is added to every page.
3. Submit `https://yourdomain.com/sitemap.xml`. `robots.txt` already points to it.

## 3. Google Analytics 4 (optional, consent-based)
1. Create a GA4 property; copy the Measurement ID (`G-XXXXXXXXXX`) into `PHISHGUARD_GA_ID`.
2. That's all. A cookie banner appears; **nothing loads from Google until a visitor clicks Accept**. Decline keeps it off.
   "Cookie settings" in the footer lets people change their mind. The privacy and cookie pages switch to describing Analytics automatically.
3. In GA4, turn **off** Google signals and ad personalization if you don't need them (Admin > Data collection).

## 4. Google Ads (optional)
Ads here means advertising **to** PhishGuard (the site shows no ads).
1. In Google Ads create a **conversion action** (Website, "Submit lead form"); you get a conversion ID `AW-XXXXXXXXX` and a label.
2. Set `PHISHGUARD_ADS_ID=AW-XXXXXXXXX` and `PHISHGUARD_ADS_CONVERSION=<label>`.
3. The conversion fires on `/thank-you` **only** after a real contact/review submission (the page needs a signed, 10-minute token),
   and only for visitors who accepted cookies. Visiting `/thank-you` directly counts nothing.
4. Use `https://yourdomain.com/` as the landing page; `/about`, `/privacy`, `/terms`, `/contact` already exist for ad review.

### Ads policy points to check before you spend money
- **Business identity & contact:** policies expect clear "who we are" and a way to reach you. `/about` and `/contact` cover this, but
  add whatever your country/Google requires (e.g. a business name or address). Your personal email is deliberately **not** published.
- **Claims:** don't advertise "100% safe/accurate". The site says 73% / ~1 in 4 slips through; keep ad copy consistent with that.
- **EEA/UK visitors:** Google requires consent (Consent Mode v2). This is implemented: default denied, updated only on Accept.
- **Legal pages:** have the privacy policy, terms and cookie policy reviewed for your jurisdiction (GDPR, India DPDP Act, etc.) before running ads.
  They describe exactly what the code does, but the last-updated date (`LEGAL_UPDATED` in `sitepages.py`) and your obligations are yours.
- Google can still disapprove an ad or account for reasons outside this code. Nothing here guarantees approval.

## 5. Contact form delivery and reviews
- Messages and reviews are saved in `data/messages.jsonl` and `data/reviews.jsonl` (on ephemeral hosts this disk resets on redeploy).
  To be emailed instead, set `PHISHGUARD_SMTP_HOST`, `PHISHGUARD_SMTP_PORT` (587), `PHISHGUARD_SMTP_USER`, `PHISHGUARD_SMTP_PASS`,
  `PHISHGUARD_SMTP_TO` (and optionally `PHISHGUARD_SMTP_FROM`). Use a mail account you control; never commit these.
- **Testimonials are never invented.** The homepage shows reviews only from `data/reviews_approved.json`, which you edit by hand
  after reading a submitted review (format: `[{"rating": 5, "comment": "…", "name": "Asha"}]`). With none approved, the section just
  invites a review. Only publish reviews from people who ticked the permission box (`"publish": true` in `reviews.jsonl`).
- Delete a person's stored message if they ask (see the privacy policy): remove its line from `data/messages.jsonl`.

## 6. Spam protection (built in, no CAPTCHA)
Hidden honeypot field, minimum-fill-time check, signed expiring form token, same-origin check, 5 submissions/hour per IP, max 2 links
per message, input length limits. Bots that trip the honeypot or the timer receive a normal-looking "thank you" and nothing is stored.
If spam still gets through, add Cloudflare Turnstile (free) later; it needs a key and a third-party script, so it is not on by default.

## 7. SEO checklist (done)
Unique `<title>` + meta description + canonical on every page; Open Graph and Twitter cards with a 1200x630 preview image (`static/og-image.png`,
regenerate with `python tools/make_assets.py`); alt text / `aria-label` for every illustration; one `<h1>` per page; internal links in nav,
footer, breadcrumbs and body text; `sitemap.xml` and `robots.txt`; JSON-LD for Organization, WebSite, SoftwareApplication, FAQPage and
BreadcrumbList; noindex on thank-you/offline/404 pages; custom 404; HTTPS redirect + HSTS; fast self-hosted fonts.
Still on you: get a few real backlinks, keep content fresh, and check Search Console for coverage issues.

## 8. Mobile app
Installable PWA (manifest + service worker + maskable icon), bottom tab bar, offline page, and "Share to PhishGuard" from other apps
(shared text stays in the browser). Android Chrome shows an install option in the **More** sheet; on iPhone use Share > Add to Home Screen.
Share-target works for the *installed* app on Android.
