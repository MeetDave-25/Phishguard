"""Run: python tests/test_i18n.py   Languages: key completeness, safe HTML, rendering, URL prefixes, forms, localized results."""
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
for k in [k for k in os.environ if k.startswith("PHISHGUARD_")]:
    del os.environ[k]
os.environ["PHISHGUARD_NO_ML"] = "1"

import i18n  # noqa: E402
import sitepages  # noqa: E402
from app import app  # noqa: E402

sitepages.DATA = Path(tempfile.mkdtemp())
c = app.test_client()
passed = 0
OTHER = [k for k in i18n.LANGS if k != "en"]


def check(name, cond, extra=""):
    global passed
    assert cond, f"FAIL: {name} {extra}"
    passed += 1
    print(f"  ok  {name}")


EN = json.loads((ROOT / "translations" / "en.json").read_text("utf-8"))
TR = {k: json.loads((ROOT / "translations" / f"{k}.json").read_text("utf-8")) for k in OTHER}
ph = lambda s: sorted(re.findall(r"\{(\w+)\}", s))  # noqa: E731
OPTIONAL = {"help.extra_c", "help.extra_d", "help.extra_href"}  # only some languages add a local helpline

print("translation files")
for lang, d in TR.items():
    check(f"{lang}: every English string is translated", not [k for k in EN if k not in d], [k for k in EN if k not in d][:5])
    check(f"{lang}: no unknown keys (typos)", not [k for k in d if k not in EN and k not in OPTIONAL], [k for k in d if k not in EN and k not in OPTIONAL])
    check(f"{lang}: {{placeholders}} match English exactly", not [k for k in d if k in EN and ph(d[k]) != ph(EN[k])], [k for k in d if k in EN and ph(d[k]) != ph(EN[k])][:5])
    check(f"{lang}: no empty values", all(str(v).strip() for v in d.values()))
    bad_tags = [k for k, v in d.items() if re.search(r"<(?!/?(?:em|b|br|strong|code)\b)(?!a href='\{\w+\}'>)(?!/a>)", v)]
    check(f"{lang}: only safe HTML tags (em/b/br/strong/code/a)", not bad_tags, bad_tags[:5])
    check(f"{lang}: no script/handler injection", not any(re.search(r"<script|javascript:|on\w+\s*=", v, re.I) for v in d.values()))
    different = sum(1 for k, v in d.items() if k in EN and v != EN[k])
    check(f"{lang}: actually translated (>=90% of strings differ from English)", different / len(EN) > 0.9, f"{different}/{len(EN)}")
check("English source has no empty values or script", all(str(v).strip() for v in EN.values()) and not any("<script" in v for v in EN.values()))

print("every key used by a template exists")
used = set()
for f in (ROOT / "templates").glob("*.html"):
    used |= set(re.findall(r"\bt[a]?\('([\w.]+)'", f.read_text("utf-8")))
    used |= set(re.findall(r"has_t\('([\w.]+)'", f.read_text("utf-8")))
missing = sorted(k for k in used if not k.endswith(".") and k not in EN and k not in OPTIONAL)  # "topic." + number is built dynamically
check(f"all {len(used)} template keys are defined in en.json", not missing, missing)
check("FAQ + server messages are defined", all(f"faq.{n}.q" in EN and f"faq.{n}.a" in EN for n in range(1, 9)) and all(f"topic.{n}" in EN for n in range(1, 7)))

print("pages render in every language")
EXPECT = {"hi": "स्कैम असली लगते हैं", "gu": "સ્કેમ સાચા લાગે છે", "mr": "स्कॅम खरे वाटतात", "es": "Las estafas parecen reales"}
for lang in OTHER:
    for path in ("/", "/contact", "/feedback", "/thank-you", "/about", "/privacy", "/terms", "/cookies", "/no-such-page"):
        r = c.get(f"/{lang}{path}")
        h = r.get_data(as_text=True)
        check(f"/{lang}{path} -> {r.status_code}, lang={lang}", r.status_code == (404 if "no-such" in path else 200) and f'<html lang="{lang}">' in h)
        visible = re.sub(r'<script type="application/json" id="i18n">.*?</script>', "", h, flags=re.S)  # JS fills those {n}/{err} later
        check(f"/{lang}{path} has no unresolved {{placeholders}} or Jinja", not re.search(r"\{(year|owner|n|about_url|privacy_url|review_url|contact_url)\}|\{\{|\{%", visible))
    h = c.get(f"/{lang}/").get_data(as_text=True)
    check(f"/{lang}/ shows the translated headline", EXPECT[lang] in h)
    check(f"/{lang}/ has no leftover English UI strings", not any(s in h for s in ("Check a link", "Privacy first", "Questions <em>", "Skip to the content", "Got a screenshot?")))
    check(f"/{lang}/ og:locale is {i18n.LANGS[lang][2]}", f'property="og:locale" content="{i18n.LANGS[lang][2]}"' in h)
    check(f"/{lang}/ og:image alt is translated", i18n.plain("meta.og_alt", lang)[:25] in h)

print("URL prefixes, canonical, hreflang, switcher")
h = c.get("/hi/").get_data(as_text=True)
no_switcher = re.sub(r'<details class="lang".*?</details>|<div class="sheet-langs">.*?</div></div>', "", h, flags=re.S)  # the switcher legitimately links to other languages
internal = re.findall(r'href="(/[^"#]*)', no_switcher)
unprefixed = [x for x in internal if not x.startswith(("/hi/", "/hi", "/static/", "/manifest")) and x != "/hi"]
check("every internal link in /hi/ keeps the /hi/ prefix", not unprefixed, unprefixed)
check("canonical of /hi/ is /hi/", 'rel="canonical" href="http://localhost/hi/"' in h)
langs_h = re.findall(r'<link rel="alternate" hreflang="([\w-]+)" href="([^"]+)"', h)
check("hreflang lists en, hi, gu, mr, es + x-default", {a for a, _ in langs_h} == {"en", "hi", "gu", "mr", "es", "x-default"}, langs_h)
check("hreflang URLs are correct", ("gu", "http://localhost/gu/") in langs_h and ("x-default", "http://localhost/") in langs_h and ("en", "http://localhost/") in langs_h)
check("og:locale:alternate lists the other languages", h.count('property="og:locale:alternate"') == 4)
en_h = c.get("/").get_data(as_text=True)
check("English home also has hreflang alternates", 'hreflang="hi" href="http://localhost/hi/"' in en_h)
priv = c.get("/hi/privacy").get_data(as_text=True)
check("English-only page in Hindi shows a notice + links to the English original", 'class="lang-note"' in priv and 'hreflang="en"' in priv)
check("English-only page canonical points at the English URL (no duplicate content)", 'rel="canonical" href="http://localhost/privacy"' in priv)
check("English-only page has no hreflang alternates", 'rel="alternate" hreflang' not in priv)
check("translated page has no English-only notice", 'class="lang-note"' not in h)
sw = c.get("/gu/contact").get_data(as_text=True)
check("language switcher links to the same page in other languages", 'href="/hi/contact" hreflang="hi"' in sw and 'href="/contact" hreflang="en"' in sw and 'href="/es/contact" hreflang="es"' in sw)
check("current language is marked", re.search(r'href="/gu/contact" hreflang="gu" lang="gu" aria-current="true"', sw) is not None)
check("mobile sheet lists the languages too", 'class="sheet-langs"' in sw)
check("languages are shown in their own script", all(n in sw for n in ("हिन्दी", "ગુજરાતી", "मराठी", "Español", "English")))
check("/hi without a slash works", c.get("/hi").status_code == 200)
check("'/his' is not mistaken for a language", c.get("/his").status_code == 404)

print("language data for the checker script")
blob = re.search(r'<script type="application/json" id="i18n">(.*?)</script>', c.get("/hi/").get_data(as_text=True), re.S).group(1)
js = json.loads(blob)
check("JS bundle is valid JSON, Hindi, contains result strings", js["bad_t"] == TR["hi"]["js.bad_t"] and "report_href" in js and "analyze" in js)
check("JS bundle falls back to English for missing keys", set(json.loads(re.search(r'id="i18n">(.*?)</script>', c.get("/").get_data(as_text=True), re.S).group(1))) == set(js))

print("forms keep the language")
sitepages._hits.clear()
good = {"t": sitepages._ser().dumps({"k": "contact", "t": int(time.time()) - 10}, salt="form"), "name": "Asha", "email": "a@example.com",
        "message": "यह संदेश परीक्षण के लिए है, कृपया अनदेखा करें।", "topic": "Other"}
r = c.post("/hi/contact", data=good, headers={"Origin": "http://localhost"})
check("POST /hi/contact redirects to /hi/thank-you with a signed token", r.status_code == 303 and r.headers["Location"].startswith("/hi/thank-you?for=contact&k="), r.headers.get("Location"))
ty = c.get(r.headers["Location"]).get_data(as_text=True)
check("thank-you page is in Hindi and still earns the conversion flag", "धन्यवाद" in ty and 'data-conv="1"' in ty)
bad = dict(good, email="nope", t=sitepages._ser().dumps({"k": "contact", "t": int(time.time()) - 10}, salt="form"))
r = c.post("/hi/contact", data=bad, headers={"Origin": "http://localhost"})
check("validation errors are shown in Hindi", r.status_code == 400 and TR["hi"]["err.email"] in r.get_data(as_text=True))
check("form posts back to the same language", 'action="/hi/contact"' in r.get_data(as_text=True))
check("topic options are translated but values stay English", 'value="Bug or problem"' in r.get_data(as_text=True) and TR["hi"]["topic.3"] in r.get_data(as_text=True))
r = c.post("/es/feedback", data={"t": sitepages._ser().dumps({"k": "review", "t": int(time.time()) - 10}, salt="form"), "rating": "9", "comment": "Muy útil, gracias."}, headers={"Origin": "http://localhost"})
check("Spanish rating error", r.status_code == 400 and TR["es"]["err.rating"] in r.get_data(as_text=True))

print("analysis results are translated (scores never change)")
URL = "http://paypa1-secure-login.xyz/verify/account"


def api(lang, text=URL, **kw):
    return c.post("/api/analyze", json={"input": text, "lang": lang, **kw})


en = api("en").get_json()
check("English result is unchanged", any(f["title"].startswith("Impersonates") for f in en["findings"]))
for lang in OTHER:
    r = api(lang).get_json()
    check(f"{lang}: score and verdict identical to English", r["score"] == en["score"] and r["verdict"] == en["verdict"])
    titles = [f["title"] for f in r["findings"]]
    check(f"{lang}: finding titles are translated", TR[lang]["f.impersonates.t"].replace("{brand}", "Paypal") in titles, titles)
    check(f"{lang}: details keep their numbers/names", any("paypa1-secure-login.xyz" in f["detail"] or "paypal.com" in f["detail"] for f in r["findings"]))
    check(f"{lang}: points are untouched", [f["points"] for f in r["findings"]] == [f["points"] for f in en["findings"]])
msg = "तुरंत अपना KYC अपडेट करें और OTP शेयर करें। http://sbi-kyc-update.top/login"
r = api("hi", msg).get_json()
check("Hindi message: titles translated and the user's own matched words are kept", any(f["title"] == TR["hi"]["f.t_otp.t"] for f in r["findings"])
      and any("OTP" in f["detail"] and f["detail"].startswith("मिला") for f in r["findings"]))
check("nested link findings in a message are translated", any(f["title"] == TR["hi"]["f.no_https.t"] for u in r["urls"] for f in u["findings"]))
check("unknown language falls back to English", api("xx").get_json()["findings"][0]["title"] == en["findings"][0]["title"])
check("missing language falls back to English", c.post("/api/analyze", json={"input": URL}).get_json()["score"] == en["score"])
check("empty-input error is localized", c.post("/api/analyze", json={"input": "", "lang": "gu"}).get_json()["error"] == TR["gu"]["err.empty"])
r = c.post("/api/analyze-image", data={"lang": "mr"})
check("image error is localized", r.status_code == 400 and r.get_json()["error"] == TR["mr"]["err.img"])
check("translating never raises on odd input", all(api(lang, "http://[::1]/x?a=b").status_code in (200, 400) for lang in i18n.LANGS))

print("fonts")
css = (ROOT / "static" / "style.css").read_text("utf-8")
for fam, f in (("Noto Sans Devanagari", "noto-sans-devanagari-devanagari-400-normal.woff2"), ("Noto Sans Gujarati", "noto-sans-gujarati-gujarati-400-normal.woff2"),
               ("Noto Serif Devanagari", "noto-serif-devanagari-devanagari-400-normal.woff2"), ("Noto Serif Gujarati", "noto-serif-gujarati-gujarati-400-normal.woff2")):
    check(f"{fam} is self-hosted and served", f in css and c.get(f"/static/fonts/{f}").status_code == 200)
check("Indic fonts use unicode-range so English visitors never download them", css.count("unicode-range:U+0900") == 3 and css.count("unicode-range:U+0A80") == 3)
check("no third-party font hosts", "fonts.googleapis" not in css and "gstatic" not in css)

print(f"\nall {passed} checks passed")
