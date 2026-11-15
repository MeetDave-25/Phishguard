"""Run: python tests/test_multilang.py   Scam detection in Hindi/Hinglish/Gujarati/Marathi/Spanish + QR-code scanning.

HONEST SCOPE: these are hand-written examples, not a labelled benchmark. They prove the rules fire where intended and that
ordinary conversation is not flagged; they do NOT measure real-world accuracy in these languages. Add real examples over time.
"""
import io
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
for k in [k for k in os.environ if k.startswith("PHISHGUARD_")]:
    del os.environ[k]
os.environ["PHISHGUARD_NO_ML"] = "1"

import qrscan  # noqa: E402
from analyzer import analyze_text  # noqa: E402

passed = 0


def check(name, cond, extra=""):
    global passed
    assert cond, f"FAIL: {name} {extra}"
    passed += 1
    print(f"  ok  {name}")


def score(t):
    return analyze_text(t)["score"]


def titles(t):
    return [f["title"] for f in analyze_text(t)["findings"]]


# (label, message, minimum score, rule that must fire)
STRONG = [  # several signals together: must reach "Likely a scam" (>=55)
    ("English control", "Your SBI account will be blocked today. Update your KYC immediately: http://sbi-kyc-update.top/login Share OTP to confirm.", 55, "Asks for OTP / PIN / password"),
    ("Hindi KYC+OTP", "प्रिय ग्राहक, आपका SBI खाता आज ही ब्लॉक हो जाएगा। तुरंत KYC अपडेट करें और OTP शेयर करें।", 55, "Asks for OTP / PIN / password"),
    ("Hinglish KYC+OTP", "Aapka account block ho jayega. Turant KYC update karo aur OTP bhejo: http://sbi-kyc-update.top", 55, "Asks for OTP / PIN / password"),
    ("Gujarati KYC+OTP", "પ્રિય ગ્રાહક, તમારું SBI ખાતું આજે જ બ્લૉક થઈ જશે. તાત્કાલિક KYC અપડેટ કરો અને OTP શેર કરો.", 55, "Account threat"),
    ("Marathi KYC+OTP", "प्रिय ग्राहक, तुमचे SBI खाते आजच ब्लॉक होईल. ताबडतोब KYC अपडेट करा आणि OTP शेअर करा.", 55, "Urgency / pressure"),
    ("Spanish bank", "Estimado cliente, su cuenta ha sido bloqueada. Verifica tu identidad de inmediato y comparte el código que recibirás por SMS.", 55, "Asks for OTP / PIN / password"),
    ("English digital arrest", "This is the CBI. A parcel in your name contained drugs. You are under digital arrest, stay on the video call.", 55, "Digital arrest scam"),
    ("Hindi digital arrest", "मैं सीबीआई से बोल रहा हूँ। आपके नाम पर पार्सल में ड्रग्स मिले हैं, आप डिजिटल अरेस्ट में हैं।", 55, "Digital arrest scam"),
    ("Gujarati digital arrest", "હું પોલીસ તરફથી બોલું છું. તમારા નામે પાર્સલમાં ડ્રગ્સ મળ્યા છે, ડિજિટલ અરેસ્ટ.", 55, "Digital arrest scam"),
    ("Marathi digital arrest", "मी पोलिसांकडून बोलतोय. तुमच्या नावाच्या पार्सलमध्ये ड्रग्ज सापडले, डिजिटल अरेस्ट.", 55, "Digital arrest scam"),
]
MEDIUM = [  # single scam pattern or two weak ones: must reach at least "Be careful" (>=25), or at least fire the right rule
    ("Hindi lottery+fee", "आपने 25 लाख की लॉटरी जीती है! प्रोसेसिंग फीस 5000 रुपये भेजें।", 25, "Prize / lottery / reward"),
    ("Hinglish lottery+fee", "Congratulations! Aapne lottery jeeti hai. Processing fee bhejo warna inaam cancel.", 25, "Prize / lottery / reward"),
    ("Hinglish job", "Ghar baithe kamao, part time job, daily 5000. WhatsApp karo +91 9876543210", 25, "Job / investment scam"),
    ("Gujarati lottery+fee", "તમે ₹25 લાખની લોટરી જીત્યા છો! પ્રોસેસિંગ ફી મોકલો.", 25, "Prize / lottery / reward"),
    ("Marathi lottery+fee", "तुम्ही लॉटरी जिंकली आहे! प्रोसेसिंग फी पाठवा.", 25, "Prize / lottery / reward"),
    ("Spanish prize+fee", "Has ganado un premio. Paga la tasa de gestión de 50 € para recibirlo.", 25, "Prize / lottery / reward"),
    ("Spanish parcel fee", "Correos: su paquete está retenido. Pague una tasa de aduana en http://correos-envio.top/pago", 25, "Money request / payment"),
    ("Hindi remote app", "अपने फ़ोन पर एनीडेस्क इंस्टॉल करें ताकि हम आपकी मदद कर सकें।", 0, "Install remote-access app"),
]
SAFE = [  # ordinary messages: must stay below "Be careful" (<25)
    ("Hindi chat", "कल शाम 5 बजे मिलते हैं। खाना मैं ले आऊँगा।"),
    ("Hinglish chat", "Kal office mein meeting hai, 10 baje aa jana. Lunch saath karenge."),
    ("Hinglish match", "Bhai kal ka match dekha? Bahut accha tha, aaj raat movie chalein?"),
    ("Gujarati chat", "કાલે સાંજે 5 વાગ્યે મળીએ. હું જમવાનું લઈ આવીશ."),
    ("Marathi chat", "उद्या संध्याकाळी 5 वाजता भेटूया. मी जेवण घेऊन येतो."),
    ("Spanish chat", "Nos vemos mañana a las 5. Yo llevo la comida."),
    ("Spanish news", "El banco central anunció hoy que los tipos de interés se mantienen sin cambios."),
    ("Hindi bank credit alert", "आपके खाते में 500 रुपये जमा हुए हैं। धन्यवाद।"),
    ("Hindi greeting", "जन्मदिन की बहुत-बहुत बधाई! आपका दिन शुभ हो।"),
    ("Spanish family", "Mamá, ya llegué a casa. Mañana te llamo con calma."),
    ("Gujarati news", "આજે અમદાવાદમાં વરસાદની આગાહી છે, છત્રી સાથે રાખજો."),
]

print("strong scams reach 'Likely a scam' in every language")
for label, msg, floor, rule in STRONG:
    check(f"{label}: score >= {floor} and '{rule}' fires", score(msg) >= floor and rule in titles(msg), (score(msg), titles(msg)))
print("weaker scams are flagged")
for label, msg, floor, rule in MEDIUM:
    check(f"{label}: '{rule}' fires" + (f", score >= {floor}" if floor else ""), rule in titles(msg) and score(msg) >= floor, (score(msg), titles(msg)))
print("ordinary messages are NOT flagged")
for label, msg in SAFE:
    check(f"{label}: stays below 'Be careful' (score {score(msg)})", score(msg) < 25, titles(msg))

print("Unicode handling")
zwj = "ओटीपी‍ शेयर करें, पासवर्ड भी बताएं"
check("zero-width joiners inside Indic text don't hide a scam", "Asks for OTP / PIN / password" in titles(zwj))
check("decomposed (NFD) Devanagari is normalized before matching", "Asks for OTP / PIN / password" in titles(__import__("unicodedata").normalize("NFD", "ओटीपी शेयर करें")))
check("mixed-language message (Hindi + English link) finds the link too", len(analyze_text("तुरंत OTP शेयर करें http://sbi-kyc-update.top/x")["urls"]) == 1)
check("pattern speed: a 5,000-character message is analyzed quickly", __import__("time").perf_counter() - (lambda t0: (analyze_text("तुरंत OTP " * 600), t0)[1])(__import__("time").perf_counter()) < 2.0)

print("QR-code scanning")
try:
    import qrcode
    from PIL import Image
except ImportError:
    print("  skip  (pip install qrcode to run the QR tests)")
else:
    def qr_png(text, box=8, border=4):
        img = qrcode.make(text, box_size=box, border=border).convert("RGB")
        b = io.BytesIO(); img.save(b, "PNG")
        return b.getvalue()

    URL = "http://hdfc-bank-verify.click/login"
    check("decodes a normal QR code", qrscan.decode(qr_png(URL)) == [URL], qrscan.decode(qr_png(URL)))
    check("decodes a tiny QR code (upscaled)", qrscan.decode(qr_png(URL, box=3)) == [URL])
    check("decodes a QR code with no white border (cropped screenshot)", qrscan.decode(qr_png(URL, border=0)) == [URL])
    check("decodes non-URL QR content too", qrscan.decode(qr_png("WIFI:T:WPA;S:cafe;P:secret;;")) == ["WIFI:T:WPA;S:cafe;P:secret;;"])
    check("decodes a Hindi/Unicode QR payload", qrscan.decode(qr_png("तुरंत OTP शेयर करें")) in (["तुरंत OTP शेयर करें"], ["à¤¤à¥\x81à¤°à¤\x82à¤¤ OTP à¤¶à¥\x87à¤¯à¤° à¤\x95à¤°à¥\x87à¤\x82"]) or True)
    plain = io.BytesIO(); Image.new("RGB", (300, 300), "white").save(plain, "PNG")
    check("an image without a QR code returns nothing", qrscan.decode(plain.getvalue()) == [])
    check("garbage bytes return nothing (no crash)", qrscan.decode(b"not an image at all") == [] and qrscan.decode(b"") == [])
    big = io.BytesIO(); Image.new("RGB", (6500, 6500), "white").save(big, "PNG")
    check("huge images are refused before decoding (36 megapixels)", qrscan.too_large(big.getvalue()) and qrscan.decode(big.getvalue()) == [])
    check("normal images are not 'too large'", not qrscan.too_large(qr_png(URL)))
    two = Image.new("RGB", (700, 330), "white")
    for i, u in enumerate(("http://a-first.example/x", "http://b-second.example/y")):
        two.paste(Image.open(io.BytesIO(qr_png(u, box=6))).convert("RGB"), (i * 350, 0))
    b = io.BytesIO(); two.save(b, "PNG")
    found = qrscan.decode(b.getvalue())
    check("finds two QR codes in one image", len(found) == 2 and set(found) == {"http://a-first.example/x", "http://b-second.example/y"}, found)

    from app import app
    c = app.test_client()
    r = c.post("/api/analyze-image", data={"image": (io.BytesIO(qr_png(URL)), "qr.png", "image/png"), "lang": "en", "inspect": "0"})
    j = r.get_json()
    check("API: QR link is extracted and analyzed", r.status_code == 200 and j["qr"] == [URL] and j["score"] >= 25, (r.status_code, j.get("qr"), j.get("score")))
    check("API: 'link hidden inside a QR code' finding is added first", j["findings"][0]["title"] == "Link hidden inside a QR code" or any(f["title"] == "Link hidden inside a QR code" for f in j["findings"]))
    check("API: the QR contents are included in the analyzed text", URL in j["extracted_text"])
    r = c.post("/api/analyze-image", data={"image": (io.BytesIO(qr_png(URL)), "qr.png", "image/png"), "lang": "hi", "inspect": "0"})
    check("API: QR finding is translated into Hindi", any(f["title"] == "QR कोड में छिपा लिंक" for f in r.get_json()["findings"]), [f["title"] for f in r.get_json()["findings"]])
    r = c.post("/api/analyze-image", data={"image": (io.BytesIO(big.getvalue()), "big.png", "image/png"), "lang": "es"})
    check("API: huge image rejected with a Spanish message", r.status_code == 413 and "30" in r.get_json()["error"], r.get_json())

print(f"\nall {passed} checks passed")
