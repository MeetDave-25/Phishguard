import os
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, redirect, request

import ai
import i18n
import inspector
import mlmodel
import qrscan
import reputation
import sitepages
from analyzer import analyze, verdict

mlmodel.available()  # load the model at startup so the first request is not slower or unscored

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024
IMAGE_TYPES = {"image/png", "image/jpeg", "image/webp", "image/gif"}
app.register_blueprint(sitepages.bp)
app.wsgi_app = i18n.LangPrefixMiddleware(app.wsgi_app)  # /hi/about is served by the /about route in Hindi

# Behind a reverse proxy (Render, Fly, Cloudflare, nginx) set PHISHGUARD_PROXY=1 so client IPs and HTTPS are read correctly.
if os.getenv("PHISHGUARD_PROXY"):
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ---- abuse protection: tiny in-memory sliding-window limiter (per IP, nothing written to disk) ----
LIMITS = {"analyze": (30, 60), "image": (8, 60)}  # (requests, per seconds)
_hits: dict = defaultdict(deque)


def rate_limited(kind: str) -> bool:
    max_req, window = LIMITS[kind]
    now, key = time.time(), (kind, request.remote_addr)
    q = _hits[key]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= max_req:
        return True
    q.append(now)
    if len(_hits) > 5000:  # bound memory
        for k in [k for k, v in _hits.items() if not v or now - v[-1] > 120]:
            _hits.pop(k, None)
    return False


@app.before_request
def force_https():
    """In production set PHISHGUARD_FORCE_HTTPS=1 (and PHISHGUARD_PROXY=1 behind a proxy): plain-HTTP requests get a 301 to HTTPS."""
    if sitepages.config()["force_https"] and not request.is_secure and request.path != "/healthz":
        return redirect(request.url.replace("http://", "https://", 1), 301)


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = sitepages.csp()
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin" if sitepages.config()["ga_id"] or sitepages.config()["ads_id"] else "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    if request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.path.startswith("/api/") or request.path == "/healthz":
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Robots-Tag"] = "noindex"
    return resp


def full_analysis(text: str, live: bool, use_ai: bool, inspect: bool = False) -> dict:
    result = analyze(text, live=live)
    if "error" in result:
        return result
    result = reputation.enrich(result)
    if inspect:
        result = inspector.run(result)
    if use_ai and ai.available():
        try:
            result["ai"] = ai.analyze_message(text, result)
            # a confident AI "dangerous" on a message the rules missed should still raise the alarm
            if result["ai"]["verdict"] == "dangerous" and result["score"] < 55:
                result["score"], result["verdict"] = 60, "dangerous"
            elif result["ai"]["verdict"] == "suspicious" and result["score"] < 25:
                result["score"], result["verdict"] = 30, "suspicious"
        except Exception:
            result["ai_error"] = "AI analysis failed; showing rule-based result only."
    return result


@app.get("/healthz")
def healthz():
    return jsonify(ok=True, ml=mlmodel.available())


@app.get("/api/status")
def api_status():
    return jsonify({**reputation.status(), "ai": ai.available(), "ml": mlmodel.available(),
                    "ocr": ai.available() or ai.ocr_available() or _tesseract_ok()})


def _lang(v) -> str:
    return v if v in i18n.LANGS else i18n.DEFAULT


@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True) or {}
    lang = _lang(data.get("lang"))
    if rate_limited("analyze"):
        return jsonify({"error": i18n.plain("err.api_rate", lang)}), 429
    result = full_analysis(str(data.get("input", "")), bool(data.get("live")), bool(data.get("ai")), bool(data.get("inspect")))
    if "error" in result:
        result["error"] = i18n.plain("err.empty", lang)
        return jsonify(result), 400
    return jsonify(i18n.localize_result(result, lang))


@app.post("/api/analyze-image")
def api_analyze_image():
    lang = _lang(request.form.get("lang"))
    if rate_limited("image"):
        return jsonify({"error": i18n.plain("err.api_rate", lang)}), 429
    f = request.files.get("image")
    if not f or f.mimetype not in IMAGE_TYPES:
        return jsonify({"error": i18n.plain("err.img", lang)}), 400
    raw = f.read()
    if qrscan.too_large(raw):
        return jsonify({"error": i18n.plain("err.pixels", lang)}), 413
    codes = qrscan.decode(raw)  # links hidden inside QR codes ("quishing") are invisible to text filters
    try:
        read = ai.read_image(raw, f.mimetype)
    except RuntimeError as e:
        if not codes:
            return jsonify({"error": str(e)}), 501
        read = {"text": "", "engine": "qr"}
    except Exception:
        if not codes:
            return jsonify({"error": i18n.plain("err.noocr", lang)}), 502
        read = {"text": "", "engine": "qr"}
    text = (read["text"] + "\n" + "\n".join(codes)).strip() if codes else read["text"]
    if not text:
        return jsonify({"error": i18n.plain("err.noocr", lang)}), 422
    result = full_analysis(text, request.form.get("live") == "1", request.form.get("ai") == "1", request.form.get("inspect") == "1")
    result["extracted_text"], result["ocr_engine"], result["qr"] = text, read["engine"], codes
    if codes:
        result["findings"].insert(0, {"level": "low", "title": "Link hidden inside a QR code",
                                      "detail": "A QR code hides the address from your eyes. Scammers use QR codes to get past text filters ('quishing').", "points": 8})
        result["score"] = min(100, result["score"] + 8)
        result["verdict"] = verdict(result["score"])
    return jsonify(i18n.localize_result(result, lang))


@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": i18n.plain("err.big")}), 413


def _tesseract_ok() -> bool:
    try:
        import pytesseract
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


if __name__ == "__main__":
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)  # don't print request lines: privacy by default
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")),
            debug=bool(os.getenv("PHISHGUARD_DEBUG")))
