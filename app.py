import os
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, render_template, request

import ai
import inspector
import mlmodel
import reputation
from analyzer import analyze

mlmodel.available()  # load the model at startup so the first request is not slower or unscored

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024
IMAGE_TYPES = {"image/png", "image/jpeg", "image/webp", "image/gif"}

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


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    if request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
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


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/privacy")
def privacy():
    return render_template("privacy.html")


@app.get("/healthz")
def healthz():
    return jsonify(ok=True, ml=mlmodel.available())


@app.get("/api/status")
def api_status():
    return jsonify({**reputation.status(), "ai": ai.available(), "ml": mlmodel.available(),
                    "ocr": ai.available() or ai.ocr_available() or _tesseract_ok()})


@app.post("/api/analyze")
def api_analyze():
    if rate_limited("analyze"):
        return jsonify({"error": "Too many requests. Please wait a minute and try again."}), 429
    data = request.get_json(silent=True) or {}
    result = full_analysis(str(data.get("input", "")), bool(data.get("live")), bool(data.get("ai")), bool(data.get("inspect")))
    return jsonify(result), (400 if "error" in result else 200)


@app.post("/api/analyze-image")
def api_analyze_image():
    if rate_limited("image"):
        return jsonify({"error": "Too many requests. Please wait a minute and try again."}), 429
    f = request.files.get("image")
    if not f or f.mimetype not in IMAGE_TYPES:
        return jsonify({"error": "Upload a PNG, JPG, WEBP or GIF screenshot."}), 400
    try:
        read = ai.read_image(f.read(), f.mimetype)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 501
    except Exception:
        return jsonify({"error": "Could not read the screenshot."}), 502
    if not read["text"]:
        return jsonify({"error": "No text found in that image."}), 422
    result = full_analysis(read["text"], request.form.get("live") == "1", request.form.get("ai") == "1", request.form.get("inspect") == "1")
    result["extracted_text"], result["ocr_engine"] = read["text"], read["engine"]
    return jsonify(result)


@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "File too large (max 6 MB)."}), 413


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
