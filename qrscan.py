"""QR-code decoding for screenshots and photos ("quishing": scam links hidden inside QR codes so text filters never see them).

Uses OpenCV's built-in QR detector (already installed as a dependency of the OCR package): offline, no extra service.
Decoded contents are UNTRUSTED text; the caller runs them through the normal analysis pipeline.
"""
import io

MAX_PIXELS = 30_000_000  # reject huge images before decoding them (memory-exhaustion guard)
MAX_CODES, MAX_LEN = 5, 2000


def image_size(data: bytes):
    """(width, height) read from the image header without decoding the pixels, or None if unreadable."""
    try:
        from PIL import Image
        return Image.open(io.BytesIO(data)).size
    except Exception:
        return None


def too_large(data: bytes) -> bool:
    size = image_size(data)
    return bool(size and size[0] * size[1] > MAX_PIXELS)


def decode(data: bytes) -> list:
    """Return the distinct QR code contents found in an image (possibly several), or []."""
    try:
        import cv2
        import numpy as np
    except ImportError:
        return []
    size = image_size(data)
    if not size or size[0] * size[1] > MAX_PIXELS:
        return []
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        return []
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    h, w = gray.shape[:2]
    variants = [img, gray]
    if max(h, w) < 700:  # small screenshots: upscale so the finder patterns are big enough
        variants.append(cv2.resize(gray, None, fx=3, fy=3, interpolation=cv2.INTER_CUBIC))
    # QR codes need a white "quiet zone"; screenshots often crop it away
    variants.append(cv2.copyMakeBorder(gray, 60, 60, 60, 60, cv2.BORDER_CONSTANT, value=255))
    found = []
    # OpenCV 5.0's classic QRCodeDetector fails even on clean codes, while the Aruco-based one works, so try it first.
    detectors = [getattr(cv2, name)() for name in ("QRCodeDetectorAruco", "QRCodeDetector") if hasattr(cv2, name)]
    for im in variants:
        for det in detectors:
            try:
                ok, decoded, _pts, _ = det.detectAndDecodeMulti(im)
            except Exception:
                continue
            if ok:
                for d in decoded:
                    d = (d or "").strip()[:MAX_LEN]
                    if d and d not in found:
                        found.append(d)
            if found:
                return found[:MAX_CODES]
    return found[:MAX_CODES]
