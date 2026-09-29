from .base import Recon
import asyncio
import tempfile
from pathlib import Path
from urllib.parse import quote_plus

import aiohttp
import numpy as np
from bs4 import BeautifulSoup

_app = None
HIGH = 0.50
MEDIUM = 0.35
MIN_DET = 0.6


def _load():
    global _app
    if _app is None:
        try:
            from insightface.app import FaceAnalysis
        except ImportError:
            raise SystemExit('Face extra missing. Run: python -m pip install -e ".[face]"')
        _app = FaceAnalysis(name="buffalo_l", providers=["CPUExecutionProvider"])
        _app.prepare(ctx_id=-1, det_size=(640, 640))
    return _app


def embed(path):
    """Return (embedding, None) or (None, reason)."""
    import cv2

    img = cv2.imread(str(path))
    if img is None:
        return None, "unreadable image"
    faces = [f for f in _load().get(img) if f.det_score >= MIN_DET]
    if not faces:
        return None, "no face"
    if len(faces) > 1:
        return None, "multiple faces"
    return faces[0].normed_embedding, None


def compare(a, b):
    return float(np.dot(a, b))


def band(score):
    if score >= HIGH:
        return "high"
    if score >= MEDIUM:
        return "medium"
    return "low"


def pick_image():
    from tkinter import Tk, filedialog

    root = Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    path = filedialog.askopenfilename(
        title="Select image",
        filetypes=[("Images", "*.jpg *.jpeg *.png *.webp")],
    )
    root.destroy()
    return path or None


def capture_camera():
    """SPACE = capture, Q = quit. Returns temp file path or None."""
    import cv2
    import os

    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW) if os.name == "nt" else cv2.VideoCapture(0)
    if not cap.isOpened():
        print("Camera not available")
        return None
    path = None
    try:
        for _ in range(10):  # warmup
            cap.read()
        while True:
            ok, frame = cap.read()
            if not ok:
                break
            cv2.imshow("SPACE = capture, Q = quit", frame)
            key = cv2.waitKey(1) & 0xFF
            if key == ord(" "):
                tmp = tempfile.NamedTemporaryFile(suffix=".jpg", delete=False)
                tmp.close()
                cv2.imwrite(tmp.name, frame)
                path = tmp.name
                break
            if key == ord("q"):
                break
    finally:
        cap.release()
        cv2.destroyAllWindows()
    return path


def search_links(image_url):
    """Reverse image search URLs. Needs public image URL."""
    u = quote_plus(image_url)
    return {
        "Google Lens": f"https://lens.google.com/uploadbyurl?url={u}",
        "Yandex": f"https://yandex.com/images/search?rpt=imageview&url={u}",
        "TinEye": f"https://tineye.com/search?url={u}",
        "Bing": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{u}",
    }


async def _fetch_bytes(session, url):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status != 200:
                return None
            return await r.read()
    except Exception:
        return None

async def upload_temp_host(session, path):
    """Upload image to catbox.moe (anonymous, no key). Returns public URL or None."""
    data = aiohttp.FormData()
    data.add_field("reqtype", "fileupload")
    data.add_field("fileToUpload", open(path, "rb"), filename=Path(path).name)
    try:
        async with session.post("https://catbox.moe/user/api.php", data=data, timeout=aiohttp.ClientTimeout(total=30)) as r:
            text = await r.text()
            return text.strip() if text.startswith("http") else None
    except Exception:
        return None

async def _og_image(session, page_url):
    """Profile/page URL -> og:image URL."""
    try:
        async with session.get(page_url, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status != 200:
                return None
            soup = BeautifulSoup(await r.text(), "html.parser")
            tag = soup.find("meta", property="og:image")
            return tag["content"] if tag and tag.get("content") else None
    except Exception:
        return None


class FaceRecon(Recon):
    """
    target: path to image
    candidates: list of image URLs or page URLs to compare against
    """

    def __init__(self, target, candidates=None):
        super().__init__(target)
        self.candidates = candidates or []
        self.search_urls = {}

    def run(self):
        target_emb, err = embed(self.target)
        if target_emb is None:
            self.results = {"target": self.target, "error": f"target photo: {err}"}
            return self.results
        matches = asyncio.run(self._match(target_emb))
        self.results = {
            "target": self.target,
            "search_urls": self.search_urls,
            "matches": matches,
            "verified": [m for m in matches if m["band"] in ("high", "medium")],
        }
        return self.results

    async def _match(self, target_emb):
        out = []
        async with aiohttp.ClientSession() as session:
            public_url = await upload_temp_host(session, self.target)
            if public_url:
                self.search_urls = search_links(public_url)
            with tempfile.TemporaryDirectory() as tmp:
                for i, url in enumerate(self.candidates):
                    data = await _fetch_bytes(session, url)
                    # not an image? treat as page, try og:image
                    if data is None or not data[:4] in (b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1", b"\xff\xd8\xff\xdb", b"\x89PNG", b"RIFF"):
                        img_url = await _og_image(session, url)
                        data = await _fetch_bytes(session, img_url) if img_url else None
                    if not data:
                        out.append({"url": url, "score": None, "band": "no image"})
                        continue
                    p = Path(tmp) / f"{i}.img"
                    p.write_bytes(data)
                    emb, err = embed(p)
                    if emb is None:
                        out.append({"url": url, "score": None, "band": err})
                        continue
                    s = round(compare(target_emb, emb), 3)
                    out.append({"url": url, "score": s, "band": band(s)})
        out.sort(key=lambda m: m["score"] if m["score"] is not None else -1, reverse=True)
        return out