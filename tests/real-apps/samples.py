#!/usr/bin/env python3
"""Small sample files for the real-app test, one per common file type, and
the choice of one for an app from the file types its menu entry lists.

    python3 -I tests/real-apps/samples.py make DIR
    python3 -I tests/real-apps/samples.py pick DIR TYPE[;TYPE…]

`make` writes the files into DIR (made here, nothing is downloaded; video
and sound need ffmpeg, images use Pillow or ImageMagick when installed).
`pick` prints the path of the sample that fits the first type the app
opens, or nothing.
"""
import os
import shutil
import subprocess
import sys
import zipfile

# Exact types first; then by kind (the part before "/").
EXACT = {
    "image/png": "sample.png",
    "image/jpeg": "sample.jpg",
    "image/gif": "sample.gif",
    "image/webp": "sample.webp",
    "image/bmp": "sample.bmp",
    "image/svg+xml": "sample.svg",
    "application/pdf": "sample.pdf",
    "text/plain": "sample.txt",
    "text/markdown": "sample.md",
    "text/x-markdown": "sample.md",
    "text/html": "sample.html",
    "application/xhtml+xml": "sample.html",
    "text/csv": "sample.csv",
    "application/json": "sample.json",
    "application/xml": "sample.xml",
    "text/xml": "sample.xml",
    "text/x-python": "sample.py",
    "text/x-csrc": "sample.c",
    "application/x-shellscript": "sample.sh",
    "application/zip": "sample.zip",
    "video/mp4": "sample.mp4",
    "video/webm": "sample.webm",
    "video/x-matroska": "sample.mkv",
    "audio/ogg": "sample.ogg",
    "audio/x-vorbis+ogg": "sample.ogg",
    "audio/mpeg": "sample.mp3",
    "audio/flac": "sample.flac",
    "audio/x-wav": "sample.wav",
    "audio/wav": "sample.wav",
}
BY_KIND = {"image": "sample.png", "video": "sample.webm", "audio": "sample.ogg", "text": "sample.txt"}

PDF = b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 200]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj
4 0 obj<</Length 44>>stream
BT /F1 24 Tf 40 100 Td (SAM sample) Tj ET
endstream endobj
5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj
trailer<</Root 1 0 R>>
%%EOF
"""


def image(path, fmt):
    try:
        from PIL import Image, ImageDraw
        im = Image.new("RGB", (320, 200), (40, 90, 160))
        ImageDraw.Draw(im).rectangle((40, 40, 280, 160), fill=(240, 200, 60))
        im.save(path, fmt)
        return True
    except Exception:  # noqa: S110 -- no image library: the plain sample below is used
        pass
    if shutil.which("magick"):
        return subprocess.run(["magick", "-size", "320x200", "gradient:blue-yellow", path],
                              capture_output=True).returncode == 0
    return False


def ffmpeg(path, *args):
    if not shutil.which("ffmpeg"):
        return False
    return subprocess.run(["ffmpeg", "-loglevel", "error", "-y", *args, path],
                          capture_output=True).returncode == 0


def make(d):
    os.makedirs(d, exist_ok=True)
    p = lambda n: os.path.join(d, n)
    for name, fmt in [("sample.png", "PNG"), ("sample.jpg", "JPEG"), ("sample.gif", "GIF"),
                      ("sample.webp", "WEBP"), ("sample.bmp", "BMP")]:
        image(p(name), fmt)
    texts = {
        "sample.txt": "SAM sample text\nSecond line.\n",
        "sample.md": "# SAM sample\n\nSome *text*.\n",
        "sample.html": "<!doctype html><title>SAM sample</title><h1>SAM sample</h1>\n",
        "sample.csv": "name,value\nsam,1\n",
        "sample.json": '{"sam": "sample"}\n',
        "sample.xml": "<?xml version=\"1.0\"?><sam>sample</sam>\n",
        "sample.py": "print('SAM sample')\n",
        "sample.c": "int main(void) { return 0; }\n",
        "sample.sh": "#!/bin/sh\necho SAM sample\n",
        "sample.svg": '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">'
                      '<rect width="64" height="64" fill="#2a5aa0"/></svg>\n',
    }
    for name, text in texts.items():
        open(p(name), "w").write(text)
    open(p("sample.pdf"), "wb").write(PDF)
    with zipfile.ZipFile(p("sample.zip"), "w") as z:
        z.writestr("sample.txt", texts["sample.txt"])
    video = ["-f", "lavfi", "-i", "testsrc=duration=2:size=320x240:rate=15"]
    ffmpeg(p("sample.webm"), *video, "-c:v", "libvpx")
    ffmpeg(p("sample.mp4"), *video, "-c:v", "libx264", "-pix_fmt", "yuv420p")
    ffmpeg(p("sample.mkv"), *video, "-c:v", "libvpx")
    tone = ["-f", "lavfi", "-i", "sine=frequency=440:duration=2"]
    ffmpeg(p("sample.ogg"), *tone, "-c:a", "libvorbis")
    ffmpeg(p("sample.mp3"), *tone, "-c:a", "libmp3lame")
    ffmpeg(p("sample.flac"), *tone, "-c:a", "flac")
    ffmpeg(p("sample.wav"), *tone)


def pick(d, types):
    for t in filter(None, (x.strip().lower() for x in types.split(";"))):
        name = EXACT.get(t) or BY_KIND.get(t.split("/")[0])
        if name and os.path.exists(os.path.join(d, name)):
            return os.path.join(d, name)
    return ""


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "make":
        make(sys.argv[2])
    elif len(sys.argv) >= 4 and sys.argv[1] == "pick":
        print(pick(sys.argv[2], sys.argv[3]))
    else:
        sys.exit(__doc__)
