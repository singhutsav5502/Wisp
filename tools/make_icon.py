"""Draw the Wisp app icon with CoreGraphics (macOS only; run with the project's venv).

    .venv/bin/python tools/make_icon.py

Writes assets/wisp-1024.png, the macOS iconset/.icns, and the small PNG that
wisp.py embeds for the window icon (Windows title bar / taskbar, Mac Dock)."""
import base64
import math
import os
import random
import subprocess
import sys

import Quartz as Q

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ASSETS = os.path.join(ROOT, "assets")


def rgba(h, a=1.0):
    h = h.lstrip("#")
    return [int(h[i:i + 2], 16) / 255.0 for i in (0, 2, 4)] + [a]


def gradient(stops):
    cs = Q.CGColorSpaceCreateDeviceRGB()
    comps, locs = [], []
    for loc, col in stops:
        comps += col
        locs.append(loc)
    return Q.CGGradientCreateWithColorComponents(cs, comps, locs, len(locs))


def rounded_rect(c, x, y, w, h, r):
    Q.CGContextBeginPath(c)
    Q.CGContextMoveToPoint(c, x + r, y)
    Q.CGContextAddArcToPoint(c, x + w, y, x + w, y + h, r)
    Q.CGContextAddArcToPoint(c, x + w, y + h, x, y + h, r)
    Q.CGContextAddArcToPoint(c, x, y + h, x, y, r)
    Q.CGContextAddArcToPoint(c, x, y, x + w, y, r)
    Q.CGContextClosePath(c)


def sparkle(c, cx, cy, r, col):
    """four-point twinkle"""
    k = r * 0.22
    Q.CGContextBeginPath(c)
    Q.CGContextMoveToPoint(c, cx, cy + r)
    Q.CGContextAddQuadCurveToPoint(c, cx + k, cy + k, cx + r, cy)
    Q.CGContextAddQuadCurveToPoint(c, cx + k, cy - k, cx, cy - r)
    Q.CGContextAddQuadCurveToPoint(c, cx - k, cy - k, cx - r, cy)
    Q.CGContextAddQuadCurveToPoint(c, cx - k, cy + k, cx, cy + r)
    Q.CGContextClosePath(c)
    Q.CGContextSetFillColorWithColor(c, Q.CGColorCreateGenericRGB(*col))
    Q.CGContextFillPath(c)


def flame_path(c, s=1.0, ox=512, oy=430):
    """teardrop wisp body; tip flicks up and to the right. s scales around (ox, oy)"""
    def p(x, y):
        return ox + (x - 512) * s, oy + (y - 430) * s
    Q.CGContextBeginPath(c)
    Q.CGContextMoveToPoint(c, *p(628, 830))
    for pts in (((648, 720), (700, 560), (684, 438)),
                ((668, 300), (592, 248), (512, 248)),
                ((420, 248), (338, 318), (338, 432)),
                ((338, 560), (440, 616), (520, 676)),
                ((574, 716), (612, 760), (628, 830))):
        a, b, d = (p(*q) for q in pts)
        Q.CGContextAddCurveToPoint(c, a[0], a[1], b[0], b[1], d[0], d[1])
    Q.CGContextClosePath(c)


def cursor_path(c, x, y, s, ang):
    """classic arrow pointer, tip at (x, y), pointing up-left, rotated by ang (radians)"""
    pts = [(0, 0), (0, -17), (4, -13), (7.2, -20), (10, -18.8), (7, -12), (12.5, -12)]
    ca, sa = math.cos(ang), math.sin(ang)
    Q.CGContextBeginPath(c)
    for i, (px, py) in enumerate(pts):
        px, py = px * s, py * s
        X, Y = x + px * ca - py * sa, y + px * sa + py * ca
        (Q.CGContextMoveToPoint if i == 0 else Q.CGContextAddLineToPoint)(c, X, Y)
    Q.CGContextClosePath(c)


def draw(size=1024):
    cs = Q.CGColorSpaceCreateDeviceRGB()
    c = Q.CGBitmapContextCreate(None, size, size, 8, 0, cs, Q.kCGImageAlphaPremultipliedLast)
    Q.CGContextScaleCTM(c, size / 1024.0, size / 1024.0)
    Q.CGContextSetShouldAntialias(c, True)

    # night-sky tile (macOS icon grid: 824 px body, 100 px margin)
    Q.CGContextSaveGState(c)
    Q.CGContextSetShadowWithColor(c, (0, -12), 28, Q.CGColorCreateGenericRGB(0, 0, 0, 0.35))
    rounded_rect(c, 100, 100, 824, 824, 186)
    Q.CGContextSetFillColorWithColor(c, Q.CGColorCreateGenericRGB(*rgba("#1a1040")))
    Q.CGContextFillPath(c)
    Q.CGContextRestoreGState(c)
    Q.CGContextSaveGState(c)
    rounded_rect(c, 100, 100, 824, 824, 186)
    Q.CGContextClip(c)
    Q.CGContextDrawLinearGradient(c, gradient([(0, rgba("#3b1d6e")), (0.55, rgba("#21135a")),
                                               (1, rgba("#0d0a2b"))]),
                                  (512, 100), (512, 924), 0)
    # misty violet horizon
    Q.CGContextDrawRadialGradient(c, gradient([(0, rgba("#b45cff", 0.45)), (1, rgba("#b45cff", 0))]),
                                  (512, 60), 0, (512, 60), 520, 0)
    # stars
    rnd = random.Random(11)
    for _ in range(26):
        x, y = rnd.uniform(140, 884), rnd.uniform(560, 890)
        if abs(x - 560) < 150 and y < 760:
            continue
        r = rnd.choice((3, 3.5, 4.5, 6))
        Q.CGContextSetFillColorWithColor(c, Q.CGColorCreateGenericRGB(1, 1, 0.95, rnd.uniform(0.35, 0.9)))
        Q.CGContextFillEllipseInRect(c, ((x - r, y - r), (2 * r, 2 * r)))
    # rolling hills of the two "realms"
    for col, base, amp, ph in (("#2a1660", 210, 48, 0.3), ("#160c3a", 150, 36, 2.1)):
        Q.CGContextBeginPath(c)
        Q.CGContextMoveToPoint(c, 100, 100)
        for i in range(0, 41):
            x = 100 + i * 824 / 40.0
            Q.CGContextAddLineToPoint(c, x, base + amp * math.sin(x / 140.0 + ph))
        Q.CGContextAddLineToPoint(c, 924, 100)
        Q.CGContextClosePath(c)
        Q.CGContextSetFillColorWithColor(c, Q.CGColorCreateGenericRGB(*rgba(col)))
        Q.CGContextFillPath(c)

    # glow around the wisp
    Q.CGContextDrawRadialGradient(c, gradient([(0, rgba("#7dffe0", 0.70)), (0.45, rgba("#4ee6d0", 0.25)),
                                               (1, rgba("#4ee6d0", 0))]),
                                  (512, 470), 0, (512, 470), 380, 0)
    # trail of embers drifting down-left (where it came from)
    for (x, y, r, a) in ((300, 300, 15, 0.8), (250, 252, 10, 0.6), (214, 216, 7, 0.45)):
        Q.CGContextSetFillColorWithColor(c, Q.CGColorCreateGenericRGB(*rgba("#9ffff0", a)))
        Q.CGContextFillEllipseInRect(c, ((x - r, y - r), (2 * r, 2 * r)))

    # body: outer flame, then a brighter inner flame
    Q.CGContextSaveGState(c)
    flame_path(c)
    Q.CGContextClip(c)
    Q.CGContextDrawRadialGradient(c, gradient([(0, rgba("#f2fffb")), (0.45, rgba("#8ff7df")),
                                               (1, rgba("#22b8b0"))]),
                                  (500, 400), 0, (520, 470), 420, Q.kCGGradientDrawsAfterEndLocation)
    Q.CGContextRestoreGState(c)
    Q.CGContextSaveGState(c)
    flame_path(c, s=0.62, ox=500, oy=392)
    Q.CGContextClip(c)
    Q.CGContextDrawRadialGradient(c, gradient([(0, rgba("#ffffff", 0.95)), (1, rgba("#c9fff2", 0.35))]),
                                  (496, 370), 0, (496, 380), 200, Q.kCGGradientDrawsAfterEndLocation)
    Q.CGContextRestoreGState(c)

    # face
    for ex in (458, 566):
        Q.CGContextSetFillColorWithColor(c, Q.CGColorCreateGenericRGB(*rgba("#1d1245")))
        Q.CGContextFillEllipseInRect(c, ((ex - 21, 400), (42, 62)))
        Q.CGContextSetFillColorWithColor(c, Q.CGColorCreateGenericRGB(1, 1, 1, 1))
        Q.CGContextFillEllipseInRect(c, ((ex - 9, 436), (16, 16)))
    for bx in (418, 606):
        Q.CGContextSetFillColorWithColor(c, Q.CGColorCreateGenericRGB(*rgba("#ff7fb6", 0.55)))
        Q.CGContextFillEllipseInRect(c, ((bx - 24, 366), (48, 26)))
    Q.CGContextSetStrokeColorWithColor(c, Q.CGColorCreateGenericRGB(*rgba("#1d1245")))
    Q.CGContextSetLineWidth(c, 9)
    Q.CGContextSetLineCap(c, Q.kCGLineCapRound)
    Q.CGContextBeginPath(c)
    Q.CGContextMoveToPoint(c, 494, 376)
    Q.CGContextAddQuadCurveToPoint(c, 512, 356, 530, 376)
    Q.CGContextStrokePath(c)

    # the cursor it carries, bobbing off to the right
    Q.CGContextSaveGState(c)
    Q.CGContextSetShadowWithColor(c, (0, -6), 14, Q.CGColorCreateGenericRGB(0, 0, 0, 0.45))
    cursor_path(c, 676, 360, 9.5, -0.35)
    Q.CGContextSetFillColorWithColor(c, Q.CGColorCreateGenericRGB(1, 1, 1, 1))
    Q.CGContextFillPath(c)
    Q.CGContextRestoreGState(c)
    cursor_path(c, 676, 360, 9.5, -0.35)
    Q.CGContextSetStrokeColorWithColor(c, Q.CGColorCreateGenericRGB(*rgba("#1d1245")))
    Q.CGContextSetLineWidth(c, 9)
    Q.CGContextSetLineJoin(c, Q.kCGLineJoinRound)
    Q.CGContextStrokePath(c)

    # twinkles
    sparkle(c, 290, 690, 46, rgba("#fff6c8"))
    sparkle(c, 760, 720, 30, rgba("#ffffff", 0.9))
    sparkle(c, 800, 500, 20, rgba("#d8c8ff", 0.9))
    sparkle(c, 236, 470, 18, rgba("#ffffff", 0.75))
    Q.CGContextRestoreGState(c)
    return Q.CGBitmapContextCreateImage(c)


def save_png(img, path):
    url = Q.CFURLCreateWithFileSystemPath(None, path, Q.kCFURLPOSIXPathStyle, False)
    d = Q.CGImageDestinationCreateWithURL(url, "public.png", 1, None)
    Q.CGImageDestinationAddImage(d, img, None)
    if not Q.CGImageDestinationFinalize(d):
        raise SystemExit("could not write " + path)


def main():
    os.makedirs(ASSETS, exist_ok=True)
    save_png(draw(1024), os.path.join(ASSETS, "wisp-1024.png"))
    iconset = os.path.join(ASSETS, "Wisp.iconset")
    os.makedirs(iconset, exist_ok=True)
    for s in (16, 32, 128, 256, 512):
        save_png(draw(s), os.path.join(iconset, "icon_%dx%d.png" % (s, s)))
        save_png(draw(s * 2), os.path.join(iconset, "icon_%dx%d@2x.png" % (s, s)))
    icns = os.path.join(ROOT, "Wisp.app", "Contents", "Resources", "Wisp.icns")
    os.makedirs(os.path.dirname(icns), exist_ok=True)
    subprocess.check_call(["iconutil", "-c", "icns", iconset, "-o", icns])
    # window icon embedded in wisp.py (Tk reads PNG natively)
    for s in (32, 128):
        p = os.path.join(ASSETS, "wisp-%d.png" % s)
        save_png(draw(s), p)
    print("wrote", icns)
    with open(os.path.join(ASSETS, "wisp-128.png"), "rb") as f:
        print("embedded icon is %d bytes base64" % len(base64.b64encode(f.read())))


if __name__ == "__main__":
    sys.exit(main())
