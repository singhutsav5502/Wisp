#!/usr/bin/env python3
"""Wisp - share one keyboard + mouse between computers (Windows and macOS, either way).

  Windows (has the keyboard/mouse):
      python wisp.py server --edge right --token SECRET
  Mac:
      python3 wisp.py client --host <windows-ip> --token SECRET --side left

Push the cursor off the Windows --edge and it appears on the Mac; push it back off
the Mac's --side edge to return. The keyboard always follows the mouse.
Panic key (Windows keyboard): Ctrl+Alt+Shift+Esc -> control returns to Windows.

Windows server: Python standard library only (direct Win32 low-level hooks).
Mac client:     pip install pyobjc-framework-Quartz

Run with no arguments (or double-click) to open the app window instead.
"""
import argparse
import ctypes
import hmac
import json
import math
import os
import platform
import queue
import random
import secrets
import socket
import sys
import threading
import time
import traceback

PORT = 24800
EDGES = ("left", "right", "top", "bottom")

VERSION = "2026.11.05-5"  # shown to the other computer so mismatched copies are obvious

# ============================== key tables ==============================
# Windows virtual-key code -> neutral key name
WIN_VK = {
    0x08: "backspace", 0x09: "tab", 0x0D: "enter", 0x10: "shift", 0x11: "ctrl",
    0x12: "alt", 0x13: "pause", 0x14: "caps_lock", 0x1B: "esc", 0x20: "space",
    0x21: "page_up", 0x22: "page_down", 0x23: "end", 0x24: "home", 0x25: "left",
    0x26: "up", 0x27: "right", 0x28: "down", 0x2C: "print_screen", 0x2D: "insert",
    0x2E: "delete", 0x5B: "meta", 0x5C: "meta_r", 0x5D: "menu",
    0x6A: "kp_multiply", 0x6B: "kp_add", 0x6D: "kp_subtract", 0x6E: "kp_decimal",
    0x6F: "kp_divide", 0x90: "num_lock", 0x91: "scroll_lock",
    0xA0: "shift", 0xA1: "shift_r", 0xA2: "ctrl", 0xA3: "ctrl_r", 0xA4: "alt",
    0xA5: "alt_r", 0xAD: "mute", 0xAE: "volume_down", 0xAF: "volume_up",
    0xBA: "semicolon", 0xBB: "equal", 0xBC: "comma", 0xBD: "minus", 0xBE: "period",
    0xBF: "slash", 0xC0: "grave", 0xDB: "bracket_left", 0xDC: "backslash",
    0xDD: "bracket_right", 0xDE: "quote", 0xE2: "intl_backslash",
}
for _i in range(26):
    WIN_VK[0x41 + _i] = chr(97 + _i)
for _i in range(10):
    WIN_VK[0x30 + _i] = str(_i)
    WIN_VK[0x60 + _i] = "kp_%d" % _i
for _i in range(20):
    WIN_VK[0x70 + _i] = "f%d" % (_i + 1)


# scan code (set 1, non-extended) -> neutral name for the main typing block. Scan codes
# are the physical key position, so these keys can't be changed by Windows' keyboard layout,
# remapping software or a keyboard driver handing out unusual virtual-key codes.
WIN_SC_TYPING = {0x29: "grave", 0x0C: "minus", 0x0D: "equal", 0x1A: "bracket_left",
                 0x1B: "bracket_right", 0x2B: "backslash", 0x27: "semicolon", 0x28: "quote",
                 0x33: "comma", 0x34: "period", 0x35: "slash", 0x56: "intl_backslash",
                 0x39: "space", 0x0E: "backspace", 0x0F: "tab", 0x1C: "enter"}
for _i, _c in enumerate("1234567890"):
    WIN_SC_TYPING[0x02 + _i] = _c
for _row, _sc in (("qwertyuiop", 0x10), ("asdfghjkl", 0x1E), ("zxcvbnm", 0x2C)):
    for _i, _c in enumerate(_row):
        WIN_SC_TYPING[_sc + _i] = _c


def win_key_name(vk, flags, scan=0):
    ext = flags & 0x01  # LLKHF_EXTENDED
    if vk == 0x0D and ext:  # numpad Enter
        return "kp_enter"
    if scan and not ext and scan in WIN_SC_TYPING:
        return WIN_SC_TYPING[scan]
    return WIN_VK.get(vk)


# neutral key name -> macOS virtual keycode (kVK_*; ANSI positions)
MAC_KVK = {
    "a": 0x00, "s": 0x01, "d": 0x02, "f": 0x03, "h": 0x04, "g": 0x05, "z": 0x06,
    "x": 0x07, "c": 0x08, "v": 0x09, "intl_backslash": 0x0A, "b": 0x0B, "q": 0x0C,
    "w": 0x0D, "e": 0x0E, "r": 0x0F, "y": 0x10, "t": 0x11, "1": 0x12, "2": 0x13,
    "3": 0x14, "4": 0x15, "6": 0x16, "5": 0x17, "equal": 0x18, "9": 0x19, "7": 0x1A,
    "minus": 0x1B, "8": 0x1C, "0": 0x1D, "bracket_right": 0x1E, "o": 0x1F, "u": 0x20,
    "bracket_left": 0x21, "i": 0x22, "p": 0x23, "enter": 0x24, "l": 0x25, "j": 0x26,
    "quote": 0x27, "k": 0x28, "semicolon": 0x29, "backslash": 0x2A, "comma": 0x2B,
    "slash": 0x2C, "n": 0x2D, "m": 0x2E, "period": 0x2F, "tab": 0x30, "space": 0x31,
    "grave": 0x32, "backspace": 0x33, "esc": 0x35, "meta_r": 0x36, "meta": 0x37,
    "shift": 0x38, "caps_lock": 0x39, "alt": 0x3A, "ctrl": 0x3B, "shift_r": 0x3C,
    "alt_r": 0x3D, "ctrl_r": 0x3E, "f17": 0x40, "kp_decimal": 0x41,
    "kp_multiply": 0x43, "kp_add": 0x45, "num_lock": 0x47, "volume_up": 0x48,
    "volume_down": 0x49, "mute": 0x4A, "kp_divide": 0x4B, "kp_enter": 0x4C,
    "kp_subtract": 0x4E, "f18": 0x4F, "f19": 0x50, "kp_0": 0x52, "kp_1": 0x53,
    "kp_2": 0x54, "kp_3": 0x55, "kp_4": 0x56, "kp_5": 0x57, "kp_6": 0x58,
    "kp_7": 0x59, "f20": 0x5A, "kp_8": 0x5B, "kp_9": 0x5C, "f5": 0x60, "f6": 0x61,
    "f7": 0x62, "f3": 0x63, "f8": 0x64, "f9": 0x65, "f11": 0x67, "f13": 0x69,
    "print_screen": 0x69, "f16": 0x6A, "f14": 0x6B, "scroll_lock": 0x6B,
    "f10": 0x6D, "menu": 0x6E, "f12": 0x6F, "f15": 0x71, "pause": 0x71,
    "insert": 0x72, "home": 0x73, "page_up": 0x74, "delete": 0x75, "f4": 0x76,
    "end": 0x77, "f2": 0x78, "page_down": 0x79, "f1": 0x7A, "left": 0x7B,
    "right": 0x7C, "down": 0x7D, "up": 0x7E,
}
MAC_MOD_FLAG = {"shift": 0x20000, "shift_r": 0x20000, "ctrl": 0x40000, "ctrl_r": 0x40000,
                "alt": 0x80000, "alt_r": 0x80000, "meta": 0x100000, "meta_r": 0x100000}
MAC_EXTRA_FLAG = {"left": 0xA00000, "right": 0xA00000, "up": 0xA00000, "down": 0xA00000,
                  "home": 0x800000, "end": 0x800000, "page_up": 0x800000,
                  "page_down": 0x800000, "delete": 0x800000, "insert": 0x800000}
# Windows Ctrl acts as Mac Cmd (Ctrl+C -> Cmd+C); the Windows key acts as Mac Ctrl.
SWAP_WIN_TO_MAC = {"ctrl": "meta", "ctrl_r": "meta_r", "meta": "ctrl", "meta_r": "ctrl_r"}

# ============================== wire protocol ==============================


def encode(obj):
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode()


class LineReader:
    """Newline-delimited JSON reader that tolerates socket timeouts."""

    def __init__(self, sock):
        self.sock, self.buf = sock, b""

    def read(self):
        while True:
            if b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                if line.strip():
                    return json.loads(line)
                continue
            d = self.sock.recv(65536)
            if not d:
                return None
            self.buf += d

    def pending(self):
        """Complete messages already buffered (no blocking)."""
        out = []
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            if line.strip():
                out.append(json.loads(line))
        return out


def coalesce(msgs):
    """Merge runs of consecutive mouse moves into one (order of everything else kept)."""
    out = []
    for m in msgs:
        if m.get("t") == "m" and out and out[-1].get("t") == "m":
            out[-1] = {"t": "m", "dx": out[-1]["dx"] + m["dx"], "dy": out[-1]["dy"] + m["dy"]}
        else:
            out.append(m)
    return out


# ============================== multi-screen geometry ==============================
class Desktop:
    """A set of screen rectangles (x0, y0, x1, y1), x1/y1 exclusive, in any arrangement.
    A 'free' edge is a screen edge with no other screen beyond it: that's where the
    cursor may leave for the other computer."""

    def __init__(self, rects):
        self.rects = [tuple(int(v) for v in r) for r in rects if r[2] > r[0] and r[3] > r[1]]
        if not self.rects:
            raise ValueError("no screens")
        self.bounds = (min(r[0] for r in self.rects), min(r[1] for r in self.rects),
                       max(r[2] for r in self.rects), max(r[3] for r in self.rects))

    def find(self, x, y):
        for r in self.rects:
            if r[0] <= x < r[2] and r[1] <= y < r[3]:
                return r
        return None

    def clamp(self, x, y):
        """nearest point that is on a real screen"""
        if self.find(x, y):
            return x, y
        best, bd = None, None
        for r in self.rects:
            cx, cy = min(max(x, r[0]), r[2] - 1), min(max(y, r[1]), r[3] - 1)
            d = (cx - x) ** 2 + (cy - y) ** 2
            if bd is None or d < bd:
                best, bd = (cx, cy), d
        return best

    def free(self, x, y, side):
        r = self.find(x, y)
        if not r:
            return False
        if side == "right":
            return x >= r[2] - 1 and not self.find(r[2], y)
        if side == "left":
            return x <= r[0] and not self.find(r[0] - 1, y)
        if side == "top":
            return y <= r[1] and not self.find(x, r[1] - 1)
        return y >= r[3] - 1 and not self.find(x, r[3])

    def ratio(self, side, x, y):
        """position along the whole edge span, 0..1"""
        bx0, by0, bx1, by1 = self.bounds
        if side in ("left", "right"):
            return min(max((y - by0) / max(1, by1 - by0 - 1), 0.0), 1.0)
        return min(max((x - bx0) / max(1, bx1 - bx0 - 1), 0.0), 1.0)

    def edge_point(self, side, r, inset=0):
        """point just inside a free `side` edge, as close as possible to span ratio r"""
        bx0, by0, bx1, by1 = self.bounds
        horiz = side in ("left", "right")
        t = by0 + r * (by1 - by0 - 1) if horiz else bx0 + r * (bx1 - bx0 - 1)
        best, bkey = None, None
        for q in self.rects:
            lo, hi = (q[1], q[3] - 1) if horiz else (q[0], q[2] - 1)
            tt = min(max(t, lo), hi)
            edge = {"right": q[2] - 1, "left": q[0], "top": q[1], "bottom": q[3] - 1}[side]
            pt = (edge, tt) if horiz else (tt, edge)
            if not self.free(pt[0], pt[1], side):
                # a neighbour covers this spot; try the part of the edge it doesn't cover
                continue
            out = {"right": -q[2], "left": q[0], "top": q[1], "bottom": -q[3]}[side]
            key = (abs(tt - t), out)
            if bkey is None or key < bkey:
                w = (q[2] - q[0]) if horiz else (q[3] - q[1])
                ins = min(inset, w - 1)
                step = {"right": -ins, "left": ins, "top": ins, "bottom": -ins}[side]
                best = (edge + step, tt) if horiz else (tt, edge + step)
                bkey = key
        if best is None:  # fall back: outermost screen in that direction
            q = {"right": max, "left": min, "top": min, "bottom": max}[side](
                self.rects, key=lambda q: {"right": q[2], "left": q[0], "top": q[1], "bottom": q[3]}[side])
            best = self.clamp((q[0] + q[2]) // 2, (q[1] + q[3]) // 2)
        return best

    def park(self):
        """centre of the largest screen (never in a gap between screens)"""
        q = max(self.rects, key=lambda q: (q[2] - q[0]) * (q[3] - q[1]))
        return (q[0] + q[2]) // 2, (q[1] + q[3]) // 2


# ============================== server core (OS independent) ==============================
WM_MOUSEMOVE = 0x200
WM_MOUSEWHEEL, WM_XBUTTONDOWN, WM_XBUTTONUP, WM_MOUSEHWHEEL = 0x20A, 0x20B, 0x20C, 0x20E
BTN_MSG = {0x201: ("left", True), 0x202: ("left", False), 0x204: ("right", True),
           0x205: ("right", False), 0x207: ("middle", True), 0x208: ("middle", False)}
KEY_DOWN_MSG, KEY_UP_MSG = (0x100, 0x104), (0x101, 0x105)
VK_CTRL, VK_ALT, VK_SHIFT, VK_ESC = {0x11, 0xA2, 0xA3}, {0x12, 0xA4, 0xA5}, {0x10, 0xA0, 0xA1}, 0x1B


def _s16(v):
    v &= 0xFFFF
    return v - 0x10000 if v >= 0x8000 else v


class ServerCore:
    """Decides, for every low-level input event on the server, whether it stays local
    or is forwarded (and swallowed). Called from the hook thread; must be fast.

    osi must provide: monitors() -> [(x0, y0, x1, y1), ...], get_cursor() -> (x, y),
    set_cursor(x, y), hide_cursor(), show_cursor().
    """

    def __init__(self, osi, edge, send=None, log=print):
        self.os, self.edge, self.send, self.log = osi, edge, send or (lambda o: None), log
        self.lock = threading.RLock()
        self.remote = False
        self.connected = False
        self.local_btns, self.remote_btns = set(), set()
        self.local_keys, self.remote_keys, self.passthru = set(), {}, set()
        self.warp_to = None
        self.os_name = getattr(osi, "os_name", "Windows")
        self.peer_name = None
        self.rtt_ms = None  # smoothed network round trip, for the UI
        self.late_hooks = 0  # events our hook handled too late (Windows may have leaked them)
        self.worst_late_ms = 0
        self._late_logged = 0.0
        self.trace_keys = False
        self.key_seq = 0

    # ---- geometry ----
    def _desk(self):
        mons = tuple(tuple(m) for m in self.os.monitors())
        if getattr(self, "_desk_key", None) != mons:
            self._desk_key, self._desk_obj = mons, Desktop(mons)
        return self._desk_obj

    def _warp(self, x, y):
        self.warp_to = (int(x), int(y))
        self.os.set_cursor(int(x), int(y))

    # ---- mode switches ----
    def _enter(self, x, y):
        r = self._desk().ratio(self.edge, x, y)
        self.remote = True
        self.remote_btns.clear()
        self.remote_keys.clear()
        self.passthru = set(self.local_keys)  # keys held while crossing: their key-ups stay here
        self.send({"t": "enter", "r": r})
        self._warp(*self._desk().park())
        self.os.hide_cursor()
        self.log("-> remote")

    def _go_local(self, r=0.5):
        if not self.remote:
            return
        self.remote = False
        self.remote_btns.clear()
        self.remote_keys.clear()
        self.passthru.clear()
        r = min(max(float(r), 0.0), 1.0)
        self._warp(*self._desk().edge_point(self.edge, r, inset=4))
        self.os.show_cursor()
        self.log("<- local")

    def note_late_hook(self, lag):
        self.late_hooks += 1
        self.worst_late_ms = max(self.worst_late_ms, lag)
        now = time.monotonic()
        if now - self._late_logged > 2:
            self._late_logged = now
            self.log("WARNING: input hook ran %d ms late (%d so far). The system may have kept "
                     "that input on this computer instead of sending it." % (lag, self.late_hooks))

    def set_connected(self, c):
        with self.lock:
            self.connected = c
            if not c:
                self._go_local(0.5)

    def client_left(self, r):
        with self.lock:
            self._go_local(r)

    def panic(self):
        with self.lock:
            if self.remote:
                self.send({"t": "leave"})
                self._go_local(0.5)

    # ---- OS-neutral entry points (any capture adapter): return True to swallow ----
    def motion(self, x, y, dx, dy):
        """pointer moved: (x, y) is where it would go locally, (dx, dy) the raw movement"""
        with self.lock:
            if self.remote:
                if dx or dy:
                    self.send({"t": "m", "dx": dx, "dy": dy})
                return True
            if self.connected and not self.local_btns and self._desk().free(x, y, self.edge):
                self._enter(x, y)
                return True
            return False

    def button(self, name, down):
        with self.lock:
            if self.remote:
                (self.remote_btns.add if down else self.remote_btns.discard)(name)
                self.send({"t": "b", "b": name, "p": down})
                return True
            (self.local_btns.add if down else self.local_btns.discard)(name)
            return False

    def wheel(self, dx, dy):
        """dx/dy in wheel notches; dy > 0 scrolls up, dx > 0 scrolls right"""
        with self.lock:
            if self.remote:
                self.send({"t": "s", "dx": dx, "dy": dy})
                return True
            return False

    def key(self, kid, name, down, detail=""):
        """kid: the OS key code (identifies the physical key); name: neutral key name"""
        with self.lock:
            if not self.remote:
                (self.local_keys.add if down else self.local_keys.discard)(kid)
                return False
            if kid in self.passthru:  # held before crossing: belongs to this computer
                if not down:
                    self.passthru.discard(kid)
                    self.local_keys.discard(kid)
                    return False
                return True  # autorepeat of that held key: swallow, don't forward
            if down:
                self.remote_keys[kid] = name
            else:
                self.remote_keys.pop(kid, None)
            held = set(self.remote_keys.values())
            if down and name == "esc" and held & {"ctrl", "ctrl_r"} and held & {"alt", "alt_r"} \
                    and held & {"shift", "shift_r"}:
                self.panic()
                return True
            if name:
                self.key_seq += 1
                m = {"t": "k", "n": name, "p": down, "q": self.key_seq}
                if detail:
                    m["d"] = detail  # raw OS key data, shown in the receiver's keystroke log
                self.send(m)
            if self.trace_keys:
                self.log("key #%d %s %s  (%s)" % (self.key_seq, name or "?",
                                                 "down" if down else "up", detail))
            return True

    def held_names(self):
        """names of keys currently held down on the other computer (for the resync)"""
        return sorted(n for n in self.remote_keys.values() if n) if self.remote else []

    # ---- Windows low-level hook entry points ----
    def on_mouse(self, msg, x, y, data, injected):
        with self.lock:
            if injected:
                return False
            if msg == WM_MOUSEMOVE and self.warp_to is not None and (x, y) == self.warp_to:
                self.warp_to = None  # echo of our own SetCursorPos (if Windows reports one)
                return self.remote
            if msg == WM_MOUSEMOVE:
                if not self.remote:
                    return self.motion(x, y, 0, 0)
                cx0, cy0 = self.os.get_cursor()
                self.motion(x, y, x - cx0, y - cy0)
                ccx, ccy = self._desk().park()
                if self.remote and (abs(cx0 - ccx) > 50 or abs(cy0 - ccy) > 50):
                    self._warp(ccx, ccy)  # keep parked away from screen edges
                return True
            if msg in BTN_MSG:
                return self.button(*BTN_MSG[msg])
            if msg in (WM_XBUTTONDOWN, WM_XBUTTONUP):
                return self.button("x1" if (data >> 16) & 0xFFFF == 1 else "x2",
                                   msg == WM_XBUTTONDOWN)
            if msg == WM_MOUSEWHEEL:
                return self.wheel(0, _s16(data >> 16) / 120.0)
            if msg == WM_MOUSEHWHEEL:  # positive = scroll right
                return self.wheel(_s16(data >> 16) / 120.0, 0)
            return self.remote

    def on_key(self, msg, vk, flags, injected, scan=0):
        if injected:
            return False
        down = msg in KEY_DOWN_MSG
        if not down and msg not in KEY_UP_MSG:
            return False
        # identify the physical key by scan code so down/up always pair up
        kid = ("sc", scan, flags & 0x01) if scan else vk
        return self.key(kid, win_key_name(vk, flags, scan), down,
                        "vk %#04x scan %#04x flags %#x" % (vk, scan, flags))


# ============================== client core (OS independent) ==============================
class ClientCore:
    """Applies server events to the local machine through an injector.

    inj must provide: displays() -> [(x0, y0, x1, y1), ...] [x1/y1 exclusive], get_pos(),
    move(x, y, dx, dy, btns, flags), button(name, down, x, y, clicks, flags),
    scroll(lines_y, lines_x), key(keycode, down, flags, repeat).
    Optional: os_name ("Darwin" default), key_code(name), key_flags(held_names, name),
    wheel(notches_y, notches_x) (used instead of scroll() when present).
    """

    def __init__(self, inj, side="left", speed=1.0, swap=True, scroll_lines=3.0,
                 invert_scroll=False, send=None, log=print):
        self.inj, self.side, self.speed, self.swap = inj, side, speed, swap
        self.scroll_lines, self.invert_scroll = scroll_lines, invert_scroll
        self.send, self.log = send or (lambda o: None), log
        self.lock = threading.RLock()
        self.peer_os = None
        self.peer_name = None
        self.connected = False
        self.last_error = None  # e.g. "bad token" from the server
        self.active = False
        self.x = self.y = 0.0
        self.btns = set()
        self.keys = {}  # local key name -> keycode
        self.key_orig = {}  # local key name -> name the other computer sent
        self.os_name = getattr(inj, "os_name", "Darwin")
        self.stuck_released = 0
        self.last_click = (None, 0.0, 0, 0, 0)
        self.trace_keys = False
        self.last_seq = None
        self.seq_gaps = 0
        self.scroll_acc = [0.0, 0.0]

    def _mods(self):
        f = 0
        for n in self.keys:
            f |= MAC_MOD_FLAG.get(n, 0)
        return f

    def handle(self, m):
        with self.lock:
            t = m.get("t")
            if t == "ping":
                self.send({"t": "pong", "ts": m.get("ts")})
                if isinstance(m.get("held"), list):
                    self._resync(set(m["held"]))
            elif t == "hello":
                self.peer_os = m.get("os")
                self.peer_name = m.get("name")
                self.peer_ver = m.get("ver")
                self.connected = True
                self.log("the other computer: %s, %s, Wisp %s%s" % (
                    m.get("name") or "?", m.get("os") or "?", m.get("ver") or "older",
                    "" if m.get("ver") == VERSION else
                    "  (this computer has %s - update both to the same copy)" % VERSION))
            elif t == "enter":
                self._enter(float(m["r"]))
            elif t == "leave":
                self.release_all()
                self.active = False
            elif not self.active:
                return
            elif t == "m":
                self._move(m["dx"], m["dy"])
            elif t == "b":
                self._button(m["b"], bool(m["p"]))
            elif t == "s":
                self._scroll(float(m.get("dx", 0)), float(m.get("dy", 0)))
            elif t == "k":
                q = m.get("q")
                if isinstance(q, int):
                    if self.last_seq is not None and q != self.last_seq + 1:
                        self.seq_gaps += 1
                        self.log("WARNING: key #%d arrived after #%d (out of order or lost)"
                                 % (q, self.last_seq))
                    self.last_seq = q
                self._key(m["n"], bool(m["p"]), q, m.get("d"))

    def _desk(self, refresh=False):
        if refresh and hasattr(self.inj, "refresh"):
            self.inj.refresh()
        rects = tuple(tuple(d) for d in self.inj.displays())
        if getattr(self, "_desk_key", None) != rects:
            self._desk_key, self._desk_obj = rects, Desktop(rects)
        return self._desk_obj

    def _enter(self, r):
        d = self._desk(refresh=True)  # pick up displays plugged in since last time
        self.x, self.y = d.edge_point(self.side, min(max(r, 0.0), 1.0), inset=2)
        self.active = True
        self.btns.clear()
        self.inj.move(math.floor(self.x), math.floor(self.y), 0, 0, self.btns, self._mods())

    def _move(self, dx, dy):
        d = self._desk()
        tx, ty = self.x + dx * self.speed, self.y + dy * self.speed
        cx, cy = d.clamp(tx, ty)  # stay on real displays (no dead zones between them)
        beyond = {"left": tx < cx, "right": tx > cx, "top": ty < cy, "bottom": ty > cy}[self.side]
        self.x, self.y = cx, cy
        if beyond and not self.btns and d.free(cx, cy, self.side):
            r = d.ratio(self.side, cx, cy)
            self.release_all()
            self.active = False
            self.send({"t": "leave", "r": r})
            return
        self.inj.move(math.floor(self.x), math.floor(self.y), dx, dy, self.btns, self._mods())

    def _button(self, name, down):
        if name not in ("left", "right", "middle", "x1", "x2"):
            return
        if not down and name not in self.btns:
            return
        x, y = math.floor(self.x), math.floor(self.y)
        if down:
            b, t, lx, ly, n = self.last_click
            now = time.monotonic()
            n = n + 1 if b == name and now - t < 0.5 and abs(x - lx) <= 4 and abs(y - ly) <= 4 else 1
            self.last_click = (name, now, x, y, n)
            self.btns.add(name)
        else:
            self.btns.discard(name)
        clicks = self.last_click[4] if self.last_click[0] == name else 1
        self.inj.button(name, down, x, y, clicks, self._mods())

    def _scroll(self, dx, dy):
        sign = -1.0 if self.invert_scroll else 1.0
        wheel = getattr(self.inj, "wheel", None)
        if wheel:  # injector takes wheel notches directly (Windows); 3 lines = 1 notch
            k = sign * self.scroll_lines / 3.0
            wheel(dy * k, dx * k)
            return
        self.scroll_acc[0] += dy * self.scroll_lines * sign
        self.scroll_acc[1] += -dx * self.scroll_lines * sign  # mac wheel2: positive = left
        ly, lx = int(self.scroll_acc[0]), int(self.scroll_acc[1])
        self.scroll_acc[0] -= ly
        self.scroll_acc[1] -= lx
        if ly or lx:
            self.inj.scroll(ly, lx)

    def _resync(self, held):
        """safety net: release anything we hold that the other computer says isn't held"""
        for name in list(self.keys):
            if self.key_orig.get(name, name) not in held:
                self.stuck_released += 1
                self.log("released stuck key %s (the other computer no longer holds it)"
                         % self.key_orig.get(name, name))
                self._key_raw(name, False)

    def _key(self, name, down, seq=None, detail=None):
        orig = name
        if self.swap and self.peer_os and self.peer_os != self.os_name:
            name = SWAP_WIN_TO_MAC.get(name, name)  # Ctrl <-> Cmd/Win between Windows and Mac
        self._key_raw(name, down, seq, orig, detail)

    def _code(self, name):
        f = getattr(self.inj, "key_code", None)
        return f(name) if f else MAC_KVK.get(name)

    def _flags(self, name):
        f = getattr(self.inj, "key_flags", None)
        if f:
            return f(set(self.keys), name)
        return self._mods() | MAC_EXTRA_FLAG.get(name, 0)

    def _key_raw(self, name, down, seq=None, orig=None, detail=None):
        code = self._code(name)
        if code is None:
            if self.trace_keys:
                self.log("key #%s %s %s: no key for it here, ignored  [%s]" % (
                    "?" if seq is None else seq, orig or name, "down" if down else "up",
                    detail or ""))
            return
        if not down and name not in self.keys:
            return
        repeat = down and name in self.keys
        if down:
            self.keys[name] = code
            self.key_orig[name] = orig or name
        else:
            del self.keys[name]
            self.key_orig.pop(name, None)
        flags = self._flags(name)
        self.inj.key(code, down, flags, repeat)
        if self.trace_keys:
            held = "+".join(sorted(n for n in self.keys if n in MAC_MOD_FLAG)) or "-"
            self.log("key #%s %s%s %s -> %s keycode %#04x flags %#x%s  held: %s%s" % (
                "?" if seq is None else seq, orig or name,
                "" if (orig or name) == name else "(as %s)" % name,
                "down" if down else "up", "mac" if self.os_name == "Darwin" else "win",
                code, flags, " repeat" if repeat else "", held,
                "  [%s]" % detail if detail else ""))

    def release_all(self):
        with self.lock:
            for name in list(self.keys):
                self._key_raw(name, False)
            for b in list(self.btns):
                self.btns.discard(b)
                self.inj.button(b, False, math.floor(self.x), math.floor(self.y), 1, self._mods())


# ============================== networking ==============================
def run_server_net(core, port, token, bind="0.0.0.0", stop=None, ready=None,
                   hb=1.0, hb_timeout=4.0, log=print, stats=False):
    stop = stop or threading.Event()
    outq = queue.Queue()
    cur = {"conn": None}
    core.send = outq.put

    def sender():
        while not stop.is_set():
            try:
                batch = [outq.get(timeout=0.2)]
            except queue.Empty:
                continue
            while len(batch) < 1000:  # grab everything queued meanwhile
                try:
                    batch.append(outq.get_nowait())
                except queue.Empty:
                    break
            c = cur["conn"]
            if c is None:
                continue
            try:
                c.sendall(b"".join(encode(m) for m in coalesce(batch)))
            except OSError:
                try:
                    c.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def pinger():
        while not stop.wait(hb):
            if cur["conn"] is not None:
                with core.lock:  # same lock as key events -> the snapshot is in stream order
                    outq.put({"t": "ping", "ts": time.monotonic(), "held": core.held_names()})

    done = threading.Event()

    def stopper():  # on stop, cut the live connection so the read loop ends at once
        while not stop.wait(0.5):
            if done.is_set():
                return
        c = cur["conn"]
        if c is not None:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    threading.Thread(target=sender, daemon=True).start()
    threading.Thread(target=pinger, daemon=True).start()
    threading.Thread(target=stopper, daemon=True).start()

    srv = socket.socket()
    try:
        if sys.platform == "win32":  # Windows' SO_REUSEADDR would let two servers share a port
            srv.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_EXCLUSIVEADDRUSE", -5), 1)
        else:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind, port))
        srv.listen(2)
    except OSError:
        done.set()
        srv.close()
        raise
    srv.settimeout(0.5)
    if ready:
        ready(srv.getsockname()[1])
    try:
        while not stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.settimeout(5)
            try:
                rd = LineReader(conn)
                hello = rd.read()
                if not hello or not hmac.compare_digest(str(hello.get("token", "")), token):
                    log("rejected %s: bad token" % (addr[0],))
                    conn.sendall(encode({"t": "error", "msg": "bad token"}))
                    continue
                while not outq.empty():
                    outq.get_nowait()
                # server key/mouse codes are always Windows ones (see ServerCore)
                conn.sendall(encode({"t": "hello", "os": core.os_name, "proto": 3,
                                     "name": socket.gethostname(), "ver": VERSION}))
                core.peer_name = hello.get("name") or addr[0]
                cur["conn"] = conn
                core.set_connected(True)
                log("client connected: %s (Wisp %s)" % (addr[0], hello.get("ver") or "older"))
                conn.settimeout(hb_timeout)
                rtts, last_report = [], time.monotonic()
                while not stop.is_set():
                    m = rd.read()
                    if m is None:
                        break
                    t = m.get("t")
                    if t == "leave":
                        core.client_left(m.get("r", 0.5))
                    elif t == "pong" and isinstance(m.get("ts"), (int, float)):
                        rtt = (time.monotonic() - m["ts"]) * 1000
                        core.rtt_ms = rtt if core.rtt_ms is None else core.rtt_ms * 0.7 + rtt * 0.3
                        rtts.append(rtt)
                        if stats and time.monotonic() - last_report >= 5 and rtts:
                            log("network round trip: avg %.1f ms, max %.1f ms (%d samples)"
                                % (sum(rtts) / len(rtts), max(rtts), len(rtts)))
                            rtts, last_report = [], time.monotonic()
            except socket.timeout:
                log("client timed out")
            except (OSError, ValueError) as e:
                log("client error: %s" % (e,))
            finally:
                if cur["conn"] is conn:
                    cur["conn"] = None
                    core.rtt_ms = None
                    core.set_connected(False)
                    log("client disconnected")
                try:
                    conn.close()
                except OSError:
                    pass
    finally:
        done.set()
        srv.close()


def run_client_net(core, host, port, token, stop=None, retry=2.0, timeout=5.0, log=print):
    stop = stop or threading.Event()
    core.last_error = None
    core.net_error = None

    done = threading.Event()

    def stopper():
        while not stop.wait(0.5):
            if done.is_set():
                return
        s = getattr(core, "_sock", None)
        if s is not None:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
    threading.Thread(target=stopper, daemon=True).start()
    try:
        _client_loop(core, host, port, token, stop, retry, timeout, log)
    finally:
        done.set()


def _client_loop(core, host, port, token, stop, retry, timeout, log):
    while not stop.is_set():
        s = None
        try:
            s = socket.create_connection((host, port), timeout=3)
            core._sock = s
            if stop.is_set():
                break
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            lock = threading.Lock()

            def send(obj, s=s):
                with lock:
                    s.sendall(encode(obj))
            core.send = send
            send({"t": "hello", "token": token, "os": getattr(core, "os_name", platform.system()),
                  "name": socket.gethostname(), "ver": VERSION})
            s.settimeout(timeout)
            rd = LineReader(s)
            log("connected to %s:%d" % (host, port))
            while not stop.is_set():
                m = rd.read()
                if m is None:
                    raise ConnectionError("server closed the connection")
                for m in coalesce([m] + rd.pending()):  # skip stale intermediate moves
                    if m.get("t") == "error":
                        log("server says: %s" % m.get("msg"))
                        core.last_error = m.get("msg")
                        return
                    core.handle(m)
        except (OSError, ValueError) as e:
            if not stop.is_set():
                log("connection lost: %s" % (e,))
                core.net_error = str(e)
        finally:
            with core.lock:
                core.release_all()
                core.active = False
                core.connected = False
            core._sock = None
            if s:
                s.close()
        stop.wait(retry)


# ============================== discovery ==============================
DISCOVER_ASK, DISCOVER_REPLY = b"KMSHARE?", b"KMSHARE!"


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is sent; just picks the LAN interface
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def discovery_responder(port, name, stop, bind="0.0.0.0", ready=None):
    """answers 'is there a Wisp PC?' broadcasts on UDP port+1 (never reveals the code)"""
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        u.bind((bind, port + 1))
    except OSError:
        u.close()
        if ready:
            ready(False)
        return
    u.settimeout(0.3)
    if ready:
        ready(True)
    try:
        while not stop.is_set():
            try:
                data, addr = u.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                continue
            if data == DISCOVER_ASK:
                try:
                    u.sendto(DISCOVER_REPLY + json.dumps({"name": name, "port": port}).encode(), addr)
                except OSError:
                    pass
    finally:
        u.close()


def discover(port=PORT, timeout=1.2, extra=()):
    """find Wisp PCs on the local network -> [{"ip", "name", "port"}]"""
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    u.settimeout(0.1)
    targets = ["255.255.255.255"] + list(extra)
    ip = local_ip()
    if ip.count(".") == 3 and not ip.startswith("127."):
        targets.append(ip.rsplit(".", 1)[0] + ".255")
    found = {}
    try:
        end = time.time() + timeout
        next_send = 0
        while time.time() < end:
            if time.time() >= next_send:  # resend a few times: UDP over Wi-Fi can drop
                for t in targets:
                    try:
                        u.sendto(DISCOVER_ASK, (t, port + 1))
                    except OSError:
                        pass
                next_send = time.time() + 0.4
            try:
                data, addr = u.recvfrom(512)
            except (socket.timeout, OSError):
                continue
            if data.startswith(DISCOVER_REPLY):
                try:
                    info = json.loads(data[len(DISCOVER_REPLY):])
                except ValueError:
                    continue
                found[addr[0]] = {"ip": addr[0], "name": str(info.get("name", addr[0])),
                                  "port": int(info.get("port", port))}
    finally:
        u.close()
    by_pc = {}
    for f in sorted(found.values(), key=lambda f: (f["ip"].startswith("127."), f["ip"])):
        by_pc.setdefault((f["name"], f["port"]), f)  # prefer a LAN address over loopback
    return sorted(by_pc.values(), key=lambda f: (f["name"].lower(), f["ip"]))


# ============================== per-OS defaults ==============================
def default_capture_os():
    if sys.platform == "win32":
        return WinOS()
    if sys.platform == "darwin":
        return MacOS()
    raise RuntimeError("sharing is supported on Windows and macOS")


def default_install_capture(core):
    if sys.platform == "win32":
        return win_install_hooks(core)
    if sys.platform == "darwin":
        return mac_install_tap(core)
    return "sharing is supported on Windows and macOS"


def default_injector():
    if sys.platform == "win32":
        return WinInjector()
    if sys.platform == "darwin":
        return MacInjector()
    raise RuntimeError("receiving is supported on Windows and macOS")


def panic_keys_text(os_name):
    return "Ctrl+Option+Shift+Esc" if os_name == "Darwin" else "Ctrl+Alt+Shift+Esc"


# ============================== services (start/stop for the app) ==============================
class ServerService:
    """runs the sharing side; the input hooks are installed once and stay passive when stopped"""

    def __init__(self, make_os=None, install_hooks=None, log=print):
        self.make_os = make_os or default_capture_os
        self.install_hooks = install_hooks or default_install_capture
        self.log = log
        self.core = self.osi = self.stop_ev = self.thread = None
        self.error = None
        self.port = PORT

    def start(self, edge, port, token, hide=True, bind="0.0.0.0"):
        if self.running():
            return
        self.error = None
        if self.core is None:
            self.osi = self.make_os()
            if hasattr(self.osi, "restore_cursors"):
                self.osi.restore_cursors()
            core = ServerCore(self.osi, edge, log=self.log)
            err = self.install_hooks(core)
            if err:
                self.error = err
                raise RuntimeError(err)
            self.core = core
        self.apply(edge=edge, hide=hide)
        self.port = port
        self.stop_ev = stop = threading.Event()
        bound = threading.Event()

        def run():
            try:
                run_server_net(self.core, port, token, bind=bind, stop=stop, log=self.log,
                               ready=lambda p: bound.set())
            except OSError as e:
                self.error = "port %d is busy (is Wisp already running?)" % port \
                    if getattr(e, "errno", None) in (48, 98, 10048) else str(e)
                self.log("server error: %s" % e)
            finally:
                bound.set()
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        threading.Thread(target=discovery_responder, args=(port, socket.gethostname(), stop, bind),
                         daemon=True).start()
        bound.wait(3)

    def apply(self, edge=None, hide=None, trace=None, **_):
        if self.core is not None and trace is not None:
            self.core.trace_keys = bool(trace)
        if self.core is not None and edge:
            self.core.edge = edge
        if self.osi is not None and hide is not None and hasattr(self.osi, "hide_enabled"):
            self.osi.hide_enabled = hide

    def stop(self):
        if self.stop_ev:
            self.stop_ev.set()
        if self.thread:
            self.thread.join(3)
        if self.core is not None:
            self.core.set_connected(False)
        if self.osi is not None and hasattr(self.osi, "restore_cursors"):
            self.osi.restore_cursors()

    def running(self):
        return bool(self.thread and self.thread.is_alive())

    def state(self):
        if not self.running():
            return "error" if self.error else "stopped"
        if self.core.remote:
            return "remote"
        return "connected" if self.core.connected else "waiting"

    def rtt(self):
        return self.core.rtt_ms if self.core is not None and self.running() else None


class ClientService:
    def __init__(self, make_inj=None, log=print):
        self.make_inj = make_inj or default_injector
        self.log = log
        self.core = self.stop_ev = self.thread = None
        self.host = None

    def start(self, host, port, token, side="left", speed=1.0, swap=True, scroll=3.0,
              invert=False):
        if self.running():
            return
        if self.core is None:
            self.core = ClientCore(self.make_inj(), log=self.log)
        self.apply(side=side, speed=speed, swap=swap, scroll=scroll, invert=invert)
        self.host = host
        self.stop_ev = stop = threading.Event()
        self.thread = threading.Thread(target=run_client_net, args=(self.core, host, port, token),
                                       kwargs=dict(stop=stop, log=self.log), daemon=True)
        self.thread.start()

    def apply(self, side=None, speed=None, swap=None, scroll=None, invert=None, trace=None,
              **_):
        c = self.core
        if c is None:
            return
        with c.lock:
            if trace is not None:
                c.trace_keys = bool(trace)
            if side:
                c.side = side
            if speed is not None:
                c.speed = float(speed)
            if swap is not None:
                c.swap = bool(swap)
            if scroll is not None:
                c.scroll_lines = float(scroll)
            if invert is not None:
                c.invert_scroll = bool(invert)

    def stop(self):
        if self.stop_ev:
            self.stop_ev.set()
        if self.thread:
            self.thread.join(4)

    def running(self):
        return bool(self.thread and self.thread.is_alive())

    def state(self):
        c = self.core
        if not self.running():
            return "error" if c is not None and c.last_error else "stopped"
        if c.active:
            return "remote"
        return "connected" if c.connected else "connecting"


# ============================== Windows adapter ==============================
class MSLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_int32), ("y", ctypes.c_int32), ("mouseData", ctypes.c_uint32),
                ("flags", ctypes.c_uint32), ("time", ctypes.c_uint32),
                ("extra", ctypes.c_size_t)]


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("vkCode", ctypes.c_uint32), ("scanCode", ctypes.c_uint32),
                ("flags", ctypes.c_uint32), ("time", ctypes.c_uint32),
                ("extra", ctypes.c_size_t)]


LATE_HOOK_MS = 200  # Windows gives up waiting for a hook after ~300-1000 ms


def _check_lag(core, now_ms, event_ms):
    """Windows stamps each input event; if our hook runs much later, Windows may already
    have given the event to the PC (input leaks / keys go missing on the Mac)."""
    if now_ms is None:
        return
    lag = (now_ms() - event_ms) & 0xFFFFFFFF
    if LATE_HOOK_MS < lag < 600000:
        core.note_late_hook(lag)


def make_mouse_proc(core, call_next, now_ms=None):
    def proc(n, w, l):
        if n == 0:
            try:
                d = MSLLHOOKSTRUCT.from_address(l)
                _check_lag(core, now_ms, d.time)
                if core.on_mouse(w, d.x, d.y, d.mouseData, bool(d.flags & 0x3)):
                    return 1
            except Exception:
                traceback.print_exc()
        return call_next(n, w, l)
    return proc


def make_key_proc(core, call_next, now_ms=None):
    def proc(n, w, l):
        if n == 0:
            try:
                d = KBDLLHOOKSTRUCT.from_address(l)
                _check_lag(core, now_ms, d.time)
                if core.on_key(w, d.vkCode, d.flags, bool(d.flags & 0x12), d.scanCode):
                    return 1
            except Exception:
                traceback.print_exc()
        return call_next(n, w, l)
    return proc


class WinOS:
    os_name = "Windows"
    OCR_IDS = (32512, 32513, 32514, 32515, 32516, 32642, 32643, 32644, 32645, 32646,
               32648, 32649, 32650)

    def __init__(self, hide=True):
        from ctypes import wintypes as wt
        self.wt = wt
        u = self.u = ctypes.WinDLL("user32", use_last_error=True)
        u.GetSystemMetrics.argtypes = (ctypes.c_int,)
        u.SetCursorPos.argtypes = (ctypes.c_int, ctypes.c_int)
        u.GetCursorPos.argtypes = (ctypes.POINTER(wt.POINT),)
        u.CreateCursor.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
        u.CreateCursor.restype = ctypes.c_void_p
        u.SetSystemCursor.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        u.SystemParametersInfoW.argtypes = (ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p,
                                            ctypes.c_uint)
        self._mons = self._enum_monitors()
        threading.Thread(target=self._monitor_worker, daemon=True).start()
        self.hide_enabled = hide
        self.cq = queue.Queue()
        self._and = ctypes.create_string_buffer(b"\xff" * 128)
        self._xor = ctypes.create_string_buffer(b"\x00" * 128)
        threading.Thread(target=self._cursor_worker, daemon=True).start()

    def virtual_bounds(self):
        g = self.u.GetSystemMetrics
        return g(76), g(77), g(78), g(79)

    def _enum_monitors(self):
        def fb():
            x, y, w, h = self.virtual_bounds()
            return (x, y, x + w, y + h)
        return win_enum_monitors(self.u, fb)

    def monitors(self):
        return self._mons

    def _monitor_worker(self):
        while True:
            time.sleep(2)  # pick up plugged/unplugged/rearranged monitors
            try:
                self._mons = self._enum_monitors()
            except Exception:
                traceback.print_exc()

    def get_cursor(self):
        p = self.wt.POINT()
        self.u.GetCursorPos(ctypes.byref(p))
        return p.x, p.y

    def set_cursor(self, x, y):
        self.u.SetCursorPos(int(x), int(y))

    def hide_cursor(self):
        if self.hide_enabled:
            self.cq.put("hide")

    def show_cursor(self):
        self.cq.put("show")

    def restore_cursors(self):
        self.u.SystemParametersInfoW(0x57, 0, None, 0)  # SPI_SETCURSORS

    def _cursor_worker(self):
        while True:
            op = self.cq.get()
            try:
                if op == "hide":
                    for ocr in self.OCR_IDS:
                        h = self.u.CreateCursor(None, 0, 0, 32, 32, self._and, self._xor)
                        if h:
                            self.u.SetSystemCursor(h, ocr)
                else:
                    self.restore_cursors()
            except Exception:
                traceback.print_exc()


# ---------- Windows receiving side (SendInput) ----------
# neutral key name -> Windows virtual key (prefer the left/right specific codes)
WIN_NAME_VK = {}
for _vk, _n in sorted(WIN_VK.items()):
    WIN_NAME_VK.setdefault(_n, _vk)
WIN_NAME_VK.update({"shift": 0xA0, "shift_r": 0xA1, "ctrl": 0xA2, "ctrl_r": 0xA3, "alt": 0xA4,
                    "alt_r": 0xA5, "meta": 0x5B, "meta_r": 0x5C, "kp_enter": 0x0D})
# keys that need KEYEVENTF_EXTENDEDKEY
WIN_EXTENDED = {"ctrl_r", "alt_r", "insert", "delete", "home", "end", "page_up", "page_down",
                "left", "right", "up", "down", "kp_divide", "kp_enter", "num_lock", "meta",
                "meta_r", "menu", "print_screen"}
KMSHARE_TAG = 0x4B4D5348  # dwExtraInfo on events we inject ("KMSH")


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", ctypes.c_int32), ("dy", ctypes.c_int32), ("mouseData", ctypes.c_uint32),
                ("dwFlags", ctypes.c_uint32), ("time", ctypes.c_uint32),
                ("dwExtraInfo", ctypes.c_size_t)]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", ctypes.c_uint16), ("wScan", ctypes.c_uint16), ("dwFlags", ctypes.c_uint32),
                ("time", ctypes.c_uint32), ("dwExtraInfo", ctypes.c_size_t)]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", ctypes.c_uint32), ("wParamL", ctypes.c_uint16),
                ("wParamH", ctypes.c_uint16)]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32), ("u", _INPUTUNION)]


WIN_BTN_FLAGS = {"left": (0x0002, 0x0004, 0), "right": (0x0008, 0x0010, 0),
                 "middle": (0x0020, 0x0040, 0), "x1": (0x0080, 0x0100, 1),
                 "x2": (0x0080, 0x0100, 2)}


def win_enum_monitors(u, fallback=None):
    from ctypes import wintypes as wt
    MONENUM = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
                                 ctypes.POINTER(wt.RECT), ctypes.c_ssize_t)
    u.EnumDisplayMonitors.argtypes = (ctypes.c_void_p, ctypes.c_void_p, MONENUM, ctypes.c_ssize_t)
    out = []

    def cb(hmon, hdc, rc, lp):
        r = rc.contents
        out.append((r.left, r.top, r.right, r.bottom))
        return 1
    u.EnumDisplayMonitors(None, None, MONENUM(cb), 0)
    if not out and fallback:
        out = [fallback()]
    return out


class WinInjector:
    """receiving side on Windows: replays the other computer's input with SendInput"""
    os_name = "Windows"

    def __init__(self, user32=None):
        from ctypes import wintypes as wt
        self.wt = wt
        u = self.u = user32 or ctypes.WinDLL("user32", use_last_error=True)
        u.SendInput.argtypes = (ctypes.c_uint, ctypes.POINTER(INPUT), ctypes.c_int)
        u.SendInput.restype = ctypes.c_uint
        u.MapVirtualKeyW.argtypes = (ctypes.c_uint, ctypes.c_uint)
        u.MapVirtualKeyW.restype = ctypes.c_uint
        u.GetSystemMetrics.argtypes = (ctypes.c_int,)
        u.GetCursorPos.argtypes = (ctypes.POINTER(wt.POINT),)
        self._displays = None
        self.wheel_acc = [0.0, 0.0]
        self.sent = 0

    def _virtual(self):
        g = self.u.GetSystemMetrics
        return g(76), g(77), g(78), g(79)

    def refresh(self):
        def fb():
            x, y, w, h = self._virtual()
            return (x, y, x + w, y + h)
        self._displays = win_enum_monitors(self.u, fb)

    def displays(self):
        if self._displays is None:
            self.refresh()
        return self._displays

    def get_pos(self):
        p = self.wt.POINT()
        self.u.GetCursorPos(ctypes.byref(p))
        return p.x, p.y

    def _send(self, *inputs):
        arr = (INPUT * len(inputs))(*inputs)
        self.sent += self.u.SendInput(len(inputs), arr, ctypes.sizeof(INPUT))

    def _mouse(self, flags, dx=0, dy=0, data=0):
        i = INPUT(type=0)
        i.u.mi = MOUSEINPUT(dx, dy, data & 0xFFFFFFFF, flags, 0, KMSHARE_TAG)
        return i

    def move(self, x, y, dx, dy, btns, flags):
        vx, vy, vw, vh = self._virtual()
        ax = int(round((x - vx) * 65535.0 / max(1, vw - 1)))
        ay = int(round((y - vy) * 65535.0 / max(1, vh - 1)))
        # MOVE | ABSOLUTE | VIRTUALDESK
        self._send(self._mouse(0x0001 | 0x8000 | 0x4000, ax, ay))

    def button(self, name, down, x, y, clicks, flags):
        dn, up, xb = WIN_BTN_FLAGS[name]
        self._send(self._mouse(dn if down else up, data=xb))

    def wheel(self, notches_y, notches_x):
        acc = self.wheel_acc
        acc[0] += notches_y * 120
        acc[1] += notches_x * 120
        out = []
        for i, flag in ((0, 0x0800), (1, 0x1000)):  # WHEEL, HWHEEL
            d = int(acc[i])
            if d:
                acc[i] -= d
                out.append(self._mouse(flag, data=d))
        if out:
            self._send(*out)

    def scroll(self, lines_y, lines_x):  # not used (wheel() is preferred), kept for the interface
        self.wheel(lines_y / 3.0, -lines_x / 3.0)

    def key_code(self, name):
        return WIN_NAME_VK.get(name)

    def key_flags(self, held, name):
        return 0x0001 if name in WIN_EXTENDED else 0  # KEYEVENTF_EXTENDEDKEY

    def key(self, vk, down, flags, repeat):
        i = INPUT(type=1)
        scan = self.u.MapVirtualKeyW(vk, 0) & 0xFF  # MAPVK_VK_TO_VSC
        i.u.ki = KEYBDINPUT(vk, scan, (flags & 0x1) | (0 if down else 0x0002), 0, KMSHARE_TAG)
        self._send(i)


def win_set_dpi_aware():
    u = ctypes.windll.user32
    try:
        u.SetProcessDpiAwarenessContext.argtypes = (ctypes.c_void_p,)
        if u.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):  # PER_MONITOR_AWARE_V2
            return
    except (AttributeError, OSError):
        pass
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return
    except (AttributeError, OSError):
        pass
    u.SetProcessDPIAware()


def win_run_hooks(core, ready):
    u = ctypes.WinDLL("user32", use_last_error=True)
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int, ctypes.c_size_t, ctypes.c_ssize_t)
    u.SetWindowsHookExW.argtypes = (ctypes.c_int, HOOKPROC, ctypes.c_void_p, ctypes.c_uint32)
    u.SetWindowsHookExW.restype = ctypes.c_void_p
    u.CallNextHookEx.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t, ctypes.c_ssize_t)
    u.CallNextHookEx.restype = ctypes.c_ssize_t
    u.GetMessageW.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint)
    k.GetModuleHandleW.argtypes = (ctypes.c_wchar_p,)
    k.GetModuleHandleW.restype = ctypes.c_void_p

    def call_next(n, w, l):
        return u.CallNextHookEx(None, n, w, l)

    k.GetTickCount.restype = ctypes.c_uint32
    mp = HOOKPROC(make_mouse_proc(core, call_next, now_ms=k.GetTickCount))
    kp = HOOKPROC(make_key_proc(core, call_next, now_ms=k.GetTickCount))
    hmod = k.GetModuleHandleW(None)
    hm = u.SetWindowsHookExW(14, mp, hmod, 0)  # WH_MOUSE_LL
    hk = u.SetWindowsHookExW(13, kp, hmod, 0)  # WH_KEYBOARD_LL
    if not hm or not hk:
        ready(ctypes.get_last_error() or -1)
        return
    ready(0)
    msg = ctypes.create_string_buffer(64)  # MSG
    while u.GetMessageW(msg, None, 0, 0) > 0:
        pass


def win_install_hooks(core):
    """install the low-level hooks on their own thread; returns None or an error string"""
    res, ev = [], threading.Event()
    threading.Thread(target=win_run_hooks, args=(core, lambda r: (res.append(r), ev.set())),
                     daemon=True).start()
    ev.wait(5)
    if not res or res[0] != 0:
        return "failed to install input hooks (error %s)" % (res[0] if res else "timeout")
    return None


def server_main(a):
    """share this computer's keyboard and mouse (Windows or macOS)"""
    sys.setswitchinterval(0.001)  # hand the GIL over quickly -> lower input latency
    if sys.platform == "win32":
        win_set_dpi_aware()
    osi = default_capture_os()
    if hasattr(osi, "hide_enabled"):
        osi.hide_enabled = not a.no_hide
    if hasattr(osi, "restore_cursors"):
        osi.restore_cursors()  # in case a previous run died while the cursor was hidden
    core = ServerCore(osi, a.edge)
    err = default_install_capture(core)
    if err:
        raise SystemExit(err)
    print("Wisp: sharing; the other computer is beyond the %s edge; port %d" % (a.edge, a.port))
    for m in osi.monitors():
        print("  screen %dx%d at (%d,%d)" % (m[2] - m[0], m[3] - m[1], m[0], m[1]))
    print("panic key: %s   quit: Ctrl+C in this window" % panic_keys_text(osi.os_name))
    try:
        run_server_net(core, a.port, a.token, bind=a.bind, stats=a.stats)
    except KeyboardInterrupt:
        pass
    finally:
        core.set_connected(False)
        if hasattr(osi, "restore_cursors"):
            osi.restore_cursors()


# ============================== macOS adapter ==============================
class MacInjector:
    os_name = "Darwin"

    def __init__(self):
        import Quartz as Q
        self.Q = Q
        self.src = Q.CGEventSourceCreate(Q.kCGEventSourceStateHIDSystemState)
        self.BTN = {
            "left": (Q.kCGEventLeftMouseDown, Q.kCGEventLeftMouseUp,
                     Q.kCGEventLeftMouseDragged, Q.kCGMouseButtonLeft),
            "right": (Q.kCGEventRightMouseDown, Q.kCGEventRightMouseUp,
                      Q.kCGEventRightMouseDragged, Q.kCGMouseButtonRight),
            "middle": (Q.kCGEventOtherMouseDown, Q.kCGEventOtherMouseUp,
                       Q.kCGEventOtherMouseDragged, 2),
            "x1": (Q.kCGEventOtherMouseDown, Q.kCGEventOtherMouseUp,
                   Q.kCGEventOtherMouseDragged, 3),
            "x2": (Q.kCGEventOtherMouseDown, Q.kCGEventOtherMouseUp,
                   Q.kCGEventOtherMouseDragged, 4),
        }
        self._bounds = None

    def refresh(self):
        Q = self.Q
        err, ids, n = Q.CGGetActiveDisplayList(16, None, None)
        rects = [Q.CGDisplayBounds(d) for d in (ids or [])[:n]] or \
            [Q.CGDisplayBounds(Q.CGMainDisplayID())]
        self._displays = [(int(r.origin.x), int(r.origin.y), int(r.origin.x + r.size.width),
                           int(r.origin.y + r.size.height)) for r in rects]

    def displays(self):
        if self._bounds is None:
            self.refresh()
            self._bounds = True
        return self._displays

    def get_pos(self):
        loc = self.Q.CGEventGetLocation(self.Q.CGEventCreate(None))
        return loc.x, loc.y

    # event builders (separate from posting so they can be tested without moving anything)
    def ev_move(self, x, y, dx, dy, btns, flags):
        Q = self.Q
        held = next((b for b in ("left", "right", "middle", "x1", "x2") if b in btns), None)
        typ, button = (self.BTN[held][2], self.BTN[held][3]) if held else (Q.kCGEventMouseMoved, 0)
        e = Q.CGEventCreateMouseEvent(self.src, typ, (x, y), button)
        Q.CGEventSetIntegerValueField(e, Q.kCGMouseEventDeltaX, int(dx))
        Q.CGEventSetIntegerValueField(e, Q.kCGMouseEventDeltaY, int(dy))
        Q.CGEventSetFlags(e, flags)
        return e

    def ev_button(self, name, down, x, y, clicks, flags):
        Q = self.Q
        b = self.BTN[name]
        e = Q.CGEventCreateMouseEvent(self.src, b[0] if down else b[1], (x, y), b[3])
        Q.CGEventSetIntegerValueField(e, Q.kCGMouseEventClickState, int(clicks))
        Q.CGEventSetFlags(e, flags)
        return e

    def ev_scroll(self, lines_y, lines_x):
        Q = self.Q
        return Q.CGEventCreateScrollWheelEvent(self.src, Q.kCGScrollEventUnitLine, 2,
                                               int(lines_y), int(lines_x))

    def ev_key(self, code, down, flags, repeat):
        Q = self.Q
        e = Q.CGEventCreateKeyboardEvent(self.src, code, down)
        Q.CGEventSetFlags(e, flags)
        if repeat:
            Q.CGEventSetIntegerValueField(e, Q.kCGKeyboardEventAutorepeat, 1)
        return e

    def _post(self, e):
        self.Q.CGEventPost(self.Q.kCGHIDEventTap, e)

    def move(self, *a):
        self._post(self.ev_move(*a))

    def button(self, *a):
        self._post(self.ev_button(*a))

    def scroll(self, *a):
        self._post(self.ev_scroll(*a))

    def key(self, *a):
        self._post(self.ev_key(*a))


# ---------- macOS sharing side (event tap) ----------
# mac keycode -> neutral name; where two names share a keycode, keep the key's PC role
MAC_KC_NAME = {}
for _n, _kc in sorted(MAC_KVK.items()):
    MAC_KC_NAME.setdefault(_kc, _n)
MAC_KC_NAME.update({0x69: "print_screen", 0x6B: "scroll_lock", 0x71: "pause", 0x72: "insert",
                    0x47: "num_lock", 0x51: "kp_equal"})
# modifier keycode -> device-specific flag bit telling whether that exact key is down
MAC_MOD_DEVICE_BIT = {0x38: 0x00000002, 0x3C: 0x00000004, 0x3B: 0x00000001, 0x3E: 0x00002000,
                      0x3A: 0x00000020, 0x3D: 0x00000040, 0x37: 0x00000008, 0x36: 0x00000010}
MAC_KC_CAPS, MAC_KC_FN = 0x39, 0x3F
# CGEventType numbers (stable public values)
MAC_EV = {"lmd": 1, "lmu": 2, "rmd": 3, "rmu": 4, "move": 5, "ldrag": 6, "rdrag": 7, "kd": 10,
          "ku": 11, "flags": 12, "scroll": 22, "omd": 25, "omu": 26, "odrag": 27,
          "tap_timeout": 0xFFFFFFFE, "tap_user": 0xFFFFFFFF}
MAC_OTHER_BTN = {2: "middle", 3: "x1", 4: "x2"}


def mac_decode(Q, typ, ev):
    """CGEvent -> plain tuple the core understands (kept separate so it can be tested on
    real CGEvents without installing a tap)"""
    E = MAC_EV
    if typ in (E["move"], E["ldrag"], E["rdrag"], E["odrag"]):
        loc = Q.CGEventGetLocation(ev)
        return ("move", loc.x, loc.y,
                Q.CGEventGetIntegerValueField(ev, Q.kCGMouseEventDeltaX),
                Q.CGEventGetIntegerValueField(ev, Q.kCGMouseEventDeltaY))
    if typ in (E["lmd"], E["lmu"]):
        return ("btn", "left", typ == E["lmd"])
    if typ in (E["rmd"], E["rmu"]):
        return ("btn", "right", typ == E["rmd"])
    if typ in (E["omd"], E["omu"]):
        n = Q.CGEventGetIntegerValueField(ev, Q.kCGMouseEventButtonNumber)
        name = MAC_OTHER_BTN.get(n)
        return ("btn", name, typ == E["omd"]) if name else ("other",)
    if typ == E["scroll"]:
        dy = Q.CGEventGetDoubleValueField(ev, Q.kCGScrollWheelEventFixedPtDeltaAxis1)
        dx = Q.CGEventGetDoubleValueField(ev, Q.kCGScrollWheelEventFixedPtDeltaAxis2)
        return ("scroll", -dx, dy)  # mac axis2 positive = left; wire dx positive = right
    if typ in (E["kd"], E["ku"]):
        kc = Q.CGEventGetIntegerValueField(ev, Q.kCGKeyboardEventKeycode)
        return ("key", kc, typ == E["kd"])
    if typ == E["flags"]:
        kc = Q.CGEventGetIntegerValueField(ev, Q.kCGKeyboardEventKeycode)
        return ("flags", kc, int(Q.CGEventGetFlags(ev)))
    return ("other",)


def mac_dispatch(core, info):
    """route a decoded mac event into the core; returns True to swallow it"""
    kind = info[0]
    if kind == "move":
        return core.motion(info[1], info[2], info[3], info[4])
    if kind == "btn":
        return core.button(info[1], info[2])
    if kind == "scroll":
        return core.wheel(info[1], info[2])
    if kind == "key":
        kc, down = info[1], info[2]
        return core.key(kc, MAC_KC_NAME.get(kc), down, "mac keycode %#04x" % kc)
    if kind == "flags":
        kc, flags = info[1], info[2]
        if kc in MAC_MOD_DEVICE_BIT:
            down = bool(flags & MAC_MOD_DEVICE_BIT[kc])
            return core.key(kc, MAC_KC_NAME.get(kc), down, "mac keycode %#04x" % kc)
        if kc == MAC_KC_CAPS:  # macOS reports caps lock as a toggle: send a full press
            a = core.key(kc, "caps_lock", True, "caps lock")
            core.key(kc, "caps_lock", False, "caps lock")
            return a
        return core.remote  # fn etc.: nothing to forward
    return core.remote


class MacOS:
    """sharing side on macOS: cursor control for ServerCore"""
    os_name = "Darwin"

    def __init__(self):
        import Quartz as Q
        self.Q = Q
        self.hidden = False
        self._displays = None
        try:
            Q.CGSetLocalEventsSuppressionInterval(0.0)  # warps must not freeze the real mouse
        except Exception:
            pass
        mac_cursor_in_background()

    def monitors(self):
        Q = self.Q
        err, ids, n = Q.CGGetActiveDisplayList(16, None, None)
        rects = [Q.CGDisplayBounds(d) for d in (ids or [])[:n]] or \
            [Q.CGDisplayBounds(Q.CGMainDisplayID())]
        mons = [(int(r.origin.x), int(r.origin.y), int(r.origin.x + r.size.width),
                 int(r.origin.y + r.size.height)) for r in rects]
        self._displays = mons
        return mons

    def get_cursor(self):
        loc = self.Q.CGEventGetLocation(self.Q.CGEventCreate(None))
        return loc.x, loc.y

    def set_cursor(self, x, y):
        self.Q.CGWarpMouseCursorPosition((x, y))

    def hide_cursor(self):
        Q = self.Q
        Q.CGAssociateMouseAndMouseCursorPosition(False)  # mouse moves no longer move the cursor
        if not self.hidden:
            Q.CGDisplayHideCursor(Q.CGMainDisplayID())
            self.hidden = True

    def show_cursor(self):
        Q = self.Q
        Q.CGAssociateMouseAndMouseCursorPosition(True)
        if self.hidden:
            Q.CGDisplayShowCursor(Q.CGMainDisplayID())
            self.hidden = False

    def restore_cursors(self):
        self.show_cursor()


def mac_cursor_in_background():
    """let a background app hide the cursor (what other KVM tools do; best effort)"""
    try:
        cg = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/ApplicationServices.framework/"
                                     "ApplicationServices")
        cf = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/CoreFoundation.framework/"
                                     "CoreFoundation")
        cg._CGSDefaultConnection.restype = ctypes.c_int
        cf.CFStringCreateWithCString.restype = ctypes.c_void_p
        cf.CFStringCreateWithCString.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32)
        cg.CGSSetConnectionProperty.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p,
                                                ctypes.c_void_p)
        key = cf.CFStringCreateWithCString(None, b"SetsCursorInBackground", 0x08000100)
        true = ctypes.c_void_p.in_dll(cf, "kCFBooleanTrue")
        conn = cg._CGSDefaultConnection()
        cg.CGSSetConnectionProperty(conn, conn, key, true)
        return True
    except Exception:
        return False


def mac_install_tap(core, log=print):
    """install the event tap on its own run-loop thread; returns None or an error string"""
    import Quartz as Q
    E = MAC_EV
    res, ready = [], threading.Event()
    state = {}

    def callback(proxy, typ, ev, refcon):
        if typ in (E["tap_timeout"], E["tap_user"]):
            # macOS switched the tap off (it was too slow): note it and switch it back on
            core.note_late_hook(1000)
            Q.CGEventTapEnable(state["tap"], True)
            return ev
        try:
            if Q.CGEventGetIntegerValueField(ev, Q.kCGEventSourceUnixProcessID) == os.getpid():
                return ev  # our own injected events (if this Mac is also receiving)
            if mac_dispatch(core, mac_decode(Q, typ, ev)):
                return None
        except Exception:
            traceback.print_exc()
        return ev

    def run():
        mask = 0
        for t in (E["lmd"], E["lmu"], E["rmd"], E["rmu"], E["move"], E["ldrag"], E["rdrag"],
                  E["kd"], E["ku"], E["flags"], E["scroll"], E["omd"], E["omu"], E["odrag"]):
            mask |= 1 << t
        tap = Q.CGEventTapCreate(Q.kCGSessionEventTap, Q.kCGHeadInsertEventTap,
                                 Q.kCGEventTapOptionDefault, mask, callback, None)
        if not tap:
            res.append("macOS refused the input tap. Allow Wisp under Privacy & Security > "
                       "Accessibility and Input Monitoring, then reopen it.")
            ready.set()
            return
        state["tap"] = tap
        src = Q.CFMachPortCreateRunLoopSource(None, tap, 0)
        Q.CFRunLoopAddSource(Q.CFRunLoopGetCurrent(), src, Q.kCFRunLoopCommonModes)
        Q.CGEventTapEnable(tap, True)
        res.append(None)
        ready.set()
        Q.CFRunLoopRun()

    threading.Thread(target=run, daemon=True, name="wisp-tap").start()
    ready.wait(5)
    return res[0] if res else "input tap did not start"


def mac_input_monitoring():
    """(check, prompt) for macOS Input Monitoring, which the sharing side needs"""
    try:
        iokit = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/IOKit.framework/IOKit")
        iokit.IOHIDCheckAccess.argtypes = (ctypes.c_uint32,)
        iokit.IOHIDRequestAccess.argtypes = (ctypes.c_uint32,)
        iokit.IOHIDRequestAccess.restype = ctypes.c_bool
    except (OSError, AttributeError):
        return None, None

    def check():
        return iokit.IOHIDCheckAccess(1) == 0  # kIOHIDRequestTypeListenEvent; 0 = granted

    def prompt():
        iokit.IOHIDRequestAccess(1)
        import subprocess
        subprocess.Popen(["open", "x-apple.systempreferences:com.apple.preference.security"
                                  "?Privacy_ListenEvent"])
    return check, prompt


def client_main(a):
    """use the other computer's keyboard and mouse here (Windows or macOS)"""
    sys.setswitchinterval(0.001)  # hand the GIL over quickly -> lower input latency
    if sys.platform == "win32":
        win_set_dpi_aware()
    if sys.platform == "darwin":
        try:
            from ApplicationServices import AXIsProcessTrusted
            if not AXIsProcessTrusted():
                print("WARNING: this terminal app lacks Accessibility permission; macOS will "
                      "silently drop injected input.\n  System Settings > Privacy & Security > "
                      "Accessibility -> enable your terminal app, then restart it.")
        except ImportError:
            pass
    activity = mac_latency_critical() if sys.platform == "darwin" else None  # noqa: F841
    inj = default_injector()
    core = ClientCore(inj, side=a.side, speed=a.speed, swap=a.swap,
                      scroll_lines=a.scroll, invert_scroll=a.invert_scroll)
    print("Wisp: receiving; the sharing computer is beyond the %s edge; connecting to %s:%d"
          % (a.side, a.host, a.port))
    for d in inj.displays():
        print("  display %dx%d at (%d,%d)" % (d[2] - d[0], d[3] - d[1], d[0], d[1]))
    try:
        run_client_net(core, a.host, a.port, a.token)
    except KeyboardInterrupt:
        pass
    finally:
        core.release_all()


# ============================== app window ==============================
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".wisp.json")
DIR_TEXT = {"top": " ▲  Above", "left": " ◀  Left", "right": " Right  ▶",
            "bottom": " ▼  Below"}
DIR_POS = {"top": (0, 1), "left": (1, 0), "right": (1, 2), "bottom": (2, 1)}
DIR_EDGE_WORD = {"top": "top", "left": "left", "right": "right", "bottom": "bottom"}
COLORS = {"grey": "#9aa0a6", "amber": "#f2a600", "green": "#22b8a0", "blue": "#7b5cff",
          "red": "#d64545"}
BANNER_SUB = "one keyboard & mouse, drifting between your computers"
BTN_SERVER = ("Summon the wisp", "Dismiss the wisp")  # main button: (idle, running)
BTN_CLIENT = ("Invite the wisp", "Send it home")
SKY = {"top": "#3b1d6e", "bottom": "#120c34", "title": "#f4fffb", "sub": "#cdbfff",
       "star": "#fff6c8"}
AX_SETTINGS_URL = "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"


def load_config(path):
    try:
        with open(path) as f:
            c = json.load(f)
        return c if isinstance(c, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(path, cfg):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(cfg, f, indent=2)
        os.replace(tmp, path)
    except OSError:
        pass


def new_code():
    return "%06d" % secrets.randbelow(1000000)


def fmt_code(c):
    c = "".join(ch for ch in str(c) if ch.isdigit())
    return c[:3] + " " + c[3:] if len(c) == 6 else c


def clean_code(c):
    return "".join(ch for ch in str(c) if ch.isdigit())


def parse_host(text):
    """'DESKTOP-1 (192.168.1.50)' -> '192.168.1.50'; plain text is returned trimmed"""
    t = text.strip()
    if t.endswith(")") and "(" in t:
        return t[t.rindex("(") + 1:-1].strip()
    return t


class QueueWriter:
    """file-like object sending text to the app's activity log (also used under pythonw)"""

    def __init__(self, q):
        self.q = q

    def write(self, s):
        if s and s.strip():
            self.q.put(s.rstrip())
        return len(s or "")

    def flush(self):
        pass


# app icon (drawn by tools/make_icon.py) - embedded so wisp.py stays a single file
ICON_PNG = {
  128: (
    "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"
    "rkJggg=="),
  32: (
    "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"),
}


def window_icon(root, size=128):
    """Tk PhotoImage of the wisp; size 64 is the 128 px icon halved. None if Tk can't read PNG"""
    import tkinter as tk
    try:
        if size == 32:
            return tk.PhotoImage(master=root, data=ICON_PNG[32])
        img = tk.PhotoImage(master=root, data=ICON_PNG[128])
        return img.subsample(128 // size) if size < 128 else img
    except Exception:
        return None


LOG_PATH = os.path.join(os.path.expanduser("~"), ".wisp.log")


class FileLogQueue(queue.Queue):
    """activity-log queue that also appends every line to ~/.wisp.log (kept < 2 MB)"""

    def __init__(self, path=LOG_PATH):
        super().__init__()
        self.path, self._flock = path, threading.Lock()

    def put(self, item, *a, **k):
        try:
            with self._flock:
                if os.path.exists(self.path) and os.path.getsize(self.path) > 2_000_000:
                    os.replace(self.path, self.path + ".old")
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write("%s.%03d %s\n" % (time.strftime("%H:%M:%S"),
                                              int(time.time() * 1000) % 1000, item))
        except OSError:
            pass
        super().put(item, *a, **k)


class App:
    POLL_MS = 250

    def __init__(self, root, role, service, cfg_path=CONFIG_PATH, discover_fn=None,
                 ax_check=None, ax_prompt=None, logq=None, hostname=None, ip=None,
                 login_path=None, os_name=None, perms=None, on_switch=None):
        import tkinter as tk
        from tkinter import ttk
        self.tk, self.ttk = tk, ttk
        self.root, self.role, self.svc = root, role, service
        self.server = role == "server"
        self.cfg_path = cfg_path
        self.cfg = load_config(cfg_path)
        self.discover_fn = discover_fn or discover
        self.os_name = os_name or ("Windows" if sys.platform == "win32" else platform.system())
        self.this_label = "This Mac" if self.os_name == "Darwin" else "This PC"
        if perms is None:
            perms = []
            if ax_check is not None:
                perms.append({"name": "Accessibility", "check": ax_check, "prompt": ax_prompt,
                              "why": "to move the pointer and type on this computer"})
        self.perms = perms
        self.on_switch = on_switch
        self.logq = logq or queue.Queue()
        self.login_path = login_path or login_item_path()
        self.hostname = hostname or socket.gethostname()
        self.ip = ip or local_ip()
        self.found = []
        self.searching = False
        self._next_search = 0
        self._results = queue.Queue()
        self.start_error = None
        self._ax_next = 0
        self._ax_prompted = False
        if self.server:  # the code this computer shows; older configs kept it under "code"
            if not clean_code(self.cfg.get("share_code", "")):
                old = clean_code(self.cfg.get("code", "")) if not self.cfg.get("host") else ""
                self.cfg["share_code"] = old if len(old) == 6 else new_code()
        self._build()
        self._save()
        self.closed = False
        root.protocol("WM_DELETE_WINDOW", self.close)
        self._poll()
        if not self.server:
            self.search(auto=True)
        if self.cfg.get("autostart") and self._can_start()[0]:
            root.after(300, self.start)

    # ---------------- layout ----------------
    def _banner(self, parent):
        """night-sky header with the wisp, its name and a few stars"""
        tk = self.tk
        h = 86
        import tkinter.font as tkfont
        sub_font = tkfont.Font(root=self.root, family="TkDefaultFont", size=11)
        need = 89 + sub_font.measure(BANNER_SUB) + 30  # wide enough for the tagline + a star
        cv = tk.Canvas(parent, height=h, width=max(440, need), highlightthickness=0, bd=0,
                       bg=SKY["bottom"])
        img = window_icon(self.root, 64)
        cv._img = img  # keep a reference (Tk drops images that Python forgets)

        def paint(_e=None):
            cv.delete("all")
            w = max(cv.winfo_width(), int(cv.cget("width")))
            top = [int(SKY["top"][i:i + 2], 16) for i in (1, 3, 5)]
            bot = [int(SKY["bottom"][i:i + 2], 16) for i in (1, 3, 5)]
            for y in range(h):
                k = y / float(h - 1)
                col = "#%02x%02x%02x" % tuple(int(top[j] + (bot[j] - top[j]) * k) for j in range(3))
                cv.create_line(0, y, w, y, fill=col)
            t1 = cv.create_text(88, 33, text="Wisp", anchor="w", fill=SKY["title"],
                                font=("TkDefaultFont", 22, "bold"))
            t2 = cv.create_text(89, 60, anchor="w", fill=SKY["sub"], font=sub_font,
                                text=BANNER_SUB)
            boxes = [cv.bbox(t) for t in (t1, t2)]
            boxes.append((0, 0, 84, h))  # the icon

            def clear(x, y, pad=4):
                return not any(b and b[0] - pad <= x <= b[2] + pad and b[1] - pad <= y <= b[3] + pad
                               for b in boxes)
            rnd = random.Random(5)
            for _ in range(int(w / 9)):
                x, y = rnd.uniform(4, w - 6), rnd.uniform(4, h - 4)
                r = rnd.choice((0.8, 1.0, 1.4))
                if clear(x, y):
                    cv.create_oval(x - r, y - r, x + r, y + r, fill=SKY["star"], outline="")
            for (x, y, r) in ((w - 40, 22, 7), (w - 74, 60, 4.5), (w - 18, 64, 3.5)):
                if not clear(x, y, pad=r + 2):
                    continue
                cv.create_polygon(x, y - r, x + r * .25, y - r * .25, x + r, y, x + r * .25,
                                  y + r * .25, x, y + r, x - r * .25, y + r * .25, x - r, y,
                                  x - r * .25, y - r * .25, fill=SKY["star"], outline="",
                                  smooth=False)
            if img is not None:
                cv.create_image(12, h // 2, image=img, anchor="w")
            cv.tag_raise(t1)
            cv.tag_raise(t2)
        cv.bind("<Configure>", paint)
        paint()
        return cv

    def _build(self):
        tk, ttk, root, cfg = self.tk, self.ttk, self.root, self.cfg
        root.title("Wisp")
        if not getattr(root, "_wisp_icons", None):
            icons = [i for i in (window_icon(root, 128), window_icon(root, 32)) if i is not None]
            if icons:
                root.iconphoto(True, *icons)
            root._wisp_icons = icons
        root.resizable(False, False)
        st = ttk.Style(root)
        st.configure("Title.TLabel", font=("TkDefaultFont", 20, "bold"))
        st.configure("Sub.TLabel", foreground="#6b7280")
        st.configure("Code.TLabel", font=("TkFixedFont", 30, "bold"))
        st.configure("Status.TLabel", font=("TkDefaultFont", 13, "bold"))
        st.configure("Box.TLabel", relief="solid", borderwidth=1, padding=(14, 10),
                     anchor="center", justify="center")
        st.configure("Big.TButton", font=("TkDefaultFont", 13, "bold"), padding=(18, 8))

        f = self.frame = ttk.Frame(root, padding=(22, 18, 22, 16))
        f.grid(row=0, column=0, sticky="nsew")
        f.columnconfigure(0, weight=1)
        r = 0
        self.banner = self._banner(f)
        self.banner.grid(row=r, column=0, sticky="ew")
        r += 1
        rf = ttk.Frame(f)
        rf.grid(row=r, column=0, sticky="w", pady=(12, 0))
        r += 1
        self.role_var = tk.StringVar(value=self.role)
        for i, (val, text) in enumerate((
                ("server", "\u2726 This computer has the keyboard & mouse \u2013 lend them out"),
                ("client", "\u2727 Borrow another computer's keyboard & mouse here"))):
            ttk.Radiobutton(rf, text=text, value=val, variable=self.role_var,
                            command=self._role_clicked).grid(row=i, column=0, sticky="w")

        # where is the other computer?
        lf = ttk.LabelFrame(f, text=" \u263E Which way lies the other computer? ", padding=(12, 8))
        lf.grid(row=r, column=0, sticky="ew", pady=(14, 0))
        r += 1
        for c in range(3):
            lf.columnconfigure(c, weight=1)
        self.dir = tk.StringVar(value=cfg.get("direction", "right" if self.server else "left"))
        self.dir_buttons = {}
        for d, (gr, gc) in DIR_POS.items():
            b = ttk.Radiobutton(lf, text=DIR_TEXT[d], value=d, variable=self.dir,
                                command=self._changed)
            b.grid(row=gr, column=gc, padx=6, pady=4)
            self.dir_buttons[d] = b
        ttk.Label(lf, text=self.this_label,
                  style="Box.TLabel", width=10).grid(row=1, column=1, padx=6, pady=4)
        ttk.Label(lf, style="Sub.TLabel",
                  text="Same side as on your desk. Extra monitors are handled automatically.",
                  ).grid(row=3, column=0, columnspan=3, pady=(4, 0))

        # pairing
        pf = ttk.LabelFrame(f, text=" \u2726 Secret code ", padding=(12, 8))
        pf.grid(row=r, column=0, sticky="ew", pady=(12, 0))
        r += 1
        pf.columnconfigure(1, weight=1)
        if self.server:
            ttk.Label(pf, text="On the other computer, open Wisp and whisper this code:").grid(
                row=0, column=0, columnspan=2, sticky="w")
            self.code_lbl = ttk.Label(pf, text=fmt_code(cfg["share_code"]), style="Code.TLabel")
            self.code_lbl.grid(row=1, column=0, sticky="w", pady=(2, 2))
            self.newcode_btn = ttk.Button(pf, text="New code", command=self.regen_code)
            self.newcode_btn.grid(row=1, column=1, sticky="e")
            ttk.Label(pf, style="Sub.TLabel", text="%s: %s  ·  %s" % (
                self.this_label, self.hostname, self.ip)).grid(row=2, column=0, columnspan=2,
                                                              sticky="w")
        else:
            ttk.Label(pf, text="Share from").grid(row=0, column=0, sticky="w", padx=(0, 8))
            self.host = ttk.Combobox(pf, width=30)
            self.host.set(cfg.get("host_label", cfg.get("host", "")))
            self.host.grid(row=0, column=1, sticky="ew")
            self.host.bind("<<ComboboxSelected>>", lambda e: self._changed())
            self.host.bind("<FocusOut>", lambda e: self._changed())
            self.find_btn = ttk.Button(pf, text="Find", width=6, command=self.search)
            self.find_btn.grid(row=0, column=2, padx=(8, 0))
            ttk.Label(pf, text="Code").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=(8, 0))
            self.code_var = tk.StringVar(value=fmt_code(cfg.get("code", "")))
            self.code = ttk.Entry(pf, width=10, textvariable=self.code_var,
                                  font=("TkFixedFont", 16))
            self.code.grid(row=1, column=1, sticky="w", pady=(8, 0))
            self.code.bind("<FocusOut>", lambda e: self._changed())
            self.code.bind("<Return>", lambda e: self.toggle())
            self.find_lbl = ttk.Label(pf, style="Sub.TLabel", text="", wraplength=340,
                                      justify="left")
            self.find_lbl.grid(row=2, column=0, columnspan=3, sticky="w", pady=(6, 0))

        # main action + status
        af = ttk.Frame(f)
        af.grid(row=r, column=0, sticky="ew", pady=(16, 0))
        r += 1
        af.columnconfigure(1, weight=1)
        self.main_btn = ttk.Button(af, style="Big.TButton", command=self.toggle,
                                   text=BTN_SERVER[0] if self.server else BTN_CLIENT[0])
        self.main_btn.grid(row=0, column=0, rowspan=2, sticky="w")
        sf = ttk.Frame(af)
        sf.grid(row=0, column=1, sticky="w", padx=(14, 0))
        bg = st.lookup("TFrame", "background") or root.cget("bg")
        self.dot = tk.Canvas(sf, width=14, height=14, highlightthickness=0, bd=0, bg=bg)
        self.dot_id = self.dot.create_oval(2, 2, 13, 13, fill=COLORS["grey"], outline="")
        self.dot.grid(row=0, column=0, padx=(0, 6))
        self.status_lbl = ttk.Label(sf, text="", style="Status.TLabel")
        self.status_lbl.grid(row=0, column=1, sticky="w")
        self.hint_lbl = ttk.Label(f, text="", style="Sub.TLabel", wraplength=380, justify="left")
        self.hint_lbl.grid(row=r, column=0, sticky="w", pady=(10, 0))
        r += 1

        # OS permissions (macOS)
        self.perm_rows = []
        pr = ttk.Frame(f)
        if self.perms:
            pr.grid(row=r, column=0, sticky="ew", pady=(10, 0))
            pr.columnconfigure(0, weight=1)
        for i, perm in enumerate(self.perms):
            lbl = ttk.Label(pr, text="", wraplength=300, justify="left")
            lbl.grid(row=i, column=0, sticky="w", pady=2)
            btn = ttk.Button(pr, text="Allow…", command=lambda p=perm: self.allow_perm(p))
            btn.grid(row=i, column=1, sticky="e", pady=2)
            self.perm_rows.append((perm, lbl, btn))
        if self.perm_rows:  # first row kept under the old names for compatibility
            self.ax_lbl, self.ax_btn = self.perm_rows[0][1], self.perm_rows[0][2]
        r += 1

        # more options
        self.more_open = tk.BooleanVar(value=False)
        self.more_btn = ttk.Checkbutton(f, text="More options", variable=self.more_open,
                                        command=self._toggle_more)
        self.more_btn.grid(row=r, column=0, sticky="w", pady=(12, 0))
        r += 1
        o = self.opts = ttk.Frame(f, padding=(18, 4, 0, 0))
        self.opts_row = r
        r += 1
        o.columnconfigure(1, weight=1)
        orow = 0
        self.autostart = tk.BooleanVar(value=bool(cfg.get("autostart", False)))
        self.port_var = tk.StringVar(value=str(cfg.get("port", PORT)))
        if self.server:
            self.hide = tk.BooleanVar(value=bool(cfg.get("hide", True)))
            ttk.Checkbutton(o, text="Hide this cursor while using the other computer",
                            variable=self.hide, command=self._changed).grid(
                row=orow, column=0, columnspan=3, sticky="w")
            orow += 1
            ttk.Checkbutton(o, text="Summon the wisp as soon as Wisp opens", variable=self.autostart,
                            command=self._changed).grid(row=orow, column=0, columnspan=3, sticky="w")
            orow += 1
        else:
            self.speed = tk.DoubleVar(value=float(cfg.get("speed", 1.0)))
            self.scroll = tk.DoubleVar(value=float(cfg.get("scroll", 3.0)))
            self.speed_lbl = ttk.Label(o, width=5)
            self.scroll_lbl = ttk.Label(o, width=5)
            for lbl, var, lo, hi, vl in (("Mouse speed", self.speed, 0.3, 3.0, self.speed_lbl),
                                         ("Scroll speed", self.scroll, 1.0, 10.0, self.scroll_lbl)):
                ttk.Label(o, text=lbl).grid(row=orow, column=0, sticky="w")
                ttk.Scale(o, from_=lo, to=hi, variable=var, length=170,
                          command=lambda v: self._changed(live_only=True)).grid(
                    row=orow, column=1, sticky="ew", padx=8)
                vl.grid(row=orow, column=2, sticky="w")
                orow += 1
            self.invert = tk.BooleanVar(value=bool(cfg.get("invert", False)))
            self.swap = tk.BooleanVar(value=bool(cfg.get("swap", True)))
            for text, var in (("Swap Ctrl and ⌘ Command between Mac and Windows "
                               "(Ctrl+C ↔ ⌘C)", self.swap),
                              ("Reverse scroll direction", self.invert),
                              ("Invite the wisp as soon as Wisp opens", self.autostart)):
                ttk.Checkbutton(o, text=text, variable=var, command=self._changed).grid(
                    row=orow, column=0, columnspan=3, sticky="w")
                orow += 1
        self.login = tk.BooleanVar(value=os.path.exists(self.login_path))
        ttk.Checkbutton(o, text="Open Wisp when I log in", variable=self.login,
                        command=self._login_changed).grid(row=orow, column=0, columnspan=3,
                                                          sticky="w")
        orow += 1
        ttk.Label(o, text="Port").grid(row=orow, column=0, sticky="w", pady=(4, 0))
        self.port = ttk.Entry(o, width=7, textvariable=self.port_var)
        self.port.grid(row=orow, column=1, sticky="w", padx=8, pady=(4, 0))
        self.port.bind("<FocusOut>", lambda e: self._changed())
        orow += 1
        self.trace = tk.BooleanVar(value=bool(self.cfg.get("trace")))
        ttk.Checkbutton(o, text="Log keystrokes (troubleshooting \u2013 records what you type)",
                        variable=self.trace, command=self._trace_changed).grid(
            row=orow, column=0, columnspan=3, sticky="w")
        orow += 1
        self.showlog = tk.BooleanVar(value=False)
        ttk.Checkbutton(o, text="Show activity log", variable=self.showlog,
                        command=self._toggle_log).grid(row=orow, column=0, columnspan=3,
                                                       sticky="w", pady=(4, 0))
        orow += 1
        self.log_txt = tk.Text(o, height=8, width=52, font=("TkFixedFont", 10), state="disabled",
                               relief="flat", borderwidth=1)
        self.log_row = orow
        self._update_value_labels()

    def _toggle_more(self):
        if self.more_open.get():
            self.opts.grid(row=self.opts_row, column=0, sticky="ew")
        else:
            self.opts.grid_remove()

    def _toggle_log(self):
        if self.showlog.get():
            self.log_txt.grid(row=self.log_row, column=0, columnspan=3, sticky="ew", pady=(4, 0))
        else:
            self.log_txt.grid_remove()

    def _update_value_labels(self):
        if not self.server:
            self.speed_lbl.config(text="%.1f×" % self.speed.get())
            self.scroll_lbl.config(text="%.0f" % self.scroll.get())

    # ---------------- settings ----------------
    def settings(self):
        s = {"direction": self.dir.get(), "autostart": bool(self.autostart.get())}
        try:
            s["port"] = int(self.port_var.get())
        except ValueError:
            s["port"] = PORT
        if self.server:
            s["share_code"] = self.cfg["share_code"]
            s["hide"] = bool(self.hide.get())
        else:
            label = self.host.get().strip()
            s["host_label"], s["host"] = label, parse_host(label)
            s["code"] = clean_code(self.code_var.get())
            s["speed"] = round(float(self.speed.get()), 2)
            s["scroll"] = round(float(self.scroll.get()), 1)
            s["invert"] = bool(self.invert.get())
            s["swap"] = bool(self.swap.get())
        return s

    def _save(self):
        self.cfg.update(self.settings())
        save_config(self.cfg_path, self.cfg)

    def _changed(self, live_only=False):
        self._update_value_labels()
        s = self.settings()
        if self.server:
            self.svc.apply(edge=s["direction"], hide=s["hide"])
        else:
            self.svc.apply(side=s["direction"], speed=s["speed"], swap=s["swap"],
                           scroll=s["scroll"], invert=s["invert"])
        self.cfg.update(s)
        save_config(self.cfg_path, self.cfg)

    def _trace_changed(self):
        on = bool(self.trace.get())
        self.svc.apply(trace=on)
        self.cfg["trace"] = on  # remembered so a restart doesn't lose the troubleshooting log
        save_config(self.cfg_path, self.cfg)
        if on and not self.showlog.get():
            self.showlog.set(True)
            self._toggle_log()
        self.logq.put("keystroke logging %s" % ("ON" if on else "off"))

    def _login_changed(self):
        err = set_login_item(self.login.get(), path=self.login_path)
        if err:
            self.login.set(os.path.exists(self.login_path))
            self.logq.put("couldn't change the login item: %s" % err)

    def regen_code(self):
        if self.svc.running():
            self.svc.stop()
        self.cfg["share_code"] = new_code()
        self.code_lbl.config(text=fmt_code(self.cfg["share_code"]))
        self._save()

    # ---------------- actions ----------------
    def _can_start(self):
        s = self.settings()
        if not (0 < s["port"] < 65535):
            return False, "Port must be a number like %d." % PORT
        if not self.server:
            if not s["host"]:
                return False, "Pick the sharing computer (press Find) or type its IP address."
            if len(s["code"]) != 6:
                return False, "Enter the 6-digit code shown in Wisp on the other computer."
        return True, ""

    def toggle(self):
        if self.svc.running():
            self.stop()
        else:
            self.start()

    def start(self):
        ok, why = self._can_start()
        self.start_error = None if ok else why
        if not ok:
            self._render()
            return
        self._save()
        s = self.settings()
        try:
            if self.server:
                self._ask_permissions()
                self.svc.start(edge=s["direction"], port=s["port"], token=s["share_code"],
                               hide=s["hide"])
                self.svc.apply(trace=bool(self.trace.get()))
            else:
                self._ask_permissions()
                self.svc.start(host=s["host"], port=s["port"], token=s["code"], side=s["direction"],
                               speed=s["speed"], swap=s["swap"], scroll=s["scroll"],
                               invert=s["invert"])
                self.svc.apply(trace=bool(self.trace.get()))
        except Exception as e:  # shown in the window instead of a traceback
            self.start_error = str(e)
        self._render()

    def stop(self):
        self.svc.stop()
        self._render()

    def search(self, auto=False):
        if self.server or self.searching:
            return
        self.searching = True
        self.find_btn.state(["disabled"])
        self.find_lbl.config(text="Looking for wisps nearby…")
        try:
            port = int(self.port_var.get())
        except ValueError:
            port = PORT

        def work():
            try:
                res = self.discover_fn(port=port)
            except Exception:
                res = []
            self._results.put((res, auto))
        threading.Thread(target=work, daemon=True).start()

    def _search_done(self, res, auto):
        self.searching = False
        self._next_search = time.time() + 4  # keep looking until the PC shows up
        self.find_btn.state(["!disabled"])
        self.found = res
        labels = ["%s (%s)" % (f["name"], f["ip"]) for f in res]
        self.host.config(values=labels)
        if res:
            cur = parse_host(self.host.get())
            match = [l for f, l in zip(res, labels) if f["ip"] == cur]
            if not cur:
                self.host.set(labels[0])
                self._changed()
            elif match:
                self.host.set(match[0])  # show the PC's name next to a typed/saved IP
                self._changed()
            self.find_lbl.config(text="Found %d computer%s." % (len(res), "" if len(res) == 1 else "s"))
        else:
            self.find_lbl.config(text="No wisps nearby yet. Press \u201c%s\u201d on the other "
                                      "computer, " % BTN_SERVER[0] +
                                      "check both are on the same network, or type its IP "
                                      "address.")

    def _ask_permissions(self):
        """ask macOS once per session for any permission that is still missing"""
        if self._ax_prompted:
            return
        missing = [p for p in self.perms if p.get("prompt") and not self._perm_ok(p)]
        if missing:
            self._ax_prompted = True
            missing[0]["prompt"]()

    def _perm_ok(self, perm):
        try:
            return bool(perm["check"]())
        except Exception:
            return False

    def allow_perm(self, perm):
        if perm.get("prompt"):
            perm["prompt"]()

    def allow_ax(self):  # first permission row (kept for older callers)
        if self.perms:
            self.allow_perm(self.perms[0])

    def _role_clicked(self):
        new = self.role_var.get()
        if new == self.role:
            return
        if self.on_switch is None:
            self.role_var.set(self.role)
            return
        self._save()
        self.cfg["role"] = new
        save_config(self.cfg_path, self.cfg)
        self.svc.stop()
        self.closed = True
        self.frame.destroy()
        self.on_switch(new)

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self._save()
            self.svc.stop()
        finally:
            self.root.destroy()

    # ---------------- status ----------------
    def view(self):
        """(color, title, hint, button_text) describing the current state"""
        st = self.svc.state()
        d = DIR_EDGE_WORD[self.dir.get()]
        panic = "Panic key: %s." % panic_keys_text(self.os_name)
        c = self.svc.core
        if self.server:
            btn = BTN_SERVER[1] if self.svc.running() else BTN_SERVER[0]
            rtt = self.svc.rtt()
            ms = "" if rtt is None else ("  \u00B7  <1 ms" if rtt < 1 else "  \u00B7  %d ms" % round(rtt))
            peer = (c.peer_name if c is not None else None) or "the other computer"
            if self.start_error:
                return "red", "The spell fizzled", self.start_error, btn
            if st == "error":
                return "red", "The spell fizzled", self.svc.error or "", btn
            if st == "stopped":
                return ("grey", "The wisp is asleep",
                        "Press \u201c%s\u201d to share this keyboard & mouse, then connect from "
                        "the other computer." % BTN_SERVER[0], btn)
            if st == "waiting":
                hint = ("On the other computer, open Wisp, choose \u201cBorrow another "
                        "computer's keyboard & mouse\u201d, pick %s and enter %s. Both must be on "
                        "the same network." % (self.hostname, fmt_code(self.cfg["share_code"])))
                if self.os_name == "Windows":
                    hint += " If it can't find this PC, allow Python in Windows Firewall."
                return "amber", "Waiting for the other computer to call\u2026", hint, btn
            if c is not None and c.late_hooks and st in ("connected", "remote"):
                return ("amber", ("The wisp is with %s" % peer if st == "remote"
                                  else "Bound to %s" % peer)
                        + ms,
                        "The system delayed Wisp's input hook %d time(s) (worst %d ms), so "
                        "some keys or clicks may have stayed on this computer. Close heavy apps "
                        "or see the activity log." % (c.late_hooks, c.worst_late_ms), btn)
            if st == "connected":
                return ("green", "Bound to %s" % peer + ms,
                        "Move the mouse off the %s edge of this screen to use it. %s"
                        % (d, panic), btn)
            return ("blue", "The wisp is with %s" % peer + ms,
                    "Keyboard and mouse are on %s. Move back off its edge to return. %s"
                    % (peer, panic), btn)
        btn = BTN_CLIENT[1] if self.svc.running() else BTN_CLIENT[0]
        if self.start_error:
            return "red", "The spell fizzled", self.start_error, btn
        if st == "error":
            return ("red", "Wrong secret code",
                    "The other computer rejected the code. Check the 6-digit code it shows.", btn)
        if st == "stopped":
            return ("grey", "The wisp is asleep",
                    "Pick the computer that's sharing, enter its code, then press "
                    "\u201c%s\u201d." % BTN_CLIENT[0], btn)
        if st == "connecting":
            hint = "Make sure Wisp is sharing on the other computer."
            if c is not None and c.net_error:
                hint = "Can't reach it yet, retrying. Is Wisp sharing on the other computer " \
                       "and are both on the same network?"
            return "amber", "Calling the wisp\u2026", hint, btn
        name = (c.peer_name if c is not None else None) or "the other computer"
        if st == "connected":
            return ("green", "Bound to %s" % name,
                    "Move its mouse off its edge to come here.", btn)
        return ("blue", "%s's wisp is here" % name,
                "Move off the %s edge of this screen to go back." % d, btn)

    def _render(self):
        color, title, hint, btn = self.view()
        self.dot.itemconfig(self.dot_id, fill=COLORS[color])
        self.status_lbl.config(text=title)
        self.hint_lbl.config(text=hint)
        self.main_btn.config(text=btn)
        if self.server:
            self.newcode_btn.state(["disabled"] if self.svc.state() in ("connected", "remote")
                                   else ["!disabled"])
        if self.perm_rows and time.time() >= self._ax_next:
            self._ax_next = time.time() + 2
            for perm, lbl, btn in self.perm_rows:
                if self._perm_ok(perm):
                    lbl.config(text="\u2713 %s permission granted" % perm["name"])
                    btn.grid_remove()
                else:
                    lbl.config(text="\u26A0 Wisp needs %s permission %s."
                               % (perm["name"], perm.get("why", "")))
                    btn.grid()

    def _poll(self):
        if self.closed:
            return
        try:
            while True:
                res, auto = self._results.get_nowait()
                self._search_done(res, auto)
        except queue.Empty:
            pass
        lines = []
        try:
            while True:
                lines.append(self.logq.get_nowait())
        except queue.Empty:
            pass
        if lines:
            t = self.log_txt
            t.config(state="normal")
            t.insert("end", "\n".join(time.strftime("%H:%M:%S ") + l for l in lines) + "\n")
            if int(t.index("end-1c").split(".")[0]) > 500:
                t.delete("1.0", "100.0")
            t.see("end")
            t.config(state="disabled")
        if self.start_error and self.svc.running():
            self.start_error = None
        if not self.server and not self.found and not self.searching \
                and not self.svc.running() and time.time() >= self._next_search:
            self.search(auto=True)
        self._render()
        self.root.after(self.POLL_MS, self._poll)


def login_item_path():
    if sys.platform == "win32":
        return os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")),
                            "Microsoft", "Windows", "Start Menu", "Programs", "Startup",
                            "Wisp.pyw")
    return os.path.join(os.path.expanduser("~"), "Library", "LaunchAgents", "local.wisp.plist")


def legacy_paths(home=None, appdata=None, platform_=None):
    """where the old name (kmshare) kept its settings and login item"""
    home = home or os.path.expanduser("~")
    plat = platform_ or sys.platform
    if plat == "win32":
        login = os.path.join(appdata or os.environ.get("APPDATA", home), "Microsoft", "Windows",
                             "Start Menu", "Programs", "Startup", "kmshare.pyw")
    else:
        login = os.path.join(home, "Library", "LaunchAgents", "local.kmshare.plist")
    return {"config": os.path.join(home, ".kmshare.json"), "login": login}


def migrate_legacy(config_path=None, login_path=None, legacy=None, **kw):
    """carry settings and the login item over from kmshare (the old name); returns notes"""
    config_path = config_path or CONFIG_PATH
    legacy = legacy or legacy_paths()
    notes = []
    try:
        if not os.path.exists(config_path) and os.path.exists(legacy["config"]):
            with open(legacy["config"]) as src, open(config_path, "w") as dst:
                dst.write(src.read())
            notes.append("brought your settings over from kmshare")
        if os.path.exists(legacy["login"]):
            os.remove(legacy["login"])
            err = set_login_item(True, path=login_path, **kw)
            notes.append("moved the open-at-login item to Wisp" if err is None
                         else "couldn't move the open-at-login item: %s" % err)
    except OSError as e:
        notes.append("couldn't bring kmshare's settings over: %s" % e)
    return notes


def set_login_item(enabled, path=None, app_dir=None, platform_=None):
    """create/remove the 'open Wisp when I log in' entry; returns None or an error string"""
    path = path or login_item_path()
    app_dir = app_dir or os.path.dirname(os.path.abspath(__file__))
    plat = platform_ or sys.platform
    try:
        if not enabled:
            if os.path.exists(path):
                os.remove(path)
            return None
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if plat == "win32":
            body = ("# opens Wisp at login (created by Wisp; untick the option to remove)\n"
                    "import sys\nsys.path.insert(0, %r)\nimport wisp\nwisp.main([])\n" % app_dir)
        else:
            app = os.path.join(app_dir, "Wisp.app")
            if os.path.isdir(app):
                args = ["/usr/bin/open", "-a", app]
            else:
                py = os.path.join(app_dir, ".venv", "bin", "python")
                args = [py if os.path.exists(py) else sys.executable,
                        os.path.join(app_dir, "wisp.py"), "app"]
            items = "".join("<string>%s</string>" % a.replace("&", "&amp;").replace("<", "&lt;")
                            for a in args)
            body = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                    '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                    '<plist version="1.0"><dict>'
                    '<key>Label</key><string>local.wisp</string>'
                    '<key>ProgramArguments</key><array>%s</array>'
                    '<key>RunAtLoad</key><true/>'
                    '</dict></plist>\n' % items)
        with open(path, "w") as f:
            f.write(body)
        return None
    except OSError as e:
        return str(e)


def mac_latency_critical():
    """opt out of App Nap / timer throttling while Wisp runs in the background"""
    try:
        from Foundation import NSProcessInfo
        # NSActivityUserInitiated | NSActivityLatencyCritical
        return NSProcessInfo.processInfo().beginActivityWithOptions_reason_(
            0x00FFFFFF | 0xFF00000000, "Wisp is forwarding live keyboard and mouse input")
    except Exception:
        return None


def mac_ax_funcs():
    try:
        from ApplicationServices import AXIsProcessTrusted, AXIsProcessTrustedWithOptions
        from ApplicationServices import kAXTrustedCheckOptionPrompt
    except ImportError:
        return None, None

    def prompt():
        try:
            AXIsProcessTrustedWithOptions({kAXTrustedCheckOptionPrompt: True})
        except Exception:
            pass
        import subprocess
        subprocess.Popen(["open", AX_SETTINGS_URL])
    return AXIsProcessTrusted, prompt


def permission_rows(role):
    """macOS permissions each role needs (none on Windows)"""
    if sys.platform != "darwin":
        return []
    rows = []
    ax_check, ax_prompt = mac_ax_funcs()
    if ax_check:
        rows.append({"name": "Accessibility", "check": ax_check, "prompt": ax_prompt,
                     "why": "to control the pointer and keyboard" if role == "server"
                     else "to move the pointer and type on this Mac"})
    if role == "server":
        im_check, im_prompt = mac_input_monitoring()
        if im_check:
            rows.append({"name": "Input Monitoring", "check": im_check, "prompt": im_prompt,
                         "why": "to read this keyboard and mouse"})
    return rows


def default_role(cfg):
    return cfg.get("role") or ("server" if sys.platform == "win32" else "client")


def app_main(role=None):
    import tkinter as tk
    sys.setswitchinterval(0.001)
    if sys.platform == "win32":
        win_set_dpi_aware()
    logq = FileLogQueue()
    for note in migrate_legacy():
        logq.put(note)
    writer = QueueWriter(logq)
    sys.stdout = sys.stderr = writer  # also makes pythonw (no console) safe
    log = logq.put
    root = tk.Tk()
    if sys.platform == "darwin":
        root._wisp_activity = mac_latency_critical()  # keep a reference for the app's lifetime
    services = {}  # one per role, reused when switching (capture hooks are installed once)

    def build(role):
        if role not in services:
            services[role] = ServerService(log=log) if role == "server" else ClientService(log=log)
        cfg = load_config(CONFIG_PATH)
        if cfg.get("role") != role:
            cfg["role"] = role
            save_config(CONFIG_PATH, cfg)
        App(root, role, services[role], logq=logq, perms=permission_rows(role), on_switch=build)
    build(role or default_role(load_config(CONFIG_PATH)))
    root.mainloop()


def main(argv=None):
    p = argparse.ArgumentParser(description="share one keyboard+mouse between computers "
                                            "(Windows and macOS, either direction)")
    sub = p.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("server", help="run on the computer that has the keyboard/mouse")
    s.add_argument("--edge", choices=EDGES, default="right",
                   help="screen edge the other computer is beyond")
    s.add_argument("--port", type=int, default=PORT)
    s.add_argument("--bind", default="0.0.0.0")
    s.add_argument("--token", required=True)
    s.add_argument("--no-hide", action="store_true",
                   help="don't hide this cursor while using the other computer")
    s.add_argument("--stats", action="store_true", help="print network round-trip time every 5s")
    c = sub.add_parser("client", help="run on the computer that should receive the input")
    c.add_argument("--host", required=True)
    c.add_argument("--port", type=int, default=PORT)
    c.add_argument("--token", required=True)
    c.add_argument("--side", choices=EDGES, default="left",
                   help="screen edge the sharing computer is beyond")
    c.add_argument("--speed", type=float, default=1.0, help="mouse speed multiplier")
    c.add_argument("--scroll", type=float, default=3.0, help="lines per wheel notch")
    c.add_argument("--invert-scroll", action="store_true")
    c.add_argument("--no-swap", dest="swap", action="store_false",
                   help="don't swap Ctrl and Cmd/Win between Mac and Windows")
    g = sub.add_parser("app", help="open the app window (default when run without arguments)")
    g.add_argument("--role", choices=("server", "client"))
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = ["app"]
    a = p.parse_args(argv)
    if a.mode == "app":
        app_main(a.role)
        return
    (server_main if a.mode == "server" else client_main)(a)


if __name__ == "__main__":
    main()
