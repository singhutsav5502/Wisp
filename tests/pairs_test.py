"""Every sharing/receiving pairing over real TCP:
    Windows -> Mac, Mac -> Windows, Mac -> Mac, Windows -> Windows
The sharing Mac is simulated with event-tap semantics (a swallowed mouse move still moves
the cursor unless it is decoupled); the receiving Windows side is the *real* WinInjector
talking to a fake user32 that decodes the SendInput structures it gets.
Run: python tests/pairs_test.py
"""
import ctypes
import os
import random
import sys
import threading
import time
import traceback

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
if not hasattr(ctypes, "WINFUNCTYPE"):
    ctypes.WINFUNCTYPE = ctypes.CFUNCTYPE  # for win_enum_monitors on non-Windows test hosts
import wisp as K  # noqa: E402
from sim_test import FakeWin, FakeMac, wait  # noqa: E402

MOD_DEVICE = {v: k for k, v in K.MAC_MOD_DEVICE_BIT.items()}  # bit -> keycode (unused helper)
MAC_GENERIC = {0x38: 0x20000, 0x3C: 0x20000, 0x3B: 0x40000, 0x3E: 0x40000, 0x3A: 0x80000,
               0x3D: 0x80000, 0x37: 0x100000, 0x36: 0x100000}


# ---------------------------------------------------------------- sharing Mac
class FakeMacShare:
    """a Mac with the keyboard/mouse: displays, cursor, and event-tap behaviour"""
    os_name = "Darwin"

    def __init__(self, rects=None):
        self.rects = rects or [(0, 0, 1710, 1107)]
        self.desk = K.Desktop(self.rects)
        self.cur = [self.rects[0][0] + 400, (self.rects[0][1] + self.rects[0][3]) // 2]
        self.coupled = True
        self.hidden = False
        self.apps = []  # what reached Mac apps (events the tap let through)
        self.devflags = 0
        self.core = None

    def attach(self, core):
        self.core = core

    # --- OS interface (MacOS) ---
    def monitors(self):
        return self.rects

    def get_cursor(self):
        return tuple(self.cur)

    def set_cursor(self, x, y):
        self.cur = list(self.desk.clamp(int(x), int(y)))

    def hide_cursor(self):
        self.coupled, self.hidden = False, True

    def show_cursor(self):
        self.coupled, self.hidden = True, False

    def restore_cursors(self):
        self.show_cursor()

    # --- hardware through the real dispatch ---
    def _tap(self, info):
        return K.mac_dispatch(self.core, info)

    def hw_move(self, dx, dy):
        if self.coupled:  # the cursor moves even if the tap swallows the event
            px, py = self.desk.clamp(self.cur[0] + dx, self.cur[1] + dy)
            self.cur = [px, py]
        x, y = self.cur
        if not self._tap(("move", float(x), float(y), dx, dy)):
            self.apps.append(("move", x, y))

    def hw_button(self, name, down):
        if not self._tap(("btn", name, down)):
            self.apps.append(("btn", name, down))

    def hw_wheel(self, notches, horizontal=False):
        info = ("scroll", float(notches), 0.0) if horizontal else ("scroll", 0.0, float(notches))
        if not self._tap(info):
            self.apps.append(("wheel", notches, horizontal))

    def hw_key(self, name, down):
        kc = K.MAC_KVK[name]
        if kc in K.MAC_MOD_DEVICE_BIT:  # modifiers arrive as flagsChanged with device bits
            bit = K.MAC_MOD_DEVICE_BIT[kc]
            self.devflags = (self.devflags | bit) if down else (self.devflags & ~bit)
            gen = 0
            for k2, b2 in K.MAC_MOD_DEVICE_BIT.items():
                if self.devflags & b2:
                    gen |= MAC_GENERIC[k2]
            sup = self._tap(("flags", kc, gen | self.devflags))
        else:
            sup = self._tap(("key", kc, down))
        if not sup:
            self.apps.append(("key", name, down))


class WinShare(FakeWin):
    """FakeWin with a name-based keyboard so pairings can share one script"""

    def hw_key(self, name, down, flags=0, sys_=False):  # noqa: D401
        if isinstance(name, int):
            return FakeWin.hw_key(self, name, down, flags, sys_)
        vk = K.WIN_NAME_VK[name]
        ext = 1 if name == "kp_enter" else 0
        return FakeWin.hw_key(self, vk, down, flags=ext, sys_=name in ("alt", "alt_r"))

    def hw_button(self, name, down):
        return FakeWin.hw_button(self, name, down)


# ---------------------------------------------------------------- receiving Windows
class FakeUser32:
    """decodes what WinInjector hands to SendInput"""

    def __init__(self, mons):
        self.mons = mons
        x0 = min(m[0] for m in mons)
        y0 = min(m[1] for m in mons)
        x1 = max(m[2] for m in mons)
        y1 = max(m[3] for m in mons)
        self.virt = (x0, y0, x1 - x0, y1 - y0)
        self.cur = [mons[0][0] + 10, mons[0][1] + 10]
        self.events = []
        self.lock = threading.Lock()
        self.errors = []
        for name in ("SendInput", "MapVirtualKeyW", "GetSystemMetrics", "GetCursorPos",
                     "EnumDisplayMonitors"):
            setattr(self, name, _Fn(getattr(self, "_" + name)))

    def _GetSystemMetrics(self, i):
        return {76: self.virt[0], 77: self.virt[1], 78: self.virt[2], 79: self.virt[3]}[i]

    def _GetCursorPos(self, pp):
        pp._obj.x, pp._obj.y = self.cur
        return 1

    def _MapVirtualKeyW(self, vk, mode):
        return (vk * 7) & 0xFF  # any stable scan code

    def _EnumDisplayMonitors(self, hdc, clip, cb, lp):
        from ctypes import wintypes as wt
        for m in self.mons:
            rc = wt.RECT(*m)
            cb(None, None, ctypes.pointer(rc), 0)
        return 1

    def _SendInput(self, n, arr, size):
        with self.lock:
            if size != ctypes.sizeof(K.INPUT):
                self.errors.append("bad cbSize %d" % size)
            for i in range(n):
                inp = arr[i]
                if inp.type == 0:
                    mi = inp.u.mi
                    if mi.dwExtraInfo != K.KMSHARE_TAG:
                        self.errors.append("untagged mouse input")
                    f = mi.dwFlags
                    if f & 0x0001:
                        if not (f & 0x8000 and f & 0x4000):
                            self.errors.append("move without ABSOLUTE|VIRTUALDESK")
                        vx, vy, vw, vh = self.virt
                        x = vx + mi.dx * (vw - 1) / 65535.0
                        y = vy + mi.dy * (vh - 1) / 65535.0
                        self.cur = [int(round(x)), int(round(y))]
                        if not any(m[0] <= self.cur[0] < m[2] and m[1] <= self.cur[1] < m[3]
                                   for m in self.mons):
                            self.errors.append("cursor sent off-screen %s" % (self.cur,))
                        self.events.append(("move", self.cur[0], self.cur[1]))
                    for name, (dn, up, xb) in K.WIN_BTN_FLAGS.items():
                        if f & (dn | up) and (xb == 0 or mi.mouseData == xb):
                            if xb == 0 and f & 0x0080:
                                continue
                            self.events.append(("btn", name, bool(f & dn)))
                    if f & 0x0800:
                        self.events.append(("wheel", ctypes.c_int32(mi.mouseData).value, False))
                    if f & 0x1000:
                        self.events.append(("wheel", ctypes.c_int32(mi.mouseData).value, True))
                elif inp.type == 1:
                    ki = inp.u.ki
                    if ki.dwExtraInfo != K.KMSHARE_TAG:
                        self.errors.append("untagged key input")
                    if ki.wScan != (ki.wVk * 7) & 0xFF:
                        self.errors.append("scan code missing for vk %#x" % ki.wVk)
                    self.events.append(("key", ki.wVk, not (ki.dwFlags & 0x2),
                                        bool(ki.dwFlags & 0x1)))
                else:
                    self.errors.append("unknown input type %d" % inp.type)
            return n


class _Fn:
    def __init__(self, f):
        self.f, self.argtypes, self.restype = f, None, None

    def __call__(self, *a):
        return self.f(*a)


class WinRecv:
    """receiving Windows: the real WinInjector + FakeUser32, with a uniform test view"""

    def __init__(self, mons=None):
        self.u = FakeUser32(mons or [(0, 0, 1920, 1080)])
        self.inj = K.WinInjector(user32=self.u)

    @property
    def errors(self):
        return self.u.errors

    @property
    def pos(self):
        return tuple(self.u.cur)

    @staticmethod
    def _name(vk, ext):
        if vk == 0x0D:  # Return and numpad Enter share VK_RETURN; the extended bit tells them apart
            return "kp_enter" if ext else "enter"
        for n, v in K.WIN_NAME_VK.items():
            if v == vk:
                return n
        return hex(vk)

    def keys(self):
        return [(self._name(e[1], e[3]), e[2]) for e in self.u.events if e[0] == "key"]

    def btns(self):
        return [(e[1], e[2]) for e in self.u.events if e[0] == "btn"]

    def wheel_total(self):
        return sum(e[1] for e in self.u.events if e[0] == "wheel" and not e[2])

    def ext_flags(self):
        return {self._name(e[1], e[3]): e[3] for e in self.u.events if e[0] == "key"}


class MacRecv:
    def __init__(self, rects=None):
        self.m = FakeMac(rects=rects)
        self.inj = self.m

    @property
    def errors(self):
        return self.m.errors

    @property
    def pos(self):
        return self.m.pos

    def keys(self):
        return [(K.MAC_KC_NAME.get(e[1], hex(e[1])), e[2]) for e in self.m.of("key")]

    def btns(self):
        return [(e[1], e[2]) for e in self.m.of("btn")]

    def wheel_total(self):
        return sum(e[1] for e in self.m.of("scroll"))  # lines


# ---------------------------------------------------------------- rig over real TCP
class PairRig:
    def __init__(self, share, recv, edge="right"):
        self.kind = (share, recv)
        self.share = WinShare() if share == "win" else FakeMacShare()
        self.recv = WinRecv() if recv == "win" else MacRecv()
        self.logs = []
        self.score = K.ServerCore(self.share, edge, log=self.logs.append)
        self.share.attach(self.score)
        side = {"right": "left", "left": "right", "top": "bottom", "bottom": "top"}[edge]
        self.ccore = K.ClientCore(self.recv.inj, side=side, log=self.logs.append)
        self.stop, self.cstop, port = threading.Event(), threading.Event(), []
        self.st = threading.Thread(target=K.run_server_net, kwargs=dict(
            core=self.score, port=0, token="t", bind="127.0.0.1", stop=self.stop,
            ready=port.append, hb=0.15, hb_timeout=1.0, log=self.logs.append), daemon=True)
        self.st.start()
        wait(lambda: port)
        self.ct = threading.Thread(target=K.run_client_net, kwargs=dict(
            core=self.ccore, host="127.0.0.1", port=port[0], token="t", stop=self.cstop,
            retry=0.2, timeout=1.0, log=self.logs.append), daemon=True)
        self.ct.start()
        wait(lambda: self.score.connected and self.ccore.peer_os, msg="connected")

    def settle(self, t=0.12):
        time.sleep(t)

    def cross(self):
        for _ in range(300):
            if self.score.remote:
                break
            self.share.hw_move(40, 0)
        assert self.score.remote, "did not cross"
        wait(lambda: self.ccore.active, msg="receiver active")

    def back(self):
        for _ in range(300):
            if not self.ccore.active:
                break
            self.share.hw_move(-40, 0)
            time.sleep(0.003)
        wait(lambda: not self.score.remote, msg="back home")

    def tap(self, name):
        self.share.hw_key(name, True)
        self.share.hw_key(name, False)

    def close(self):
        assert not self.recv.errors, self.recv.errors
        bad = [l for l in self.logs if "Traceback" in str(l)]
        assert not bad, bad
        self.cstop.set()
        self.stop.set()
        self.ct.join(3)
        self.st.join(3)


PAIRS = [("win", "mac"), ("mac", "win"), ("mac", "mac"), ("win", "win")]
TESTS = []


def test(f):
    TESTS.append(f)
    return f


def each_pair(fn):
    def run():
        for pair in PAIRS:
            r = PairRig(*pair)
            try:
                fn(r, pair)
            except AssertionError as e:
                raise AssertionError("%s -> %s: %s" % (pair[0], pair[1], e))
            finally:
                r.close()
    run.__name__ = fn.__name__
    TESTS.append(run)
    return run


@each_pair
def handshake_reports_real_os(r, pair):
    expect = {"win": "Windows", "mac": "Darwin"}
    assert r.ccore.peer_os == expect[pair[0]], r.ccore.peer_os
    assert r.ccore.os_name == expect[pair[1]]


@each_pair
def cross_and_move_exactly(r, pair):
    r.cross()
    if pair[0] == "mac":
        assert not r.share.coupled and r.share.hidden, "mac cursor must be frozen and hidden"
    else:
        assert r.share.hidden
    r.settle()
    start = r.recv.pos
    tot = [0, 0]
    rnd = random.Random(5)
    for _ in range(200):
        dx, dy = rnd.randint(-2, 5), rnd.randint(-3, 3)
        r.share.hw_move(dx, dy)
        tot[0] += dx
        tot[1] += dy
    exp = (start[0] + tot[0], start[1] + tot[1])
    wait(lambda: abs(r.recv.pos[0] - exp[0]) <= 1 and abs(r.recv.pos[1] - exp[1]) <= 1,
         msg="receiver at %s (is %s)" % (exp, r.recv.pos))
    if pair[0] == "mac":
        park = r.share.desk.park()
        assert tuple(r.share.cur) == park, "mac cursor drifted while frozen: %s" % (r.share.cur,)


@each_pair
def clicks_and_wheel_only_on_receiver(r, pair):
    r.cross()
    n = len(r.share.apps)
    for b in ("left", "right", "middle", "x1", "x2"):
        r.share.hw_button(b, True)
        r.share.hw_button(b, False)
    r.share.hw_wheel(1)
    r.share.hw_wheel(1)
    r.settle()
    assert r.share.apps[n:] == [], "leaked to the sharing computer: %s" % r.share.apps[n:]
    exp = [(b, d) for b in ("left", "right", "middle", "x1", "x2") for d in (True, False)]
    wait(lambda: r.recv.btns() == exp, msg="buttons %s" % r.recv.btns())
    total = r.recv.wheel_total()
    assert total == (240 if pair[1] == "win" else 6), total  # 2 notches: 2x120 / 2x3 lines


@each_pair
def typing_and_shortcut_mapping(r, pair):
    r.cross()
    # "Hi" then the platform's copy shortcut
    seq = [("shift", True), ("h", True), ("h", False), ("shift", False), ("i", True), ("i", False)]
    copy_mod = "ctrl" if pair[0] == "win" else "meta"
    seq += [(copy_mod, True), ("c", True), ("c", False), (copy_mod, False)]
    for name, down in seq:
        r.share.hw_key(name, down)
    r.settle()
    cross_os = pair[0] != pair[1]
    expect_mod = {"win": "ctrl", "mac": "meta"}[pair[1]] if cross_os else copy_mod
    exp = [(n if n != copy_mod else expect_mod, d) for n, d in seq]
    wait(lambda: r.recv.keys() == exp, msg="keys\n got %s\n exp %s" % (r.recv.keys(), exp))
    assert not [a for a in r.share.apps if a[0] == "key"], r.share.apps


@each_pair
def windows_and_mac_extra_keys(r, pair):
    r.cross()
    names = ["left", "home", "delete", "enter", "kp_enter", "esc", "f5", "tab", "backspace",
             "alt_r", "ctrl_r", "grave", "slash", "kp_divide"]
    for n in names:
        if pair[0] == "mac" and n == "kp_enter":
            continue
        r.tap(n)
    r.settle()
    got = [k for k in r.recv.keys()]
    sw = {"ctrl": "meta", "ctrl_r": "meta_r", "meta": "ctrl", "meta_r": "ctrl_r"}
    exp = []
    for n in names:
        if pair[0] == "mac" and n == "kp_enter":
            continue
        m = sw.get(n, n) if pair[0] != pair[1] else n
        exp += [(m, True), (m, False)]
    wait(lambda: r.recv.keys() == exp, msg="\n got %s\n exp %s" % (got, exp))
    if pair[1] == "win":
        ext = r.recv.ext_flags()
        for n in ("left", "home", "delete", "kp_divide", "alt_r"):
            assert ext.get(n) is True, "%s must be an extended key on Windows" % n
        assert ext.get("enter") is False and ext.get("esc") is False


@each_pair
def key_held_while_crossing_stays_home(r, pair):
    r.share.hw_key("shift", True)
    r.cross()
    r.tap("a")
    r.share.hw_key("shift", False)
    r.settle()
    names = [k[0] for k in r.recv.keys()]
    assert "shift" not in names, "shift leaked to the receiver: %s" % names
    assert ("key", "shift", False) in [(a[0], a[1], a[2]) for a in r.share.apps if a[0] == "key"] \
        or ("key", K.WIN_NAME_VK["shift"], False) in r.share.apps, r.share.apps


@each_pair
def return_home_restores_cursor(r, pair):
    r.cross()
    r.share.hw_move(100, 0)
    r.share.hw_key("ctrl", True)
    r.back()
    assert not r.share.hidden
    if pair[0] == "mac":
        assert r.share.coupled, "mac cursor must follow the mouse again"
    wait(lambda: all(not d for _, d in r.recv.keys()[-1:]), msg="receiver released keys")
    n = len(r.share.apps)
    r.share.hw_button("left", True)
    r.share.hw_button("left", False)
    assert [a[:3] for a in r.share.apps[n:]] == [("btn", "left", True), ("btn", "left", False)]


@each_pair
def panic_key_works_on_both_oses(r, pair):
    r.cross()
    for n in ("ctrl", "alt", "shift"):
        r.share.hw_key(n, True)
    r.share.hw_key("esc", True)
    assert not r.score.remote and not r.share.hidden
    wait(lambda: not r.ccore.active and not r.ccore.keys, msg="receiver released")
    assert all(k[0] != "esc" for k in r.recv.keys())


@each_pair
def stuck_key_is_released_by_resync(r, pair):
    r.cross()
    # simulate a key-up that never arrived: the receiver thinks Option/Alt is held
    with r.ccore.lock:
        r.ccore._key("alt", True)
    assert "alt" in r.ccore.keys or "alt" in [k for k in r.ccore.keys]
    wait(lambda: not r.ccore.keys, timeout=2, msg="stuck key released by the heartbeat")
    assert r.ccore.stuck_released == 1
    assert any("released stuck key alt" in str(l) for l in r.logs)
    # a key that is really held must NOT be released
    r.share.hw_key("shift", True)
    time.sleep(0.5)  # several heartbeats
    assert "shift" in r.ccore.keys, r.ccore.keys
    r.share.hw_key("shift", False)


@each_pair
def caps_lock_and_repeat(r, pair):
    r.cross()
    r.share.hw_key("caps_lock", True)
    r.share.hw_key("caps_lock", False)
    r.share.hw_key("a", True)
    r.share.hw_key("a", True)  # autorepeat
    r.share.hw_key("a", False)
    r.settle()
    exp = [("caps_lock", True), ("caps_lock", False), ("a", True), ("a", True), ("a", False)]
    wait(lambda: r.recv.keys() == exp, msg="\n got %s\n exp %s" % (r.recv.keys(), exp))


@test
def mac_sharer_layouts_and_dead_zones():
    """Mac with an external monitor sharing to a Windows PC with two monitors, all edges"""
    for mac_rects in ([(0, 0, 1710, 1107)], [(0, 0, 1710, 1107), (-2560, -300, 0, 1140)],
                      [(0, 0, 1710, 1107), (0, -1440, 2560, 0)]):
        for edge, d in (("right", (1, 0)), ("left", (-1, 0)), ("top", (0, -1)), ("bottom", (0, 1))):
            share = FakeMacShare(mac_rects)
            recv = WinRecv([(0, 0, 1920, 1080), (1920, -180, 4480, 1260)])
            back = []
            core = K.ServerCore(share, edge, log=lambda *a: None)
            share.attach(core)
            side = {"right": "left", "left": "right", "top": "bottom", "bottom": "top"}[edge]
            cc = K.ClientCore(recv.inj, side=side, send=back.append, log=lambda *a: None)
            core.send = cc.handle
            cc.peer_os = "Darwin"
            core.set_connected(True)

            def move(dx, dy):
                share.hw_move(dx, dy)
                while back:
                    m = back.pop(0)
                    if m["t"] == "leave":
                        core.client_left(m["r"])
            ctx = (mac_rects, edge)
            for _ in range(400):
                if core.remote:
                    break
                move(d[0] * 37, d[1] * 37)
            assert core.remote, ctx
            assert share.desk.find(*share.cur), ctx
            rnd = random.Random(1)
            for _ in range(300):
                if not core.remote:
                    for _ in range(400):
                        if core.remote:
                            break
                        move(d[0] * 37, d[1] * 37)
                move(rnd.randint(-90, 90), rnd.randint(-90, 90))
            for _ in range(600):
                if not core.remote:
                    break
                move(-d[0] * 45, -d[1] * 45)
            assert not core.remote and share.coupled and not share.hidden, ctx
            assert share.desk.find(*share.cur), (ctx, share.cur)
            for _ in range(3):
                if core.remote:
                    break
                move(d[0] * 4, d[1] * 4)
            assert core.remote, (ctx, "landed away from the edge", share.cur)
            assert not recv.errors, (ctx, recv.errors)


@test
def real_quartz_events_decode():
    if sys.platform != "darwin":
        print("    (skipped: not macOS)")
        return
    import Quartz as Q
    src = Q.CGEventSourceCreate(Q.kCGEventSourceStateHIDSystemState)
    e = Q.CGEventCreateMouseEvent(src, Q.kCGEventMouseMoved, (120.5, 300.0), 0)
    Q.CGEventSetIntegerValueField(e, Q.kCGMouseEventDeltaX, 7)
    Q.CGEventSetIntegerValueField(e, Q.kCGMouseEventDeltaY, -3)
    assert K.mac_decode(Q, Q.CGEventGetType(e), e) == ("move", 120.5, 300.0, 7, -3)
    e = Q.CGEventCreateMouseEvent(src, Q.kCGEventLeftMouseDragged, (1, 2), 0)
    assert K.mac_decode(Q, Q.CGEventGetType(e), e)[0] == "move"
    for typ, exp in ((Q.kCGEventLeftMouseDown, ("btn", "left", True)),
                     (Q.kCGEventRightMouseUp, ("btn", "right", False))):
        e = Q.CGEventCreateMouseEvent(src, typ, (1, 2), 0)
        assert K.mac_decode(Q, Q.CGEventGetType(e), e) == exp
    for n, name in ((2, "middle"), (3, "x1"), (4, "x2")):
        e = Q.CGEventCreateMouseEvent(src, Q.kCGEventOtherMouseDown, (1, 2), n)
        assert K.mac_decode(Q, Q.CGEventGetType(e), e) == ("btn", name, True), n
    e = Q.CGEventCreateScrollWheelEvent(src, Q.kCGScrollEventUnitLine, 2, 2, -1)
    kind, dx, dy = K.mac_decode(Q, Q.CGEventGetType(e), e)
    assert kind == "scroll" and dy == 2.0 and dx == 1.0, (dx, dy)  # mac axis2 -1 (right) -> +1
    e = Q.CGEventCreateKeyboardEvent(src, 0x08, True)
    assert K.mac_decode(Q, Q.CGEventGetType(e), e) == ("key", 0x08, True)
    e = Q.CGEventCreateKeyboardEvent(src, 0x08, False)
    assert K.mac_decode(Q, Q.CGEventGetType(e), e) == ("key", 0x08, False)
    e = Q.CGEventCreateKeyboardEvent(src, 0x37, True)
    Q.CGEventSetType(e, Q.kCGEventFlagsChanged)
    Q.CGEventSetFlags(e, 0x100000 | 0x8)
    info = K.mac_decode(Q, Q.CGEventGetType(e), e)
    assert info[:2] == ("flags", 0x37) and info[2] & 0x8, info
    # and dispatching it presses left Cmd ("meta")
    sent = []
    win = FakeWin()
    core = K.ServerCore(win, "right", send=sent.append, log=lambda *a: None)
    core.remote = True
    assert K.mac_dispatch(core, info) is True and sent[-1]["n"] == "meta" and sent[-1]["p"]
    info_up = ("flags", 0x37, 0x0)
    K.mac_dispatch(core, info_up)
    assert sent[-1]["n"] == "meta" and not sent[-1]["p"]


@test
def windows_struct_layout_64bit():
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        return
    assert ctypes.sizeof(K.INPUT) == 40 and ctypes.sizeof(K.MOUSEINPUT) == 32
    assert ctypes.sizeof(K.KEYBDINPUT) == 24
    assert K.INPUT.u.offset == 8


@test
def key_tables_round_trip():
    for name in K.MAC_KVK:
        assert name in K.WIN_NAME_VK, name
    for name, vk in K.WIN_NAME_VK.items():
        assert K.WIN_VK.get(vk) == name or (name == "kp_enter" and vk == 0x0D), name
    for kc, name in K.MAC_KC_NAME.items():
        if name in K.MAC_KVK:
            assert K.MAC_KVK[name] == kc, (name, kc)


if __name__ == "__main__":
    only = sys.argv[1:]
    failed = 0
    for t in TESTS:
        if only and t.__name__ not in only:
            continue
        t0 = time.time()
        try:
            t()
            print("PASS  %-46s %.2fs" % (t.__name__, time.time() - t0))
        except Exception:
            failed += 1
            print("FAIL  %s" % t.__name__)
            traceback.print_exc()
    print("\n%d failed" % failed if failed else "\nall passed")
    sys.exit(1 if failed else 0)
