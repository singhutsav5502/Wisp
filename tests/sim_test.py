"""End-to-end simulation of kmshare: fake Windows (low-level hook semantics) <-> real TCP
<-> fake Mac injector. Runs on any OS:  python tests/sim_test.py
"""
import ctypes
import os
import random
import sys
import threading
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import wisp as K  # noqa: E402

MOVE = 0x200
BTN_DOWN = {"left": 0x201, "right": 0x204, "middle": 0x207}
BTN_UP = {"left": 0x202, "right": 0x205, "middle": 0x208}


def wait(cond, timeout=2.0, msg="condition"):
    # poll by yielding, not sleeping: macOS can stretch short sleeps to ~100 ms on battery
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return
        time.sleep(0)
    raise AssertionError("timed out waiting for " + msg)


class FakeWin:
    """Simulates Windows: cursor, screen, and WH_*_LL hook semantics. Hardware events go
    through the real ctypes hook procs; only events the hook doesn't swallow reach `apps`."""

    def __init__(self, w=2560, h=1440, x0=0, y0=0, echo=None, echo_injected=False, mons=None):
        self.mons = mons or [(x0, y0, x0 + w, y0 + h)]
        self.desk = K.Desktop(self.mons)
        m = self.mons[0]
        self.cur = [m[0] + (m[2] - m[0]) // 4, (m[1] + m[3]) // 2]
        self.hidden = False
        self.echo, self.echo_injected = echo, echo_injected
        self.apps = []
        self.core = None

    def attach(self, core):
        self.core = core
        self.mproc = K.make_mouse_proc(core, lambda n, w, l: 0)
        self.kproc = K.make_key_proc(core, lambda n, w, l: 0)

    # --- OS interface used by ServerCore ---
    def monitors(self):
        return self.mons

    def get_cursor(self):
        return tuple(self.cur)

    def _clamp(self, x, y):  # Windows keeps the cursor on a real monitor
        cx, cy = self.desk.clamp(int(x), int(y))
        return int(cx), int(cy)

    def set_cursor(self, x, y):
        x, y = self._clamp(x, y)
        if self.echo == "before":
            self._mouse(MOVE, x, y, 0, self.echo_injected)
        self.cur = [x, y]
        if self.echo == "after":
            self._mouse(MOVE, x, y, 0, self.echo_injected)

    def hide_cursor(self):
        self.hidden = True

    def show_cursor(self):
        self.hidden = False

    # --- hook plumbing ---
    def _mouse(self, msg, x, y, data, injected):
        s = K.MSLLHOOKSTRUCT(x, y, data, 1 if injected else 0, 0, 0)
        return self.mproc(0, msg, ctypes.addressof(s)) == 1

    def _key(self, msg, vk, flags, scan=None):
        if scan is None:  # real Windows always fills in the scan code (US layout here)
            scan = 0 if flags & 1 else US_VK_SCAN.get(vk, 0)
        s = K.KBDLLHOOKSTRUCT(vk, scan, flags, 0, 0)
        return self.kproc(0, msg, ctypes.addressof(s)) == 1

    # --- hardware ---
    def hw_move(self, dx, dy):
        px, py = self._clamp(self.cur[0] + dx, self.cur[1] + dy)
        if not self._mouse(MOVE, px, py, 0, False):
            self.cur = [px, py]
            self.apps.append(("move", px, py))

    def hw_button(self, name, down):
        if name in ("x1", "x2"):
            msg, data = (0x20B if down else 0x20C), (1 if name == "x1" else 2) << 16
        else:
            msg, data = (BTN_DOWN if down else BTN_UP)[name], 0
        if not self._mouse(msg, self.cur[0], self.cur[1], data, False):
            self.apps.append(("btn", name, down, tuple(self.cur)))

    def hw_wheel(self, notches, horizontal=False):
        data = (int(round(notches * 120)) & 0xFFFF) << 16
        if not self._mouse(0x20E if horizontal else 0x20A, self.cur[0], self.cur[1], data, False):
            self.apps.append(("wheel", notches, horizontal))

    def hw_key(self, vk, down, flags=0, sys_=False, scan=None):
        msg = (0x104 if sys_ else 0x100) if down else (0x105 if sys_ else 0x101)
        if not self._key(msg, vk, flags, scan):
            self.apps.append(("key", vk, down))

    def click(self, name="left"):
        self.hw_button(name, True)
        self.hw_button(name, False)

    def tap(self, vk):
        self.hw_key(vk, True)
        self.hw_key(vk, False)


class FakeMac:
    def __init__(self, w=1470, h=956, rects=None):
        self.w, self.h = w, h
        self.rects = rects or [(0, 0, w, h)]
        self.desk = K.Desktop(self.rects)
        self.pos = self.desk.park()
        self.errors = []
        self.ev = []
        self.lock = threading.Lock()

    def displays(self):
        return self.rects

    def get_pos(self):
        return self.pos

    def move(self, x, y, dx, dy, btns, flags):
        with self.lock:
            if not self.desk.find(x, y):
                self.errors.append("mac cursor posted off-screen at %s" % ((x, y),))
                raise AssertionError(self.errors[-1])
            self.pos = (x, y)
            self.ev.append(("drag" if btns else "move", x, y))

    def button(self, name, down, x, y, clicks, flags):
        with self.lock:
            self.ev.append(("btn", name, down, x, y, clicks, flags))

    def scroll(self, ly, lx):
        with self.lock:
            self.ev.append(("scroll", ly, lx))

    def key(self, code, down, flags, repeat):
        with self.lock:
            self.ev.append(("key", code, down, flags, repeat))

    def of(self, kind):
        with self.lock:
            return [e for e in self.ev if e[0] == kind]

    def held_keys(self):
        held = {}
        for e in self.of("key"):
            held[e[1]] = e[2]
        return {k for k, v in held.items() if v}

    def held_btns(self):
        held = {}
        for e in self.of("btn"):
            held[e[1]] = e[2]
        return {k for k, v in held.items() if v}


class Rig:
    def __init__(self, edge="right", side="left", token="tok", client_token=None, hb=0.2,
                 hb_timeout=1.0, speed=1.0, swap=True, mac_rects=None, **winkw):
        self.win, self.mac = FakeWin(**winkw), FakeMac(rects=mac_rects)
        self.logs = []
        log = self.logs.append
        self.score = K.ServerCore(self.win, edge, log=log)
        self.win.attach(self.score)
        self.ccore = K.ClientCore(self.mac, side=side, speed=speed, swap=swap, log=log)
        self.stop = threading.Event()
        self.cstop = threading.Event()
        port = []
        self.st = threading.Thread(target=K.run_server_net, kwargs=dict(
            core=self.score, port=0, token=token, bind="127.0.0.1", stop=self.stop,
            ready=port.append, hb=hb, hb_timeout=hb_timeout, log=log), daemon=True)
        self.st.start()
        wait(lambda: port, msg="server listening")
        self.port = port[0]
        self.ct = threading.Thread(target=K.run_client_net, kwargs=dict(
            core=self.ccore, host="127.0.0.1", port=self.port,
            token=client_token or token, stop=self.cstop, retry=0.2, timeout=1.0, log=log),
            daemon=True)
        self.ct.start()

    def win_errors(self):
        return [l for l in self.logs if "Traceback" in str(l)]

    def connected(self):
        wait(lambda: self.score.connected and self.ccore.peer_os, msg="connection")

    def settle(self, t=0.15):
        time.sleep(t)

    def cross(self):
        """move right until we are on the Mac"""
        for _ in range(200):
            if self.score.remote:
                break
            self.win.hw_move(40, 0)
        assert self.score.remote, "did not cross"
        wait(lambda: self.ccore.active, msg="client active")

    def close(self):
        assert not self.mac.errors, self.mac.errors
        assert not self.win_errors(), self.win_errors()
        self.cstop.set()
        self.stop.set()
        self.ct.join(3)
        self.st.join(3)


# independent US-layout table: Windows VK -> set-1 scan code, as a real keyboard reports them
US_VK_SCAN = {0x1B: 0x01, 0x08: 0x0E, 0x09: 0x0F, 0x0D: 0x1C, 0x20: 0x39, 0x14: 0x3A,
              0xA0: 0x2A, 0xA1: 0x36, 0xA2: 0x1D, 0xA4: 0x38}
for _row, _sc in (("1234567890\xbd\xbb", 0x02), ("QWERTYUIOP\xdb\xdd", 0x10),
                  ("ASDFGHJKL\xba\xde\xc0", 0x1E), ("\xdcZXCVBNM\xbc\xbe\xbf", 0x2B)):
    for _i, _c in enumerate(_row):
        US_VK_SCAN[ord(_c)] = _sc + _i
US_VK_SCAN[0xE2] = 0x56

TESTS = []


def test(f):
    TESTS.append(f)
    return f


# ------------------------------------------------------------------ tests
@test
def struct_layout():
    assert ctypes.sizeof(K.MSLLHOOKSTRUCT) == (32 if ctypes.sizeof(ctypes.c_void_p) == 8 else 24)
    assert ctypes.sizeof(K.KBDLLHOOKSTRUCT) == (24 if ctypes.sizeof(ctypes.c_void_p) == 8 else 20)


@test
def key_tables_complete():
    for vk, name in K.WIN_VK.items():
        if name in ("f21", "f22", "f23", "f24", "menu"):
            continue
        assert name in K.MAC_KVK, "no mac keycode for %s (vk %#x)" % (name, vk)
    assert len(set(K.MAC_KVK[c] for c in "abcdefghijklmnopqrstuvwxyz0123456789")) == 36


@test
def bad_token_rejected():
    r = Rig(token="right", client_token="wrong")
    try:
        wait(lambda: any("bad token" in str(l) for l in r.logs), msg="rejection")
        r.ct.join(2)
        assert not r.ct.is_alive(), "client should exit on bad token"
        assert not r.score.connected
        for _ in range(100):
            r.win.hw_move(40, 0)
        assert not r.score.remote, "must not cross without an authenticated client"
    finally:
        r.close()


@test
def local_moves_stay_local():
    r = Rig()
    try:
        r.connected()
        r.win.hw_move(100, 50)
        r.win.click()
        r.settle()
        assert not r.score.remote
        assert ("btn", "left", True, tuple(r.win.cur)) in r.win.apps
        assert r.mac.ev == [], r.mac.ev
    finally:
        r.close()


@test
def no_cross_without_client():
    win = FakeWin()
    core = K.ServerCore(win, "right", log=lambda *a: None)
    win.attach(core)
    for _ in range(200):
        win.hw_move(40, 0)
    assert not core.remote and win.cur[0] == 2559


@test
def cross_hides_and_parks_cursor():
    r = Rig()
    try:
        r.connected()
        r.win.cur = [2000, 360]  # 25% height
        r.cross()
        assert r.win.hidden, "windows cursor must be hidden on the mac"
        assert tuple(r.win.cur) == (1280, 720), r.win.cur
        wait(lambda: r.mac.of("move"), msg="mac enter move")
        x, y = r.mac.of("move")[0][1:]
        assert x == 2 and abs(y - 0.25 * 955) <= 2, (x, y)
    finally:
        r.close()


@test
def remote_moves_forwarded_exactly_and_windows_frozen():
    r = Rig()
    try:
        r.connected()
        r.cross()
        n_apps = len(r.win.apps)
        start = r.mac.pos
        tot = [0, 0]
        rnd = random.Random(1)
        for _ in range(300):
            dx, dy = rnd.randint(-3, 6), rnd.randint(-4, 4)
            r.win.hw_move(dx, dy)
            tot[0] += dx
            tot[1] += dy
            if not r.ccore.active:
                break
        assert r.ccore.active, "random walk should stay on the mac"
        wait(lambda: r.mac.pos == (min(max(start[0] + tot[0], 0), 1469),
                                   min(max(start[1] + tot[1], 0), 955)) or True)
        r.settle()
        ex = (start[0] + tot[0], start[1] + tot[1])
        assert abs(r.mac.pos[0] - ex[0]) <= 1 and abs(r.mac.pos[1] - ex[1]) <= 1, (r.mac.pos, ex)
        assert len(r.win.apps) == n_apps, "windows apps saw input while remote: %s" % r.win.apps[n_apps:]
        assert tuple(r.win.cur) == (1280, 720)
    finally:
        r.close()


@test
def big_fast_moves_not_lost():
    r = Rig()
    try:
        r.connected()
        r.cross()
        r.win.hw_move(500, 300)  # one huge delta
        r.settle()
        assert r.mac.pos == (2 + 500, int(0.5 * 955) + 300), r.mac.pos
    finally:
        r.close()


@test
def clicks_only_on_mac_when_remote():  # the reported bug
    r = Rig()
    try:
        r.connected()
        r.cross()
        r.win.hw_move(300, 0)
        n_apps = len(r.win.apps)
        for b in ("left", "right", "middle", "x1", "x2"):
            r.win.click(b)
        r.win.hw_wheel(1)
        r.win.hw_wheel(-2)
        r.win.hw_wheel(1, horizontal=True)
        r.settle()
        assert r.win.apps[n_apps:] == [], "leaked to windows: %s" % r.win.apps[n_apps:]
        btns = r.mac.of("btn")
        assert [(e[1], e[2]) for e in btns] == [(b, d) for b in ("left", "right", "middle", "x1", "x2")
                                                 for d in (True, False)], btns
        assert all(e[3] == 302 for e in btns), btns
        assert r.mac.of("scroll") == [("scroll", 3, 0), ("scroll", -6, 0), ("scroll", 0, -3)], r.mac.of("scroll")
    finally:
        r.close()


@test
def double_click_and_drag():
    r = Rig()
    try:
        r.connected()
        r.cross()
        r.win.click()
        r.win.click()
        r.settle()
        downs = [e for e in r.mac.of("btn") if e[2]]
        assert [e[5] for e in downs] == [1, 2], downs
        r.mac.ev.clear()
        r.win.hw_button("left", True)
        r.win.hw_move(10, 5)
        r.win.hw_move(10, 5)
        r.win.hw_button("left", False)
        r.settle()
        kinds = [e[0] for e in r.mac.ev]
        # moves may be merged in transit; must be: press, >=1 drag, release, ending at +20,+10
        assert kinds[0] == "btn" and kinds[-1] == "btn" and set(kinds[1:-1]) == {"drag"}, r.mac.ev
        assert r.mac.ev[-1][3:5] == (r.mac.ev[0][3] + 20, r.mac.ev[0][4] + 10), r.mac.ev
        time.sleep(0.6)
        r.win.click()
        r.settle()
        assert r.mac.of("btn")[-2][5] == 1
    finally:
        r.close()


@test
def keys_forwarded_with_ctrl_to_cmd_swap():
    r = Rig()
    try:
        r.connected()
        r.cross()
        n_apps = len(r.win.apps)
        r.win.tap(0x48)  # h
        r.win.tap(0x49)  # i
        r.win.hw_key(0xA2, True)   # left ctrl
        r.win.tap(0x43)            # c
        r.win.hw_key(0xA2, False)
        r.win.hw_key(0xA0, True)   # shift
        r.win.tap(0x41)            # A
        r.win.hw_key(0xA0, False)
        r.win.hw_key(0xA4, True, sys_=True)  # alt (WM_SYSKEYDOWN)
        r.win.hw_key(0x09, True, sys_=True)  # tab
        r.win.hw_key(0x09, False, sys_=True)
        r.win.hw_key(0xA4, False, sys_=True)
        r.win.hw_key(0x5B, True)   # windows key
        r.win.hw_key(0x5B, False)
        r.win.tap(0x25)            # left arrow
        r.win.hw_key(0x0D, True, flags=1)  # numpad enter
        r.win.hw_key(0x0D, False, flags=1)
        r.settle()
        assert r.win.apps[n_apps:] == [], "keys leaked to windows: %s" % r.win.apps[n_apps:]
        ks = [(e[1], e[2], e[3]) for e in r.mac.of("key")]
        CMD, SH, ALT = 0x100000, 0x20000, 0x80000
        exp = [(0x04, True, 0), (0x04, False, 0), (0x22, True, 0), (0x22, False, 0),
               (0x37, True, CMD), (0x08, True, CMD), (0x08, False, CMD), (0x37, False, 0),
               (0x38, True, SH), (0x00, True, SH), (0x00, False, SH), (0x38, False, 0),
               (0x3A, True, ALT), (0x30, True, ALT), (0x30, False, ALT), (0x3A, False, 0),
               (0x3B, True, 0x40000), (0x3B, False, 0),
               (0x7B, True, 0xA00000), (0x7B, False, 0xA00000),
               (0x4C, True, 0), (0x4C, False, 0)]
        assert ks == exp, "\n got %s\n exp %s" % (ks, exp)
    finally:
        r.close()


@test
def key_autorepeat():
    r = Rig()
    try:
        r.connected()
        r.cross()
        for _ in range(3):
            r.win.hw_key(0x41, True)
        r.win.hw_key(0x41, False)
        r.settle()
        assert [e[4] for e in r.mac.of("key")] == [False, True, True, False]
    finally:
        r.close()


@test
def key_held_while_crossing_returns_to_windows():
    r = Rig()
    try:
        r.connected()
        r.win.hw_key(0xA0, True)  # hold shift on windows
        r.cross()
        r.win.hw_key(0xA0, True)  # autorepeat while on mac
        r.win.tap(0x41)
        r.win.hw_key(0xA0, False)  # release: must go to windows, not the mac
        r.settle()
        assert ("key", 0xA0, False) in r.win.apps, r.win.apps
        assert r.mac.held_keys() == set()
        assert all(e[1] != 0x38 for e in r.mac.of("key")), "shift leaked to mac"
    finally:
        r.close()


@test
def no_cross_while_button_held():
    r = Rig()
    try:
        r.connected()
        r.win.hw_button("left", True)
        for _ in range(100):
            r.win.hw_move(40, 0)
        assert not r.score.remote
        r.win.hw_button("left", False)
        r.win.hw_move(5, 0)
        assert r.score.remote
    finally:
        r.close()


@test
def return_to_windows_via_mac_edge():
    r = Rig()
    try:
        r.connected()
        r.win.cur = [2000, 1080]  # 75% height
        r.cross()
        r.win.hw_move(200, 0)
        r.win.hw_key(0xA2, True)  # hold ctrl (=cmd on mac) while leaving
        r.win.hw_button("left", True)
        r.win.hw_button("left", False)
        for _ in range(50):
            r.win.hw_move(-20, 0)
            time.sleep(0.02)
            if not r.ccore.active:
                break
        wait(lambda: not r.score.remote, msg="return to windows")
        assert not r.win.hidden, "cursor must be visible again"
        assert r.win.cur[0] == 2559 - 4 and abs(r.win.cur[1] - 1080) <= 3, r.win.cur
        wait(lambda: r.mac.held_keys() == set(), msg="mac released cmd")
        n = len(r.mac.ev)
        r.win.hw_key(0xA2, False)  # ctrl released after return: windows gets it
        r.win.click()
        r.win.hw_move(-50, 0)
        r.settle()
        assert len(r.mac.ev) == n, "mac got events after return: %s" % r.mac.ev[n:]
        assert ("btn", "left", True, tuple(r.win.apps[-2][3])) in r.win.apps
        r.cross()  # and back again
        assert r.ccore.active
    finally:
        r.close()


@test
def no_return_while_dragging_on_mac():
    r = Rig()
    try:
        r.connected()
        r.cross()
        r.win.hw_button("left", True)
        for _ in range(20):
            r.win.hw_move(-50, 0)
        r.settle()
        assert r.score.remote and r.ccore.active
        r.win.hw_button("left", False)
        r.win.hw_move(-5, 0)
        wait(lambda: not r.score.remote, msg="return after release")
    finally:
        r.close()


@test
def panic_key():
    r = Rig()
    try:
        r.connected()
        r.cross()
        for vk in (0xA2, 0xA4, 0xA0):
            r.win.hw_key(vk, True)
        r.win.hw_key(0x1B, True)
        assert not r.score.remote and not r.win.hidden
        wait(lambda: not r.ccore.active and r.mac.held_keys() == set(), msg="mac released")
        assert all(e[1] != 0x35 for e in r.mac.of("key")), "esc must not reach the mac"
        for vk in (0x1B, 0xA2, 0xA4, 0xA0):
            r.win.hw_key(vk, False)
        r.win.click()
        assert r.win.apps[-1][0] == "btn"
    finally:
        r.close()


@test
def client_crash_returns_control():
    r = Rig()
    try:
        r.connected()
        r.cross()
        r.cstop.set()  # client process goes away
        r.ct.join(3)
        assert not r.ct.is_alive()
        wait(lambda: not r.score.remote, timeout=3, msg="server back to local after client gone")
        assert not r.win.hidden
        r.win.click()
        assert r.win.apps[-1][0] == "btn"
    finally:
        r.close()


@test
def silent_client_times_out():
    win = FakeWin()
    core = K.ServerCore(win, "right", log=lambda *a: None)
    win.attach(core)
    stop, port = threading.Event(), []
    threading.Thread(target=K.run_server_net, kwargs=dict(
        core=core, port=0, token="t", bind="127.0.0.1", stop=stop, ready=port.append,
        hb=0.1, hb_timeout=0.5, log=lambda *a: None), daemon=True).start()
    wait(lambda: port)
    import socket
    s = socket.create_connection(("127.0.0.1", port[0]))
    s.sendall(K.encode({"t": "hello", "token": "t"}))
    wait(lambda: core.connected)
    for _ in range(100):
        win.hw_move(40, 0)
    assert core.remote
    # never answer pings, never read -> server must time out and return control
    wait(lambda: not core.remote, timeout=3, msg="timeout to local")
    assert not win.hidden
    s.close()
    stop.set()


@test
def client_reconnects():
    r = Rig()
    try:
        r.connected()
        r.cross()
        # drop the server side of the connection
        r.stop.set()
        r.st.join(3)
        wait(lambda: not r.ccore.active, msg="client deactivated")
        assert r.mac.held_keys() == set() and r.mac.held_btns() == set()
    finally:
        r.close()


@test
def setcursor_echo_variants():
    for echo in ("before", "after"):
        for inj in (False, True):
            r = Rig(echo=echo, echo_injected=inj)
            try:
                r.connected()
                r.cross()
                start = r.mac.pos
                for _ in range(40):
                    r.win.hw_move(7, 3)
                r.settle()
                assert r.mac.pos == (start[0] + 280, start[1] + 120), (echo, inj, start, r.mac.pos)
                assert tuple(r.win.cur) == (1280, 720)
                for _ in range(100):
                    r.win.hw_move(-30, 0)
                wait(lambda: not r.score.remote, msg="return (%s,%s)" % (echo, inj))
                assert r.win.cur[0] == 2555
            finally:
                r.close()


@test
def other_edges_and_offset_virtual_screen():
    # dual-monitor style virtual screen starting at negative x; mac above (top edge)
    r = Rig(edge="top", side="bottom", w=3840, h=1080, x0=-1920, y0=0)
    try:
        r.connected()
        r.win.cur = [0, 500]  # middle of the virtual screen horizontally
        for _ in range(100):
            if r.score.remote:
                break
            r.win.hw_move(0, -40)
        assert r.score.remote
        wait(lambda: r.mac.of("move"))
        x, y = r.mac.of("move")[0][1:]
        assert abs(x - 1920 / 3839 * 1469) <= 2 and y == 956 - 3, (x, y)
        assert tuple(r.win.cur) == (0, 540)
        for _ in range(100):
            r.win.hw_move(0, 30)
        wait(lambda: not r.score.remote)
        assert r.win.cur[1] == 4
    finally:
        r.close()


@test
def hook_is_fast():
    win = FakeWin()
    core = K.ServerCore(win, "right", send=lambda o: None, log=lambda *a: None)
    core.connected = True
    win.attach(core)
    for _ in range(100):
        win.hw_move(40, 0)
    assert core.remote
    t = time.perf_counter()
    for i in range(20000):
        win.hw_move(1, -1 if i % 2 else 1)
    per = (time.perf_counter() - t) / 20000
    assert per < 0.0005, "hook too slow: %.1f us" % (per * 1e6)
    print("    hook cost: %.1f us/event" % (per * 1e6))


@test
def hook_exception_passes_event_through():
    class Boom:
        def on_mouse(self, *a):
            raise RuntimeError("x")

        def on_key(self, *a):
            raise RuntimeError("x")
    calls = []
    p = K.make_mouse_proc(Boom(), lambda n, w, l: calls.append(1) or 7)
    s = K.MSLLHOOKSTRUCT(1, 2, 0, 0, 0, 0)
    import io
    old, sys.stderr = sys.stderr, io.StringIO()
    try:
        assert p(0, 0x201, ctypes.addressof(s)) == 7 and calls
    finally:
        sys.stderr = old


@test
def fuzz_invariants():
    rnd = random.Random(42)
    r = Rig()
    try:
        r.connected()
        vks = [0x41, 0x42, 0xA0, 0xA2, 0xA4, 0x5B, 0x25, 0x20]
        held_k, held_b = set(), set()
        for step in range(3000):
            op = rnd.random()
            was_remote = r.score.remote
            n_apps = len(r.win.apps)
            if op < 0.55:
                r.win.hw_move(rnd.randint(-60, 60), rnd.randint(-30, 30))
            elif op < 0.75:
                vk = rnd.choice(vks)
                down = vk not in held_k
                (held_k.add if down else held_k.discard)(vk)
                r.win.hw_key(vk, down)
            elif op < 0.9:
                b = rnd.choice(["left", "right"])
                down = b not in held_b
                (held_b.add if down else held_b.discard)(b)
                r.win.hw_button(b, down)
            else:
                r.win.hw_wheel(rnd.choice([-1, 1]))
            new = r.win.apps[n_apps:]
            if was_remote and r.score.remote:
                for e in new:
                    assert e[0] == "key" and e[2] is False, "leak while remote at %d: %s" % (step, e)
            assert r.win.hidden == r.score.remote, "cursor visibility mismatch at %d" % step
            if r.score.remote:
                assert tuple(r.win.cur) == (1280, 720)
            if step % 200 == 0:
                time.sleep(0.02)
        for vk in list(held_k):
            r.win.hw_key(vk, False)
        for b in list(held_b):
            r.win.hw_button(b, False)
        for _ in range(200):
            if not r.score.remote:
                break
            r.win.hw_move(-60, 0)
            time.sleep(0.002)
        wait(lambda: not r.score.remote and not r.ccore.active, msg="final return")
        r.settle()
        assert r.mac.held_keys() == set(), r.mac.held_keys()
        assert r.mac.held_btns() == set(), r.mac.held_btns()
        assert not r.win.hidden
    finally:
        r.close()


@test
def mac_event_builders():
    if sys.platform != "darwin":
        print("    (skipped: not macOS)")
        return
    import Quartz as Q
    m = K.MacInjector()
    ds = m.displays()
    assert ds and all(d[2] > d[0] and d[3] > d[1] for d in ds)
    x0, y0, x1, y1 = K.Desktop(ds).bounds
    e = m.ev_move(100, 200, 3, -2, set(), 0)
    assert Q.CGEventGetType(e) == Q.kCGEventMouseMoved
    loc = Q.CGEventGetLocation(e)
    assert (loc.x, loc.y) == (100, 200)
    assert Q.CGEventGetIntegerValueField(e, Q.kCGMouseEventDeltaX) == 3
    e = m.ev_move(1, 2, 0, 0, {"left"}, 0)
    assert Q.CGEventGetType(e) == Q.kCGEventLeftMouseDragged
    e = m.ev_move(1, 2, 0, 0, {"right"}, 0)
    assert Q.CGEventGetType(e) == Q.kCGEventRightMouseDragged
    e = m.ev_button("left", True, 5, 6, 2, 0x100000)
    assert Q.CGEventGetType(e) == Q.kCGEventLeftMouseDown
    assert Q.CGEventGetIntegerValueField(e, Q.kCGMouseEventClickState) == 2
    assert Q.CGEventGetFlags(e) & 0x100000
    e = m.ev_button("right", False, 5, 6, 1, 0)
    assert Q.CGEventGetType(e) == Q.kCGEventRightMouseUp
    e = m.ev_button("x1", True, 5, 6, 1, 0)
    assert Q.CGEventGetType(e) == Q.kCGEventOtherMouseDown
    assert Q.CGEventGetIntegerValueField(e, Q.kCGMouseEventButtonNumber) == 3
    e = m.ev_scroll(3, -1)
    assert Q.CGEventGetType(e) == Q.kCGEventScrollWheel
    assert Q.CGEventGetIntegerValueField(e, Q.kCGScrollWheelEventDeltaAxis1) == 3
    assert Q.CGEventGetIntegerValueField(e, Q.kCGScrollWheelEventDeltaAxis2) == -1
    e = m.ev_key(0x08, True, 0x100000, False)
    assert Q.CGEventGetType(e) == Q.kCGEventKeyDown
    assert Q.CGEventGetIntegerValueField(e, Q.kCGKeyboardEventKeycode) == 0x08
    assert Q.CGEventGetFlags(e) & 0x100000
    e = m.ev_key(0x00, True, 0, True)
    assert Q.CGEventGetIntegerValueField(e, Q.kCGKeyboardEventAutorepeat) == 1
    e = m.ev_key(0x00, False, 0, False)
    assert Q.CGEventGetType(e) == Q.kCGEventKeyUp
    print("    mac screen bounds:", (x0, y0, x1, y1))


@test
def cli_parses():
    import argparse  # noqa
    for argv in (["server", "--edge", "right", "--token", "x"],
                 ["client", "--host", "1.2.3.4", "--token", "x", "--side", "left", "--speed", "0.7"]):
        try:
            orig = K.server_main, K.client_main
            got = []
            K.server_main = K.client_main = got.append
            K.main(argv)
            assert got and got[0].token == "x"
        finally:
            K.server_main, K.client_main = orig

@test
def coalesce_keeps_order_and_totals():
    msgs = [{"t": "m", "dx": 1, "dy": 2}, {"t": "m", "dx": 3, "dy": -1},
            {"t": "b", "b": "left", "p": True}, {"t": "m", "dx": 5, "dy": 0},
            {"t": "m", "dx": -2, "dy": 4}, {"t": "k", "n": "a", "p": True}]
    assert K.coalesce(msgs) == [{"t": "m", "dx": 4, "dy": 1}, {"t": "b", "b": "left", "p": True},
                                {"t": "m", "dx": 3, "dy": 4}, {"t": "k", "n": "a", "p": True}]


@test
def high_rate_mouse_burst_low_latency():
    """1000 Hz mouse for 2 s with a click in the middle: Mac must end exactly right,
    click must land at the right spot, and the backlog must stay tiny."""
    r = Rig()
    try:
        r.connected()
        r.cross()
        start = r.mac.pos
        lags = []
        sent = 0
        t0 = time.perf_counter()
        for i in range(2000):
            r.win.hw_move(1 if i % 2 else 0, 1 if i % 8 == 0 else 0)
            sent += 1
            if i == 1000:
                r.win.click()
                click_at = (start[0] + sum(1 if j % 2 else 0 for j in range(1001)),
                            start[1] + sum(1 if j % 8 == 0 else 0 for j in range(1001)))
            # pace like a real 1000 Hz mouse
            while time.perf_counter() < t0 + (i + 1) / 1000:
                pass
            if i % 100 == 99:
                exp_x = start[0] + sum(1 if j % 2 else 0 for j in range(i + 1))
                tw = time.perf_counter()
                wait(lambda: r.mac.pos[0] >= exp_x, timeout=1, msg="catch up")
                lags.append((time.perf_counter() - tw) * 1000)
        exp = (start[0] + 1000, start[1] + 250)
        wait(lambda: r.mac.pos == exp, timeout=1, msg="final position %s (got %s)" % (exp, r.mac.pos))
        downs = [e for e in r.mac.of("btn") if e[2]]
        assert (downs[0][3], downs[0][4]) == click_at, (downs[0], click_at)
        n_moves = len(r.mac.of("move"))
        print("    %d hook moves -> %d mac moves; catch-up lag max %.1f ms"
              % (sent, n_moves, max(lags)))
        assert max(lags) < 50, lags
    finally:
        r.close()


@test
def stats_reports_round_trip():
    win, mac = FakeWin(), FakeMac()
    logs = []
    core = K.ServerCore(win, "right", log=logs.append)
    win.attach(core)
    cc = K.ClientCore(mac, log=lambda *a: None)
    stop, port = threading.Event(), []
    threading.Thread(target=K.run_server_net, kwargs=dict(
        core=core, port=0, token="t", bind="127.0.0.1", stop=stop, ready=port.append,
        hb=0.05, hb_timeout=1, log=logs.append, stats=True), daemon=True).start()
    wait(lambda: port)
    orig = time.monotonic
    threading.Thread(target=K.run_client_net, kwargs=dict(
        core=cc, host="127.0.0.1", port=port[0], token="t", stop=stop, log=lambda *a: None),
        daemon=True).start()
    wait(lambda: any("round trip" in str(l) for l in logs), timeout=7, msg="stats line")
    print("    " + [l for l in logs if "round trip" in str(l)][0])
    stop.set()


WIN_LAYOUTS = {
    "single": [(0, 0, 2560, 1440)],
    "laptop+monitor_right": [(0, 0, 1920, 1080), (1920, -180, 4480, 1260)],
    "monitor_left+laptop": [(-2560, -180, 0, 1260), (0, 0, 1920, 1080)],
    "monitor_above_laptop": [(0, -1440, 2560, 0), (320, 0, 2240, 1080)],
    "laptop_above_monitor": [(320, -1080, 2240, 0), (0, 0, 2560, 1440)],
    "portrait_monitor+laptop": [(0, 0, 1440, 2560), (1440, 1480, 3360, 2560)],
}
MAC_LAYOUTS = {
    "single": [(0, 0, 1710, 1107)],
    "monitor_left": [(0, 0, 1710, 1107), (-2560, -300, 0, 1140)],
    "monitor_right": [(0, 0, 1710, 1107), (1710, -300, 4270, 1140)],
    "monitor_above": [(0, 0, 1710, 1107), (-425, -1440, 2135, 0)],
    "monitor_below": [(0, 0, 1710, 1107), (0, 1107, 2560, 2547)],
    "portrait_monitor_left": [(0, 1453, 1710, 2560), (-1440, 0, 0, 2560)],
}
DIRS = {"right": (1, 0), "left": (-1, 0), "top": (0, -1), "bottom": (0, 1)}
OPPOSITE = {"right": "left", "left": "right", "top": "bottom", "bottom": "top"}


class DirectRig:
    """server and client cores wired directly (network is covered by other tests)"""

    def __init__(self, win_mons, mac_rects, edge):
        self.win, self.mac = FakeWin(mons=win_mons), FakeMac(rects=mac_rects)
        self.edge, self.side = edge, OPPOSITE[edge]
        self.back = []
        self.s = K.ServerCore(self.win, edge, log=lambda *a: None)
        self.c = K.ClientCore(self.mac, side=self.side, log=lambda *a: None, send=self.back.append)
        self.s.send = self.c.handle
        self.c.peer_os = "Windows"
        self.win.attach(self.s)
        self.s.set_connected(True)

    def move(self, dx, dy):
        was_remote = self.s.remote
        proposed = self.win._clamp(self.win.cur[0] + dx, self.win.cur[1] + dy)
        self.win.hw_move(dx, dy)
        if not was_remote and self.s.remote:  # crossed: only allowed at a free edge
            assert self.win.desk.free(proposed[0], proposed[1], self.edge), \
                "crossed at non-free point %s (edge %s)" % (proposed, self.edge)
        while self.back:
            m = self.back.pop(0)
            if m["t"] == "leave":
                self.s.client_left(m["r"])

    def cross(self, jitter=0):
        ex, ey = DIRS[self.edge]
        for i in range(400):
            if self.s.remote:
                return
            j = jitter if i % 2 else -jitter
            self.move(ex * 37 + (j if ey else 0), ey * 37 + (j if ex else 0))
        raise AssertionError("never crossed")


@test
def layout_matrix():
    rnd = random.Random(7)
    n = 0
    for wn, wm in WIN_LAYOUTS.items():
        for mn, mm in MAC_LAYOUTS.items():
            for edge in DIRS:
                ctx = "%s / %s / edge=%s" % (wn, mn, edge)
                r = DirectRig(wm, mm, edge)
                wd, md, side = r.win.desk, r.mac.desk, r.side
                ex, ey = DIRS[edge]
                sx, sy = DIRS[side]
                # windows park point is on a real monitor
                assert wd.find(*wd.park()), ctx
                # cross from a few different starting monitors
                for start in wm:
                    r.win.cur = [(start[0] + start[2]) // 2, (start[1] + start[3]) // 2]
                    r.win.apps.clear()
                    r.cross(jitter=rnd.randint(0, 9))
                    lastmove = [a for a in r.win.apps if a[0] == "move"]
                    if lastmove:  # crossing happened at a free edge of a real monitor
                        x, y = lastmove[-1][1:]
                        assert wd.free(x, y, edge) or wd.free(*wd.clamp(x + ex * 37, y + ey * 37), edge), ctx
                    assert r.win.hidden and tuple(r.win.cur) == wd.park(), ctx
                    # mac entry is on a display, next to a free edge facing windows
                    px, py = r.mac.pos
                    probe = md.clamp(px + sx * 5, py + sy * 5)
                    assert md.free(probe[0], probe[1], side), (ctx, r.mac.pos)
                    n_apps = len(r.win.apps)
                    # random walk on the mac (FakeMac asserts every point is on-screen)
                    for _ in range(300):
                        if not r.s.remote:
                            r.cross()
                        r.move(rnd.randint(-80, 80), rnd.randint(-80, 80))
                    if not r.s.remote:
                        r.cross()
                    # no dead zones: after a hard push in any non-exit direction,
                    # a small move back must take effect immediately
                    for d in DIRS:
                        if d == side:
                            continue
                        dx, dy = DIRS[d]
                        for _ in range(60):
                            r.move(dx * 90, dy * 90)
                        if not r.s.remote:
                            r.cross()
                            continue
                        before = r.mac.pos
                        r.move(-dx * 10, -dy * 10)
                        after = r.mac.pos
                        assert (after[0] - before[0], after[1] - before[1]) == (-dx * 10, -dy * 10), \
                            (ctx, "stuck after pushing " + d, before, after)
                    assert all(a[0] == "key" and not a[2] for a in r.win.apps[n_apps:]) or \
                        not any(a[0] in ("btn", "wheel") for a in r.win.apps[n_apps:]), ctx
                    # go back: push toward the windows side
                    for _ in range(400):
                        if not r.s.remote:
                            break
                        r.move(sx * 45, sy * 45)
                    assert not r.s.remote and not r.win.hidden, ctx
                    # landed on a real monitor right next to a free edge: a small push re-crosses
                    assert wd.find(*r.win.cur), (ctx, r.win.cur)
                    for _ in range(3):
                        if r.s.remote:
                            break
                        r.move(ex * 4, ey * 4)
                    assert r.s.remote, (ctx, "landed away from the edge", r.win.cur)
                    for _ in range(400):
                        if not r.s.remote:
                            break
                        r.move(sx * 45, sy * 45)
                    assert not r.mac.errors, (ctx, r.mac.errors)
                    n += 1
    print("    %d layout/start combinations OK" % n)


@test
def taller_mac_monitor_no_dead_zone():
    """MacBook next to a much taller monitor: cursor never sits in the gap below the MacBook"""
    r = DirectRig([(0, 0, 2560, 1440)], [(0, 0, 1710, 1107), (-2560, -300, 0, 1140)], "right")
    r.cross()  # enters the big monitor's left edge (monitor is left of the MacBook)
    assert r.mac.pos[0] == -2560 + 2, r.mac.pos
    for _ in range(80):
        r.move(60, 0)  # walk onto the MacBook
    assert r.mac.pos[0] >= 0
    for _ in range(40):
        r.move(0, 80)  # push down hard
    assert r.mac.pos[1] == 1106, r.mac.pos
    r.move(0, -5)
    assert r.mac.pos[1] == 1101, "cursor stuck in dead zone: %s" % (r.mac.pos,)
    for _ in range(80):
        r.move(-60, 0)  # back across both displays to windows
    assert not r.s.remote
    assert not r.mac.errors, r.mac.errors


@test
def desktop_geometry_units():
    d = K.Desktop([(0, 0, 100, 100), (100, -50, 300, 150)])
    assert d.free(299, 0, "right") and not d.free(99, 50, "right") and d.free(0, 50, "left")
    assert d.free(50, 0, "top") and d.free(150, -50, "top") and not d.free(150, 0, "top")
    assert d.clamp(50, 120) == (50, 99) and d.clamp(400, 10) == (299, 10)
    assert d.edge_point("left", 0.0) == (100, -50)   # part of the big screen's left edge is free
    assert d.edge_point("left", 1.0) == (100, 149)
    assert d.edge_point("left", 0.5) == (0, 49.5)    # covered there -> the small screen's edge
    assert d.edge_point("right", 0.5, inset=4) == (295, 49.5)
    assert d.park() == (200, 50)
    assert abs(d.ratio("right", 299, 49.5) - 0.5) < 1e-9


@test
def client_rounds_down_at_negative_coords():
    # MacBook only 50 tall, monitor to its left 100 tall: (-0.2, 80) is on the monitor;
    # truncating to (0, 80) would land in the gap below the MacBook
    mac = FakeMac(rects=[(0, 0, 100, 50), (-100, 0, 0, 100)])
    c = K.ClientCore(mac, side="left", speed=0.5, log=lambda *a: None)
    c.active, c.x, c.y = True, -0.2, 80.0
    c._move(0, 0)
    c._move(1, 1)  # -> (0.3, 80.5) is in the gap -> clamped onto the monitor
    assert not mac.errors, mac.errors
    assert mac.of("move")[0][1:] == (-1, 80), mac.of("move")
    assert mac.desk.find(*mac.of("move")[1][1:]), mac.of("move")


@test
def typing_during_heavy_mouse_traffic_keeps_exact_order():
    """type a sentence with Shift while the mouse streams at ~1000 Hz: the Mac must get
    exactly the same key sequence, nothing reordered, dropped or merged"""
    r = Rig()
    try:
        r.connected()
        r.cross()
        text = "The Quick Brown Fox, 123!"
        shifted = {"!": "1", ",": None}
        exp = []
        rnd = random.Random(3)
        def vk_for(ch):
            if ch.isalpha():
                return 0x41 + ord(ch.lower()) - 97, ch.isupper()
            if ch.isdigit():
                return 0x30 + int(ch), False
            return {" ": (0x20, False), ",": (0xBC, False), "!": (0x31, True)}[ch]
        for ch in text:
            vk, sh = vk_for(ch)
            for _ in range(rnd.randint(0, 6)):
                r.win.hw_move(rnd.choice([-2, -1, 1, 2]), rnd.choice([-1, 0, 1]))
            if sh:
                r.win.hw_key(0xA0, True)
            r.win.hw_key(vk, True)
            for _ in range(rnd.randint(0, 4)):
                r.win.hw_move(1, 0)
            r.win.hw_key(vk, False)
            if sh:
                r.win.hw_key(0xA0, False)
            name = K.win_key_name(vk, 0)
            code = K.MAC_KVK[name]
            if sh:
                exp += [(0x38, True, 0x20000), (code, True, 0x20000), (code, False, 0x20000),
                        (0x38, False, 0)]
            else:
                exp += [(code, True, 0), (code, False, 0)]
        wait(lambda: len(r.mac.of("key")) >= len(exp), msg="all keys")
        r.settle()
        got = [(e[1], e[2], e[3]) for e in r.mac.of("key")]
        assert got == exp, "\n got %s\n exp %s" % (got, exp)
        assert r.ccore.seq_gaps == 0
    finally:
        r.close()


@test
def late_hook_is_detected_and_reported():
    logs = []
    win = FakeWin()
    core = K.ServerCore(win, "right", send=lambda o: None, log=logs.append)
    clock = {"now": 10000}
    kp = K.make_key_proc(core, lambda n, w, l: 0, now_ms=lambda: clock["now"])
    mp = K.make_mouse_proc(core, lambda n, w, l: 0, now_ms=lambda: clock["now"])
    def key(t):
        st = K.KBDLLHOOKSTRUCT(0x41, 0, 0, t, 0)
        kp(0, 0x100, ctypes.addressof(st))
    key(9990)  # 10 ms: fine
    assert core.late_hooks == 0
    key(9500)  # 500 ms late
    key(9400)  # 600 ms late (rate-limited: no second warning line)
    assert core.late_hooks == 2 and core.worst_late_ms == 600
    assert sum("ran 500 ms late" in l for l in logs) == 1 and len(logs) == 1, logs
    ms = K.MSLLHOOKSTRUCT(1, 1, 0, 0, 9000, 0)
    mp(0, 0x200, ctypes.addressof(ms))
    assert core.late_hooks == 3
    clock["now"] = 5  # tick counter wrapped around (49.7 days): must not count as late
    key(0xFFFFFFF0)
    assert core.late_hooks == 3


@test
def key_trace_lines_on_both_ends():
    r = Rig()
    try:
        r.connected()
        r.cross()
        r.score.trace_keys = True
        r.ccore.trace_keys = True
        r.win.hw_key(0xA2, True)   # ctrl
        r.win.tap(0x43)            # c
        r.win.hw_key(0xA2, False)
        r.settle()
        srv = [l for l in r.logs if str(l).startswith("key #") and "vk" in str(l) and "mac keycode" not in str(l)]
        cli = [l for l in r.logs if "mac keycode" in str(l)]
        assert len(srv) == 4 and len(cli) == 4, (srv, cli)
        assert "ctrl(as meta) down -> mac keycode 0x37" in cli[0], cli[0]
        assert "c down -> mac keycode 0x08 flags 0x100000" in cli[1] and "held: meta" in cli[1], cli[1]
        assert "key #1 ctrl down" in srv[0] and "vk 0xa2" in srv[0], srv[0]
    finally:
        r.close()


@test
def typing_uses_physical_keys_even_when_windows_reports_odd_vk_codes():
    """seen on a real PC: Windows handed the hook random virtual-key codes (numpad *, digits)
    for letters; the scan code still names the physical key, so that must win"""
    r = Rig()
    try:
        r.connected()
        r.cross()
        rnd = random.Random(7)
        junk = [0x6A, 0x6B, 0x6D, 0x31, 0x35, 0xBC, 0xBF, 0x45, 0x4B]
        text = "the quick brown fox 123"
        exp = []
        for ch in text:
            vk = 0x20 if ch == " " else ord(ch.upper())
            sc = US_VK_SCAN[vk]
            # down and up may even get different bogus VKs
            r.win.hw_key(rnd.choice(junk), True, scan=sc)
            r.win.hw_key(rnd.choice(junk), False, scan=sc)
            code = K.MAC_KVK["space" if ch == " " else ch]
            exp += [(code, True, 0), (code, False, 0)]
        wait(lambda: len(r.mac.of("key")) >= len(exp), msg="all keys")
        r.settle()
        got = [(e[1], e[2], e[3]) for e in r.mac.of("key")]
        assert got == exp, "\n got %s\n exp %s" % (got, exp)
        assert not r.ccore.keys and not r.score.remote_keys, "nothing may stay held"
        # keys outside the typing block still come from the VK (numpad, arrows, F-keys)
        r.win.tap(0x6A)   # numpad * (scan 0x37)
        r.win.hw_key(0x25, True, flags=1, scan=0x4B)   # left arrow (extended)
        r.win.hw_key(0x25, False, flags=1, scan=0x4B)
        r.win.hw_key(0x67, True, scan=0x47)  # numpad 7 (same scan as Home, not extended)
        r.win.hw_key(0x67, False, scan=0x47)
        r.win.hw_key(0x0D, True, flags=1, scan=0x1C)  # numpad Enter shares Enter's scan code
        r.win.hw_key(0x0D, False, flags=1, scan=0x1C)
        n = len(exp)
        wait(lambda: len(r.mac.of("key")) >= n + 8, msg="extra keys")
        got = [e[1] for e in r.mac.of("key")[n::2]]
        assert got == [K.MAC_KVK[x] for x in ("kp_multiply", "left", "kp_7", "kp_enter")], got
    finally:
        r.close()


@test
def key_sequence_gap_is_reported():
    mac = FakeMac()
    logs = []
    c = K.ClientCore(mac, log=logs.append)
    c.active, c.peer_os = True, "Windows"
    c.handle({"t": "k", "n": "a", "p": True, "q": 1})
    c.handle({"t": "k", "n": "a", "p": False, "q": 2})
    c.handle({"t": "k", "n": "b", "p": True, "q": 4})
    assert c.seq_gaps == 1 and any("#4 arrived after #2" in l for l in logs), logs


if __name__ == "__main__":
    only = sys.argv[1:]
    failed = 0
    for t in TESTS:
        if only and t.__name__ not in only:
            continue
        t0 = time.time()
        try:
            t()
            print("PASS  %-50s %.2fs" % (t.__name__, time.time() - t0))
        except Exception:
            failed += 1
            print("FAIL  %s" % t.__name__)
            traceback.print_exc()
    print("\n%d failed" % failed if failed else "\nall passed")
    sys.exit(1 if failed else 0)
