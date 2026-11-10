"""Exercise the Windows-only code paths (WinOS, win_run_hooks, win_set_dpi_aware,
server_main wiring) against a mocked user32/kernel32 so they run on any OS."""
import ctypes
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class Fn:
    def __init__(self, name, impl):
        self.name, self.impl, self.argtypes, self.restype = name, impl, None, None

    def __call__(self, *a):
        return self.impl(*a)


class FakeDLL:
    def __init__(self, impls):
        self._impls = impls
        self.calls = []

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name not in self._impls:
            raise AttributeError("unmocked API " + name)
        impl = self._impls[name]

        def rec(*a):
            self.calls.append((name, a))
            return impl(*a)
        f = Fn(name, rec)
        setattr(self, name, f)
        return f


state = {"cursor": (100, 100), "hooks": {}, "sys_cursors": 0, "restored": 0}


def GetCursorPos(pp):
    pp._obj.x, pp._obj.y = state["cursor"]
    return 1


def SetCursorPos(x, y):
    state["cursor"] = (x, y)
    return 1


def SetWindowsHookExW(idh, proc, hmod, tid):
    state["hooks"][idh] = proc
    return 1000 + idh


msgs = []


def GetMessageW(msg, h, a, b):
    while not msgs:
        time.sleep(0.01)
    return msgs.pop(0)


user32 = FakeDLL({
    "GetSystemMetrics": lambda i: {76: 0, 77: 0, 78: 1920, 79: 1080}[i],
    "GetCursorPos": GetCursorPos, "SetCursorPos": SetCursorPos,
    "CreateCursor": lambda *a: 55,
    "SetSystemCursor": lambda h, i: state.__setitem__("sys_cursors", state["sys_cursors"] + 1) or 1,
    "SystemParametersInfoW": lambda *a: state.__setitem__("restored", state["restored"] + 1) or 1,
    "SetWindowsHookExW": SetWindowsHookExW, "CallNextHookEx": lambda *a: 0,
    "GetMessageW": GetMessageW,
    "SetProcessDpiAwarenessContext": lambda c: 1,
    "EnumDisplayMonitors": lambda hdc, clip, cb, lp: enum_monitors(cb),
})


def enum_monitors(cb):
    from ctypes import wintypes as wt
    for m in MONITORS:
        rc = wt.RECT(*m)
        cb(None, None, ctypes.pointer(rc), 0)
    return 1


MONITORS = [(0, 0, 1920, 1080), (1920, -180, 4480, 1260)]
kernel32 = FakeDLL({"GetModuleHandleW": lambda n: 4242, "GetTickCount": lambda: 5})

ctypes.WinDLL = lambda name, use_last_error=False: {"user32": user32, "kernel32": kernel32}[name]
ctypes.windll = type("W", (), {"user32": user32, "shcore": FakeDLL({})})()
if not hasattr(ctypes, "WINFUNCTYPE"):
    ctypes.WINFUNCTYPE = ctypes.CFUNCTYPE
ctypes.get_last_error = lambda: 0

import wisp as K  # noqa: E402

# DPI
K.win_set_dpi_aware()
assert user32.calls[-1][0] == "SetProcessDpiAwarenessContext"

# WinOS
osi = K.WinOS()
assert osi.virtual_bounds() == (0, 0, 1920, 1080)
assert osi.monitors() == MONITORS, osi.monitors()
osi.set_cursor(10.7, 20.2)
assert osi.get_cursor() == (10, 20)
osi.hide_cursor()
time.sleep(0.1)
assert state["sys_cursors"] == len(K.WinOS.OCR_IDS), state
osi.show_cursor()
time.sleep(0.1)
assert state["restored"] == 1

# hooks
core = K.ServerCore(osi, "right", send=lambda o: sent.append(o), log=lambda *a: None)
sent = []
res = []
t = threading.Thread(target=K.win_run_hooks, args=(core, res.append), daemon=True)
t.start()
time.sleep(0.2)
assert res == [0], res
assert set(state["hooks"]) == {13, 14}
assert all(c[1][2] == 4242 for c in user32.calls if c[0] == "SetWindowsHookExW")

# call the real ctypes callbacks the way Windows would
core.connected = True
mproc, kproc = state["hooks"][14], state["hooks"][13]
state["cursor"] = (1918, 540)
s = K.MSLLHOOKSTRUCT(1919, 540, 0, 0, 0, 0)
assert mproc(0, 0x200, ctypes.addressof(s)) == 0  # laptop->monitor edge is not free: stays local
assert not core.remote
state["cursor"] = (4478, 540)
s = K.MSLLHOOKSTRUCT(4479, 540, 0, 0, 0, 0)
assert mproc(0, 0x200, ctypes.addressof(s)) == 1  # crossing swallowed
assert core.remote and sent[0]["t"] == "enter"
assert state["cursor"] == (3200, 540), state["cursor"]
s = K.MSLLHOOKSTRUCT(3205, 538, 0, 0, 0, 0)
assert mproc(0, 0x200, ctypes.addressof(s)) == 1
assert sent[-1] == {"t": "m", "dx": 5, "dy": -2}
s = K.MSLLHOOKSTRUCT(3200, 540, 0, 0, 0, 0)
assert mproc(0, 0x201, ctypes.addressof(s)) == 1  # click swallowed
assert sent[-1] == {"t": "b", "b": "left", "p": True}
k = K.KBDLLHOOKSTRUCT(0x41, 30, 0, 0, 0)
assert kproc(0, 0x100, ctypes.addressof(k)) == 1
assert sent[-1] == {"t": "k", "n": "a", "p": True, "q": 1, "d": "vk 0x41 scan 0x1e flags 0x0"}, sent[-1]
k = K.KBDLLHOOKSTRUCT(0x41, 30, 0x10, 0, 0)  # injected -> pass through
assert kproc(0, 0x100, ctypes.addressof(k)) == 0
assert kproc(1, 0x100, ctypes.addressof(k)) == 0  # nCode != HC_ACTION -> pass through
assert core.late_hooks == 0, "events stamped at the current tick must not count as late"
msgs.append(0)  # end message loop
t.join(1)
assert not t.is_alive()

# server_main wiring (network loop stubbed)
import types
K.sys = types.SimpleNamespace(platform="win32", stderr=sys.stderr, exit=sys.exit, setswitchinterval=sys.setswitchinterval)
called = {}
K.run_server_net = lambda core, port, token, bind, stats=False: called.update(port=port, token=token, bind=bind)
osi_restores = state["restored"]
threading.Thread(target=lambda: (time.sleep(0.3), msgs.append(0)), daemon=True).start()
K.main(["server", "--edge", "right", "--token", "abc"])
assert called == {"port": 24800, "token": "abc", "bind": "0.0.0.0"}, called
time.sleep(0.1)
assert state["restored"] >= osi_restores + 2  # restored at start and at exit
print("windows adapter mock: all passed")
