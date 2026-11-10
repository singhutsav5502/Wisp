"""App-window tests: a PC app and a Mac app in one process (hidden windows), using the
real services, real UDP discovery and real TCP, with the simulator's fake Windows/Mac."""
import os
import socket
import sys
import tempfile
import time
import traceback
import tkinter as tk

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import wisp as K  # noqa: E402
from sim_test import FakeWin, FakeMac  # noqa: E402

root = tk.Tk()
root.withdraw()


def pump(cond=None, timeout=4.0, msg="condition"):
    """run the Tk loop until cond() is true (or for ~2 refresh cycles when cond is None)"""
    end = time.time() + timeout
    settle = time.time() + 0.6
    while True:
        root.update()
        if cond is None:
            if time.time() >= settle:
                return
        elif cond():
            return
        if time.time() > end:
            raise AssertionError("timed out waiting for " + msg)
        time.sleep(0.01)


KEEP = []  # keep finished test windows alive: Tk objects must not be garbage-collected
# from worker threads (the real app has one window for its whole life)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Pair:
    def __init__(self, server_cfg=None, client_cfg=None, port=None):
        self.port = port or free_port()
        KEEP.append(self)
        self.dir = tempfile.mkdtemp()
        self.scfg, self.ccfg = os.path.join(self.dir, "s.json"), os.path.join(self.dir, "c.json")
        if server_cfg is not None:
            K.save_config(self.scfg, dict(server_cfg, port=self.port))
        else:
            K.save_config(self.scfg, {"port": self.port})
        K.save_config(self.ccfg, dict(client_cfg or {}, port=self.port))
        self.win, self.mac = FakeWin(), FakeMac()
        self.logs = []
        import queue as _q
        self.slogq, self.clogq = _q.Queue(), _q.Queue()  # like app_main: services log into the window
        self.ssvc = K.ServerService(make_os=lambda: self.win, install_hooks=self._hooks,
                                    log=lambda m: (self.logs.append(m), self.slogq.put(m)))
        self.csvc = K.ClientService(make_inj=lambda: self.mac,
                                    log=lambda m: (self.logs.append(m), self.clogq.put(m)))
        self.stop = tk.Toplevel(root)
        self.stop.withdraw()
        self.ctop = tk.Toplevel(root)
        self.ctop.withdraw()
        self.sapp = K.App(self.stop, "server", self.ssvc, cfg_path=self.scfg,
                          hostname="TEST-PC", ip="127.0.0.1", logq=self.slogq,
                          login_path=os.path.join(self.dir, "login_s"))
        self.ax = {"ok": False, "prompted": 0}
        self.capp = K.App(self.ctop, "client", self.csvc, cfg_path=self.ccfg,
                          discover_fn=lambda port: K.discover(port, timeout=0.6, extra=["127.0.0.1"]),
                          ax_check=lambda: self.ax["ok"], ax_prompt=self._prompt, logq=self.clogq,
                          login_path=os.path.join(self.dir, "Library", "LaunchAgents", "k.plist"))

    def _prompt(self):
        self.ax["prompted"] += 1

    def _hooks(self, core):
        self.win.attach(core)
        return None

    def sview(self):
        return self.sapp.view()

    def cview(self):
        return self.capp.view()

    def close(self):
        for a in (self.capp, self.sapp):
            try:
                a.close()
            except tk.TclError:
                pass


TESTS = []


def test(f):
    TESTS.append(f)
    return f


@test
def server_generates_and_keeps_code():
    p = Pair()
    try:
        code = K.clean_code(p.sapp.cfg["share_code"])
        assert len(code) == 6
        assert K.load_config(p.scfg)["share_code"] == code
        assert p.sapp.code_lbl.cget("text") == code[:3] + " " + code[3:]
        assert p.sview()[:2] == ("grey", "The wisp is asleep")
        assert p.sapp.main_btn.cget("text") == K.BTN_SERVER[0]
    finally:
        p.close()


@test
def full_flow_discover_pair_use_disconnect():
    p = Pair()
    try:
        code = p.sapp.cfg["share_code"]
        p.sapp.main_btn.invoke()  # Start sharing
        pump(lambda: p.ssvc.state() == "waiting", msg="server waiting")
        assert p.sview()[1].startswith("Waiting for the other computer")
        assert p.sapp.main_btn.cget("text") == K.BTN_SERVER[1]
        # mac: Find -> PC appears and is selected automatically
        p.capp.find_btn.invoke()
        pump(lambda: p.capp.found, timeout=5, msg="discovery")
        assert any(f["port"] == p.port for f in p.capp.found), p.capp.found
        assert "(" in p.capp.host.get(), p.capp.host.get()
        # wrong code first
        p.capp.code_var.set("000 000" if code != "000000" else "111 111")
        p.capp.main_btn.invoke()
        pump(lambda: p.csvc.state() == "error", msg="wrong code rejected")
        assert p.cview()[:2] == ("red", "Wrong secret code"), p.cview()
        assert p.ssvc.state() == "waiting"
        # right code, typed with a space like it is displayed
        p.capp.code_var.set(K.fmt_code(code))
        p.capp.main_btn.invoke()
        pump(lambda: p.csvc.state() == "connected", msg="client connected")
        pump(lambda: p.ssvc.state() == "connected", msg="server connected")
        assert p.cview()[1] == "Bound to %s" % socket.gethostname(), p.cview()
        assert p.capp.main_btn.cget("text") == K.BTN_CLIENT[1]
        assert p.ax["prompted"] == 1, "should ask for Accessibility when missing"
        pump(lambda: p.ssvc.rtt() is not None, timeout=3, msg="latency shown")
        assert "ms" in p.sview()[1] and p.sview()[1].startswith("Bound to %s" % socket.gethostname()), p.sview()
        pump(lambda: p.sapp.newcode_btn.instate(["disabled"]), msg="new-code locked while paired")
        # use the mac
        for _ in range(100):
            if p.ssvc.state() == "remote":
                break
            p.win.hw_move(40, 0)
        pump(lambda: p.csvc.state() == "remote", msg="client in use")
        assert p.sview()[1].startswith("The wisp is with %s" % socket.gethostname()) and p.sview()[0] == "blue"
        assert p.cview()[1].endswith("wisp is here") and p.cview()[0] == "blue"
        # live settings: speed and direction apply without reconnecting
        p.capp.speed.set(2.0)
        p.capp._changed(live_only=True)
        assert p.csvc.core.speed == 2.0
        start = p.mac.pos
        p.win.hw_move(10, 0)
        pump(lambda: p.mac.pos[0] == start[0] + 20, msg="speed applied")
        assert p.capp.speed_lbl.cget("text") == "2.0×"
        # go back to the PC
        for _ in range(100):
            if p.ssvc.state() != "remote":
                break
            p.win.hw_move(-40, 0)
            pump(lambda: True)
        pump(lambda: p.ssvc.state() == "connected" and p.csvc.state() == "connected",
             msg="back on PC")
        # disconnect from the mac -> pc waits again
        p.capp.main_btn.invoke()
        pump(lambda: p.ssvc.state() == "waiting", msg="server waiting after disconnect")
        assert p.cview()[:2] == ("grey", "The wisp is asleep")
        # stop sharing
        p.sapp.main_btn.invoke()
        pump(lambda: p.ssvc.state() == "stopped", msg="stopped")
        assert not p.win.hidden
    finally:
        p.close()


@test
def stop_sharing_while_mac_in_use_returns_control():
    p = Pair()
    try:
        p.sapp.start()
        pump(lambda: p.ssvc.state() == "waiting")
        p.capp.host.set("127.0.0.1")
        p.capp.code_var.set(p.sapp.cfg["share_code"])
        p.capp.start()
        pump(lambda: p.ssvc.state() == "connected")
        for _ in range(100):
            p.win.hw_move(40, 0)
        assert p.ssvc.state() == "remote" and p.win.hidden
        t = time.time()
        p.sapp.stop()
        assert time.time() - t < 2, "stop should be quick"
        assert p.ssvc.state() == "stopped" and not p.win.hidden and not p.ssvc.core.remote
        p.win.click()
        assert p.win.apps[-1][0] == "btn", "windows must get its input back"
        pump(lambda: p.csvc.state() == "connecting", msg="client notices and retries")
        # start again: the mac reconnects on its own
        p.sapp.start()
        pump(lambda: p.csvc.state() == "connected", timeout=6, msg="auto reconnect")
    finally:
        p.close()


@test
def client_validation_messages():
    p = Pair()
    try:
        p.capp.host.set("")
        p.capp.code_var.set("")
        p.capp.found = []
        p.capp.main_btn.invoke()
        pump()
        c, title, hint, _ = p.cview()
        assert c == "red" and "Pick the sharing computer" in hint, p.cview()
        assert not p.csvc.running()
        p.capp.host.set("10.0.0.5")
        p.capp.code_var.set("12")
        p.capp.main_btn.invoke()
        pump()
        assert "6-digit" in p.cview()[2]
        p.capp.port_var.set("99999")
        p.capp.code_var.set("123456")
        p.capp.main_btn.invoke()
        pump()
        assert "Port" in p.cview()[2]
    finally:
        p.close()


@test
def unreachable_pc_shows_retrying():
    p = Pair()
    try:
        p.capp.host.set("127.0.0.1")
        p.capp.code_var.set("123456")
        p.capp.main_btn.invoke()  # nothing is sharing on that port
        pump(lambda: p.csvc.core is not None and p.csvc.core.net_error, timeout=5, msg="net error")
        c, title, hint, btn = p.cview()
        assert c == "amber" and "Can't reach it" in hint and btn == K.BTN_CLIENT[1], p.cview()
        t = time.time()
        p.capp.main_btn.invoke()
        assert time.time() - t < 4.5
        assert p.cview()[1] == "The wisp is asleep"
    finally:
        p.close()


@test
def settings_persist_and_autostart():
    p = Pair(client_cfg={"direction": "top", "speed": 1.7, "swap": False, "invert": True,
                         "scroll": 5.0})
    try:
        p.sapp.dir.set("bottom")
        p.sapp._changed()
        p.sapp.autostart.set(True)
        p.sapp._changed()
        code = p.sapp.cfg["share_code"]
        assert p.capp.dir.get() == "top" and abs(p.capp.speed.get() - 1.7) < 1e-9
        assert p.capp.swap.get() is False and p.capp.invert.get() is True
        p.capp.host.set("127.0.0.1")
        p.capp.code_var.set(code)
        p.capp.autostart.set(True)
        p.capp._changed()
    finally:
        p.close()
    # reopen both: same code, settings, and both start on their own
    port = p.port
    q = Pair.__new__(Pair)
    KEEP.append(q)
    q.port, q.scfg, q.ccfg, q.dir = port, p.scfg, p.ccfg, p.dir
    q.win, q.mac, q.logs = FakeWin(), FakeMac(), []
    q.ssvc = K.ServerService(make_os=lambda: q.win, install_hooks=lambda c: q.win.attach(c),
                             log=q.logs.append)
    q.csvc = K.ClientService(make_inj=lambda: q.mac, log=q.logs.append)
    q.stop, q.ctop = tk.Toplevel(root), tk.Toplevel(root)
    q.stop.withdraw()
    q.ctop.withdraw()
    q.sapp = K.App(q.stop, "server", q.ssvc, cfg_path=q.scfg, login_path=q.dir + "/ls")
    q.capp = K.App(q.ctop, "client", q.csvc, cfg_path=q.ccfg,
                   discover_fn=lambda port: [], login_path=q.dir + "/lc")
    try:
        assert q.sapp.cfg["share_code"] == code and q.sapp.dir.get() == "bottom"
        assert q.capp.host.get() == "127.0.0.1" and K.clean_code(q.capp.code_var.get()) == code
        pump(lambda: q.ssvc.state() == "connected" and q.csvc.state() == "connected",
             timeout=8, msg="autostart both")
        assert q.ssvc.core.edge == "bottom" and q.csvc.core.side == "top"
        assert q.csvc.core.swap is False and q.csvc.core.invert_scroll is True
        assert q.csvc.core.scroll_lines == 5.0
    finally:
        Pair.close(q)


@test
def new_code_disconnects_old_pairing():
    p = Pair()
    try:
        old = p.sapp.cfg["share_code"]
        p.sapp.start()
        pump(lambda: p.ssvc.state() == "waiting")
        p.sapp.regen_code()
        assert p.sapp.cfg["share_code"] != old and not p.ssvc.running()
        assert K.load_config(p.scfg)["share_code"] == p.sapp.cfg["share_code"]
        p.sapp.start()
        p.capp.host.set("127.0.0.1")
        p.capp.code_var.set(old)
        p.capp.start()
        pump(lambda: p.csvc.state() == "error", msg="old code rejected")
    finally:
        p.close()


@test
def busy_port_is_explained():
    blocker = socket.socket()
    blocker.bind(("0.0.0.0", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    p = Pair(port=port)
    try:
        p.sapp.start()
        pump(lambda: p.ssvc.state() == "error", msg="error state")
        c, title, hint, _ = p.sview()
        assert c == "red" and "busy" in hint, p.sview()
    finally:
        p.close()
        blocker.close()


@test
def accessibility_row():
    p = Pair()
    try:
        pump()
        assert "needs Accessibility" in p.capp.ax_lbl.cget("text")
        p.capp.ax_btn.invoke()
        assert p.ax["prompted"] == 1
        p.ax["ok"] = True
        p.capp._ax_next = 0
        pump()
        assert "granted" in p.capp.ax_lbl.cget("text")
    finally:
        p.close()


@test
def options_and_log_toggle():
    p = Pair()
    try:
        assert not p.capp.opts.winfo_manager()
        p.capp.more_btn.invoke()
        pump()
        assert p.capp.opts.winfo_manager() == "grid"
        p.capp.showlog.set(True)
        p.capp._toggle_log()
        p.capp.logq.put("hello log")
        pump()
        assert "hello log" in p.capp.log_txt.get("1.0", "end")
        p.capp.more_btn.invoke()
        pump()
        assert not p.capp.opts.winfo_manager()
    finally:
        p.close()


@test
def no_thread_leak_on_failed_connects():
    import threading as th
    p = Pair()
    try:
        p.sapp.start()
        pump(lambda: p.ssvc.state() == "waiting")
        base = len(th.enumerate())
        for i in range(8):  # wrong code repeatedly
            p.capp.host.set("127.0.0.1")
            p.capp.code_var.set("999999" if p.sapp.cfg["share_code"] != "999999" else "888888")
            p.capp.start()
            pump(lambda: p.csvc.state() == "error", msg="rejected %d" % i)
        time.sleep(1.2)  # stoppers poll every 0.5s
        grown = len(th.enumerate()) - base
        assert grown <= 1, "threads leaked: %d" % grown
    finally:
        p.close()


@test
def login_item_toggle_both_platforms():
    import plistlib
    p = Pair()
    try:
        # mac window checkbox -> LaunchAgent plist that opens Wisp.app
        assert p.capp.login.get() is False
        p.capp.login.set(True)
        p.capp._login_changed()
        lp = p.capp.login_path
        with open(lp, "rb") as f:
            pl = plistlib.load(f)
        assert pl["Label"] == "local.wisp" and pl["RunAtLoad"] is True
        args = pl["ProgramArguments"]
        assert args[:2] == ["/usr/bin/open", "-a"] and args[2].endswith("Wisp.app"), args
        assert os.path.isdir(args[2]), "plist must point at the real app bundle"
        p.capp.login.set(False)
        p.capp._login_changed()
        assert not os.path.exists(lp)
        # windows flavour: a .pyw in the Startup folder that opens the app
        wp = os.path.join(p.dir, "Startup", "Wisp.pyw")
        assert K.set_login_item(True, path=wp, app_dir="C:\\Users\\me\\kmshare", platform_="win32") is None
        body = open(wp).read()
        compile(body, wp, "exec")
        ns = {}
        fake = type(sys)("wisp")
        calls = []
        fake.main = lambda argv: calls.append(argv)
        saved = sys.modules.get("wisp")
        sys.modules["wisp"] = fake
        try:
            exec(body, ns)
        finally:
            sys.modules["wisp"] = saved
            sys.path.remove("C:\\Users\\me\\kmshare")
        assert calls == [[]], calls
        assert K.set_login_item(False, path=wp) is None and not os.path.exists(wp)
        # unwritable location -> checkbox reverts, reason goes to the log
        p.capp.login_path = "/dev/null/nope/x.plist"
        p.capp.login.set(True)
        p.capp._login_changed()
        assert p.capp.login.get() is False
    finally:
        p.close()


@test
def discovery_dedupes_one_pc_on_two_addresses():
    import threading as th
    stop = th.Event()
    port = free_port()
    ok = []
    th.Thread(target=K.discovery_responder, args=(port, "ONE-PC", stop),
              kwargs=dict(ready=ok.append), daemon=True).start()
    pump(lambda: ok, msg="responder up")
    try:
        res = K.discover(port, timeout=0.6, extra=["127.0.0.1"])
        assert [r["name"] for r in res] == ["ONE-PC"], res
    finally:
        stop.set()


@test
def latency_label_formats():
    p = Pair()
    try:
        p.sapp.start()
        pump(lambda: p.ssvc.state() == "waiting")
        p.ssvc.core.connected = True
        p.ssvc.core.rtt_ms = 0.3
        assert p.sview()[1].endswith("<1 ms"), p.sview()
        p.ssvc.core.rtt_ms = 23.6
        assert p.sview()[1].endswith("24 ms"), p.sview()
        p.ssvc.core.connected = False
    finally:
        p.close()


@test
def keystroke_logging_toggle_and_late_hook_warning():
    p = Pair()
    try:
        p.sapp.start()
        pump(lambda: p.ssvc.state() == "waiting")
        p.capp.host.set("127.0.0.1")
        p.capp.code_var.set(p.sapp.cfg["share_code"])
        p.capp.start()
        pump(lambda: p.csvc.state() == "connected" and p.ssvc.state() == "connected")
        for app, svc in ((p.sapp, p.ssvc), (p.capp, p.csvc)):
            assert svc.core.trace_keys is False
            app.trace.set(True)
            app._trace_changed()
            assert svc.core.trace_keys is True and app.showlog.get() is True
        for _ in range(100):
            p.win.hw_move(40, 0)
        pump(lambda: p.csvc.state() == "remote")
        p.win.tap(0x41)
        pump(lambda: "mac keycode 0x00" in p.capp.log_txt.get("1.0", "end"), msg="client trace shown")
        pump(lambda: "vk 0x41" in p.sapp.log_txt.get("1.0", "end"), msg="server trace shown")
        # late hook -> amber status with an explanation on the PC
        p.ssvc.core.note_late_hook(450)
        c, title, hint, _ = p.sview()
        assert c == "amber" and "450 ms" in hint and "stayed on this computer" in hint, p.sview()
        assert K.load_config(p.sapp.cfg_path).get("trace") is True  # remembered
        p.capp.trace.set(False)
        p.capp._trace_changed()
        assert p.csvc.core.trace_keys is False
        assert K.load_config(p.capp.cfg_path).get("trace") is False
    finally:
        p.close()


@test
def switch_role_in_the_window():
    p = Pair()
    try:
        switched = []
        p.capp.on_switch = switched.append
        p.capp.host.set("127.0.0.1")
        p.capp.code_var.set("123456")
        p.capp.start()
        assert p.csvc.running()
        p.capp.role_var.set("server")
        p.capp._role_clicked()
        assert switched == ["server"] and not p.csvc.running() and p.capp.closed
        assert K.load_config(p.ccfg)["role"] == "server"
        # without a switch handler the choice snaps back
        p.sapp.role_var.set("client")
        p.sapp._role_clicked()
        assert p.sapp.role_var.get() == "server" and not p.sapp.closed
    finally:
        p.close()


@test
def old_server_config_keeps_its_code():
    d = tempfile.mkdtemp()
    cfg = os.path.join(d, "old.json")
    K.save_config(cfg, {"direction": "right", "code": "482913", "port": free_port()})
    top = tk.Toplevel(root)
    top.withdraw()
    win = FakeWin()
    svc = K.ServerService(make_os=lambda: win, install_hooks=lambda c: win.attach(c), log=lambda *a: None)
    app = K.App(top, "server", svc, cfg_path=cfg, login_path=d + "/l")
    KEEP.append(app)
    try:
        assert app.cfg["share_code"] == "482913", app.cfg
        assert app.code_lbl.cget("text") == "482 913"
    finally:
        app.close()
    # a mac client config's "code" is the *other* computer's code: never reused for sharing
    cfg2 = os.path.join(d, "client.json")
    K.save_config(cfg2, {"host": "192.168.1.50", "code": "246810"})
    top2 = tk.Toplevel(root)
    top2.withdraw()
    app2 = K.App(top2, "server", K.ServerService(make_os=lambda: FakeWin(),
                 install_hooks=lambda c: None, log=lambda *a: None), cfg_path=cfg2, login_path=d + "/l2")
    KEEP.append(app2)
    try:
        assert app2.cfg["share_code"] != "246810" and len(app2.cfg["share_code"]) == 6
    finally:
        app2.close()


@test
def several_permission_rows():
    d = tempfile.mkdtemp()
    top = tk.Toplevel(root)
    top.withdraw()
    state = {"ax": False, "im": False, "asked": []}
    perms = [{"name": "Accessibility", "check": lambda: state["ax"],
              "prompt": lambda: state["asked"].append("ax"), "why": "to control things"},
             {"name": "Input Monitoring", "check": lambda: state["im"],
              "prompt": lambda: state["asked"].append("im"), "why": "to read the keyboard"}]
    win = FakeWin()
    svc = K.ServerService(make_os=lambda: win, install_hooks=lambda c: win.attach(c), log=lambda *a: None)
    K.save_config(d + "/c.json", {"port": free_port()})
    app = K.App(top, "server", svc, cfg_path=d + "/c.json", login_path=d + "/l", perms=perms,
                os_name="Darwin")
    KEEP.append(app)
    try:
        pump()
        texts = [r[1].cget("text") for r in app.perm_rows]
        assert "needs Accessibility" in texts[0] and "needs Input Monitoring" in texts[1], texts
        app.start()
        assert state["asked"] == ["ax"], "asks for the first missing one, once"
        app.stop()
        app.start()
        assert state["asked"] == ["ax"]
        app.perm_rows[1][2].invoke()
        assert state["asked"] == ["ax", "im"]
        state["ax"] = state["im"] = True
        app._ax_next = 0
        pump()
        assert all("granted" in r[1].cget("text") for r in app.perm_rows)
        assert "Ctrl+Option+Shift+Esc" in K.panic_keys_text("Darwin")
        assert app.this_label == "This Mac"
    finally:
        app.close()


@test
def helpers():
    assert K.parse_host("DESKTOP-1 (192.168.1.50)") == "192.168.1.50"
    assert K.parse_host("  192.168.1.9 ") == "192.168.1.9"
    assert K.fmt_code("482913") == "482 913" and K.clean_code("482 913") == "482913"
    w = K.QueueWriter(__import__("queue").Queue())
    w.write("x\n")
    w.write("\n")
    assert w.q.get_nowait() == "x" and w.q.empty()


@test
def settings_and_login_item_move_over_from_kmshare():
    import plistlib
    d = tempfile.mkdtemp()
    old = K.legacy_paths(home=d, platform_="darwin")
    os.makedirs(os.path.dirname(old["login"]))
    with open(old["config"], "w") as f:
        f.write('{"role": "client", "host": "192.168.1.50", "code": "246810"}')
    with open(old["login"], "w") as f:
        f.write("<plist/>")
    cfg = os.path.join(d, ".wisp.json")
    newlogin = os.path.join(d, "Library", "LaunchAgents", "local.wisp.plist")
    notes = K.migrate_legacy(config_path=cfg, login_path=newlogin, legacy=old,
                             platform_="darwin")
    assert K.load_config(cfg)["host"] == "192.168.1.50", notes
    assert not os.path.exists(old["login"]) and os.path.exists(newlogin), notes
    with open(newlogin, "rb") as f:
        assert plistlib.load(f)["Label"] == "local.wisp"
    assert len(notes) == 2, notes
    # second run: nothing left to move, and Wisp's own settings are never overwritten
    with open(old["config"], "w") as f:
        f.write('{"host": "10.0.0.9"}')
    assert K.migrate_legacy(config_path=cfg, login_path=newlogin, legacy=old) == []
    assert K.load_config(cfg)["host"] == "192.168.1.50"
    win = K.legacy_paths(home=d, appdata="C:\\AppData", platform_="win32")
    assert win["login"].endswith("kmshare.pyw") and "Startup" in win["login"]


@test
def window_has_the_wisp_banner_and_icon():
    p = Pair()
    try:
        for app in (p.sapp, p.capp):
            assert app.banner.winfo_exists() and app.banner._img is not None
            texts = [app.banner.itemcget(i, "text") for i in app.banner.find_all()
                     if app.banner.type(i) == "text"]
            assert "Wisp" in texts, texts
        assert K.window_icon(root, 128).width() == 128 and K.window_icon(root, 32).width() == 32
        assert K.window_icon(root, 64).width() == 64
        assert p.sapp.main_btn.cget("text") == K.BTN_SERVER[0]
        assert p.capp.main_btn.cget("text") == K.BTN_CLIENT[0]
    finally:
        p.close()


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
    root.destroy()
    print("\n%d failed" % failed if failed else "\nall passed")
    sys.exit(1 if failed else 0)
