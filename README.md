# Wisp

One keyboard & mouse, drifting between your computers.

Wisp shares the keyboard and mouse of one computer with another over your local
network. It works between Windows and macOS in either direction, as well as Mac to
Mac and PC to PC. Move the pointer off a screen edge and it carries on onto the
other computer.

<img src="assets/wisp-1024.png" width="160" alt="Wisp icon">

## Features

- Either computer can share its keyboard and mouse, or receive them.
- Multi-monitor layouts on both sides, including stacked (vertical) arrangements.
  The pointer only crosses at screen edges that have no monitor beyond them.
- Ctrl and ⌘ are swapped between Mac and Windows, so ⌘C on a Mac keyboard does
  Ctrl+C on a PC (optional).
- Finds the other computer on the network automatically and pairs with a 6-digit code.
- Safety net for stuck keys, and a panic key that brings the input back:
  Ctrl+Alt+Shift+Esc on Windows, Ctrl+Option+Shift+Esc on a Mac.
- Optional "open at login".
- A single Python file. Windows needs nothing beyond Python; macOS needs PyObjC.

## Install

**Windows:** install Python 3, put `wisp.py` and `Wisp.pyw` in one folder, then
double-click `Wisp.pyw`.

**macOS:**

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
open Wisp.app
```

The Mac asks for **Accessibility** permission to receive input. To share its own
keyboard and mouse it also needs **Input Monitoring**. The window has an **Allow…**
button for each.

## Use

1. On the computer with the keyboard & mouse, choose *"This computer has the
   keyboard & mouse"*, pick which side the other computer is on, then press
   **Summon the wisp**.
2. On the other computer, choose *"Borrow another computer's keyboard & mouse"*,
   pick the first computer, enter its code, then press **Invite the wisp**.
3. Move the pointer off that edge of the screen.

Settings are kept in `~/.wisp.json`, and the activity log in `~/.wisp.log`.

## Good to know

- **Latency:** Wisp is only as good as the network link between the two computers.
  A wired connection is best. On Wi-Fi, big downloads can delay input because of
  bufferbloat in the router.
- **Security:** traffic is not encrypted yet, so use Wisp only on a network you trust.
- **Windows limits:** Windows blocks injected input into windows running as
  administrator, the UAC prompt and the lock screen.
- **Garbled keys from a PC:** anti-keylogging software scrambles what Wisp reads
  from the keyboard. One example is Citrix Workspace App Protection, which does this
  while its main connection window is open. Close that window while you use Wisp.

## Tests

```bash
.venv/bin/python tests/sim_test.py        # fake Windows hooks <-> real TCP <-> fake Mac
.venv/bin/python tests/pairs_test.py      # every OS pairing, both directions
.venv/bin/python tests/gui_test.py        # the window, driven against real services
.venv/bin/python tests/win_adapter_mock.py
```
