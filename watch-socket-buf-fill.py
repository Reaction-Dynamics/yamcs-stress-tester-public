#!/usr/bin/env python3
"""
sockbuf_mon.py - live terminal view of Linux socket receive-buffer fill levels.

Reads each socket's memory info (the same data as `ss -m` skmem):
    r   rmem_alloc  bytes currently charged to the receive buffer (incl. skb overhead)
    rb  rcvbuf      receive buffer limit
    d   drops       packets dropped by this socket (mostly meaningful for UDP)

By default the data comes straight from the kernel over a NETLINK_SOCK_DIAG
socket, with a port filter that runs in the kernel, so each sample costs one
small syscall round trip instead of spawning `ss` and parsing every socket on
the machine. If netlink isn't usable, it falls back to `ss` (also port-filtered).

Usage examples:
    sockbuf_mon.py udp:9900 udp:9901
    sockbuf_mon.py 53 tcp:443 -i 0.25 --mode sum

A target can be PORT (TCP and UDP) or tcp:PORT / udp:PORT.
Press 'q' or Ctrl-C to quit.
"""

import argparse
import errno
import os
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

try:
    import termios
except ImportError:
    termios = None

CSI = "\x1b["
RESET, BOLD, DIM = CSI + "0m", CSI + "1m", CSI + "2m"
GREEN, YELLOW, RED = CSI + "32m", CSI + "33m", CSI + "31m"
ALT_ON, ALT_OFF = CSI + "?1049h", CSI + "?1049l"   # alternate screen buffer
HIDE_CUR, SHOW_CUR = CSI + "?25l", CSI + "?25h"
WRAP_OFF, WRAP_ON = CSI + "?7l", CSI + "?7h"       # no auto-wrap => no scrolling
CLEAR = CSI + "H" + CSI + "2J"

PARTIALS = " ▏▎▍▌▋▊▉"
WARN_ZONE, CRIT_ZONE = 60.0, 85.0
PROTO_NUM = {"tcp": socket.IPPROTO_TCP, "udp": socket.IPPROTO_UDP}


# ------------------------------------------------------------ netlink sock_diag

NETLINK_SOCK_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
NLMSG_ERROR, NLMSG_DONE = 2, 3
NLM_F_REQUEST, NLM_F_DUMP = 0x1, 0x300
INET_DIAG_REQ_BYTECODE = 1
INET_DIAG_SKMEMINFO = 7
INET_DIAG_BC_JMP = 1
INET_DIAG_BC_S_EQ = 11
SK_RMEM_ALLOC, SK_RCVBUF, SK_DROPS = 0, 1, 8
DIAG_MSG_LEN = 72          # sizeof(struct inet_diag_msg)


def build_port_bytecode(ports):
    """Kernel-side filter: accept a socket if its local port is any of `ports`.

    Layout per port:  S_EQ port (8 bytes) + JMP-to-accept (4 bytes)
    followed by one final JMP-to-reject. The kernel's validator walks the
    "yes" chain, so every op is reachable that way and all jumps land on ops.
    """
    ports = sorted(ports)
    total = 12 * len(ports) + 4
    bc = b""
    for i, port in enumerate(ports):
        jmp_remaining = total - (12 * i + 8)
        # struct inet_diag_bc_op { u8 code; u8 yes; u16 no; }; operand op holds port in .no
        bc += struct.pack("=BBH", INET_DIAG_BC_S_EQ, 8, 12)   # match -> JMP, miss -> next
        bc += struct.pack("=BBH", 0, 0, port)
        bc += struct.pack("=BBH", INET_DIAG_BC_JMP, 4, jmp_remaining)  # -> end = accept
    bc += struct.pack("=BBH", INET_DIAG_BC_JMP, 4, 8)          # -> past end = reject
    return bc


class SockDiag:
    """Queries socket memory info directly from the kernel."""

    def __init__(self, protos, ports):
        self.sock = socket.socket(socket.AF_NETLINK,
                                  socket.SOCK_RAW | socket.SOCK_CLOEXEC,
                                  NETLINK_SOCK_DIAG)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        self.protos = sorted(protos)
        bc = build_port_bytecode(ports)
        self.attr = struct.pack("=HH", 4 + len(bc), INET_DIAG_REQ_BYTECODE) + bc
        self.seq = 0
        self.families = [socket.AF_INET, socket.AF_INET6]
        self.name = "netlink"

    def _dump(self, family, proto_name, out):
        self.seq += 1
        req = struct.pack("=BBBBI", family, PROTO_NUM[proto_name],
                          1 << (INET_DIAG_SKMEMINFO - 1), 0, 0xFFFFFFFF) + bytes(48)
        payload = req + self.attr
        hdr = struct.pack("=IHHII", 16 + len(payload), SOCK_DIAG_BY_FAMILY,
                          NLM_F_REQUEST | NLM_F_DUMP, self.seq, 0)
        self.sock.send(hdr + payload)
        while True:
            data = self.sock.recv(1 << 16)
            off = 0
            while off + 16 <= len(data):
                ln, typ, _flags, seq, _pid = struct.unpack_from("=IHHII", data, off)
                if ln < 16:
                    return
                if typ == NLMSG_DONE:
                    return
                if typ == NLMSG_ERROR:
                    err = struct.unpack_from("=i", data, off + 16)[0]
                    if err:
                        raise OSError(-err, os.strerror(-err))
                    return
                if typ == SOCK_DIAG_BY_FAMILY and seq == self.seq:
                    self._parse(data, off + 16, off + ln, proto_name, out)
                off += (ln + 3) & ~3

    @staticmethod
    def _parse(data, start, end, proto_name, out):
        port = struct.unpack_from("!H", data, start + 4)[0]
        a = start + DIAG_MSG_LEN
        while a + 4 <= end:
            alen, atype = struct.unpack_from("=HH", data, a)
            if alen < 4:
                break
            if atype & 0x3FFF == INET_DIAG_SKMEMINFO:
                n = (alen - 4) // 4
                if n <= SK_RCVBUF:
                    return
                mem = struct.unpack_from(f"={n}I", data, a + 4)
                out.append({"proto": proto_name, "port": port,
                            "r": mem[SK_RMEM_ALLOC], "rb": mem[SK_RCVBUF],
                            "d": mem[SK_DROPS] if n > SK_DROPS else 0})
                return
            a += (alen + 3) & ~3

    def sample(self):
        out = []
        for proto in self.protos:
            for fam in list(self.families):
                try:
                    self._dump(fam, proto, out)
                except OSError as e:
                    # No IPv6 on this host: stop asking for it.
                    if fam == socket.AF_INET6 and e.errno in (
                            errno.EAFNOSUPPORT, errno.ENOENT, errno.EINVAL):
                        self.families.remove(fam)
                    else:
                        raise
        return out


# ------------------------------------------------------------------ ss fallback

SKMEM_RE = re.compile(r"skmem:\(([^)]*)\)")
SKMEM_FIELD_RE = re.compile(r"([a-z]+)(\d+)")
NETIDS = {"tcp", "udp", "raw", "sctp", "mptcp", "u_str", "u_dgr", "u_seq",
          "p_raw", "p_dgr", "nl", "tipc", "v_str", "v_dgr", "xdp"}


def parse_ss(text, default_proto="?"):
    records, cur = [], None
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            fields = line.split()
            if fields[0] in ("Netid", "State"):
                cur = None
                continue
            cur = [fields, None]
            records.append(cur)
        m = SKMEM_RE.search(line)
        if m and cur is not None:
            cur[1] = {k: int(v) for k, v in SKMEM_FIELD_RE.findall(m.group(1))}
    socks = []
    for fields, mem in records:
        if not mem or "rb" not in mem:
            continue
        if fields[0] in NETIDS:
            proto, idx = fields[0], 4
        else:
            proto, idx = default_proto, 3
        if len(fields) <= idx:
            continue
        port = fields[idx].rsplit(":", 1)[-1]
        if not port.isdigit():
            continue
        socks.append({"proto": proto, "port": int(port),
                      "r": mem.get("r", 0), "rb": mem["rb"], "d": mem.get("d", 0)})
    return socks


class SsSampler:
    """Fallback: run ss with a port filter so it only reports what we need."""

    def __init__(self, protos, ports):
        flags = ["-" + p[0] for p in sorted(protos)]          # -t / -u
        flt = ["("]
        for i, port in enumerate(sorted(ports)):
            flt += (["or"] if i else []) + ["sport", "=", f":{port}"]
        flt.append(")")
        self.cmd = ["ss", "-n", "-a", "-m"] + flags + flt
        self.default_proto = sorted(protos)[0] if len(protos) == 1 else "?"
        self.name = "ss"

    def sample(self):
        p = subprocess.run(self.cmd, capture_output=True, text=True, timeout=2)
        if p.returncode != 0:
            raise RuntimeError((p.stderr.strip().splitlines()
                                or [f"ss exited with {p.returncode}"])[0])
        return parse_ss(p.stdout, self.default_proto)


def make_sampler(protos, ports, backend):
    if backend in ("auto", "netlink"):
        try:
            s = SockDiag(protos, ports)
            s.sample()                        # verify it actually works here
            return s, None
        except Exception as e:
            if backend == "netlink":
                raise SystemExit(f"netlink sock_diag unavailable: {e}")
            note = f"netlink unavailable ({e}); using ss"
    else:
        note = None
    return SsSampler(protos, ports), note


# ------------------------------------------------------------------ aggregation

def parse_target(text):
    proto, sep, port = text.partition(":")
    if not sep:
        proto, port = None, text
    else:
        proto = proto.lower()
        if proto not in PROTO_NUM:
            raise argparse.ArgumentTypeError(f"bad protocol in '{text}' (use tcp: or udp:)")
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise argparse.ArgumentTypeError(f"bad port '{text}'")
    return proto, int(port)


def summarize(socks, target, mode):
    proto, port = target
    matched = [s for s in socks
               if s["port"] == port and (proto is None or s["proto"] in (proto, "?"))]
    if not matched:
        return None
    if mode == "sum":
        used = sum(s["r"] for s in matched)
        size = sum(s["rb"] for s in matched)
    else:
        worst = max(matched, key=lambda s: s["r"] / s["rb"] if s["rb"] else 0.0)
        used, size = worst["r"], worst["rb"]
    return {"used": used, "size": size,
            "pct": used * 100.0 / size if size else 0.0,
            "n": len(matched), "drops": sum(s["d"] for s in matched),
            "protos": sorted({s["proto"] for s in matched if s["proto"] != "?"})}


# ---------------------------------------------------------------------- display

def fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def paint(text, color, use_color):
    return f"{color}{text}{RESET}" if use_color else text


def zone_color(pct):
    return GREEN if pct < WARN_ZONE else YELLOW if pct < CRIT_ZONE else RED


def render_bar(pct, width, ascii_mode, use_color):
    fill = max(0.0, min(pct, 100.0)) / 100.0 * width
    full = int(fill)
    part = int((fill - full) * 8)
    out, cur = [], None
    for i in range(width):
        if i < full:
            ch, filled = ("#" if ascii_mode else "█"), True
        elif i == full and part and not ascii_mode:
            ch, filled = PARTIALS[part], True
        else:
            ch, filled = ("." if ascii_mode else "░"), False
        color = zone_color((i + 0.5) * 100.0 / width) if filled else DIM
        if use_color and color != cur:
            out.append(color)
            cur = color
        out.append(ch)
    if use_color:
        out.append(RESET)
    return "".join(out)


def target_label(target):
    proto, port = target
    return f"{port}/{proto or 'any'}"


def build_lines(targets, state, cols, rows, opts, err, source):
    use_color, ascii_mode = opts.color, opts.ascii
    title = (f"Socket receive buffer monitor  {time.strftime('%H:%M:%S')}  "
             f"interval {opts.interval}s  mode={opts.mode}  via {source}")
    lines = [paint(title[:cols], BOLD, use_color)]
    if err:
        lines.append(paint(f"error: {err}"[:cols], RED, use_color))
    else:
        lines.append(f"fill = r/rb (skmem)   zones: "
                     f"{paint('<60%', GREEN, use_color)} "
                     f"{paint('60-85%', YELLOW, use_color)} "
                     f"{paint('>85%', RED, use_color)}   'q' quits")
    lines.append("")

    lw = max(len(target_label(t)) for t in targets)
    stats = {}
    for t in targets:
        s = state[t]["summary"]
        if s is None:
            continue
        extra = f"  socks:{s['n']}  drops:{s['drops']}"
        if state[t]["drop_delta"] > 0:
            extra += f" (+{state[t]['drop_delta']})"
        if t[0] is None and s["protos"]:
            extra += "  " + ",".join(s["protos"])
        stats[t] = (f"{s['pct']:6.1f}%  {fmt_bytes(s['used']):>10} / "
                    f"{fmt_bytes(s['size']):<10}{extra}")
    sw = max((len(v) for v in stats.values()), default=0)
    fixed = 2 + lw + 2 + 2
    bar_w = max(10, cols - fixed - sw)
    stats_room = max(0, cols - fixed - bar_w)

    avail = max(1, rows - len(lines))
    shown = targets if len(targets) <= avail else targets[:avail - 1]
    for t in shown:
        label = "  " + target_label(t).ljust(lw)
        st = state[t]
        s = st["summary"]
        if s is None:
            if not st["sampled"]:
                msg = "-- waiting for first sample --"
            elif st["last_seen"] is None:
                msg = "-- not present --"
            else:
                msg = f"-- gone, last seen {int(time.time() - st['last_seen'])}s ago --"
            lines.append(label + " " + paint(msg[:max(0, cols - len(label) - 1)],
                                             YELLOW, use_color))
        else:
            bar = render_bar(s["pct"], bar_w, ascii_mode, use_color)
            stat_txt = stats[t].ljust(sw)[:stats_room]
            if use_color and s["pct"] >= CRIT_ZONE:
                stat_txt = paint(stat_txt, RED, True)
            lines.append(f"{label} [{bar}] {stat_txt}")
    if len(shown) < len(targets):
        lines.append(paint(f"  ... {len(targets) - len(shown)} more ports "
                           f"(enlarge terminal)"[:cols], DIM, use_color))
    return lines[:rows]


class Screen:
    """Writes only the lines that changed since the last frame."""

    def __init__(self, out):
        self.out = out
        self.prev = []

    def invalidate(self):
        self.prev = []
        self.out.write(CLEAR)

    def draw(self, lines):
        buf = []
        for i, line in enumerate(lines):
            if i >= len(self.prev) or self.prev[i] != line:
                buf.append(f"{CSI}{i + 1};1H{CSI}2K{line}")
        if len(lines) < len(self.prev):
            buf.append(f"{CSI}{len(lines) + 1};1H{CSI}J")
        self.prev = lines
        if buf:
            self.out.write("".join(buf))
            self.out.flush()


# ------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(
        description="Monitor Linux socket receive-buffer fill levels.")
    ap.add_argument("targets", nargs="+", type=parse_target, metavar="PORT",
                    help="port to watch: N, tcp:N or udp:N")
    ap.add_argument("-i", "--interval", type=float, default=1.0,
                    help="sample interval in seconds (default 1.0)")
    ap.add_argument("--mode", choices=("max", "sum"), default="max",
                    help="max: fullest socket on the port (default); "
                         "sum: total r / total rb over all sockets on the port")
    ap.add_argument("--backend", choices=("auto", "netlink", "ss"), default="auto",
                    help="data source (default: netlink, falling back to ss)")
    ap.add_argument("--nice", type=int, default=10,
                    help="lower this process's CPU priority by N (default 10, 0 = off)")
    ap.add_argument("--ascii", action="store_true", help="ASCII-only bars")
    ap.add_argument("--no-color", action="store_true", help="disable colors")
    ap.add_argument("--once", action="store_true",
                    help="print one plain snapshot and exit")
    opts = ap.parse_args()
    if opts.interval <= 0:
        ap.error("interval must be > 0")

    if opts.nice > 0:
        try:
            os.nice(opts.nice)
        except OSError:
            pass

    targets = list(dict.fromkeys(opts.targets))
    protos = set()
    for proto, _ in targets:
        protos |= {proto} if proto else {"tcp", "udp"}
    ports = {port for _, port in targets}
    sampler, note = make_sampler(protos, ports, opts.backend)

    out = sys.stdout
    opts.color = out.isatty() and not opts.no_color and not opts.once
    if (out.encoding or "").lower().replace("-", "") != "utf8":
        opts.ascii = True

    state = {t: {"summary": None, "last_seen": None, "sampled": False,
                 "prev_drops": None, "drop_delta": 0} for t in targets}

    def take_sample():
        try:
            socks, err = sampler.sample(), None
        except Exception as e:
            socks, err = [], f"{type(e).__name__}: {e}"
        for t in targets:
            st = state[t]
            s = summarize(socks, t, opts.mode)
            st["summary"], st["sampled"] = s, True
            if s is None:
                st["prev_drops"], st["drop_delta"] = None, 0
            else:
                st["last_seen"] = time.time()
                prev = st["prev_drops"]
                st["drop_delta"] = max(0, s["drops"] - prev) if prev is not None else 0
                st["prev_drops"] = s["drops"]
        return err or note

    if opts.once:
        err = take_sample()
        cols, _ = shutil.get_terminal_size((100, 24))
        print("\n".join(build_lines(targets, state, cols, 10_000, opts, err,
                                    sampler.name)))
        return

    # Signals wake the select() below through this pipe, so the loop sleeps
    # until something actually needs doing (sample due, key, resize, clock tick).
    wake_r, wake_w = os.pipe()
    os.set_blocking(wake_r, False)
    os.set_blocking(wake_w, False)
    signal.set_wakeup_fd(wake_w)
    resized = [True]
    signal.signal(signal.SIGWINCH, lambda *_: resized.__setitem__(0, True))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    fd, old_attr = None, None
    if termios and sys.stdin.isatty():
        fd = sys.stdin.fileno()
        old_attr = termios.tcgetattr(fd)
        new_attr = termios.tcgetattr(fd)
        new_attr[3] &= ~(termios.ECHO | termios.ICANON)
        termios.tcsetattr(fd, termios.TCSADRAIN, new_attr)
    watch = [wake_r] + ([fd] if fd is not None else [])

    screen = Screen(out)
    out.write(ALT_ON + HIDE_CUR + WRAP_OFF)
    err, next_sample = None, time.monotonic()
    try:
        while True:
            now = time.monotonic()
            if now >= next_sample:
                err = take_sample()
                next_sample += opts.interval
                if next_sample <= now:              # fell behind: don't burst
                    next_sample = now + opts.interval
            if resized[0]:
                resized[0] = False
                screen.invalidate()
            cols, rows = shutil.get_terminal_size((80, 24))
            screen.draw(build_lines(targets, state, cols, rows, opts, err,
                                    sampler.name))

            # Sleep until the next sample or the next wall-clock second
            # (for the header clock), whichever comes first.
            timeout = min(next_sample - time.monotonic(), 1.0 - time.time() % 1.0)
            ready, _, _ = select.select(watch, [], [], max(0.0, timeout))
            if wake_r in ready:
                try:
                    os.read(wake_r, 512)
                except BlockingIOError:
                    pass
            if fd is not None and fd in ready and b"q" in os.read(fd, 64).lower():
                break
    except KeyboardInterrupt:
        pass
    finally:
        out.write(RESET + WRAP_ON + SHOW_CUR + ALT_OFF)
        out.flush()
        if old_attr is not None:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_attr)


if __name__ == "__main__":
    main()