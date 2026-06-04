#!/usr/bin/env python3
"""
analyze_avaya_pcaps.py
----------------------
Compare two packet captures of a SIP/VoIP softphone session and pinpoint why one
works and the other doesn't -- built for the classic "registers fine but no audio"
problem (e.g. Avaya one-X with vs. without a Zscaler tunnel in the media path).

    GOOD (baseline) : on-prem, no tunnel   -> registers AND audio works
    BAD  (problem)  : through the tunnel   -> registers, but NO audio

Surfaces: DNS/FQDNs, SIP & H.323 signaling, SDP-negotiated media (IP/port/codec),
RTP/RTCP, SRTP-aware per-direction media counts on the negotiated ports, STUN/ICE,
ICMP errors, TCP/TLS health, and a side-by-side heuristic verdict.

Uses tshark (Wireshark CLI) as the dissection engine.
    Usage: ./analyze_avaya_pcaps.py <good.pcap> <bad.pcap> [-o output_dir]
    Install tshark: brew install wireshark   |   sudo apt install tshark
"""

import argparse
import html
import os
import shutil
import subprocess
import sys
import webbrowser
from collections import Counter

# tshark prefs that matter for VoIP: treat unknown UDP as possible (S)RTP, since
# media often rides dynamic ports and encrypted media won't self-identify.
TS_OPTS = ["-o", "rtp.heuristic_rtp:TRUE", "-o", "rtcp.heuristic_rtcp:TRUE"]

LGOOD = "ON-PREM (audio WORKS)"
LBAD = "ZSCALER (NO audio)"

def find_tool(name):
    """Locate a Wireshark CLI tool on PATH, or in the standard install dirs.
    Wireshark on Windows installs tshark.exe but does NOT add it to PATH."""
    p = shutil.which(name)
    if p:
        return p
    candidates = []
    if os.name == "nt":
        exe = name + ".exe"
        bases = {
            os.environ.get("ProgramFiles", r"C:\Program Files"),
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            os.environ.get("ProgramW6432", r"C:\Program Files"),
        }
        for b in bases:
            candidates.append(os.path.join(b, "Wireshark", exe))
    else:
        for b in ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/usr/sbin"):
            candidates.append(os.path.join(b, name))
        candidates.append(f"/Applications/Wireshark.app/Contents/MacOS/{name}")
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


TSHARK = find_tool("tshark")
CAPINFOS = find_tool("capinfos")


# ---------------------------------------------------------------------------
# Output: a Doc accumulates blocks so the same content can be rendered to both
# plain text (terminal + report.txt) and a per-pcap HTML page.
# ---------------------------------------------------------------------------
class Doc:
    """Collects ('section'|'sub'|'hr'|'line', text) blocks. The analysis
    functions call .sub()/.p()/.indent()/.none_or()/.hr()/.section() exactly as
    before; rendering to text or HTML happens afterwards."""

    def __init__(self, title=""):
        self.title = title
        self.blocks = []

    def section(self, title):
        self.blocks.append(("section", title))

    def sub(self, title):
        self.blocks.append(("sub", title))

    def hr(self):
        self.blocks.append(("hr", ""))

    def p(self, text=""):
        self.blocks.append(("line", text))

    def indent(self, text, n=3):
        pad = " " * n
        for line in text.rstrip("\n").split("\n"):
            self.p(pad + line)

    def none_or(self, text, n=3):
        if text.strip():
            self.indent(text, n)
        else:
            self.p(" " * n + "(none found)")


def render_text(doc):
    """Render a Doc to the same plain-text layout as before."""
    out = []
    for kind, val in doc.blocks:
        if kind == "section":
            out += ["", "#" * 72, "## " + val, "#" * 72]
        elif kind == "sub":
            out += ["", "-" * 72, ">> " + val, "-" * 72]
        elif kind == "hr":
            out.append("-" * 72)
        else:
            out.append(val)
    return "\n".join(out)


def _html_line(line):
    """Escape a content line and add light emphasis for headings/verdicts."""
    esc = html.escape(line)
    s = line.strip()
    if s.startswith(">>"):
        return f'<span class="hd">{esc}</span>'
    if "=>" in line:
        return f'<span class="verdict">{esc}</span>'
    return esc


def render_html(doc, nav_links, page_title, subtitle=""):
    """Render a Doc to a standalone HTML page (cards + <pre> bodies)."""
    cards = []          # list of (level, heading, [body lines])
    cur = None
    for kind, val in doc.blocks:
        if kind in ("section", "sub"):
            if cur:
                cards.append(cur)
            cur = (kind, val, [])
        elif kind == "hr":
            continue    # card borders already provide separation
        else:
            if cur is None:
                cur = ("intro", "", [])
            cur[2].append(val)
    if cur:
        cards.append(cur)

    body = []
    for level, heading, lines in cards:
        pre = "\n".join(_html_line(ln) for ln in lines).rstrip("\n")
        tag = "h1" if level == "section" else "h2"
        head_html = f"<{tag}>{html.escape(heading)}</{tag}>" if heading else ""
        body.append(f'<section class="card {level}">{head_html}<pre>{pre}</pre></section>')

    nav_items = []
    for name, href, here in nav_links:
        cls = ' class="here"' if here else ""
        nav_items.append(f'<a href="{href}"{cls}>{html.escape(name)}</a>')
    nav = " · ".join(nav_items)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(page_title)}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin:0; background:#0f1115; color:#cdd3de;
         font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
  header {{ position:sticky; top:0; background:#161a22; border-bottom:1px solid #2a3140;
           padding:12px 20px; }}
  header h1 {{ margin:0 0 2px; font-size:16px; color:#e6ebf3; }}
  header .sub {{ color:#8b94a7; font-size:12px; }}
  nav {{ margin-top:8px; }}
  nav a {{ color:#7aa2f7; text-decoration:none; margin-right:4px; }}
  nav a.here {{ color:#e6ebf3; font-weight:700; text-decoration:underline; }}
  main {{ padding:16px 20px 60px; max-width:1100px; }}
  .card {{ background:#141821; border:1px solid #232a36; border-radius:8px;
          margin:14px 0; overflow:hidden; }}
  .card.section {{ border-color:#3a4256; }}
  .card h1 {{ margin:0; padding:10px 14px; font-size:14px; background:#1d2330;
             color:#9ece6a; border-bottom:1px solid #232a36; }}
  .card h2 {{ margin:0; padding:9px 14px; font-size:13px; background:#191e29;
             color:#7dcfff; border-bottom:1px solid #232a36; }}
  pre {{ margin:0; padding:10px 14px; white-space:pre-wrap; word-break:break-word; }}
  .hd {{ color:#bb9af7; font-weight:700; }}
  .verdict {{ color:#f7768e; font-weight:700; }}
</style></head>
<body>
<header>
  <h1>{html.escape(page_title)}</h1>
  <div class="sub">{html.escape(subtitle)}</div>
  <nav>{nav}</nav>
</header>
<main>
{chr(10).join(body)}
</main>
</body></html>"""


# ---------------------------------------------------------------------------
# tshark helpers
# ---------------------------------------------------------------------------
def run(cmd):
    """Run a command, return stdout as text (stderr suppressed, never raises)."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        return res.stdout
    except Exception:
        return ""


def fields(pcap, display_filter, field_list, opts=None, sep="\t"):
    """tshark -T fields extraction. Returns raw stdout (rows separated by sep)."""
    cmd = [TSHARK] + (opts or []) + ["-r", pcap]
    if display_filter:
        cmd += ["-Y", display_filter]
    cmd += ["-T", "fields"]
    for f in field_list:
        cmd += ["-e", f]
    cmd += ["-E", "separator=" + sep]
    return run(cmd)


def rows(pcap, display_filter, field_list, opts=None):
    """Like fields() but split into a list of lists (tab-separated)."""
    out = fields(pcap, display_filter, field_list, opts=opts, sep="\t")
    return [line.split("\t") for line in out.splitlines() if line]


def tap(pcap, tap_name, opts=None):
    """Run a tshark -z statistics tap, return stdout."""
    return run([TSHARK] + (opts or []) + ["-r", pcap, "-q", "-z", tap_name])


def count(pcap, display_filter, opts=None):
    """Number of packets matching a display filter."""
    out = fields(pcap, display_filter, ["frame.number"], opts=opts)
    return sum(1 for line in out.splitlines() if line.strip())


def direction_counts(pcap, display_filter):
    """Count UDP packets per 'src:sport -> dst:dport' direction."""
    c = Counter()
    for r in rows(pcap, display_filter, ["ip.src", "udp.srcport", "ip.dst", "udp.dstport"]):
        if len(r) >= 4 and all(r[:4]):
            c[f"{r[0]}:{r[1]} -> {r[2]}:{r[3]}"] += 1
    return c


def sdp_audio_ports(pcap):
    """Distinct ports advertised on SDP audio m= lines."""
    out = fields(pcap, 'sdp.media contains "audio"', ["sdp.media.port"])
    ports = set()
    for line in out.split():
        if line.isdigit():
            ports.add(int(line))
    return sorted(ports)


def ports_filter(ports):
    return " || ".join(f"udp.port=={p}" for p in ports)


def uniq_tokens(pcap, display_filter, field):
    """Distinct whitespace-separated token values of a single field."""
    out = fields(pcap, display_filter, [field])
    toks = set()
    for line in out.split():
        if line:
            toks.add(line)
    return sorted(toks)


# ---------------------------------------------------------------------------
# 0. Capture summary
# ---------------------------------------------------------------------------
def capture_summary(rpt, f, label):
    rpt.sub(f"CAPTURE SUMMARY — {label}   [{f}]")
    if CAPINFOS:
        rpt.indent(run([CAPINFOS, "-c", "-d", "-u", "-a", "-e", "-S", "-y", f]))
    else:
        rpt.p("   (capinfos unavailable)")
        rpt.p(f"   packets: {count(f, None)}")
    rpt.p("")
    rpt.p("   Protocol hierarchy:")
    rpt.indent(tap(f, "io,phs"))
    rpt.p("")
    rpt.p("   Top IP conversations (by bytes):")
    rpt.indent("\n".join(tap(f, "conv,ip").splitlines()[:25]))


# ---------------------------------------------------------------------------
# 1. DNS / FQDNs
# ---------------------------------------------------------------------------
def dns_analysis(rpt, f, label):
    rpt.sub(f"DNS QUERIES & RESPONSES — {label}")
    rpt.p("   Queries  (time  client -> server  qname  type):")
    rpt.none_or(fields(f, "dns.flags.response==0",
                       ["frame.time_relative", "ip.src", "ip.dst", "dns.qry.name", "dns.qry.type"],
                       sep="  "))
    rpt.p("")
    rpt.p("   Responses (qname -> A / CNAME ; rcode):")
    rpt.none_or(fields(f, "dns.flags.response==1",
                       ["dns.qry.name", "dns.a", "dns.cname", "dns.flags.rcode", "dns.resp.ttl"],
                       sep="  "))
    rpt.p("")
    rpt.p("   DNS FAILURES (rcode != 0 = NXDOMAIN/SERVFAIL/etc):")
    rpt.none_or(fields(f, "dns.flags.response==1 && dns.flags.rcode!=0",
                       ["dns.qry.name", "dns.flags.rcode"], sep="  "))
    rpt.p("")
    rpt.p("   Unique FQDNs queried:")
    names = uniq_tokens(f, "dns.flags.response==0", "dns.qry.name")
    rpt.none_or("\n".join(names), n=5)


# ---------------------------------------------------------------------------
# 2. SIP signaling + registration
# ---------------------------------------------------------------------------
def sip_analysis(rpt, f, label):
    rpt.sub(f"SIP SIGNALING — {label}")
    if count(f, "sip") == 0:
        rpt.p("   (no SIP traffic — call may be H.323; see H.323 section)")
        return
    rpt.p("   SIP message statistics:")
    rpt.indent(tap(f, "sip,stat"))
    rpt.p("")
    rpt.p("   SIP message ladder (time  src->dst  method/status  CSeq  Call-ID):")
    rpt.none_or(fields(f, "sip",
                       ["frame.time_relative", "ip.src", "ip.dst", "sip.Method",
                        "sip.Status-Code", "sip.CSeq.method", "sip.Call-ID"], sep="  "))
    rpt.p("")
    rpt.p("   REGISTER transactions & results:")
    rpt.none_or(fields(f, 'sip.CSeq.method=="REGISTER"',
                       ["frame.time_relative", "ip.src", "ip.dst", "sip.Method",
                        "sip.Status-Code", "sip.to.user", "sip.Contact", "sip.Expires"], sep="  "))
    rpt.p("")
    rpt.p("   SIP FAILURE responses (4xx/5xx/6xx):")
    rpt.none_or(fields(f, "sip.Status-Code >= 400",
                       ["frame.time_relative", "ip.src", "ip.dst", "sip.Status-Code",
                        "sip.Status-Line", "sip.CSeq.method"], sep="  "))
    rpt.p("")
    rpt.p("   NAT view — Via (rport/received) & Contact (advertised reachability):")
    out = fields(f, 'sip.Method=="REGISTER" || sip.Method=="INVITE"',
                 ["sip.Method", "sip.Via", "sip.Contact"], sep=" | ")
    rpt.none_or("\n".join(out.splitlines()[:20]))


# ---------------------------------------------------------------------------
# 3. SDP — the negotiated media endpoints (crux of the audio path)
# ---------------------------------------------------------------------------
def sdp_analysis(rpt, f, label):
    rpt.sub(f"SDP MEDIA NEGOTIATION — {label}  (who told whom to send audio WHERE)")
    rpt.p("   Each SDP:  src -> dst :: method/status  c=ADDR  m=audio PORT  codecs  attrs")
    rpt.none_or(fields(f, "sdp",
                       ["frame.time_relative", "ip.src", "ip.dst", "sip.Method", "sip.Status-Code",
                        "sdp.connection_info.address", "sdp.media", "sdp.media.port",
                        "sdp.media.format", "sdp.media_attr.field", "sdp.media_attr.value"], sep="  "))
    rpt.p("")
    rpt.p("   >> KEY: the c= address is where the far end will SEND audio.")
    rpt.p("      If c= is a private/on-prem IP unreachable through Zscaler, audio dies here.")
    rpt.p("")
    rpt.p("   Distinct advertised media (connection) addresses:")
    rpt.none_or("\n".join(uniq_tokens(f, "sdp", "sdp.connection_info.address")), n=5)
    rpt.p("")
    rpt.p("   Distinct audio ports advertised:")
    rpt.none_or("\n".join(str(p) for p in sdp_audio_ports(f)), n=5)


# ---------------------------------------------------------------------------
# 4. RTP / RTCP — the actual audio
# ---------------------------------------------------------------------------
def rtp_analysis(rpt, f, label):
    rpt.sub(f"RTP / RTCP MEDIA FLOWS — {label}  (the actual audio)")
    rpt.p("   RTP stream summary (src:port -> dst:port  SSRC  payload  pkts  lost  jitter):")
    rpt.none_or(tap(f, "rtp,streams", opts=TS_OPTS))
    rpt.p("")
    rpt.p("   RTP packet counts per direction (count  src:port -> dst:port):")
    c = Counter()
    for r in rows(f, "rtp", ["ip.src", "udp.srcport", "ip.dst", "udp.dstport"], opts=TS_OPTS):
        if len(r) >= 4 and all(r[:4]):
            c[f"{r[0]}:{r[1]} -> {r[2]}:{r[3]}"] += 1
    if c:
        for k, n in c.most_common(20):
            rpt.p(f"   {n:>6}  {k}")
    else:
        rpt.p("   (no RTP dissected — encrypted SRTP or none; see MEDIA UDP section)")
    rpt.p("")
    rpt.p("   RTCP reports (loss / jitter):")
    rpt.none_or(fields(f, "rtcp",
                       ["frame.time_relative", "ip.src", "ip.dst", "rtcp.senderssrc",
                        "rtcp.sender.packetcount", "rtcp.ssrc.fraction", "rtcp.ssrc.cum_nr",
                        "rtcp.ssrc.jitter"], opts=TS_OPTS, sep="  "))
    rpt.p("")
    rpt.p("   Call lifecycle (INVITE -> 200 -> ACK -> BYE; brackets the audio window):")
    rpt.none_or(fields(f, 'sip.CSeq.method=="INVITE" || sip.CSeq.method=="BYE" || sip.Method=="ACK"',
                       ["frame.time_relative", "ip.src", "ip.dst", "sip.Method",
                        "sip.Status-Code", "sip.CSeq.method"], sep="  "))


# ---------------------------------------------------------------------------
# 4b. MEDIA UDP on the SDP-negotiated ports — catches SRTP / encrypted audio.
#     This is the decisive one-way test.
# ---------------------------------------------------------------------------
def media_udp_check(rpt, f, label):
    rpt.sub(f"MEDIA UDP on SDP-negotiated ports — {label}  (catches SRTP / encrypted audio)")
    ports = sdp_audio_ports(f)
    if not ports:
        rpt.p("   (no SDP audio ports advertised — falling back to all non-signaling UDP)")
        rpt.p("   Top UDP flows (excluding 53/123/137-138) by packet count:")
        c = direction_counts(f, "udp && !(udp.port==53 || udp.port==123 || udp.port==137 || udp.port==138)")
        for k, n in c.most_common(15):
            rpt.p(f"   {n:>6}  {k}")
        return
    rpt.p("   Advertised audio ports: " + " ".join(str(p) for p in ports))
    rpt.p("")
    rpt.p("   UDP packets on those ports, by direction (count  src:port -> dst:port):")
    c = direction_counts(f, ports_filter(ports))
    for k, n in c.most_common():
        rpt.p(f"   {n:>6}  {k}")
    rpt.p("")
    rpt.p("   >> READ THIS: each direction should carry hundreds/thousands of packets for a call.")
    rpt.p("      one direction populated, reverse ~0  => ONE-WAY AUDIO.")
    rpt.p("      both directions ~0                    => media never flowed (blocked by Zscaler/FW).")


# ---------------------------------------------------------------------------
# 4c. ICMP errors  4d. STUN/ICE
# ---------------------------------------------------------------------------
def icmp_check(rpt, f, label):
    if count(f, "icmp || icmpv6") == 0:
        return
    rpt.sub(f"ICMP ERRORS — {label}  (unreachable / admin-prohibited = active drop)")
    rpt.none_or(fields(f, "icmp.type==3 || icmp.type==11 || icmpv6.type==1 || icmpv6.type==3",
                       ["frame.time_relative", "ip.src", "ip.dst", "icmp.type", "icmp.code",
                        "icmpv6.type", "icmpv6.code"], sep="  "))
    rpt.p("   (icmp code: 3=port-unreachable, 13=communication-administratively-prohibited)")


def stun_check(rpt, f, label):
    if count(f, "stun") == 0:
        return
    rpt.sub(f"STUN / ICE media negotiation — {label}")
    rpt.p("   STUN messages (binding req/resp; MAPPED-ADDRESS = public candidate):")
    rpt.none_or(fields(f, "stun",
                       ["frame.time_relative", "ip.src", "ip.dst", "stun.type",
                        "stun.att.ipv4", "stun.att.port"], sep="  "))


# ---------------------------------------------------------------------------
# 5. H.323 (Avaya one-X often uses H.323 to Communication Manager)
# ---------------------------------------------------------------------------
def h323_analysis(rpt, f, label):
    if count(f, "h225 || h245 || q931 || ras") == 0:
        return
    rpt.sub(f"H.323 SIGNALING — {label}")
    rpt.p("   H.225/RAS (registration & call setup):")
    rpt.none_or("\n".join(fields(f, "h225 || ras",
                ["frame.time_relative", "ip.src", "ip.dst", "h225.RasMessage",
                 "h225.h323_message_body"], sep="  ").splitlines()[:40]))
    rpt.p("")
    rpt.p("   H.245 (media channel negotiation — open logical channels carry RTP addr/port):")
    rpt.none_or("\n".join(fields(f, "h245",
                ["frame.time_relative", "ip.src", "ip.dst",
                 "h245.MultimediaSystemControlMessage"], sep="  ").splitlines()[:30]))


# ---------------------------------------------------------------------------
# 6. TCP / TLS health & failures
# ---------------------------------------------------------------------------
def transport_health(rpt, f, label):
    rpt.sub(f"TCP / TLS HEALTH & FAILURES — {label}")
    rpt.p("   TCP SYNs sent without a SYN-ACK reply (blocked / unreachable):")
    c = Counter()
    for r in rows(f, "tcp.flags.syn==1 && tcp.flags.ack==0", ["ip.src", "ip.dst", "tcp.dstport"]):
        if len(r) >= 3 and all(r[:3]):
            c[f"{r[0]} -> {r[1]}:{r[2]}"] += 1
    if c:
        for k, n in c.most_common():
            rpt.p(f"   {n:>6}  {k}")
    else:
        rpt.p("   (none found)")
    rpt.p("")
    rpt.p("   TCP resets (RST):")
    rpt.none_or("\n".join(fields(f, "tcp.flags.reset==1",
                ["frame.time_relative", "ip.src", "ip.dst", "tcp.dstport"], sep="  ").splitlines()[:20]))
    rpt.p("")
    rpt.p("   TCP retransmissions / zero-window (count by stream):")
    c = Counter()
    for r in rows(f, "tcp.analysis.retransmission || tcp.analysis.zero_window",
                  ["ip.src", "ip.dst", "tcp.dstport"]):
        if len(r) >= 3 and all(r[:3]):
            c[f"{r[0]} -> {r[1]}:{r[2]}"] += 1
    if c:
        for k, n in c.most_common(15):
            rpt.p(f"   {n:>6}  {k}")
    else:
        rpt.p("   (none found)")
    rpt.p("")
    rpt.p("   TLS handshakes — ClientHello SNI (where TLS sessions are going):")
    snis = sorted(set(
        line for line in fields(f, "tls.handshake.type==1",
                                ["ip.dst", "tcp.dstport", "tls.handshake.extensions_server_name"],
                                sep="  ").splitlines() if line.strip()))
    rpt.none_or("\n".join(snis))
    rpt.p("")
    rpt.p("   TLS alerts / failures:")
    rpt.none_or(fields(f, "tls.alert_message",
                       ["frame.time_relative", "ip.src", "ip.dst",
                        "tls.alert_message.level", "tls.alert_message.desc"], sep="  "))


# ---------------------------------------------------------------------------
# 7. Expert info
# ---------------------------------------------------------------------------
def expert_info(rpt, f, label):
    rpt.sub(f"TSHARK EXPERT INFO (warnings/errors) — {label}")
    rpt.none_or("\n".join(tap(f, "expert,note", opts=TS_OPTS).splitlines()[:40]))


# ---------------------------------------------------------------------------
# 8. Heuristic comparison / likely-cause summary
# ---------------------------------------------------------------------------
def facts(f):
    """Machine-readable signals for the side-by-side diff."""
    rtp_dirs = len(set(
        tuple(r[:2]) for r in rows(f, "rtp", ["ip.src", "ip.dst"], opts=TS_OPTS)
        if len(r) >= 2 and all(r[:2])))
    sdp_addrs = uniq_tokens(f, "sdp", "sdp.connection_info.address")
    reg200 = count(f, 'sip.CSeq.method=="REGISTER" && sip.Status-Code==200')
    inv200 = count(f, 'sip.CSeq.method=="INVITE" && sip.Status-Code==200')
    ports = sdp_audio_ports(f)
    if ports:
        filt = ports_filter(ports)
        media_dirs = len(set(
            tuple(r[:2]) for r in rows(f, filt, ["ip.src", "ip.dst"])
            if len(r) >= 2 and all(r[:2])))
        media_pkts = count(f, filt)
    else:
        media_dirs = media_pkts = None
    return dict(rtp_dirs=rtp_dirs, media_dirs=media_dirs, media_pkts=media_pkts,
                sdp_addrs=sdp_addrs, reg200=reg200, inv200=inv200)


def heuristic_lines(fg, fb):
    """The cross-capture verdict, as a list of text lines. Used both in the
    comparison page and pinned at the top of each per-pcap page."""
    out = []
    out.append(f"   - RTP flow directions (dissected):   good={fg['rtp_dirs']}   bad={fb['rtp_dirs']}")
    out.append(f"   - MEDIA on SDP ports (SRTP-aware):    "
               f"good: dirs={fg['media_dirs']} pkts={fg['media_pkts']}   "
               f"bad: dirs={fb['media_dirs']} pkts={fb['media_pkts']}")
    out.append("     ^ Decisive signal — it counts encrypted media the RTP dissector misses.")
    bmp, bmd, gmp = fb["media_pkts"], fb["media_dirs"], fg["media_pkts"]
    if bmp == 0:
        out.append("       => BAD: ZERO media packets on the negotiated audio ports. Audio is fully")
        out.append("          blocked outbound/inbound (Zscaler/firewall dropping UDP media). No audio.")
    elif bmd is not None and bmd < 2:
        out.append("       => BAD: media flows in only ONE direction on the audio ports => ONE-WAY AUDIO.")
        out.append("          The reverse path is dropped (return RTP to a non-routable/NAT'd address).")
    elif isinstance(bmp, int) and isinstance(gmp, int) and bmp < gmp // 4 + 1:
        out.append("       => BAD: media packet count is a fraction of the working call => heavy media")
        out.append("          loss/clipping. Partial path; inspect the directional counts above.")
    out.append("")
    out.append("   - SDP-advertised media addresses:")
    out.append(f"       good: {','.join(fg['sdp_addrs']) or 'none'}")
    out.append(f"       bad : {','.join(fb['sdp_addrs']) or 'none'}")
    out.append("       => If BAD advertises a different/private/on-prem address than where packets can")
    out.append("          actually flow under Zscaler, the far end sends audio into a black hole.")
    return out


def verdict_box(doc, fg, fb):
    """Pin the cross-capture verdict at the top of a per-pcap page."""
    doc.section("VERDICT — cross-capture summary")
    for line in heuristic_lines(fg, fb):
        doc.p(line)


def comparison(doc, fg, fb):
    doc.section("SIDE-BY-SIDE COMPARISON & LIKELY CAUSE")

    def show(lbl, d):
        doc.p(f"  {lbl} :")
        for k in ("rtp_dirs", "media_dirs", "media_pkts", "reg200", "inv200"):
            doc.p(f"        {k}={d[k]}")
        doc.p(f"        sdp_addrs={','.join(d['sdp_addrs']) or 'none'}")

    show(LGOOD, fg)
    show(LBAD, fb)
    doc.p("")
    doc.hr()
    doc.p("  HEURISTIC READING:")
    for line in heuristic_lines(fg, fb):
        doc.p(line)
    doc.p("")
    doc.p("   Classic Zscaler + Avaya audio failure modes:")
    doc.p("     1. Signaling (SIP/TLS or H.323/TCP) rides the tunnel fine -> registers.")
    doc.p("     2. RTP audio is UDP -> blocked, dropped, or NAT-rewritten -> no/one-way audio.")
    doc.p("     3. SDP c= line carries the client's *local* IP, unreachable from media gateway.")
    doc.p("     4. Zscaler changes the apparent source IP, so RTP returns to the wrong address.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Pcap discovery — so the script can run with NO command-line arguments.
# ---------------------------------------------------------------------------
PCAP_EXTS = (".pcap", ".pcapng", ".cap")
GOOD_KW = ("onprem", "on-prem", "baseline", "good", "works", "working",
           "internal", "lan", "direct", "nozscaler", "no-zscaler")
BAD_KW = ("zscaler", "zia", "zpa", "tunnel", "bad", "broken", "noaudio",
          "no-audio", "problem", "fail")


def list_pcaps(d):
    try:
        names = os.listdir(d)
    except OSError:
        return []
    return sorted(os.path.join(d, n) for n in names
                  if n.lower().endswith(PCAP_EXTS))


def classify_pair(paths):
    """Given exactly two pcap paths, guess which is the working (good) vs the
    problem (bad) capture from the filenames. Returns (good, bad)."""
    a, b = paths
    an, bn = os.path.basename(a).lower(), os.path.basename(b).lower()
    a_bad = any(k in an for k in BAD_KW)
    b_bad = any(k in bn for k in BAD_KW)
    a_good = any(k in an for k in GOOD_KW)
    b_good = any(k in bn for k in GOOD_KW)
    if (b_bad or a_good) and not (a_bad or b_good):
        return a, b
    if (a_bad or b_good) and not (b_bad or a_good):
        return b, a
    return a, b  # can't tell — fall back to alphabetical, caller announces it


def pick_file(prompt):
    """Pop a native file-chooser dialog. tkinter works on Windows/macOS/Linux;
    fall back to AppleScript on macOS. Returns a path or None."""
    try:
        import tkinter
        from tkinter import filedialog
        root = tkinter.Tk()
        root.withdraw()
        path = filedialog.askopenfilename(
            title=prompt,
            filetypes=[("Captures", "*.pcap *.pcapng *.cap"), ("All files", "*.*")])
        root.destroy()
        if path:
            return path
    except Exception:
        pass
    if sys.platform == "darwin":
        safe = prompt.replace('"', "'")
        script = f'POSIX path of (choose file with prompt "{safe}")'
        r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
        return r.stdout.strip() or None
    return None


def resolve_pcaps(good_arg, bad_arg):
    """Figure out the two captures with no required CLI args:
       1. explicit args if both given
       2. exactly two pcaps in the current dir, else in ~/Downloads
       3. macOS file-picker dialogs as a last resort."""
    if good_arg and bad_arg:
        return good_arg, bad_arg
    if good_arg or bad_arg:
        sys.exit("ERROR: pass BOTH captures or NEITHER (auto-discovery needs both empty).")

    for d in (os.getcwd(), os.path.expanduser("~/Downloads")):
        found = list_pcaps(d)
        if len(found) == 2:
            good, bad = classify_pair(found)
            print(f"Auto-discovered 2 captures in {d}:")
            print(f"   working/baseline -> {os.path.basename(good)}")
            print(f"   problem/no-audio -> {os.path.basename(bad)}")
            print("   (override by passing them explicitly: <good> <bad>)\n")
            return good, bad
        if len(found) > 2:
            print(f"Found {len(found)} pcaps in {d}; pick the two to compare.")
            break

    print("Opening file pickers — choose the two captures...")
    good = pick_file("Select the WORKING capture (audio works / on-prem)")
    bad = pick_file("Select the BROKEN capture (no audio / zscaler)")
    if good and bad:
        return good, bad

    sys.exit("ERROR: no captures selected. Put two .pcap files in this folder or "
             "~/Downloads, or run: analyze_avaya_pcaps.py <good.pcap> <bad.pcap>")


def one_line_verdict(fg, fb):
    bmp, bmd, gmp = fb["media_pkts"], fb["media_dirs"], fg["media_pkts"]
    if bmp == 0:
        return "BAD capture: ZERO media on the negotiated ports => audio FULLY BLOCKED."
    if bmd is not None and bmd < 2:
        return "BAD capture: media flows one direction only => ONE-WAY AUDIO."
    if isinstance(bmp, int) and isinstance(gmp, int) and bmp < gmp // 4 + 1:
        return "BAD capture: media far below the working call => heavy loss/clipping."
    if bmp is None:
        return "No SDP audio ports seen — check signaling; see the report."
    return "Media present both ways on the ports — look deeper (codec/jitter/firewall)."


def build_capture_doc(f, label, fg, fb):
    """Run every per-capture section into a Doc, with the verdict pinned on top."""
    doc = Doc(label)
    verdict_box(doc, fg, fb)
    capture_summary(doc, f, label)
    dns_analysis(doc, f, label)
    sip_analysis(doc, f, label)
    sdp_analysis(doc, f, label)
    h323_analysis(doc, f, label)
    rtp_analysis(doc, f, label)
    media_udp_check(doc, f, label)
    stun_check(doc, f, label)
    icmp_check(doc, f, label)
    transport_health(doc, f, label)
    expert_info(doc, f, label)
    return doc


def main():
    ap = argparse.ArgumentParser(
        description="Diff two VoIP pcaps to diagnose 'registers but no audio'.")
    ap.add_argument("good", nargs="?", help="baseline capture where audio works "
                    "(optional; auto-discovered if omitted)")
    ap.add_argument("bad", nargs="?", help="problem capture with no audio "
                    "(optional; auto-discovered if omitted)")
    ap.add_argument("-o", "--output-dir", default="./avaya_pcap_report",
                    help="report output directory (default: ./avaya_pcap_report)")
    ap.add_argument("--no-browser", action="store_true",
                    help="don't open the HTML pages in a browser")
    args = ap.parse_args()

    if not TSHARK:
        if os.name == "nt":
            sys.exit(
                "ERROR: tshark not found.\n"
                "  Wireshark is installed but tshark.exe isn't on PATH. Either:\n"
                "   - reinstall Wireshark and tick 'Add Wireshark to the system PATH', or\n"
                "   - ensure it exists at C:\\Program Files\\Wireshark\\tshark.exe\n"
                "  (Get Wireshark: https://www.wireshark.org/download.html)")
        sys.exit("ERROR: tshark not found. Install with: brew install wireshark "
                 "(macOS) or: sudo apt install tshark (Linux)")

    good_pcap, bad_pcap = resolve_pcaps(args.good, args.bad)
    for f in (good_pcap, bad_pcap):
        if not os.access(f, os.R_OK):
            sys.exit(f"ERROR: cannot read pcap: {f}")

    os.makedirs(args.output_dir, exist_ok=True)
    txt_path = os.path.join(args.output_dir, "report.txt")

    # Compute cross-capture facts once, then build a Doc per capture + comparison.
    fg, fb = facts(good_pcap), facts(bad_pcap)
    good_doc = build_capture_doc(good_pcap, LGOOD, fg, fb)
    bad_doc = build_capture_doc(bad_pcap, LBAD, fg, fb)
    cmp_doc = Doc("COMPARISON & VERDICT")
    comparison(cmp_doc, fg, fb)

    # Per-pcap HTML pages (+ a comparison page), cross-linked via a nav bar.
    pages = [
        ("good.html", good_doc, LGOOD, args.good),
        ("bad.html", bad_doc, LBAD, args.bad),
        ("comparison.html", cmp_doc, "Comparison & Verdict", "both captures"),
    ]
    nav_meta = [("On-prem (works)", "good.html"),
                ("Zscaler (no audio)", "bad.html"),
                ("Comparison", "comparison.html")]
    for fname, doc, title, src in pages:
        nav = [(name, href, href == fname) for name, href in nav_meta]
        out = render_html(doc, nav, title, subtitle=f"source: {src}")
        with open(os.path.join(args.output_dir, fname), "w") as fh:
            fh.write(out)

    # Plain-text report (terminal + report.txt): both captures then comparison.
    header = (
        "Avaya one-X / VoIP pcap comparison\n"
        f"  GOOD (baseline, audio works): {good_pcap}\n"
        f"  BAD  (problem, no audio)    : {bad_pcap}\n"
        f"  Report dir: {args.output_dir}\n"
    )
    text = header + "\n".join(render_text(d) for d in (good_doc, bad_doc, cmp_doc))
    print(text)
    with open(txt_path, "w") as fh:
        fh.write(text + "\n")

    # Loud one-line verdict at the end of the terminal output.
    banner = one_line_verdict(fg, fb)
    print("\n" + "=" * 72)
    print("VERDICT: " + banner)
    print("=" * 72)

    abspaths = {fname: os.path.abspath(os.path.join(args.output_dir, fname))
                for fname, *_ in pages}
    print(f"\nReports written to: {os.path.abspath(args.output_dir)}/")
    print("  HTML: good.html, bad.html, comparison.html   Text: report.txt")

    # Open one browser window per pcap (the request). Comparison stays linked.
    if not args.no_browser:
        for fname in ("good.html", "bad.html"):
            webbrowser.open("file://" + abspaths[fname])


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass  # output was piped into a closing reader (e.g. `| head`)
