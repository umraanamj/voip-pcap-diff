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
import os
import shutil
import subprocess
import sys
from collections import Counter

# tshark prefs that matter for VoIP: treat unknown UDP as possible (S)RTP, since
# media often rides dynamic ports and encrypted media won't self-identify.
TS_OPTS = ["-o", "rtp.heuristic_rtp:TRUE", "-o", "rtcp.heuristic_rtcp:TRUE"]

LGOOD = "ON-PREM (audio WORKS)"
LBAD = "ZSCALER (NO audio)"

TSHARK = shutil.which("tshark")
CAPINFOS = shutil.which("capinfos")


# ---------------------------------------------------------------------------
# Output: tee everything to the report file as well as stdout
# ---------------------------------------------------------------------------
class Report:
    def __init__(self, path):
        self.fh = open(path, "w")

    def p(self, text=""):
        print(text)
        self.fh.write(text + "\n")

    def hr(self):
        self.p("-" * 72)

    def section(self, title):
        self.p("")
        self.p("#" * 72)
        self.p("## " + title)
        self.p("#" * 72)

    def sub(self, title):
        self.p("")
        self.hr()
        self.p(">> " + title)
        self.hr()

    def indent(self, text, n=3):
        pad = " " * n
        for line in text.rstrip("\n").split("\n"):
            self.p(pad + line)

    def none_or(self, text, n=3):
        """Print indented text, or '(none found)' when empty."""
        if text.strip():
            self.indent(text, n)
        else:
            self.p(" " * n + "(none found)")

    def close(self):
        self.fh.close()


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


def comparison(rpt, good, bad):
    rpt.section("SIDE-BY-SIDE COMPARISON & LIKELY CAUSE")
    fg, fb = facts(good), facts(bad)

    def show(lbl, d):
        rpt.p(f"  {lbl} :")
        for k in ("rtp_dirs", "media_dirs", "media_pkts", "reg200", "inv200"):
            rpt.p(f"        {k}={d[k]}")
        rpt.p(f"        sdp_addrs={','.join(d['sdp_addrs']) or 'none'}")

    show(LGOOD, fg)
    show(LBAD, fb)
    rpt.p("")
    rpt.hr()
    rpt.p("  HEURISTIC READING:")
    rpt.p(f"   - RTP flow directions (dissected):   good={fg['rtp_dirs']}   bad={fb['rtp_dirs']}")
    rpt.p(f"   - MEDIA on SDP ports (SRTP-aware):    "
          f"good: dirs={fg['media_dirs']} pkts={fg['media_pkts']}   "
          f"bad: dirs={fb['media_dirs']} pkts={fb['media_pkts']}")
    rpt.p("     ^ This is the decisive signal — it counts encrypted media the RTP dissector misses.")

    bmp, bmd, gmp = fb["media_pkts"], fb["media_dirs"], fg["media_pkts"]
    if bmp == 0:
        rpt.p("       => BAD: ZERO media packets on the negotiated audio ports. Audio is fully")
        rpt.p("          blocked outbound/inbound (Zscaler/firewall dropping UDP media). No audio.")
    elif bmd is not None and bmd < 2:
        rpt.p("       => BAD: media flows in only ONE direction on the audio ports => ONE-WAY AUDIO.")
        rpt.p("          The reverse path is dropped (return RTP to a non-routable/NAT'd address).")
    elif (isinstance(bmp, int) and isinstance(gmp, int)
          and bmp < gmp // 4 + 1):
        rpt.p("       => BAD: media packet count is a fraction of the working call => heavy media")
        rpt.p("          loss/clipping. Partial path; inspect the directional counts above.")

    rpt.p("")
    rpt.p("   - SDP-advertised media addresses:")
    rpt.p(f"       good: {','.join(fg['sdp_addrs']) or 'none'}")
    rpt.p(f"       bad : {','.join(fb['sdp_addrs']) or 'none'}")
    rpt.p("       => If BAD advertises a different/private/on-prem address than where packets can")
    rpt.p("          actually flow under Zscaler, the far end sends audio into a black hole.")
    rpt.p("")
    rpt.p("   Classic Zscaler + Avaya audio failure modes:")
    rpt.p("     1. Signaling (SIP/TLS or H.323/TCP) rides the tunnel fine -> registers.")
    rpt.p("     2. RTP audio is UDP -> blocked, dropped, or NAT-rewritten -> no/one-way audio.")
    rpt.p("     3. SDP c= line carries the client's *local* IP, unreachable from media gateway.")
    rpt.p("     4. Zscaler changes the apparent source IP, so RTP returns to the wrong address.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Diff two VoIP pcaps to diagnose 'registers but no audio'.")
    ap.add_argument("good", help="baseline capture where audio works (on-prem)")
    ap.add_argument("bad", help="problem capture with no audio (zscaler)")
    ap.add_argument("-o", "--output-dir", default="./avaya_pcap_report",
                    help="report output directory (default: ./avaya_pcap_report)")
    args = ap.parse_args()

    if not TSHARK:
        sys.exit("ERROR: tshark not found. Install with: brew install wireshark")
    for f in (args.good, args.bad):
        if not os.access(f, os.R_OK):
            sys.exit(f"ERROR: cannot read pcap: {f}")

    os.makedirs(args.output_dir, exist_ok=True)
    rpt = Report(os.path.join(args.output_dir, "report.txt"))

    rpt.p("Avaya one-X / VoIP pcap comparison")
    rpt.p(f"  GOOD (baseline, audio works): {args.good}")
    rpt.p(f"  BAD  (problem, no audio)    : {args.bad}")
    rpt.p(f"  Report: {os.path.join(args.output_dir, 'report.txt')}")
    rpt.p(f"  tshark: {run([TSHARK, '-v']).splitlines()[0] if run([TSHARK, '-v']) else '?'}")

    for f, label in ((args.good, LGOOD), (args.bad, LBAD)):
        rpt.section(f"CAPTURE: {label}")
        capture_summary(rpt, f, label)
        dns_analysis(rpt, f, label)
        sip_analysis(rpt, f, label)
        sdp_analysis(rpt, f, label)
        h323_analysis(rpt, f, label)
        rtp_analysis(rpt, f, label)
        media_udp_check(rpt, f, label)
        stun_check(rpt, f, label)
        icmp_check(rpt, f, label)
        transport_health(rpt, f, label)
        expert_info(rpt, f, label)

    comparison(rpt, args.good, args.bad)
    rpt.p("")
    rpt.p(f"Done. Full report saved to: {os.path.join(args.output_dir, 'report.txt')}")
    rpt.close()


if __name__ == "__main__":
    main()
