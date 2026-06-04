#!/usr/bin/env bash
#
# analyze_avaya_pcaps.sh
# ----------------------
# Compare two packet captures of Avaya one-X registration + call:
#   PCAP_GOOD : on-prem, NO Zscaler   -> call works, audio heard       (baseline)
#   PCAP_BAD  : with Zscaler presence -> registers OK, NO audio heard  (problem)
#
# Goal: surface everything relevant to "registers but no audio":
#   DNS / FQDNs, SIP & H.323 signaling, registration result,
#   SDP-negotiated media (IP / port / codec), actual RTP/RTCP flows,
#   one-way-audio detection, TCP/TLS health & failures, and a side-by-side diff.
#
# Usage:
#   ./analyze_avaya_pcaps.sh <good.pcap> <bad.pcap> [output_dir]
#
# Requires: tshark (Wireshark CLI). Install: brew install wireshark
#
set -uo pipefail

# ----------------------------------------------------------------------------
# Args & setup
# ----------------------------------------------------------------------------
GOOD="${1:-}"
BAD="${2:-}"
OUTDIR="${3:-./avaya_pcap_report}"

if [[ -z "$GOOD" || -z "$BAD" ]]; then
  echo "Usage: $0 <good_onprem.pcap> <bad_zscaler.pcap> [output_dir]" >&2
  echo "  good = on-prem capture where audio works (baseline)" >&2
  echo "  bad  = zscaler capture where there's no audio (problem)" >&2
  exit 1
fi

for f in "$GOOD" "$BAD"; do
  [[ -r "$f" ]] || { echo "ERROR: cannot read pcap: $f" >&2; exit 1; }
done

TSHARK="$(command -v tshark || true)"
if [[ -z "$TSHARK" ]]; then
  echo "ERROR: tshark not found. Install with: brew install wireshark" >&2
  exit 1
fi
CAPINFOS="$(command -v capinfos || true)"

mkdir -p "$OUTDIR"
REPORT="$OUTDIR/report.txt"

# tshark preferences that matter for VoIP:
#  - treat unknown UDP as possible RTP (media often on dynamic ports / SRTP)
#  - try to detect RTP even without preceding SDP
TS_OPTS=(-o rtp.heuristic_rtp:TRUE -o rtcp.heuristic_rtcp:TRUE)

# Labels
LGOOD="ON-PREM (audio WORKS)"
LBAD="ZSCALER (NO audio)"

# ----------------------------------------------------------------------------
# Output helpers (tee everything to the report file)
# ----------------------------------------------------------------------------
exec > >(tee "$REPORT") 2>&1

hr()      { printf '%s\n' "------------------------------------------------------------------------"; }
section() { echo; echo "########################################################################"; echo "## $*"; echo "########################################################################"; }
sub()     { echo; hr; echo ">> $*"; hr; }

# Run a tshark read-filter extraction; prints a "(none)" line if empty.
run_or_none() {
  local out
  out="$("$@" 2>/dev/null)"
  if [[ -z "${out// }" ]]; then echo "   (none found)"; else echo "$out"; fi
}

# ----------------------------------------------------------------------------
# 0. Capture summary
# ----------------------------------------------------------------------------
capture_summary() {
  local f="$1" label="$2"
  sub "CAPTURE SUMMARY — $label   [$f]"
  if [[ -n "$CAPINFOS" ]]; then
    "$CAPINFOS" -c -d -u -a -e -S -y "$f" 2>/dev/null | sed 's/^/   /'
  else
    echo "   (capinfos unavailable; basic counts:)"
    echo -n "   packets: "; "$TSHARK" -r "$f" -q -z io,stat,0 2>/dev/null | grep -Eo '[0-9]+ +\|' | tail -1
  fi
  echo
  echo "   Protocol hierarchy:"
  "$TSHARK" -r "$f" -q -z io,phs 2>/dev/null | sed 's/^/   /'
  echo
  echo "   Top IP conversations (by bytes):"
  "$TSHARK" -r "$f" -q -z conv,ip 2>/dev/null | sed 's/^/   /' | head -25
}

# ----------------------------------------------------------------------------
# 1. DNS / FQDNs
# ----------------------------------------------------------------------------
dns_analysis() {
  local f="$1" label="$2"
  sub "DNS QUERIES & RESPONSES — $label"
  echo "   Queries  (time  client -> server  qname  type):"
  run_or_none "$TSHARK" -r "$f" -Y "dns.flags.response==0" -T fields \
      -e frame.time_relative -e ip.src -e ip.dst -e dns.qry.name -e dns.qry.type \
      -E separator='  ' | sed 's/^/   /'
  echo
  echo "   Responses (qname -> A / CNAME ; rcode):"
  run_or_none "$TSHARK" -r "$f" -Y "dns.flags.response==1" -T fields \
      -e dns.qry.name -e dns.a -e dns.cname -e dns.flags.rcode -e dns.resp.ttl \
      -E separator='  ' | sed 's/^/   /'
  echo
  echo "   DNS FAILURES (rcode != 0  = NXDOMAIN/SERVFAIL/etc):"
  run_or_none "$TSHARK" -r "$f" -Y "dns.flags.response==1 && dns.flags.rcode!=0" -T fields \
      -e dns.qry.name -e dns.flags.rcode -E separator='  ' | sed 's/^/   /'
  echo
  echo "   Unique FQDNs queried:"
  "$TSHARK" -r "$f" -Y "dns.flags.response==0" -T fields -e dns.qry.name 2>/dev/null \
      | tr ' ' '\n' | sed '/^$/d' | sort -u | sed 's/^/     /' || echo "     (none)"
}

# ----------------------------------------------------------------------------
# 2. SIP signaling + registration
# ----------------------------------------------------------------------------
sip_analysis() {
  local f="$1" label="$2"
  sub "SIP SIGNALING — $label"
  local n
  n="$("$TSHARK" -r "$f" -Y sip -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$n" -eq 0 ]]; then echo "   (no SIP traffic — call may be H.323; see H.323 section)"; return; fi

  echo "   SIP message statistics:"
  "$TSHARK" -r "$f" -q -z sip,stat 2>/dev/null | sed 's/^/   /'
  echo
  echo "   SIP message ladder (time  src->dst  method/status  Call-ID short):"
  run_or_none "$TSHARK" -r "$f" -Y sip -T fields \
      -e frame.time_relative -e ip.src -e ip.dst \
      -e sip.Method -e sip.Status-Code -e sip.CSeq.method -e sip.Call-ID \
      -E separator='  ' | sed 's/^/   /'
  echo
  echo "   REGISTER transactions & results:"
  run_or_none "$TSHARK" -r "$f" -Y "sip.CSeq.method==\"REGISTER\"" -T fields \
      -e frame.time_relative -e ip.src -e ip.dst -e sip.Method -e sip.Status-Code \
      -e sip.to.user -e sip.Contact -e sip.Expires -E separator='  ' | sed 's/^/   /'
  echo
  echo "   SIP FAILURE responses (4xx/5xx/6xx):"
  run_or_none "$TSHARK" -r "$f" -Y "sip.Status-Code >= 400" -T fields \
      -e frame.time_relative -e ip.src -e ip.dst -e sip.Status-Code -e sip.Status-Line \
      -e sip.CSeq.method -E separator='  ' | sed 's/^/   /'
  echo
  echo "   NAT view — Via (rport/received) & Contact (advertised reachability):"
  run_or_none "$TSHARK" -r "$f" -Y "sip.Method==\"REGISTER\" || sip.Method==\"INVITE\"" -T fields \
      -e sip.Method -e sip.Via -e sip.Contact -E separator=' | ' | sed 's/^/   /' | head -20
}

# ----------------------------------------------------------------------------
# 3. SDP — the negotiated media endpoints (crux of audio path)
# ----------------------------------------------------------------------------
sdp_analysis() {
  local f="$1" label="$2"
  sub "SDP MEDIA NEGOTIATION — $label  (who told whom to send audio WHERE)"
  echo "   Each INVITE/200-OK SDP:  signaling_src -> signaling_dst :: media c=ADDR  m=audio PORT  codecs"
  run_or_none "$TSHARK" -r "$f" -Y "sdp" -T fields \
      -e frame.time_relative -e ip.src -e ip.dst \
      -e sip.Method -e sip.Status-Code \
      -e sdp.connection_info.address \
      -e sdp.media -e sdp.media.port -e sdp.media.format \
      -e sdp.media_attr.field -e sdp.media_attr.value \
      -E separator='  ' | sed 's/^/   /'
  echo
  echo "   >> KEY: the c= address is where the far end will SEND audio."
  echo "      If c= is a private/on-prem IP unreachable through Zscaler, audio dies here."
  echo
  echo "   Distinct advertised media (connection) addresses:"
  "$TSHARK" -r "$f" -Y "sdp" -T fields -e sdp.connection_info.address 2>/dev/null \
      | tr ' ' '\n' | sed '/^$/d' | sort -u | sed 's/^/     /' || echo "     (none)"
  echo
  echo "   Distinct audio ports advertised:"
  "$TSHARK" -r "$f" -Y "sdp.media contains \"audio\"" -T fields -e sdp.media.port 2>/dev/null \
      | tr ' ' '\n' | sed '/^$/d' | sort -un | sed 's/^/     /' || echo "     (none)"
}

# ----------------------------------------------------------------------------
# 4. RTP / RTCP — the actual audio. One-way detection lives here.
# ----------------------------------------------------------------------------
rtp_analysis() {
  local f="$1" label="$2"
  sub "RTP / RTCP MEDIA FLOWS — $label  (the actual audio)"
  echo "   RTP stream summary (src:port -> dst:port  SSRC  payload  packets  lost  jitter):"
  run_or_none "$TSHARK" "${TS_OPTS[@]}" -r "$f" -q -z rtp,streams | sed 's/^/   /'
  echo
  echo "   RTP packet counts per direction (ip.src udp.srcport -> ip.dst udp.dstport : count):"
  "$TSHARK" "${TS_OPTS[@]}" -r "$f" -Y rtp -T fields \
      -e ip.src -e udp.srcport -e ip.dst -e udp.dstport 2>/dev/null \
      | sort | uniq -c | sort -rn | sed 's/^/   /' | head -20
  echo "   (none above = NO RTP detected at all — total audio failure / SRTP not on known ports)"
  echo
  echo "   RTCP reports (sender/receiver, loss, jitter):"
  run_or_none "$TSHARK" "${TS_OPTS[@]}" -r "$f" -Y rtcp -T fields \
      -e frame.time_relative -e ip.src -e ip.dst \
      -e rtcp.senderssrc -e rtcp.sender.packetcount \
      -e rtcp.ssrc.fraction -e rtcp.ssrc.cum_nr -e rtcp.ssrc.jitter \
      -E separator='  ' | sed 's/^/   /' | head -20
  echo
  echo "   Call lifecycle (INVITE -> 200 -> ACK -> BYE; brackets the audio window):"
  run_or_none "$TSHARK" -r "$f" \
      -Y "sip.CSeq.method==\"INVITE\" || sip.CSeq.method==\"BYE\" || sip.Method==\"ACK\"" \
      -T fields -e frame.time_relative -e ip.src -e ip.dst \
      -e sip.Method -e sip.Status-Code -e sip.CSeq.method \
      -E separator='  ' | sed 's/^/   /'
}

# Helper: distinct audio ports advertised in SDP (used to scope media checks).
sdp_audio_ports() {
  "$TSHARK" -r "$1" -Y "sdp.media contains \"audio\"" -T fields -e sdp.media.port 2>/dev/null \
    | tr ' ' '\n' | sed '/^$/d' | sort -un
}

# Build a tshark "udp.port==a || udp.port==b" filter from a list of ports.
ports_to_filter() {
  local p filt=""
  for p in $1; do filt="${filt:+$filt || }udp.port==$p"; done
  echo "$filt"
}

# ----------------------------------------------------------------------------
# 4b. MEDIA UDP on the SDP-negotiated ports — catches SRTP / encrypted audio
#     that the RTP dissector won't classify. This is the real one-way test.
# ----------------------------------------------------------------------------
media_udp_check() {
  local f="$1" label="$2"
  sub "MEDIA UDP on SDP-negotiated ports — $label  (catches SRTP / encrypted audio)"
  local ports filt
  ports="$(sdp_audio_ports "$f")"
  if [[ -z "$ports" ]]; then
    echo "   (no SDP audio ports advertised — falling back to all non-signaling UDP)"
    echo "   Top UDP flows (excluding 53/123/137-138) by packet count:"
    "$TSHARK" -r "$f" -Y "udp && !(udp.port==53 || udp.port==123 || udp.port==137 || udp.port==138)" \
        -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport 2>/dev/null \
        | awk 'NF>=4{print $1":"$2" -> "$3":"$4}' | sort | uniq -c | sort -rn | sed 's/^/   /' | head -15
    return
  fi
  echo "   Advertised audio ports: $(echo $ports | tr '\n' ' ')"
  filt="$(ports_to_filter "$ports")"
  echo
  echo "   UDP packets on those ports, by direction (count  src:port -> dst:port):"
  "$TSHARK" -r "$f" -Y "$filt" -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport 2>/dev/null \
      | awk 'NF>=4{print $1":"$2" -> "$3":"$4}' | sort | uniq -c | sort -rn | sed 's/^/   /'
  echo
  echo "   >> READ THIS: each direction should carry hundreds/thousands of packets for a call."
  echo "      one direction populated, reverse ~0  => ONE-WAY AUDIO."
  echo "      both directions ~0                    => media never flowed (blocked by Zscaler/FW)."
}

# ----------------------------------------------------------------------------
# 4c. ICMP errors — port/host unreachable or admin-prohibited = something
#     (firewall / Zscaler) is actively dropping signaling or media.
# ----------------------------------------------------------------------------
icmp_check() {
  local f="$1" label="$2"
  local n
  n="$("$TSHARK" -r "$f" -Y "icmp || icmpv6" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')"
  [[ "$n" -eq 0 ]] && return
  sub "ICMP ERRORS — $label  (unreachable / admin-prohibited = active drop)"
  run_or_none "$TSHARK" -r "$f" -Y "icmp.type==3 || icmp.type==11 || icmpv6.type==1 || icmpv6.type==3" \
      -T fields -e frame.time_relative -e ip.src -e ip.dst -e icmp.type -e icmp.code \
      -e icmpv6.type -e icmpv6.code -E separator='  ' | sed 's/^/   /' | head -30
  echo "   (icmp code: 3=port-unreachable, 13=communication-administratively-prohibited)"
}

# ----------------------------------------------------------------------------
# 4d. STUN / ICE — media-path discovery. Zscaler can break STUN, leaving the
#     client with a media candidate the far end can't reach.
# ----------------------------------------------------------------------------
stun_check() {
  local f="$1" label="$2"
  local n
  n="$("$TSHARK" -r "$f" -Y stun -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')"
  [[ "$n" -eq 0 ]] && return
  sub "STUN / ICE media negotiation — $label"
  echo "   STUN messages (binding requests/responses; MAPPED-ADDRESS = public candidate):"
  run_or_none "$TSHARK" -r "$f" -Y stun -T fields \
      -e frame.time_relative -e ip.src -e ip.dst -e stun.type \
      -e stun.att.ipv4 -e stun.att.port -E separator='  ' | sed 's/^/   /' | head -30
}

# ----------------------------------------------------------------------------
# 5. H.323 (Avaya one-X often uses H.323 to Communication Manager)
# ----------------------------------------------------------------------------
h323_analysis() {
  local f="$1" label="$2"
  local n
  n="$("$TSHARK" -r "$f" -Y "h225 || h245 || q931 || ras" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')"
  [[ "$n" -eq 0 ]] && return
  sub "H.323 SIGNALING — $label"
  echo "   H.225/RAS (registration & call setup):"
  run_or_none "$TSHARK" -r "$f" -Y "h225 || ras" -T fields \
      -e frame.time_relative -e ip.src -e ip.dst -e h225.RasMessage -e h225.h323_message_body \
      -E separator='  ' | sed 's/^/   /' | head -40
  echo
  echo "   H.245 (media channel negotiation — open logical channels carry RTP addr/port):"
  run_or_none "$TSHARK" -r "$f" -Y "h245" -T fields \
      -e frame.time_relative -e ip.src -e ip.dst -e h245.MultimediaSystemControlMessage \
      -E separator='  ' | sed 's/^/   /' | head -30
}

# ----------------------------------------------------------------------------
# 6. TCP / TLS health & failures
# ----------------------------------------------------------------------------
transport_health() {
  local f="$1" label="$2"
  sub "TCP / TLS HEALTH & FAILURES — $label"
  echo "   TCP SYNs sent without a SYN-ACK reply (blocked / unreachable):"
  run_or_none "$TSHARK" -r "$f" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields \
      -e ip.src -e ip.dst -e tcp.dstport -E separator='  ' \
      | sort | uniq -c | sed 's/^/   /'
  echo
  echo "   TCP resets (RST):"
  run_or_none "$TSHARK" -r "$f" -Y "tcp.flags.reset==1" -T fields \
      -e frame.time_relative -e ip.src -e ip.dst -e tcp.dstport -E separator='  ' \
      | sed 's/^/   /' | head -20
  echo
  echo "   TCP retransmissions / zero-window (count by stream):"
  run_or_none "$TSHARK" -r "$f" -Y "tcp.analysis.retransmission || tcp.analysis.zero_window" -T fields \
      -e ip.src -e ip.dst -e tcp.dstport -E separator='  ' \
      | sort | uniq -c | sort -rn | sed 's/^/   /' | head -15
  echo
  echo "   TLS handshakes — ClientHello SNI (where TLS sessions are going):"
  run_or_none "$TSHARK" -r "$f" -Y "tls.handshake.type==1" -T fields \
      -e ip.dst -e tcp.dstport -e tls.handshake.extensions_server_name -E separator='  ' \
      | sort -u | sed 's/^/   /'
  echo
  echo "   TLS alerts / failures:"
  run_or_none "$TSHARK" -r "$f" -Y "tls.alert_message" -T fields \
      -e frame.time_relative -e ip.src -e ip.dst -e tls.alert_message.level -e tls.alert_message.desc \
      -E separator='  ' | sed 's/^/   /'
}

# ----------------------------------------------------------------------------
# 7. Expert info (warnings/errors tshark itself flags)
# ----------------------------------------------------------------------------
expert_info() {
  local f="$1" label="$2"
  sub "TSHARK EXPERT INFO (warnings/errors) — $label"
  run_or_none "$TSHARK" "${TS_OPTS[@]}" -r "$f" -q -z expert,note | sed 's/^/   /' | head -40
}

# ----------------------------------------------------------------------------
# 8. Heuristic comparison / likely-cause summary
# ----------------------------------------------------------------------------
# Pull a few machine-readable facts for the diff.
facts() {
  local f="$1"
  local rtp_dirs sdp_addrs reg_ok inv_ok ports filt media_dirs media_pkts
  rtp_dirs="$("$TSHARK" "${TS_OPTS[@]}" -r "$f" -Y rtp -T fields -e ip.src -e ip.dst 2>/dev/null | sort -u | wc -l | tr -d ' ')"
  sdp_addrs="$("$TSHARK" -r "$f" -Y sdp -T fields -e sdp.connection_info.address 2>/dev/null | tr ' ' '\n' | sed '/^$/d' | sort -u | paste -sd, -)"
  reg_ok="$("$TSHARK" -r "$f" -Y "sip.CSeq.method==\"REGISTER\" && sip.Status-Code==200" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')"
  inv_ok="$("$TSHARK" -r "$f" -Y "sip.CSeq.method==\"INVITE\" && sip.Status-Code==200" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')"
  # SRTP-aware media signal: directions & packet count on the SDP-negotiated audio ports.
  ports="$(sdp_audio_ports "$f")"
  if [[ -n "$ports" ]]; then
    filt="$(ports_to_filter "$ports")"
    media_dirs="$("$TSHARK" -r "$f" -Y "$filt" -T fields -e ip.src -e ip.dst 2>/dev/null | sort -u | wc -l | tr -d ' ')"
    media_pkts="$("$TSHARK" -r "$f" -Y "$filt" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')"
  else
    media_dirs="NA"; media_pkts="NA"
  fi
  echo "rtp_dirs=$rtp_dirs|media_dirs=$media_dirs|media_pkts=$media_pkts|sdp_addrs=$sdp_addrs|reg200=$reg_ok|inv200=$inv_ok"
}

comparison() {
  section "SIDE-BY-SIDE COMPARISON & LIKELY CAUSE"
  local fg fb
  fg="$(facts "$GOOD")"; fb="$(facts "$BAD")"
  echo "  $LGOOD :"
  echo "     $fg" | tr '|' '\n' | sed 's/^/        /'
  echo "  $LBAD :"
  echo "     $fb" | tr '|' '\n' | sed 's/^/        /'
  echo
  hr
  echo "  HEURISTIC READING:"
  local g_rtp b_rtp g_sdp b_sdp g_md b_md g_mp b_mp
  g_rtp="$(sed -n 's/.*rtp_dirs=\([0-9]*\).*/\1/p' <<<"$fg")"
  b_rtp="$(sed -n 's/.*rtp_dirs=\([0-9]*\).*/\1/p' <<<"$fb")"
  g_md="$(sed -n 's/.*media_dirs=\([0-9NA]*\).*/\1/p' <<<"$fg")"
  b_md="$(sed -n 's/.*media_dirs=\([0-9NA]*\).*/\1/p' <<<"$fb")"
  g_mp="$(sed -n 's/.*media_pkts=\([0-9NA]*\).*/\1/p' <<<"$fg")"
  b_mp="$(sed -n 's/.*media_pkts=\([0-9NA]*\).*/\1/p' <<<"$fb")"
  g_sdp="$(sed -n 's/.*sdp_addrs=\([^|]*\).*/\1/p' <<<"$fg")"
  b_sdp="$(sed -n 's/.*sdp_addrs=\([^|]*\).*/\1/p' <<<"$fb")"

  echo "   - RTP flow directions (dissected):   good=$g_rtp   bad=$b_rtp"
  echo "   - MEDIA on SDP ports (SRTP-aware):    good: dirs=$g_md pkts=$g_mp   bad: dirs=$b_md pkts=$b_mp"
  echo "     ^ This is the decisive signal — it counts encrypted media the RTP dissector misses."
  if [[ "${b_mp:-0}" =~ ^[0-9]+$ && "${b_mp:-0}" -eq 0 ]]; then
    echo "       => BAD: ZERO media packets on the negotiated audio ports. Audio is fully"
    echo "          blocked outbound/inbound (Zscaler/firewall dropping UDP media). No audio."
  elif [[ "${b_md:-0}" =~ ^[0-9]+$ && "${b_md:-0}" -lt 2 ]]; then
    echo "       => BAD: media flows in only ONE direction on the audio ports => ONE-WAY AUDIO."
    echo "          The reverse path is dropped (return RTP to a non-routable/NAT'd address)."
  elif [[ "${g_mp:-0}" =~ ^[0-9]+$ && "${b_mp:-0}" =~ ^[0-9]+$ && "${b_mp}" -lt $(( ${g_mp:-0} / 4 + 1 )) ]]; then
    echo "       => BAD: media packet count is a fraction of the working call => heavy media"
    echo "          loss/clipping. Partial path; inspect the directional counts above."
  fi
  echo
  echo "   - SDP-advertised media addresses:"
  echo "       good: ${g_sdp:-none}"
  echo "       bad : ${b_sdp:-none}"
  echo "       => If the BAD capture advertises a different / private / on-prem address than"
  echo "          where packets can actually flow under Zscaler, the far end sends audio into"
  echo "          a black hole. Compare these against the real RTP flows above."
  echo
  echo "   Reminder of the classic Zscaler + Avaya audio failure modes:"
  echo "     1. Signaling (SIP/TLS or H.323/TCP) rides the Zscaler tunnel fine -> registers."
  echo "     2. RTP audio is UDP -> blocked, dropped, or NAT-rewritten -> no/one-way audio."
  echo "     3. SDP c= line carries the client's *local* IP, unreachable from media gateway."
  echo "     4. Zscaler changes the apparent source IP, so RTP returns to the wrong address."
}

# ----------------------------------------------------------------------------
# Drive it
# ----------------------------------------------------------------------------
echo "Avaya one-X pcap comparison"
echo "  GOOD (on-prem, audio works): $GOOD"
echo "  BAD  (zscaler, no audio)   : $BAD"
echo "  Report: $REPORT"
echo "  tshark: $("$TSHARK" -v 2>/dev/null | head -1)"

for pair in "GOOD|$GOOD|$LGOOD" "BAD|$BAD|$LBAD"; do
  IFS='|' read -r tag f label <<<"$pair"
  section "CAPTURE: $label"
  capture_summary  "$f" "$label"
  dns_analysis     "$f" "$label"
  sip_analysis     "$f" "$label"
  sdp_analysis     "$f" "$label"
  h323_analysis    "$f" "$label"
  rtp_analysis     "$f" "$label"
  media_udp_check  "$f" "$label"
  stun_check       "$f" "$label"
  icmp_check       "$f" "$label"
  transport_health "$f" "$label"
  expert_info      "$f" "$label"
done

comparison

echo
echo "Done. Full report saved to: $REPORT"
