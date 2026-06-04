# voip-pcap-diff

Compare two packet captures of a SIP/VoIP softphone session and pinpoint why one
works and the other doesn't — built for the classic **"the phone registers fine
but there's no audio"** problem, especially when a secure web gateway / SASE
tunnel (e.g. Zscaler) sits in the media path.

It was written to diff an **Avaya one-X** call captured two ways:

| Capture | Path | Symptom |
|---------|------|---------|
| `good` (baseline) | on-prem, no tunnel | registers **and** audio works |
| `bad`  (problem)  | through Zscaler    | registers, but **no audio** |

…but nothing in it is Avaya-specific — it works for any SIP/SDP/RTP softphone.

## Why "registers but no audio" happens

Signaling and media take different paths:

1. **Signaling** (SIP over TCP/TLS, or H.323) rides the tunnel fine → the phone registers and the call sets up.
2. **Media** (RTP/SRTP, UDP) is the part that breaks — blocked, dropped, or NAT-rewritten → no audio or one-way audio.
3. The **SDP `c=` line** may advertise the client's *local* IP, which the media gateway can't reach from the other side of the tunnel.
4. The tunnel may change the apparent source IP, so return RTP is sent to an address that never arrives.

This tool surfaces exactly which of these is happening by comparing the two captures side by side.

## What it reports

Per capture, then a side-by-side diff with a heuristic verdict:

- **Capture summary** — duration, packet/byte counts, protocol hierarchy, top conversations
- **DNS / FQDNs** — every query + response, resolved A/CNAME, failures (NXDOMAIN/SERVFAIL), unique FQDNs (catches a gateway resolving names to different IPs)
- **SIP** — full message ladder, REGISTER result, 4xx/5xx/6xx failures, NAT view (`Via` rport/received vs `Contact`)
- **SDP** — the negotiated media address (`c=`), `m=audio` port, and codecs each side offered
- **RTP / RTCP** — dissected streams, packet loss, jitter, call lifecycle
- **Media-UDP-on-SDP-ports** — the decisive check: counts media packets **per direction on the exact negotiated ports**, so it also catches **SRTP / encrypted media** that the RTP dissector won't classify
- **STUN / ICE**, **ICMP errors** (port-unreachable / admin-prohibited = active drop), **H.323** (auto-detected)
- **TCP / TLS health** — SYNs with no SYN-ACK, RSTs, retransmits, TLS SNI, TLS alerts
- **Heuristic verdict** — names the likely cause: one-way audio, fully-blocked media, or partial loss

## Requirements

- **Python 3** (standard library only — no pip installs)
- [`tshark`](https://www.wireshark.org/) (Wireshark CLI) — the dissection engine. `capinfos` (ships with Wireshark) is used if present.
  - macOS: `brew install wireshark`
  - Debian/Ubuntu: `sudo apt install tshark`

## Usage

```bash
./analyze_avaya_pcaps.py <good_baseline.pcap> <bad_problem.pcap> [-o output_dir]
```

- **good** — the capture where audio works (baseline)
- **bad** — the capture with no audio (problem)
- **-o / --output-dir** — optional; defaults to `./avaya_pcap_report/`

Output prints to the terminal **and** is saved to `<output_dir>/report.txt`.
Both `.pcap` and `.pcapng` are supported.

### Capture tips

- Capture on the **endpoint itself** (not a SPAN/mirror port) so you see media exactly as the softphone sends/receives it through the tunnel — that's what makes the per-direction media counts conclusive.
- Capture the **whole** call: registration → INVITE → a few seconds of talk → hangup.

## Try it without real captures

The repo ships a fixture generator that builds three synthetic captures
(healthy bidirectional, one-way audio, fully-blocked media):

```bash
python3 test/make_voip_fixtures.py        # writes /tmp/good.pcap and /tmp/bad.pcap
./analyze_avaya_pcaps.py /tmp/good.pcap /tmp/bad.pcap
```

The `bad.pcap` is flagged as one-way audio; swap in a signaling-only capture to
see the fully-blocked verdict.

## License

MIT
