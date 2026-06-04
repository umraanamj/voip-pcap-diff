#!/usr/bin/env python3
# Build two tiny VoIP pcaps to validate analyze_avaya_pcaps.sh:
#   good.pcap : SIP register+call, RTP BOTH directions on negotiated audio ports
#   bad.pcap  : SIP register+call, RTP only phone->server (one-way audio)
import struct

def ipchk(h):
    s=0
    for i in range(0,len(h),2): s+=(h[i]<<8)+h[i+1]
    s=(s>>16)+(s&0xffff); s+=s>>16
    return (~s)&0xffff

def ip2b(a): return bytes(int(x) for x in a.split('.'))

def udp(sp,dp,pl):
    return struct.pack('>HHHH',sp,dp,8+len(pl),0)+pl

def ipv4(src,dst,proto,pl):
    h=struct.pack('>BBHHHBBH',0x45,0,20+len(pl),1,0,64,proto,0)+ip2b(src)+ip2b(dst)
    c=ipchk(h); h=h[:10]+struct.pack('>H',c)+h[12:]
    return h+pl

def eth(src,dst,pl):
    return b'\x00\x11\x22\x33\x44\x55'+b'\x66\x77\x88\x99\xaa\xbb'+b'\x08\x00'+pl

def frame(src,dst,sp,dp,payload):
    return eth(src,dst,ipv4(src,dst,17,udp(sp,dp,payload)))

def rtp(pt=0,seq=0,ts=0,ssrc=0x1234):
    return struct.pack('>BBHII',0x80,pt&0x7f,seq,ts,ssrc)+b'\xAA'*160  # G.711-ish payload

PHONE='10.0.0.10'; SRV='10.0.0.1'
PA=40000; SA=50000  # audio ports

def sip_register():
    return (b"REGISTER sip:pbx.corp.example SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP 10.0.0.10:5060;branch=z9hG4bK1\r\n"
            b"From: <sip:1001@pbx.corp.example>;tag=a\r\nTo: <sip:1001@pbx.corp.example>\r\n"
            b"Call-ID: reg1@10.0.0.10\r\nCSeq: 1 REGISTER\r\n"
            b"Contact: <sip:1001@10.0.0.10:5060>\r\nExpires: 3600\r\nContent-Length: 0\r\n\r\n")
def sip_200_reg():
    return (b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.10:5060;branch=z9hG4bK1\r\n"
            b"From: <sip:1001@pbx.corp.example>;tag=a\r\nTo: <sip:1001@pbx.corp.example>;tag=b\r\n"
            b"Call-ID: reg1@10.0.0.10\r\nCSeq: 1 REGISTER\r\nContent-Length: 0\r\n\r\n")
def sdp(addr,port,direction="sendrecv"):
    body=(f"v=0\r\no=- 1 1 IN IP4 {addr}\r\ns=call\r\nc=IN IP4 {addr}\r\nt=0 0\r\n"
          f"m=audio {port} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n"
          f"a={direction}\r\n").encode()
    return body
def sip_invite(addr,port,direction="sendrecv"):
    b=sdp(addr,port,direction)
    return (b"INVITE sip:1002@pbx.corp.example SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.10:5060;branch=z9hG4bK2\r\n"
            b"From: <sip:1001@pbx.corp.example>;tag=c\r\nTo: <sip:1002@pbx.corp.example>\r\n"
            b"Call-ID: call1@10.0.0.10\r\nCSeq: 1 INVITE\r\nContact: <sip:1001@10.0.0.10:5060>\r\n"
            b"Content-Type: application/sdp\r\nContent-Length: "+str(len(b)).encode()+b"\r\n\r\n"+b)
def sip_200_inv(addr,port,direction="sendrecv"):
    b=sdp(addr,port,direction)
    return (b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.10:5060;branch=z9hG4bK2\r\n"
            b"From: <sip:1001@pbx.corp.example>;tag=c\r\nTo: <sip:1002@pbx.corp.example>;tag=d\r\n"
            b"Call-ID: call1@10.0.0.10\r\nCSeq: 1 INVITE\r\nContact: <sip:1002@10.0.0.1:5060>\r\n"
            b"Content-Type: application/sdp\r\nContent-Length: "+str(len(b)).encode()+b"\r\n\r\n"+b)
def sip_ack():
    return (b"ACK sip:1002@10.0.0.1:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.10:5060;branch=z9hG4bK3\r\n"
            b"From: <sip:1001@pbx.corp.example>;tag=c\r\nTo: <sip:1002@pbx.corp.example>;tag=d\r\n"
            b"Call-ID: call1@10.0.0.10\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n")

def write_pcap(path, pkts):
    with open(path,'wb') as f:
        f.write(struct.pack('<IHHiIII',0xa1b2c3d4,2,4,0,0,65535,1))  # link type 1 = ethernet
        for i,p in enumerate(pkts):
            f.write(struct.pack('<IIII',i,i*1000,len(p),len(p))+p)

def signaling():
    return [
        frame(PHONE,SRV,5060,5060,sip_register()),
        frame(SRV,PHONE,5060,5060,sip_200_reg()),
        frame(PHONE,SRV,5060,5060,sip_invite(PHONE,PA)),
        frame(SRV,PHONE,5060,5060,sip_200_inv(SRV,SA)),
        frame(PHONE,SRV,5060,5060,sip_ack()),
    ]

# GOOD: RTP both ways
good=signaling()
for n in range(20):
    good.append(frame(PHONE,SRV,PA,SA,rtp(0,n,160*n,0x1111)))   # phone -> server
    good.append(frame(SRV,PHONE,SA,PA,rtp(0,n,160*n,0x2222)))   # server -> phone
write_pcap('/tmp/good.pcap',good)

# BAD: RTP only phone->server (server's return audio dropped by Zscaler/FW)
bad=signaling()
for n in range(20):
    bad.append(frame(PHONE,SRV,PA,SA,rtp(0,n,160*n,0x1111)))    # phone -> server only
write_pcap('/tmp/bad.pcap',bad)

# ANCHOR: Avaya-style SDP with BOTH a session-level c= (internal origin address
# that never appears on the wire) AND a media-level c= (the real media anchor,
# 10.0.0.99). Media-level overrides session-level (RFC 4566 5.7). The phone sends
# RTP to the anchor; nothing returns => one-way. The internal session-level addr
# is the "address you can't find in the pcap" — and must NOT be called a problem.
ANCHOR='10.0.0.99'
INTERNAL='172.31.255.1'   # session-level c= / o= — never a media endpoint
def sip_200_dualc(sess_addr,media_addr,port):
    b=(f"v=0\r\no=- 1 1 IN IP4 {sess_addr}\r\ns=call\r\nc=IN IP4 {sess_addr}\r\nt=0 0\r\n"
       f"m=audio {port} RTP/AVP 0 8\r\nc=IN IP4 {media_addr}\r\n"
       f"a=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n").encode()
    return (b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.10:5060;branch=z9hG4bK2\r\n"
            b"From: <sip:1001@pbx.corp.example>;tag=c\r\nTo: <sip:1002@pbx.corp.example>;tag=d\r\n"
            b"Call-ID: call1@10.0.0.10\r\nCSeq: 1 INVITE\r\nContact: <sip:1002@10.0.0.1:5060>\r\n"
            b"Content-Type: application/sdp\r\nContent-Length: "+str(len(b)).encode()+b"\r\n\r\n"+b)
anchor=[
    frame(PHONE,SRV,5060,5060,sip_register()),
    frame(SRV,PHONE,5060,5060,sip_200_reg()),
    frame(PHONE,SRV,5060,5060,sip_invite(PHONE,PA)),
    frame(SRV,PHONE,5060,5060,sip_200_dualc(INTERNAL,ANCHOR,SA)),
    frame(PHONE,SRV,5060,5060,sip_ack()),
]
for n in range(20):
    anchor.append(frame(PHONE,ANCHOR,PA,SA,rtp(0,n,160*n,0x1111)))  # phone -> anchor, no return
write_pcap('/tmp/anchor.pcap',anchor)

# HOLD: the 200 OK answer carries a=inactive (SDP-layer no-media), and no RTP flows.
hold=[
    frame(PHONE,SRV,5060,5060,sip_register()),
    frame(SRV,PHONE,5060,5060,sip_200_reg()),
    frame(PHONE,SRV,5060,5060,sip_invite(PHONE,PA)),
    frame(SRV,PHONE,5060,5060,sip_200_inv(SRV,SA,direction="inactive")),
    frame(PHONE,SRV,5060,5060,sip_ack()),
]
write_pcap('/tmp/hold.pcap',hold)
print("wrote /tmp/good.pcap /tmp/bad.pcap /tmp/anchor.pcap /tmp/hold.pcap")
