#!/usr/bin/env python
# gtests/net/tcp/blocking/blocking-accept.pkt

from pycketdrill import *

for _ in setup_af():
    ln, sport = listener(local_addr(), socket.SOCK_STREAM, socket.IPPROTO_TCP)
    dport = next_unique_port()
    pcap_defaults(sport=dport, dport=sport)

    pcap_send(TCPx(flags='S', seq=0))
    synack = pcap_recv(TCP)
    pcap_send(TCPx(flags='A', ack=synack[TCP].seq+1, seq=synack[TCP].ack+1))
    ln.accept()
