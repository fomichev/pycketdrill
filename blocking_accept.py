#!/usr/bin/env python
# gtests/net/tcp/blocking/blocking-accept.pkt

from pycketdrill import *

for _ in setup_af():
    ln, sport, dport = listen(local_addr())
    pcap_defaults(sport=dport, dport=sport)

    pcap_send(TCPx(flags='S', seq=0))
    synack = pcap_recv(TCP)
    pcap_send(TCPx(flags='A', ack=synack[TCP].seq+1, seq=synack[TCP].ack+1))
    accept(ln)
