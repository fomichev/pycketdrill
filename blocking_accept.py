#!/usr/bin/env python
# gtests/net/tcp/blocking/blocking-accept.pkt

from pycketdrill import *

for _ in setup_af():
    ln, dport, sport = listen(la)

    pcap_send(IPx() / TCP(sport=sport, dport=dport, flags='S', seq=0))
    synack = pcap_recv(TCP)
    pcap_send(IPx() / TCP(sport=sport, dport=dport, flags='A', ack=synack[TCP].seq+1, seq=synack[TCP].ack+1))
    accept(ln)
