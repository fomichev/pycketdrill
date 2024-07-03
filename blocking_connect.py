#!/usr/bin/env python
# gtests/net/tcp/blocking/blocking-connect.pkt

from pycketdrill import *

for _ in setup_af():
    sk, dport = connect(remote_addr())

    syn = pcap_recv(TCP)
    assert syn[TCP].flags == 'S'

    pcap_defaults(sport=dport, dport=syn[TCP].sport)

    pcap_send(TCPx(flags='SA', ack=syn[TCP].seq+1, seq=0))
    ack = pcap_recv(TCP)

    assert ack[TCP].flags == 'A'
    assert ack[TCP].seq == syn[TCP].seq+1
    assert ack[TCP].ack == 1
