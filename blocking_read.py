#!/usr/bin/env python
# gtests/net/tcp/blocking/blocking-read.pkt

from pycketdrill import *

for _ in setup_af():
    ln, sport, dport = listen(local_addr())
    pcap_defaults(sport=dport, dport=sport)

    pcap_send(TCPx(flags='S', seq=0))
    synack = pcap_recv(TCP)
    pcap_send(TCPx(flags='A', ack=synack[TCP].seq+1, seq=1))

    sk = accept(ln)

    pcap_send(TCPx(flags='PA', ack=synack[TCP].seq+1, seq=1) / Raw(b'\x00' * 2000))
    ack = pcap_recv(TCP)
    assert ack[TCP].ack == 2001
    data = sk.recv(2000)
    assert len(data) == 2000

    pcap_send(TCPx(flags='PA', ack=synack[TCP].seq+1, seq=2001) / Raw(b'\x00' * 2000))
    ack = pcap_recv(TCP)
    assert ack[TCP].ack == 4001
    data = sk.recv(2000)
    assert len(data) == 2000

    pcap_send(TCPx(flags='PA', ack=synack[TCP].seq+1, seq=4001) / Raw(b'\x00' * 2000))
    ack = pcap_recv(TCP)
    assert ack[TCP].ack == 6001
    data = sk.recv(1000)
    assert len(data) == 1000
    data = sk.recv(1000)
    assert len(data) == 1000
