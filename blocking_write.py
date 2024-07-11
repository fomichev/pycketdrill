#!/usr/bin/env python
# gtests/net/tcp/blocking/blocking-write.pkt

from pycketdrill import *

for _ in setup_af():
    ln, sport = listener(local_addr(), socket.SOCK_STREAM, socket.IPPROTO_TCP)
    dport = next_unique_port()
    pcap_defaults(sport=dport, dport=sport)

    pcap_send(TCPx(flags='S', seq=0, options=[('MSS', 1000)]))
    synack = pcap_recv(TCP)
    pcap_send(TCPx(flags='A', ack=synack[TCP].seq+1, seq=1))

    sk, _ = ln.accept()

    ret = sk.send(b'\x00' * 2000)
    chunk1 = pcap_recv(TCP)
    assert chunk1[TCP].seq == synack[TCP].seq+1
    assert chunk1[TCP].flags == 'A'
    assert len(chunk1[TCP].payload) == 1000

    chunk2 = pcap_recv(TCP)
    assert chunk2[TCP].seq == synack[TCP].seq+1001
    assert chunk2[TCP].flags == 'PA'
    assert len(chunk2[TCP].payload) == 1000

    pcap_send(TCPx(flags='A', ack=chunk1[TCP].seq+2000, seq=1))
