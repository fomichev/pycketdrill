#!/usr/bin/env python
# gtests/net/tcp/blocking/blocking-connect.pkt

import threading

from pycketdrill import *

def blocking_connect(dport, remote_addr):
    sk = socket.socket(current_af(), socket.SOCK_STREAM, socket.IPPROTO_TCP)
    sk.connect((remote_addr, dport))
    sk.close()

for _ in setup_af():
    dport = next_unique_port()

    thread = threading.Thread(target=blocking_connect, args=(dport ,remote_addr()))
    thread.start()

    syn = pcap_recv(TCP)
    assert syn[TCP].flags == 'S'

    pcap_defaults(sport=dport, dport=syn[TCP].sport)

    pcap_send(TCPx(flags='SA', ack=syn[TCP].seq+1, seq=0))
    ack = pcap_recv(TCP)

    assert ack[TCP].flags == 'A'
    assert ack[TCP].seq == syn[TCP].seq+1
    assert ack[TCP].ack == 1

    thread.join()
