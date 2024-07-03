#!/usr/bin/env python

import argparse
import atexit
import ctypes
import ctypes.util
import logging
import os
import socket
import subprocess
import time

from scapy.sendrecv import srp1, sendp, sniff
from scapy.sendrecv import AsyncSniffer

import scapy.config
import scapy.interfaces

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.tuntap import TunTapInterface
from scapy.packet import Raw

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
logger = logging.getLogger(__name__)

TUN_DEV='tun0'

LOCAL_V4ADDR='192.168.0.2' # RFC 1918
LOCAL_V4PREFIX='/16'
REMOTE_V4ADDR='192.0.2.1' # RFC 5737
GW_V4ADDR='192.168.0.1'

LOCAL_V6ADDR='fd3d:fa7b:d17d::2' # RFC 4193
LOCAL_V6PREFIX='/48'
REMOTE_V6ADDR='2001:db8::1' # RFC 3849
GW_V6ADDR='fd3d:fa7b:d17d:0001::1'

MODE_V4 = 1
MODE_V6 = 2
MODE_V46 = 3

RECV_TIMEOUT_SEC = 1

netns_idx = 0
netns = None
tuntap = None
mode = MODE_V4
af = socket.AF_INET
unique_port = 8192
libc = None

def _netns_cleanup():
    '''Cleanup and remove temporary networking namespace.'''
    subprocess.call(['ip', 'netns', 'del', netns])

def _netns_setup():
    '''Create and setup new networking namespace for the single test run.'''
    global netns
    global netns_idx

    if netns:
        _netns_cleanup()
        atexit.unregister(_netns_cleanup)

    netns = 'pd_' + str(os.getpid()) + '_' + str(netns_idx)
    netns_idx += 1

    atexit.register(_netns_cleanup)

    # TODO: convert this to YNL instead of shelling out
    subprocess.check_call(['ip', 'netns', 'add', netns])
    subprocess.check_call(['ip', '-n', netns, 'tuntap', 'add', 'mode', 'tun', TUN_DEV ])
    subprocess.check_call(['ip', '-4', '-n', netns, 'addr', 'add', LOCAL_V4ADDR + LOCAL_V4PREFIX, 'dev', TUN_DEV])
    subprocess.check_call(['ip', '-6', '-n', netns, 'addr', 'add', LOCAL_V6ADDR + LOCAL_V6PREFIX, 'dev', TUN_DEV])
    subprocess.check_call(['ip', '-4', '-n', netns, 'link', 'set', 'dev', TUN_DEV, 'up'])
    subprocess.check_call(['ip', '-4', '-n', netns, 'route', 'add', REMOTE_V4ADDR, 'dev', TUN_DEV, 'via', GW_V4ADDR])
    subprocess.check_call(['ip', '-6', '-n', netns, 'route', 'add', REMOTE_V6ADDR, 'dev', TUN_DEV, 'via', GW_V6ADDR])
    #subprocess.check_call(['ip', '-n', netns, 'addr'])

    CLONE_NEWNET = 0x40000000

    global libc

    if not libc:
      libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

    with open("/var/run/netns/" + netns) as f:
      libc.setns(f.fileno(), CLONE_NEWNET)

def _detect_mode(v4, v6):
    '''
    Based on the environment, return a list of modes (IPv4, IPv6 or
    IPv4-over-6) that the test is supposed to run.
    '''
    if v4 and v6:
        return [MODE_V46]
    elif v4:
        return [MODE_V4]
    elif v6:
        return [MODE_V6]

    # No mode specified, evaluate everything.
    return [MODE_V4, MODE_V6, MODE_V46]

def _prepare_mode(_mode):
    '''Prepare a bunch of global variables for given mode.'''
    global mode

    mode = _mode

    global af
    global ra
    global la

    mode_str = '?'

    if mode == MODE_V4:
        af = socket.AF_INET
        ra = REMOTE_V4ADDR
        la = LOCAL_V4ADDR
        mode_str = 'AF_INET4'

    if mode == MODE_V6:
        af = socket.AF_INET6
        ra = REMOTE_V6ADDR
        la = LOCAL_V6ADDR
        mode_str = 'AF_INET6'

    if mode == MODE_V46:
        af = socket.AF_INET6
        ra = '::ffff:' + REMOTE_V4ADDR
        la = '::ffff:' + LOCAL_V4ADDR
        mode_str = 'AF_INET46'

    logger.info(f'@ {netns} {mode_str} remote={ra} local={la}')

def _pcap_begin():
    '''Create a pcap instance over tun device.'''
    scapy.config.conf.noenum.add(TCP.sport, TCP.dport, UDP.sport, UDP.dport)
    socket.setdefaulttimeout(1)

    global tuntap

    tuntap = TunTapInterface(TUN_DEV)

def IPx(*args, **kwargs):
    '''
    Create IP or IPv6 packet (based on the environment) destined
    to local address from remote address.
    '''
    if mode == MODE_V4 or mode == MODE_V46:
        return IP(dst=la, src=ra)
    return IPv6(dst=la, src=ra)

def local_addr():
    '''Return local address.'''
    return la

def remote_addr():
    '''Return remote address.'''
    return ra

def listen(addr):
    '''Wrapper around socket.bind and listen with extra logging.'''
    global unique_port
    dport = unique_port
    unique_port += 1

    ln = socket.socket(af, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    ln.bind((addr, 0))
    ln.listen(1)
    sport = ln.getsockname()[1]
    logger.info(f'  listen on {dport}')
    return (ln, sport, dport)

def connect(addr):
    '''Wrapper around non-blocking socket.connect with extra logging.'''
    global unique_port
    dport = unique_port
    unique_port += 1

    sk = socket.socket(af, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    sk.setblocking(False)
    try:
        sk.connect((addr, dport))
    except BlockingIOError as e:
        pass

    logger.info(f'  connect to {dport}')
    return (sk, dport)

def accept(ln):
    '''Wrapper around socket.accept with extra logging.'''
    sk, _ = ln.accept()
    logger.info(f'  accepted {sk}')
    return sk

def pcap_recv(tp, dump=False):
    '''Receive packet via TUN device (from local to remote).'''
    lastrx = time.time()
    while True:
        p = tuntap.recv()
        if tp in p:
            if dump:
                logger.info(f'< {p.show(dump=True)}')
            else:
                logger.info(f'< {p}')
            return p

        if time.time() - lastrx > RECV_TIMEOUT_SEC:
            logger.info(f'! recv timeout')
            break

        lastrx = time.time()
        logger.info(f'? {p}')

def pcap_send(p, dump=False):
    '''Send packet via TUN device (from remote to local).'''
    if dump:
        logger.info(f'> {p.show(dump=True)}')
    else:
        logger.info(f'> {p}')
    tuntap.send(p)

def setup_af():
    '''Parse argument and setup environemnt for IPv4, IPv6 or IPv4-over-6.'''
    parser = argparse.ArgumentParser()
    parser.add_argument('-4', dest='v4', action='store_true')
    parser.add_argument('-6', dest='v6', action='store_true')
    args = parser.parse_args()

    for m in _detect_mode(args.v4, args.v6):
        _netns_setup()
        _pcap_begin()
        _prepare_mode(m)
        yield m
