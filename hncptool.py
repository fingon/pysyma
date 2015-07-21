#!/usr/bin/env python3.4
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: hncptool.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Tue Jul 21 13:07:01 2015 mstenber
# Last modified: Tue Jul 21 13:48:32 2015 mstenber
# Edit time:     16 min
#
"""

An example HNCP transport using tool. Not for serious usage, as it is
mostly copied from babeld.py (which while working, is not 'great').

TBD: Refactor I/O under pysyma/

"""

from pysyma.dncp import HNCP, Subscriber
from pysyma.dncp_tlv import decode_tlvs, encode_tlvs

import time
import random
import os
import socket
import ipaddress
import struct
import select
import re

import logging
_logger = logging.getLogger(__name__)
_debug = _logger.debug

HNCP_GROUP = 'ff02::8808'
HNCP_PORT = 8808

class Timeout:
    done = False
    def __init__(self, lsi, t, cb, a):
        assert cb is not None
        self.lsi = lsi
        self.t = t
        self.cb = cb
        self.a = a
        _debug('%s Timeout %s', self, cb)
    def cancel(self):
        assert not self.done
        assert self in self.lsi.timeouts
        _debug('%s Timeout.cancel', self)
        self.lsi.timeouts.remove(self)
        self.done = True
    def run(self):
        assert not self.done
        assert self in self.lsi.timeouts
        _debug('%s Timeout.run %s', self, self.cb)
        self.cb(*self.a)
        self.lsi.timeouts.remove(self)
        self.done = True

class LinuxSystemInterface:
    def __init__(self):
        self.timeouts = []
        self.readers = {}
    time = time.time
    def add_reader(self, s, cb):
        self.readers[s] = cb
    def next(self):
        if not self.timeouts: return
        return min([x.t for x in self.timeouts])
    def poll(self):
        while True:
            t = time.time()
            l = [x for x in self.timeouts if x.t <= t]
            if not l:
                return
            l[0].run()
            # Just run them one by one as I CBA to track the cancel
            # dependencies :p
    def loop(self):
        self.running = True
        while True:
            self.poll()
            if not self.running: break
            to = self.next() - time.time()
            if to < 0.01:
                to = 0.01
            _debug('select %s %s', self.readers.keys(), to)
            (rlist, wlist, xlist) = select.select(self.readers.keys(), [], [], to)
            _debug('readable %s', rlist)
            for fd in rlist:
                self.readers[fd]()
    def call_later(self, dt, cb, *a):
        o = Timeout(self, dt + self.time(), cb, a)
        self.timeouts.append(o)
        return o
    schedule = call_later
    def send(self, ep, src, dst, tlvs):
        if dst is None:
            dst = HNCP_GROUP
        else:
            assert isinstance(dst, ipaddress.IPv6Address)
            dst = dst.compressed
        ifname = ep.name
        ifindex = socket.if_nametoindex(ifname)
        tlvs = list(tlvs)
        b = encode_tlvs(*tlvs)
        _debug('send @%s -> %s: %s (%d bytes)', ifname, dst, tlvs, len(b))
        self.s.sendto(b, (dst, HNCP_PORT, 0, ifindex))
    def setup_hncp(self, hncp, iflist):
        addrinfo = socket.getaddrinfo(HNCP_GROUP, None)[0]
        group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
        s = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        s.bind(('', HNCP_PORT))
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, False)
        def _f():
            data, addr = s.recvfrom(2**16)
            ads, ifname = addr[0].split('%')
            a = ipaddress.ip_address(ads)
            ep = hncp.find_or_create_ep_by_name(ifname)
            hncp.ext_received(ep, a, None, decode_tlvs(data))
        sys.add_reader(s, _f)
        for ifname in iflist:
            ep = hncp.find_or_create_ep_by_name(ifname)
            ifindex = socket.if_nametoindex(ifname)
            mreq = group_bin + struct.pack('@I', ifindex)
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
            ep.ext_ready(True)
        self.s = s

if __name__ == '__main__':
    import argparse
    import logging
    logging.basicConfig(level=logging.DEBUG)
    ap = argparse.ArgumentParser()
    ap.add_argument('-t', '--timeout', default=3, type=int, help='Timeout (seconds)')
    ap.add_argument('-d', '--debug', action='store_true', help='Enable debugging')
    ap.add_argument('ifname',
                    nargs='+',
                    help="Interfaces to listen on.")
    args = ap.parse_args()
    sys = LinuxSystemInterface()
    hncp = HNCP(sys=sys)
    if args.debug:
        import logging
        logging.basicConfig(level=logging.DEBUG)
    sys.setup_hncp(hncp, args.ifname)
    def _done():
        sys.running = False
    class HNCPSubscriber(Subscriber):
        def network_consistent(self, c):
            if c: _done()
    sys.call_later(args.timeout, _done)
    sys.loop()
