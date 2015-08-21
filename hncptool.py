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
# Last modified: Fri Aug 21 09:58:43 2015 mstenber
# Edit time:     40 min
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
import sys

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
        self.s.sendto(b, (dst, HNCP_PORT, 0, ifindex))
    def setup_hncp(self, hncp, iflist):
        addrinfo = socket.getaddrinfo(HNCP_GROUP, None)[0]
        group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
        s = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        s.bind(('', HNCP_PORT))
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, False)
        if sys.platform == 'darwin':
            IPV6_RECVPKTINFO = 61
        elif sys.platform.startswith('linux'):
            IPV6_RECVPKTINFO = 49
        else:
            raise NotImplementedError
        s.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVPKTINFO, True)
        def _f():
            data, ancdata, flags, addr = s.recvmsg(2**16, 2**10)
            assert len(ancdata) == 1
            cmsg_level, cmsg_type, cmsg_data = ancdata[0]
            dst = ipaddress.ip_address(cmsg_data[:16])
            if dst.is_multicast:
                dst = None
            else:
                dst = dst.compressed
            ads, ifname = addr[0].split('%')
            a = ipaddress.ip_address(ads)
            ep = hncp.find_or_create_ep_by_name(ifname)
            hncp.ext_received(ep, a, dst, decode_tlvs(data))
        self.add_reader(s, _f)
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
    si = LinuxSystemInterface()
    hncp = HNCP(sys=si)
    if args.debug:
        import logging
        logging.basicConfig(level=logging.DEBUG)
    si.setup_hncp(hncp, args.ifname)
    result = [False]
    def _done():
        si.running = False
    class HNCPSubscriber(Subscriber):
        def network_consistent_event(self, c):
            if c:
                si.running = False
                result[0] = True
    hncp.add_subscriber(HNCPSubscriber())
    si.call_later(args.timeout, _done)
    si.loop()
    assert result[0]
    for n in hncp.valid_sorted_nodes():
        print(n)
        for t in n.tlvs:
            print(' ', t)
        print
