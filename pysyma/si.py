#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: si.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Fri Aug 21 10:00:10 2015 mstenber
# Last modified: Fri Aug 21 10:06:33 2015 mstenber
# Edit time:     4 min
#
"""

This module defines system interface that DNCP subprotocols need.

It also describes HNCP specific one, with support for setting up HNCP
transport.


"""

from . import dncp_tlv

import time
import socket
import sys
import struct
import select
import ipaddress


import logging
_logger = logging.getLogger(__name__)
_debug = _logger.debug

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

class SystemInterface:
    proto_group = None
    proto_port = None
    time = time.time
    def __init__(self):
        self.timeouts = []
        self.readers = {}
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
            dst = self.proto_group
        else:
            assert isinstance(dst, ipaddress.IPv6Address)
            dst = dst.compressed
        ifname = ep.name
        ifindex = socket.if_nametoindex(ifname)
        tlvs = list(tlvs)
        b = dncp_tlv.encode_tlvs(*tlvs)
        self.s.sendto(b, (dst, self.proto_port, 0, ifindex))
    def setup_dncp(self, dncp, iflist):
        addrinfo = socket.getaddrinfo(self.proto_group, None)[0]
        group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
        s = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        s.bind(('', self.proto_port))
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
            ep = dncp.find_or_create_ep_by_name(ifname)
            dncp.ext_received(ep, a, dst, dncp_tlv.decode_tlvs(data))
        self.add_reader(s, _f)
        for ifname in iflist:
            ep = dncp.find_or_create_ep_by_name(ifname)
            ifindex = socket.if_nametoindex(ifname)
            mreq = group_bin + struct.pack('@I', ifindex)
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
            ep.ext_ready(True)
        self.s = s

class HNCPSystemInterface(SystemInterface):
    proto_group = 'ff02::8808'
    proto_port = 8808

