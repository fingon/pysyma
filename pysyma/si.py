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
# Last modified: Fri Aug 21 11:03:21 2015 mstenber
# Edit time:     25 min
#
"""

This module defines system interface that DNCP subprotocols need.

It also describes HNCP specific one, with support for setting up HNCP
transport.


"""

from . import dncp
from . import dncp_tlv

import time
import socket
import sys
import struct
import select
import ipaddress
import os

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


class SystemInterfaceSocket(dncp.SystemInterface):
    def __init__(self, s, si, iflist):
        self.si = si
        self.time = si.time
        self.schedule = si.schedule
        self.s = s
        self.iflist = iflist
        si.add_reader(self.s, self.handle_read)
    def send(self, ep, src, dst, tlvs):
        if dst is None:
            dst = self.si.proto_group
        else:
            assert isinstance(dst, ipaddress.IPv6Address)
            dst = dst.compressed
        ifname = ep.name
        ifindex = socket.if_nametoindex(ifname)
        tlvs = list(tlvs)
        b = dncp_tlv.encode_tlvs(*tlvs)
        self.s.sendto(b, (dst, self.si.proto_port, 0, ifindex))
    def handle_read(self):
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
        ep = self.dncp.find_or_create_ep_by_name(ifname)
        self.dncp.ext_received(ep, a, dst, dncp_tlv.decode_tlvs(data))
    def set_dncp(self, dncp):
        self.dncp = dncp
        addrinfo = socket.getaddrinfo(self.si.proto_group, None)[0]
        group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
        for ifname in self.iflist:
            ep = dncp.find_or_create_ep_by_name(ifname)
            ifindex = socket.if_nametoindex(ifname)
            mreq = group_bin + struct.pack('@I', ifindex)
            self.s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
            ep.ext_ready(True)


class SystemInterface:
    proto_group = None
    proto_port = None
    time = time.time
    def __init__(self):
        self.timeouts = []
        self.readers = {}
        r, w = os.pipe()
        r = os.fdopen(r, 'r')
        w = os.fdopen(w, 'w')
        self.pipe_r, self.pipe_w = r, w
        def _nop():
            self.pipe_r.read()
        self.add_reader(self.pipe_r, _nop)
    def add_reader(self, s, cb):
        self.readers[s] = cb
        self.pipe_w.write('x') # in case in separate thread
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
        self.set_locked(True)
        self.running = True
        while True:
            self.poll()
            if not self.running: break
            to = self.next() - time.time()
            if to < 0.01:
                to = 0.01
            _debug('select %s %s', self.readers.keys(), to)
            k = list(self.readers.keys())
            self.set_locked(False)
            (rlist, wlist, xlist) = select.select(k, [], [], to)
            self.set_locked(True)
            _debug('readable %s', rlist)
            for fd in rlist:
                self.readers[fd]()
        self.set_locked(False)
    def schedule(self, dt, cb, *a):
        o = Timeout(self, dt + self.time(), cb, a)
        self.timeouts.append(o)
        self.pipe_w.write('x') # in case in separate thread
        return o
    def create_socket(self, addr='', port=None, iflist=[]):
        s = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        if port is None: port = self.proto_port
        s.bind((addr, port))
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, False)
        if sys.platform == 'darwin':
            IPV6_RECVPKTINFO = 61
        elif sys.platform.startswith('linux'):
            IPV6_RECVPKTINFO = 49
        else:
            raise NotImplementedError
        s.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVPKTINFO, True)
        return SystemInterfaceSocket(s, self, iflist)
    def set_locked(self, locked):
        pass

class HNCPSystemInterface(SystemInterface):
    proto_group = 'ff02::8808'
    proto_port = 8808


