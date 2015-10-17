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
# Last modified: Sat Oct 17 14:59:49 2015 mstenber
# Edit time:     143 min
#
"""

This module defines system interface that DNCP subprotocols need.

It also describes HNCP specific one, with support for setting up HNCP
transport.

TBD:
- convert to asyncore (it is built-in after all)

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
import threading
import fcntl

import logging
_logger = logging.getLogger(__name__)
_debug = _logger.debug
_error = _logger.error

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

import enum

SISocketMode = enum.Enum('SISocketMode', 'none mc ul uc')

def _if_nametoindex(ifn):
    return socket.getaddrinfo('fe80::1%' + ifn, 0, socket.AF_INET6, 0)[0][4][3]

def _if_exists(ifn):
    return _if_nametoindex(ifn) > 0


class SystemInterfaceSocket(dncp.SystemInterface):
    mode = SISocketMode.none
    ep_name = None
    def __init__(self, **kw):
        self.__dict__.update(kw)
        self.time = self.si.time
        self.schedule = self.si.schedule
        self.si.add_reader(self.s, self.handle_read)
    def get_port(self):
        return self.s.getsockname()[1]
    def send(self, ep, src, dst, tlvs):
        # These sockets should have specialized sys_send due to set_dncp_*
        raise NotImplementedError
    def send_ll(self, ep, dst, tlvs):
        if dst is None:
            dst = self.default_dst
        assert dst is not None
        b = dncp_tlv.encode_tlvs(*list(tlvs))
        if len(dst) == 2:
            ifname = ep.name
            ifindex = _if_nametoindex(ifname)
            dst = list(dst) + [0, ifindex]
        else:
            assert len(dst) == 4
        try:
            self.s.sendto(b, tuple(dst))
        except OSError as e:
            _error('got OSError when sending multicast: %s', e)
    def send_u(self, src, dst, tlvs):
        if dst is None:
            dst = self.default_dst
            if dst is None: return
        assert len(dst) >= 2
        b = dncp_tlv.encode_tlvs(*list(tlvs))
        try:
            self.s.sendto(b, tuple(dst))
        except OSError as e:
            _error('got OSError when sending unicast: %s', e)
    def handle_read(self):
        try:
            data, ancdata, flags, src = self.s.recvmsg(2**16, 2**10)
            assert len(ancdata) == 1
            cmsg_level, cmsg_type, cmsg_data = ancdata[0]
            dst = ipaddress.ip_address(cmsg_data[:16])
            if dst.is_multicast:
                dst = None
            else:
                dst = (dst.compressed, self.port)
        except AttributeError:
            data, src = self.s.recvfrom(2**16)
            dst = ('', self.port) # pretend it is unicast :p
        _debug('%s handle_read %s=>%s: %d', self, src, dst, len(data))
        l = src[0].split('%')
        if len(l) == 2:
            # Multicast
            ads, ifname = l
            ep = self.dncp.find_ep_by_name(ifname)
        else:
            # Unicast-Connect
            n = tuple(src[:2])
            ep = self.dncp.find_ep_by_name(repr(n))
        if ep is None and self.ep_name is not None:
            # Unicast-Listen
            ep = self.dncp.find_ep_by_name(self.ep_name)
        if ep:
            self.dncp.ext_received(ep, src, dst, dncp_tlv.decode_tlvs(data))
        else:
            _debug(' no endpoint found, ignoring')
    def set_dncp_multicast(self, dncp, if_list=[], unicast_ep_name=None):
        assert self.mode == SystemInterfaceSocket.mode # default
        if unicast_ep_name:
            self.set_dncp_unicast_listen(dncp, ep_name=unicast_ep_name)
        self.mode = SISocketMode.mc
        self.dncp = dncp
        self.default_dst = (self.si.proto_group, self.si.proto_port)
        addrinfo = socket.getaddrinfo(self.si.proto_group, None)[0]
        group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
        for if_name in if_list:
            ep = dncp.create_ep(if_name)
            def _send(src, dst, tlvs):
                self.send_ll(ep, dst, tlvs)
            ep.sys_send = _send
            ifindex = _if_nametoindex(if_name)
            mreq = group_bin + struct.pack('@I', ifindex)
            self.s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
            ep.ext_ready(True)
    def set_dncp_unicast_connect(self, dncp, remote):
        assert self.mode == SystemInterfaceSocket.mode # default
        self.mode = SISocketMode.uc
        self.dncp = dncp
        self.default_dst = remote
        ep_name = repr(tuple(remote[:2])) # TBD: do we really want a map?
        ep = dncp.create_ep(ep_name,
                            sys_send=self.send_u,
                            per_endpoint_ka=True,
                            per_peer_ka=False)
        ep.ext_ready(True)
    def set_dncp_unicast_listen(self, dncp, ep_name='listen'):
        assert self.mode == SystemInterfaceSocket.mode # default
        # TBD: Add some sort of filter
        self.mode = SISocketMode.ul
        self.dncp = dncp
        self.default_dst = None
        self.ep_name = ep_name
        ep = dncp.create_ep(ep_name, sys_send=self.send_u,
                            per_endpoint_ka=False,
                            per_peer_ka=True)
        ep.ext_ready(True)



class SystemInterface:
    proto_group = None
    proto_port = None
    time = time.time
    current_thread = None
    def __init__(self):
        self.timeouts = []
        self.readers = {}
        r, w = os.pipe()
        fl = fcntl.fcntl(r, fcntl.F_GETFL)
        fcntl.fcntl(r, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        r = os.fdopen(r, 'r', 1)
        w = os.fdopen(w, 'w')
        self.pipe_r, self.pipe_w = r, w
        def _nop():
            self.pipe_r.read(1)
        self.add_reader(self.pipe_r, _nop)
    def add_reader(self, s, cb):
        self.readers[s] = cb
        self.break_loop()
    def break_loop(self):
        if self.current_thread is None or self.current_thread is threading.current_thread():
            return
        self.pipe_w.write('x')
    def stop(self):
        self.running = False
        self.break_loop()
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
    def loop(self, max_duration=None):
        self.current_thread = threading.current_thread()
        self.running = True
        to = None
        if max_duration is not None:
            to = self.schedule(max_duration, self.stop)
        while True:
            self.poll()
            if not self.running: break
            to = self.next() - time.time()
            if to < 0.01:
                to = 0.01
            _debug('select %s %s', self.readers.keys(), to)
            k = list(self.readers.keys())
            (rlist, wlist, xlist) = select.select(k, [], [], to)
            _debug('readable %s', rlist)
            for fd in rlist:
                self.readers[fd]()
        if to is not None and to in self.timeouts:
            self.timeouts.remove(to)
        del self.current_thread
        _debug('%s loop terminating', self)
    def schedule(self, dt, cb, *a):
        o = Timeout(self, dt + self.time(), cb, a)
        self.timeouts.append(o)
        self.break_loop()
        return o
    def create_socket(self, addr='', port=None):
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
        return SystemInterfaceSocket(s=s, si=self, port=port)
    def create_dncp(self, proto_class, if_list=[], **kw):
        try:
            s = self.create_socket()
            main = True
        except socket.error:
            s = self.create_socket(port=0)
            main = False
        p = proto_class(sys=s, **kw)
        if main:
            # Ugly hackery to provide _some_ interface for multicast use
            if not if_list:
                for if_name in ['br-lan', 'en0', 'eth0']:
                    if _if_exists(if_name):
                        if_list = [if_name]
                        break
                assert if_list
            s.set_dncp_multicast(p, if_list=if_list, unicast_ep_name='listen')
        else:
            s.set_dncp_unicast_connect(p, ('::1', self.proto_port))
        return p
    def set_locked(self, locked):
        pass

class HNCPSystemInterface(SystemInterface):
    proto_group = 'ff02::8808'
    proto_port = 8808


