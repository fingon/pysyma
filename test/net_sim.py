#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: net_sim.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Thu Jul 23 11:41:04 2015 mstenber
# Last modified: Thu Jul 23 11:43:55 2015 mstenber
# Edit time:     1 min
#
"""

Abstract away the net_sim here so it can be used by different protocols' tests.

"""

import pysyma.dncp

import collections
import heapq
import binascii

import logging
_logger = logging.getLogger(__name__)
_debug = _logger.debug

MINIMUN_TIMEOUT=0.01 # in seconds
LOOP_SELF=True # do we want to sanity check
LOOP_SELF=False

class DummyNode(pysyma.dncp.Subscriber):
    def __init__(self, s):
        self.s = s
        self.events = []
        self.h = s.proto(self)
        self.h.add_subscriber(self)
    def event(self, n, *a, **kwa):
        self.events.append((n, a, kwa))
    def schedule(self, dt, cb, *a):
        if dt < MINIMUN_TIMEOUT: dt = MINIMUN_TIMEOUT
        _debug('%s schedule +%s %s(%s)' % (self, dt, cb, a))
        heapq.heappush(self.s.timeouts, (dt+self.s.t, self.s.tid, cb, a))
        self.s.tid += 1
    def send(self, ep, src, dst, tl):
        # TBD: Do we want delay here? Not for now.
        for nep in self.s.get_common_link_neps(ep, dst):
            def _fun():
                # src is ignored
                src = ep
                assert src != dst
                _debug('delayed send %s/%s -> %s/%s', src, ep, dst, nep)
                nep.dncp.ext_received(nep, src, dst, tl)
            self.schedule(0.01, _fun)
    def time(self):
        return self.s.t
    def ep(self, n, **kwa):
        o = self.h.find_or_create_ep_by_name(n, **kwa)
        if LOOP_SELF:
            self.s.set_connected(o, o) # always connect self
        o.ext_ready(True)
        return o

class DummySystem:
    def __init__(self, t=12345678, proto=None):
        self.nodes = []
        self.timeouts = []
        self.ep2ep = collections.defaultdict(set)
        self.t = t
        self.start_t = self.t
        self.tid = 0
        self.proto = proto or pysyma.dncp.HNCP
    def add_node(self):
        n = DummyNode(self)
        self.nodes.append(n)
        return n
    def poll(self):
        while self.timeouts and self.timeouts[0][0] <= self.t:
            t, tid, cb, a = heapq.heappop(self.timeouts)
            delta = ''
            if t != self.t:
                delta = '%s' % (self.t - t)
            _debug('poll running %s(%s) %s' % (cb, a, delta))
            cb(*a)
    def get_common_link_neps(self, ep, dst):
        # Either 'dst' matches the address stored in the dest, or it
        # matches multicast address and we return all.
        for nep in self.ep2ep[ep]:
            if dst == nep:
                yield nep
                return
            elif dst is None:
                yield nep
    def set_connected(self, e1, e2, connected=True, bidir=True):
        _debug('set_connected %s -> %s: %s', e1, e2, connected)
        if connected:
            self.ep2ep[e1].add(e2)
        else:
            self.ep2ep[e1].remove(e2)
        if not bidir:
            return
        self.set_connected(e2, e1, connected=connected, bidir=False)
    def is_converged_rw(self):
        count_nodes = set([len(n.h.id2node) for n in self.nodes if len(n.h.id2node)])
        if set([len(self.nodes)]) != count_nodes:
            _debug('is_converged: not, wrong counts in general, %s', count_nodes)
            return False
        count_nodes = set([len(list(n.h.valid_sorted_nodes())) for n in self.nodes if len(n.h.id2node)])
        if set([len(self.nodes)]) != count_nodes:
            _debug('is_converged: not, wrong counts in reachable, %s', count_nodes)
            return False
        return True
    def is_converged_ro(self):
        dirty_nodes = list([n for n in self.nodes if n.h.dirty])
        if dirty_nodes:
            _debug('is_converged: not, dirty nodes %s', dirty_nodes)
            return False
        hashes = set([binascii.b2a_hex(n.h.get_network_hash()) for n in self.nodes])
        if len(hashes) != 1:
            _debug('is_converged: not 1 hash? %s', hashes)
            return False
        return True
    def is_converged(self):
        return self.is_converged_ro() and self.is_converged_rw()
    def run_seconds(self, s):
        et = self.t + s
        self.run_until(lambda :self.next_time() > et)
        self.set_time(et)
    def run_until(self, cond, iter_ceiling=10000, time_ceiling=None):
        st = self.t
        i = 0
        if cond():
            return
        while True:
            self.poll()
            if cond():
                return
            assert self.timeouts
            self.set_time(self.next_time())
            i += 1
            assert i <= iter_ceiling
            assert time_ceiling is None or (st + time_ceiling) > self.t
    def run_while(self, cond, **kwa):
        return self.run_until(lambda :not cond(), **kwa)
    def next_time(self):
        return self.timeouts[0][0]
    def set_time(self, t):
        if self.t >= t:
            return
        _debug('set_time %s (+%s)' % (t, t - self.start_t))
        self.t = t

def setup_tube(n, ep_conf={}, proto=None):
    s = DummySystem(proto=proto)
    nodes = list([s.add_node() for i in range(n)])
    for i in range(len(nodes)-1):
        s.set_connected(nodes[i].ep('down', **ep_conf),
                        nodes[i+1].ep('up', **ep_conf))
    return s, nodes
