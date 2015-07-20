#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: test_hncp.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Sun Jul 19 09:14:49 2015 mstenber
# Last modified: Mon Jul 20 18:27:58 2015 mstenber
# Edit time:     108 min
#
"""

Minimal net-sim-ish test code

This stuff uses raw Endpoint _objects_ as src/dst addresses. While not
elegant, it also makes the code test relatively DNCP- and not
HNCP-specific.

Also, e.g. real addresses are not needed anywhere, and this sort of
proves it (sticking Endpoint TLVs anywhere results in bad things due
to lack of e.g. __eq__, __hash__, .. although of course built-in
equality operation of arbitrary instances does apply)

"""

MINIMUN_TIMEOUT=0.01 # in seconds
LOOP_SELF=True # do we want to sanity check
LOOP_SELF=False

import pysyma.dncp
from pysyma.dncp_tlv import *

import heapq
import collections

import logging
_logger = logging.getLogger(__name__)
_debug = _logger.debug

# TBD: Implement something net_sim-ish here
class DummyNode:
    def __init__(self, s):
        self.s = s
        self.h = pysyma.dncp.HNCP(self)
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
    def ep(self, n):
        o = self.h.find_or_create_ep_by_name(n)
        if LOOP_SELF:
            self.s.set_connected(o, o) # always connect self
        o.ext_ready(True)
        return o

class DummySystem:
    def __init__(self, t=12345678):
        self.nodes = []
        self.timeouts = []
        self.ep2ep = collections.defaultdict(set)
        self.t = t
        self.start_t = self.t
        self.tid = 0
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
    def is_converged(self):
        dirty_nodes = list([n for n in self.nodes if n.h.dirty])
        if dirty_nodes:
            _debug('is_converged: not, dirty nodes %s', dirty_nodes)
            return False
        hashes = set([n.h.network_hash for n in self.nodes])
        if len(hashes) != 1:
            _debug('is_converged: not 1 hash? %s', hashes)
            return False
        wrong_count_nodes = list([n for n in self.nodes if len(n.h.id2node) != len(self.nodes)])
        if wrong_count_nodes:
            _debug('is_converged: not with wrong # of nodes in %s', wrong_count_nodes)
            return False
        return True
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
            self.set_time(self.timeouts[0][0])
            i += 1
            assert i <= iter_ceiling
            assert time_ceiling is None or (st + time_ceiling) > self.t
    def run_while(self, cond, **kwa):
        return self.run_until(lambda :not cond(), **kwa)
    def set_time(self, t):
        if self.t >= t:
            return
        _debug('set_time %s (+%s)' % (t, t - self.start_t))
        self.t = t

def _setup_tube(n):
    s = DummySystem()
    nodes = list([s.add_node() for i in range(n)])
    for i in range(len(nodes)-1):
        s.set_connected(nodes[i].ep('down'),
                        nodes[i+1].ep('up'))
    return s, nodes

def test_hncp_tube():
    s, nodes = _setup_tube(10)
    s.run_until(s.is_converged, time_ceiling=30) # much too 'big'

def test_hncp_collision():
    n = 6
    s, nodes = _setup_tube(n)
    # even and odd id'd nodes have same id..
    for i in range(2, n):
        nodes[i].h.set_node_id(nodes[i%2].h.own_node.node_id)
    s.run_until(s.is_converged, time_ceiling=30) # much too 'big'


def test_hncp_two():
    s = DummySystem()
    n1 = s.add_node()
    n2 = s.add_node()
    e1 = n1.ep('eth0')
    e2 = n2.ep('eth1')
    assert e1.dncp == n1.h
    assert e2.dncp == n2.h
    assert n1 != n2
    assert n1.h != n2.h
    if LOOP_SELF:
        assert set(s.get_common_link_neps(e1, None)) == set([e1])
        assert set(s.get_common_link_neps(e1, e1)) == set([e1])
    else:
        assert set(s.get_common_link_neps(e1, None)) == set([])
    assert set(s.get_common_link_neps(e1, e2)) == set([])

    s.set_connected(e1, e2)
    if LOOP_SELF:
        assert set(s.get_common_link_neps(e1, None)) == set([e1, e2])
        assert set(s.get_common_link_neps(e1, e1)) == set([e1])
    else:
        assert set(s.get_common_link_neps(e1, None)) == set([e2])

    assert set(s.get_common_link_neps(e1, e2)) == set([e2])

    assert not s.is_converged()
    s.poll()
    assert not s.is_converged()

    s.run_while(s.is_converged)
    assert not s.is_converged()

    s.run_until(s.is_converged, time_ceiling=1) # should converge in subsecond
    assert s.is_converged()

    # Stick in TLV on n1
    dummy_tlv = PadBodyTLV(t=42, body=b'asd')
    n1.h.add_tlv(dummy_tlv)

    s.run_until(s.is_converged, time_ceiling=1) # should converge in subsecond
    assert s.is_converged()
    n21 = n2.h.find_or_create_node_by_id(n1.h.own_node.node_id)
    assert list([t for t in n21.tlvs if t.t==42]) == [dummy_tlv]

    s.set_connected(e1, e2, connected=False)
    if LOOP_SELF:
        assert set(s.get_common_link_neps(e1, None)) == set([e1])

    # Should un-converge due to lack of keepalives
    s.run_while(s.is_converged, time_ceiling=123)

    # Wait out grace interval too
    nt = s.t + pysyma.dncp.HNCP.GRACE_INTERVAL
    s.run_while(lambda :s.t < nt)

    n1l = list(n1.h.valid_sorted_nodes())
    n2l = list(n2.h.valid_sorted_nodes())
    assert (len(n1l) + len(n2l)) <= 3, '%s + %s <= 3' % (n1l, n2l)

if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.DEBUG)
    #test_hncp_two()
    test_hncp_tube()

