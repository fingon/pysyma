#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: dncp.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Fri Jun 12 11:18:59 2015 mstenber
# Last modified: Fri Jun 12 13:33:55 2015 mstenber
# Edit time:     97 min
#
"""

This is a lightweight implementation of DNCP. Notably, it attempts to
functionally mirror the C one in https://github.com/sbyx/hnetd/ at
much lower line count, while being slightly more Pythonic.

In some ways it is still very similar; ext_ calls are called from
outside. The profile_ calls are to be provided by profile (as opposed
to ext.cb in the C version).

"""

import enum

import random
import bisect

TLVEvent = enum.Enum('TLVEvent', 'add remove')
NodeEvent = enum.Enum('NodeEvent', 'add remove')
EPEvent = enum.Enum('EPEvent', 'add remove update')

class Subscriber:
    def republish(self): pass
    def local_tlv_event(self, tlv, event): pass
    def tlv_event(self, n, tlv, event): pass
    def node_event(self, n, event): pass
    def ep_event(self, ep, event): pass
    # msg reception callback omitted

class Endpoint:
    # dncp supplied by constructor always
    enabled = False
    last_sent = 0
    def __init__(self, **kwargs):
        self.__dict__.update(**kwargs)
    def _trickle_set_i(self, i):
        now = self.dncp.sys.time()
        self.i = min(max(self.dncp.TRICKLE_IMIN, i), self.dncp.TRICKLE_IMAX)
        self.send_time = now + self.i * (1 + random.random()) / 2
        self.interval_end_time = now + self.i
        self.c = 0
    def _send(self):
        self.last_sent = self.dncp.sys.time()
        # TBD
    def _trickle_send_maybe(self):
        if self.c < self.dncp.TRICKLE_K:
            self._send()
        self.send_time = 0
    def _run(self):
        assert self.enabled
        now = self.dncp.sys.time()
        next = last_sent + self.dncp.KEEPALIVE_INTERVAL
        if now < next:
            self._send()
            self._trickle_set_i(self.i)
            return self._run()
        if now >= self.interval_end_time:
            self._trickle_set_i(self.i * 2)
        if self.send_time:
            if now >= self.send_time:
                self._trickle_send_maybe()
            else:
                next = min(self.send_time, next)
        return min(next, self.interval_end_time)
    def ext_ready(self, enabled):
        if enabled == self.enabled: return
        self.enabled = enabled
        self.dncp._dispatch('ep_event', self, enabled and EPEvent.add or EPEvent.remove)

# local_tlv = must publish new local node (possibly)
# local_timestamp = local timestamp is historic -> MUST publish new
# graph = prune should be ran
# network_hash = one of the node hashes may be dirty
Dirty = enum.Enum('Dirty', 'graph network_hash local_tlv local_timestamp')

class Node:
    tlvs = []
    update_number = 0
    origination_time = 0
    hash_dirty = True
    hash_data = b''
    last_reachable = 0
    # dncp supplied by constructor always
    def __init__(self, **kwargs):
        self.__dict__.update(**kwargs)
    def get_hash(self):
        if self.hash_dirty:
            data = b''.join([x.encode() for x in self.tlvs])
            self.hash_data = self.dncp.profile_hash(data)
            self.hash_dirty = False
        return self.hash_data
    def is_self(self):
        return self.dncp.own_node is self
    def set_tlvs(self, tlvs):
        # Note: This could be done more efficiently. CBA.
        s1 = set(self.tlvs)
        s2 = set(tlvs)
        for t1 in s1.difference(s2):
            self.dncp._dispatch('tlv_event', self, t1, TLVEvent.remove)
        for t2 in s2.difference(s1):
            self.dncp._dispatch('tlv_event', self, t2, TLVEvent.add)
        self.tlvs = tlvs
        self.dncp.dirty.add(Dirty.network_hash)
        self.dncp.dirty.add(Dirty.graph)
        self.hash_dirty = True

class DNCP:
    # Subclass provides various upper case values
    own_node = None
    scheduled = False
    network_hash_data = b''
    last_prune = 0
    def __init__(self, sys):
        self.name2ep = {}
        self.id2ep = {}
        self.id2node = {}
        self.node_ids = []
        self.first_free_ep_id = 1
        self.tlvs = [] # local TLVs we want to publish
        self.dirty = set()
        self.subscribers = []
        self.sys = sys
    def _dispatch(self, n, *args):
        for s in self.subscribers:
            getattr(s, n)(*args)
    def find_ep_by_id(self, ep_id):
        return self.id2ep.get(ep_id, None)
    def find_ep_by_name(self, name):
        if name not in self.name2ep:
            ep = Endpoint(dncp=self, name=name, ep_id=self.first_free_ep_id)
            self.first_free_ep_id += 1
            self.name2ep[ep.name] = ep
            self.id2ep[ep.ep_id] = ep
        return self.name2ep[name]
    # has highest id: omitted (needed only by PA)
    def set_node_id(self, node_id):
        if self.own_node is not None:
            self.remove_node(self.own_node)
        self.add_node(Node(dncp=self, node_id=node_id))
        self.schedule(Dirty.local_tlv)
    def add_node(self, n):
        self.own_node = n
        self.id2node[n.node_id] = n
        self._dispatch('node_event', n, NodeEvent.add)
        self.schedule(Dirty.graph)
        bisect.insort(self.node_ids, n.node_id)
    def remove_node(self, n):
        del self.id2node[n.node_id]
        self._dispatch('node_event', n, NodeEvent.remove)
        self.schedule(Dirty.graph)
        del self.node_ids[n.node_id]
    def add_tlv(self, x):
        if x in self.tlvs: return
        bisect.insort(self.tlvs, x)
        self._dispatch('local_tlv_event', x, TLVEvent.add)
        self.schedule(Dirty.local_tlv)
    def remove_tlv(self, x):
        del self.tlvs[x]
        self._dispatch('local_tlv_event', x, TLVEvent.remove)
        self.schedule(Dirty.local_tlv)
    def schedule(self, *args):
        for k in args:
            self.dirty.add(k)
        if self.scheduled: return
        self.scheduled = True
        self.sys.schedule(0, self._run)
    def enabled_eps(self):
        for ep in self.id2ep.values():
            if ep.enabled:
                yield ep
    def valid_sorted_nodes(self):
        for nid in self.node_ids:
            n = self.id2node[nid]
            if n is self.own_node or n.last_reachable == self.last_prune:
                yield n
    def _run(self):
        now = self.sys.time()
        next = now + 60 # by default we run every 60 seconds, no matter what
        if (now - self.own_node.origination_time) > (2**32 - 2**16):
            self.dirty.add(Dirty.local_timestamp)
        self._flush_local()
        self._calculate_network_hash()
        for ep in self.enabled_eps():
            next = min(next, ep._run())
    def _calculate_network_hash(self):
        if not Dirty.network_hash in self.dirty: return
        data = b''.join([struct.pack('>I', n.update_number) + n.get_hash() for n in self.valid_sorted_nodes()])
        if data == self.network_hash_data: return
        self.network_hash_data = data
        for ep in self.name2ep.values():
            ep.trickle_set_i(self.TRICKLE_IMIN)
    def _flush_local(self):
        if not Dirty.local_tlv in self.dirty: return
        if self.tlvs == self.own_node.tlvs and not Dirty.local_timestamp in self.dirty:
            return
        self.own_node.set_tlvs(self.tlvs[:])
        self.own_node.update_number += 1
        self.own_node.origination_time = self.sys.time()
        self.dirty.add(Dirty.network_hash)
    def profile_collision(self):
        raise NotImplementedError # child responsibility
    def profile_hash(self, h):
        raise NotImplementedError # child responsibility

import hashlib

class HNCP(DNCP):
    HASH_LENGTH = 8
    NODE_ID_LENGTH = 4
    TRICKLE_IMIN = 0.2
    TRICKLE_IMAX = 40
    TRICKLE_K = 1
    KEEPALIVE_INTERVAL = 24
    KEEPALIVE_MULTIPLIER = 2.1
    GRACE_INTERVAL = 60
    def _set_id(self, node_id):
        if node_id is None:
            node_id = bytearray([random.randint(0, 256) for i in range(self.NODE_ID_LENGTH)])
            node_id = bytes(node_id)
        self.set_node_id(node_id)
    def __init__(self, sys, node_id=None):
        DNCP.__init__(self, sys)
        self._set_id(node_id)
    def profile_hash(self, b):
        return hashlib.md5(b).digest()[:self.HASH_LENGTH]
    def profile_collision(self):
        self._set_id(None)



