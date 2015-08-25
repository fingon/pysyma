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
# Last modified: Tue Aug 25 11:19:59 2015 mstenber
# Edit time:     521 min
#
"""

This is a lightweight implementation of DNCP. Notably, it attempts to
functionally mirror the C one in https://github.com/sbyx/hnetd/ at
much lower line count, while being slightly more Pythonic.

In some ways it is still very similar; ext_ calls are called from
outside. The profile_ calls are to be provided by profile (as opposed
to ext.cb in the C version).

In some ways, it is not; it intentionally implements only HNCP
transport specific subset of DNCP (e.g. no per-peer keep-alives,
stream support).

"""

import binascii
import enum

import random
import bisect
from pysyma.dncp_tlv import *

TLVEvent = enum.Enum('TLVEvent', 'add remove')
NodeEvent = enum.Enum('NodeEvent', 'add remove')
EPEvent = enum.Enum('EPEvent', 'add remove update')

import logging
_logger = logging.getLogger(__name__)
_debug = _logger.debug

class Subscriber:
    def handle_event(self, n, *a, **kwa): return getattr(self, n)(*a, **kwa)

    # Similar to hnetd
    def republish_event(self): pass
    def local_tlv_event(self, tlv, event): pass
    def tlv_event(self, n, tlv, event): pass
    def node_event(self, n, event): pass
    def ep_event(self, ep, event): pass
    # msg reception callback omitted

    # Python specific

    # Convenience callback to identify when we're consistent with
    # someone _on the link_.
    def network_consistent_event(self, is_consistent): pass

class Trickle:
    def __init__(self, **kwargs):
        self.__dict__.update(**kwargs)
        self.last_sent = self.dncp.sys.time()
        self.set_i(0)
    def set_i(self, i):
        now = self.dncp.sys.time()
        self.i = min(max(self.dncp.TRICKLE_IMIN, i), self.dncp.TRICKLE_IMAX)
        _debug('%s set_i %s', self, self.i)
        self.send_time = now + self.i * (1 + random.random()) / 2
        self.interval_end_time = now + self.i
        self.c = 0
    def _run(self):
        now = self.dncp.sys.time()
        if now >= self.interval_end_time:
            self.set_i(self.i * 2)
            return self._run()
        ka_time = self.last_sent + self.dncp.KEEPALIVE_INTERVAL
        if now >= ka_time:
            self.send()
            self.last_sent = self.dncp.sys.time()
            return self._run()
        if now >= self.send_time:
            self._trickle_send_maybe()
        return min(ka_time, self.send_time, self.interval_end_time)
    def _trickle_send_maybe(self):
        if self.c < self.dncp.TRICKLE_K:
            self.send()
            self.last_sent = self.dncp.sys.time()
        self.send_time = self.interval_end_time

class Endpoint:
    # dncp supplied by constructor always
    enabled = False
    def __init__(self, **kwargs):
        self.per_endpoint_ka = kwargs['dncp'].PER_ENDPOINT_KA
        self.per_peer_ka = kwargs['dncp'].PER_PEER_KA
        self.__dict__.update(**kwargs)
        if self.per_endpoint_ka:
            self.trickle = Trickle(dncp=self.dncp, send=self.send_net_state)
    def __repr__(self):
        nid = self.dncp.own_node.node_id
        nid = binascii.b2a_hex(nid)
        return '<Endpoint %s[%d]@/%s>' % (self.name, self.ep_id, nid)
    def send_net_state(self, src=None, dst=None, req=False):
        l = [NetState(hash=self.dncp.get_network_hash())]
        if req:
            l.append(ReqNetState())
        elif dst:
            for n in self.dncp.valid_sorted_nodes():
                l.append(n._get_ns(short=True))
        self.send(src, dst, l)
    def send(self, src, dst, l):
        if not self.dncp.read_only:
            l[0:0] = [NodeEP(node_id=self.dncp.own_node.node_id,
                             ep_id=self.ep_id)]
        _debug('%s send %s->%s: %s', self, src, dst, l)
        self.sys_send(src, dst, l)
    def sys_send(self, src, dst, l):
        # By default, use 'global dispatch'. This may be overridden..
        return self.dncp.sys.send(self, src, dst, l)
    def _run(self):
        _debug('%s _run', self)
        assert self.enabled
        try:
            return min([x._run() for x in self.get_trickles()])
        except ValueError:
            return None
    def get_trickles(self):
        if self.per_endpoint_ka:
            yield self.trickle
        if self.per_peer_ka:
            for n in [tlv for tlv in self.dncp.get_tlv_instances(Neighbor) if tlv.ep_id == self.ep_id]:
                yield n.trickle
    def ext_ready(self, enabled):
        if enabled == self.enabled: return
        self.enabled = enabled
        self.dncp.event('ep_event', self, enabled and EPEvent.add or EPEvent.remove)

# local_tlv = must publish new local node (possibly)
# local_always = local timestamp/update# is historic -> MUST publish new
# graph = prune should be ran
# network_hash = one of the node hashes may be dirty
Dirty = enum.Enum('Dirty', 'graph network_hash local_tlv local_always')

class Node(TLVList):
    seqno = 0
    origination_time = 0
    _node_data = None
    _node_hash = None
    last_reachable = 0
    collided = False
    # dncp supplied by constructor always
    def __init__(self, **kwargs):
        self.__dict__.update(**kwargs)
    def get_node_id_hex(self):
        return binascii.b2a_hex(self.node_id)
    def get_node_hash_hex(self):
        return binascii.b2a_hex(self.get_node_hash())
    def get_node_data(self):
        if self._node_data is None:
            self._node_data = encode_tlvs(*self.tlvs)
        return self._node_data
    def get_node_hash(self):
        if self._node_hash is None:
            self._node_hash = self.dncp.profile_hash(self.get_node_data())
        return self._node_hash
    def is_self(self):
        return self.dncp.own_node is self
    def set_tlvs(self, tlvs):
        tlvs = list(tlvs)
        _debug('%s set_tlvs %s', self, tlvs)
        # Note: This could be done more efficiently. CBA.
        s1 = set(self.tlvs or [])
        s2 = set(tlvs or [])
        for t1 in s1.difference(s2):
            self.dncp.event('tlv_event', self, t1, TLVEvent.remove)
        self.tlvs = tlvs
        for t2 in s2.difference(s1):
            self.dncp.event('tlv_event', self, t2, TLVEvent.add)
        self.dncp.schedule_immediate_dirty(Dirty.network_hash, Dirty.graph)
        self._node_data = None
        self._node_hash = None
    def _prune_traverse(self):
        # Already traversed this prune?
        if self.last_reachable == self.dncp.last_prune:
            return
        _debug(' _prune_traverse %s', self)
        self.last_reachable = self.dncp.last_prune
        for ntlv, n in self._get_bidir_neighbors():
            n._prune_traverse()
    def _get_bidir_neighbors(self):
        for t1 in self.get_tlv_instances(Neighbor):
            n = self.dncp.id2node.get(t1.n_node_id)
            if not n: continue
            if self.is_self() and self.dncp.read_only:
                yield None, n
            else:
                for t2 in n.get_tlv_instances(Neighbor):
                    if t1.ep_id == t2.n_ep_id and t1.n_ep_id == t2.ep_id and t2.n_node_id == self.node_id:
                        yield t1, n
    def _get_ns(self, short):
        assert self.seqno
        if not short and self.is_self():
            self.dncp._flush_local()
        now = self.dncp.sys.time()
        return NodeState(node_id=self.node_id,
                         seqno=self.seqno,
                         age=int(1000 * (now-self.origination_time)),
                         hash=self.get_node_hash(),
                         body=(not short and self.get_node_data() or b''))
    def _update_from_ns(self, ns):
        # Ignore if it's older
        if ns.seqno < self.seqno:
            return
        # Ignore if we already have it
        if ns.seqno == self.seqno and ns.hash == self.get_node_hash():
            return
        if not ns.body:
            return True
        if self.dncp.profile_hash(ns.body) != ns.hash:
            _error('_update_from_ns received corrupted hash')
            return
        if self.is_self():
            _debug('_update_from_ns from own id - collision')
            if self.collided:
                self.dncp.profile_collision()
            else:
                self.collided = True
                self.seqno = ns.seqno + 1000
            self.dncp.schedule_immediate_dirty(Dirty.local_tlv,
                                               Dirty.local_always)
            return
        tlvs = decode_tlvs(ns.body)
        if tlvs is None:
            return
        now = self.dncp.sys.time()
        self.seqno = ns.seqno
        self.origination_time = now - ns.age / 1000.0
        self.set_tlvs(tlvs)
        self.dncp.schedule_immediate_dirty(Dirty.network_hash)
        # paranoia starts here:
        assert self.get_node_hash() == ns.hash

class SystemInterface:
    def schedule(self, dt, cb):
        raise NotImplementedError
    def send(self, ep, src, dst, tlvs):
        raise NotImplementedError
    def time(self):
        raise NotImplementedError

class DNCP(TLVList):
    # Subclass provides various upper case values
    own_node = None
    scheduled_immediate = False
    scheduled_run = 0
    last_prune = 0
    last_rns = 0 # last request node state sent
    last_seen_network_hash = None
    network_consistent = None
    network_hash = None
    read_only = False
    subscriber_class = Subscriber
    def __init__(self, sys, **kwa):
        self.__dict__.update(**kwa)
        self.name2ep = {}
        self.id2ep = {}
        self.id2node = {}
        self.node_ids = []
        self.first_free_ep_id = 1
        self.dirty = set()
        self.dirty.add(Dirty.network_hash)
        self.subscribers = []
        assert isinstance(sys, SystemInterface)
        self.sys = sys
        self.schedule_immediate_dirty()
    def add_subscriber(self, s):
        assert not self.subscriber_class or isinstance(s, self.subscriber_class)
        self.subscribers.append(s)
    def event(self, n, *a, **kw):
        _debug('%s event %s %s %s', self, n, a, kw)
        for s in self.subscribers:
            s.handle_event(n, *a, **kw)
    def find_ep_by_id(self, ep_id):
        return self.id2ep.get(ep_id, None)
    def find_ep_by_name(self, name):
        return self.name2ep.get(name, None)
    def create_ep(self, name, **kw):
        assert not self.find_ep_by_name(name)
        ep = Endpoint(dncp=self, name=name, ep_id=self.first_free_ep_id, **kw)
        self.first_free_ep_id += 1
        self.name2ep[ep.name] = ep
        self.id2ep[ep.ep_id] = ep
        return self.name2ep[name]
    def find_or_create_node_by_id(self, node_id):
        if node_id not in self.id2node:
            t = self.sys.time()-1
            t = max(t-self.GRACE_INTERVAL/2, min(t, self.last_prune-1))
            return self.add_node(Node(dncp=self, node_id=node_id, last_reachable=t))
        return self.id2node[node_id]
    # has highest id: omitted (needed only by PA)
    def set_node_id(self, node_id):
        _debug('%s set_node_id %s', self, binascii.b2a_hex(node_id))
        if self.own_node is not None:
            self.remove_node(self.own_node)
        self.schedule_immediate_dirty(Dirty.local_tlv)
        return self.add_node(Node(dncp=self, node_id=node_id), own=True)
    def add_node(self, n, own=False):
        _debug('%s add_node %s', self, n)
        if own:
            self.own_node = n
        self.id2node[n.node_id] = n
        self.event('node_event', n, NodeEvent.add)
        self.schedule_immediate_dirty(Dirty.graph)
        bisect.insort(self.node_ids, n.node_id)
        return n
    def remove_node(self, n):
        _debug('%s remove_node %s', self, n)
        del self.id2node[n.node_id]
        self.event('node_event', n, NodeEvent.remove)
        self.schedule_immediate_dirty(Dirty.graph)
        self.node_ids.remove(n.node_id)
    def add_tlv(self, x):
        if self.tlvs is None: self.tlvs = []
        ox = self.has_tlv(x)
        if ox is not None: return ox
        assert isinstance(x, Neighbor) or not self.read_only
        _debug('%s add_tlv %s', self, x)
        bisect.insort(self.tlvs, x)
        if isinstance(x, ContainerTLV): x.parent = self
        self.event('local_tlv_event', x, TLVEvent.add)
        self.schedule_immediate_dirty(Dirty.local_tlv)
        return x
    def remove_tlv(self, x):
        _debug('%s remove_tlv %s', self, x)
        if isinstance(x, ContainerTLV): del x.parent
        assert x in self.tlvs, '%s not in %s' % (x, self.tlvs)
        self.tlvs.remove(x)
        self.event('local_tlv_event', x, TLVEvent.remove)
        self.schedule_immediate_dirty(Dirty.local_tlv)
    def schedule_immediate_dirty(self, *args):
        for k in args:
            self.dirty.add(k)
        if self.scheduled_immediate: return
        _debug('%s schedule_immediate_dirty %s', self, args)
        self.scheduled_immediate = True
        self.sys.schedule(0, self._run)
    def enabled_eps(self):
        for ep in self.id2ep.values():
            if ep.enabled:
                yield ep
    def valid_sorted_nodes(self):
        for nid in self.node_ids:
            n = self.id2node[nid]
            if n.is_self():
                if self.read_only and not len(list(n.get_tlv_matching(lambda t:not isinstance(t, Neighbor)))):
                    continue
            if n.tlvs and n.last_reachable == self.last_prune:
                yield n
    def _prune(self):
        if not Dirty.graph in self.dirty:
            return
        _debug('_prune')
        self.dirty.remove(Dirty.graph)
        # Ok, let's run prune
        now = self.sys.time()
        self.last_prune = now
        self.own_node._prune_traverse()
        # Eliminate unreachable nodes
        pending_remove = []
        for node in self.id2node.values():
            if node.last_reachable and (node.last_reachable + self.GRACE_INTERVAL) < now:
                pending_remove.append(node)
        for node in pending_remove:
            self.remove_node(node)
        self.dirty.add(Dirty.network_hash)
    def _prune_neighbors(self):
        _debug('_prune_neighbors')
        now = self.sys.time()
        for ntlv in list(self.get_tlv_instances(Neighbor)):
            n = self.id2node.get(ntlv.n_node_id)
            ka_interval = self.KEEPALIVE_INTERVAL
            if n:
                ka_tlvs = list([t for t in n.get_tlv_instances(KAInterval) if t.ep_id == ntlv.ep_id or not t.ep_id])
                if ka_tlvs: ka_interval = ka_tlvs[-1].interval / 1000.0
                #_debug('ka_tlvs for %s: %s', n, ka_tlvs)
            dead_interval = ka_interval * self.KEEPALIVE_MULTIPLIER
            ttl = (ntlv.last_contact + dead_interval) - now
            if ttl < 0:
                self.remove_tlv(ntlv)
            _debug(' %s ttl %s', ntlv, ttl)
    def _run(self):
        _debug('%s _run', self)
        self.scheduled_immediate = False
        now = self.sys.time()
        next = now + 60 # by default we run every 60 seconds, no matter what
        if (now - self.own_node.origination_time) > (2**32 - 2**16):
            self.dirty.add(Dirty.local_tlv)
            self.dirty.add(Dirty.local_always)
        self._prune_neighbors()
        self._prune()
        self._flush_local()
        self.get_network_hash()
        for ep in self.enabled_eps():
            next = min(filter(None, [next, ep._run()]))
        if self.scheduled_immediate:
            return
        if self.dirty:
            _debug('_run repeating immediately - dirty: %s', self.dirty)
            self.schedule_immediate_dirty()
            return
        assert next > now
        if self.scheduled_run > now and self.scheduled_run <= next:
            return
        _debug('_run done - next: %s > %s', next, now)
        self.sys.schedule(next - now, self._run)
        self.scheduled_run = next
    def get_network_hash(self):
        if Dirty.network_hash in self.dirty:
            self.dirty.remove(Dirty.network_hash)
            _debug('%s _calculate_network_hash', self)
            l = list([(struct.pack('>I', n.seqno) + n.get_node_hash()) for n in self.valid_sorted_nodes()])
            for n in self.valid_sorted_nodes():
                _debug(' %s %d %s', n.get_node_id_hex(), n.seqno,
                       n.get_node_hash_hex())
            if l:
                data = functools.reduce(operator.add, l)
            else:
                data = b''
            data = self.profile_hash(data)
            if data != self.network_hash:
                _debug('=> %s', binascii.b2a_hex(data))
                self.network_hash = data
                # Reset Trickle
                for ep in self.name2ep.values():
                    for t in ep.get_trickles():
                        t.set_i(0)
            self.is_consistent() # send update if we match network
        return self.network_hash
    def get_network_hash_hex(self):
        return binascii.b2a_hex(self.get_network_hash())
    def _flush_local(self):
        if not Dirty.local_tlv in self.dirty: return
        self.dirty.remove(Dirty.local_tlv)
        if self.tlvs == self.own_node.tlvs:
            if not Dirty.local_always in self.dirty:
                _debug('%s _flush_local found nothing to flush', self)
                return
        try:
            self.dirty.remove(Dirty.local_always)
        except KeyError:
            pass
        self.event('republish_event')
        # To be sure nested dependencies are handled fine, we encode +
        # decode it right here..
        nl = []
        if self.tlvs:
            b = encode_tlvs(*self.tlvs)
            nl = list(decode_tlvs(b))
            assert nl
        self.own_node.set_tlvs(nl)
        self.own_node.seqno += 1
        self.own_node.origination_time = self.sys.time()
        self.schedule_immediate_dirty(Dirty.network_hash)
    def _heard(self, ep, src, dst, eptlv):
        # don't add self as neighbor, ever
        if eptlv.node_id == self.own_node.node_id: return
        ftlv = Neighbor(n_node_id=eptlv.node_id,
                        n_ep_id=eptlv.ep_id,
                        ep_id=ep.ep_id)
        for ntlv in self.get_tlv_instances(Neighbor):
            if ftlv == ntlv:
                return ntlv
        if dst is None:
            return
        ftlv.last_contact = self.sys.time()
        if ep.per_peer_ka:
            def _send_net_state():
                ep.send_net_state(src=dst, dst=src)
                ftlv.trickle.last_sent = self.sys.time()
            ftlv.trickle = Trickle(dncp=self, send=_send_net_state)
        return self.add_tlv(ftlv)
    def is_consistent(self):
        is_consistent = self.last_seen_network_hash == self.get_network_hash()
        if self.network_consistent is not is_consistent:
            self.network_consistent = is_consistent
            self.event('network_consistent_event', is_consistent)
        return is_consistent
    def ext_received(self, ep, src, dst, l):
        #l = decode_tlvs(body)
        l = list(l)
        _debug('%s ext_received on %s : %s -> %s - %s', self, ep, src, dst, l)
        ne = None
        now = self.sys.time()
        nep = None
        assert src is not None
        want_rns = False
        for t in l:
            if isinstance(t, NodeEP):
                ne = self._heard(ep, src, dst, t)
                if dst is None and ne is None:
                    want_rns = True
            elif isinstance(t, ReqNetState):
                ep.send_net_state(src=dst, dst=src)
                if ne and ep.per_peer_ka:
                    ne.trickle.last_sent = self.sys.time()
            elif isinstance(t, ReqNodeState):
                n = self.id2node.get(t.node_id)
                if n and n.last_reachable == self.last_prune:
                    ep.send(dst, src, [n._get_ns(short=False)])
                else:
                    _debug(' ignoring reqnodestate %s, not up to date', t)
            elif isinstance(t, NetState):
                self.last_seen_network_hash = t.hash
                is_consistent = self.is_consistent()
                _debug('NetState is %s (%s)', is_consistent, ne)
                if is_consistent:
                    if ne:
                        ne.last_contact = now
                else:
                    want_rns = True
            elif isinstance(t, NodeState):
                if self.find_or_create_node_by_id(t.node_id)._update_from_ns(t):
                    ep.send(dst, src, [ReqNodeState(node_id=t.node_id)])
            else:
                _error('unknown top-level TLV: %s', t)
        if dst and ne:
            ne.last_contact = now
        if want_rns and (self.last_rns + self.TRICKLE_IMIN) < now:
            self.last_rns = now
            ep.send_net_state(src=dst, dst=src, req=True)

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
    KEEPALIVE_INTERVAL = 20
    KEEPALIVE_MULTIPLIER = 2.1
    GRACE_INTERVAL = 60
    PER_PEER_KA = False
    PER_ENDPOINT_KA = True
    def _set_id(self, node_id):
        if node_id is None:
            while True:
                node_id = bytearray([random.randint(0, 255) for i in range(self.NODE_ID_LENGTH)])
                node_id = bytes(node_id)
                if node_id not in self.id2node:
                    break
        self.set_node_id(node_id)
    def __init__(self, sys, node_id=None, **kw):
        DNCP.__init__(self, sys, **kw)
        self._set_id(node_id)
    def profile_hash(self, b):
        return hashlib.md5(b).digest()[:self.HASH_LENGTH]
    def profile_collision(self):
        self._set_id(None)



