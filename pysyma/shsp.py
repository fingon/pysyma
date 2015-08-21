#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: shsp.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Thu Jul 23 11:32:17 2015 mstenber
# Last modified: Fri Aug 21 09:49:29 2015 mstenber
# Edit time:     89 min
#
"""

This module defines SHSP, which is essentially HNCP subclass which
implements it's own (mandatory, lightweight) authentication scheme
based on PSKs and provides a neat distributed key-value store with
last-modified timestamps.

"""

from . import dncp
from pysyma.dncp_tlv import TLV, PadBodyTLV, add_tlvs, ContainerTLV

import json
import binascii
import hashlib

import logging
_logger = logging.getLogger(__name__)
_debug = _logger.debug
_error = _logger.error

JSON_ENCODING='utf-8'

class SHSPKV(PadBodyTLV):
    t = 789
    body = None
    def encode(self):
        if self.body is None:
            self.body = json.dumps(self.json).encode(JSON_ENCODING)
        return PadBodyTLV.encode(self)
    def decode_buffer(self, x, ofs=0):
        PadBodyTLV.decode_buffer(self, x, ofs)
        try:
            self.json = json.loads(self.body.decode(JSON_ENCODING))
        except:
            _error('parse error when parsing %s', binascii.b2a_hex(self.body))
            self.json = None
            self.body = b''

class SHSPAuth(ContainerTLV):
    t = 790
    format = TLV.format + '16s'
    keys = TLV.keys[:] + ['hash']
    def body_decoded(self):
        h = hashlib.md5(self.key + self.body).digest()
        if h != self.hash:
            _error('SHSPAuth hash mismatch')
            self.body = b''
            self.tlvs = []
    def body_encoded(self):
        self.hash = hashlib.md5(self.key + self.body).digest()

add_tlvs(SHSPKV, SHSPAuth)

class SHSPSubscriber(dncp.Subscriber):
    def dict_update_event(self, n, od, nd):
        pass

class SHSP(dncp.HNCP, SHSPSubscriber):
    subscriber_class = SHSPSubscriber
    at = None
    def __init__(self, *a, **kw):
        self.kv_dirty_nodes = set()
        key = None
        if 'key' in kw:
            key = kw.pop('key')
            # TBD - this could be SO much cleaner :p
            # (However, as SHSPAuth objects are created during decode
            # process, they would need some link back to SHSP object
            # to get the key; in practise, this is hard, so we take
            # shortcut here; no practical problems caused by this,
            # except that one Python instance can support only one
            # key. Too bad.)
            if key is not None:
                SHSPAuth.key = key
        dncp.HNCP.__init__(self, *a, **kw)
        self.local_dict = {}
        if key is not None:
            self.at = self.add_tlv(SHSPAuth())
        self.add_subscriber(self)
    def tlv_event(self, n, tlv, event):
        if not isinstance(tlv, SHSPKV) and not isinstance(tlv, SHSPAuth):
            return
        self.node_kv_is_dirty(n)
    def node_kv_is_dirty(self, n):
        # This node is potentially dirty. Start the delayed update.
        if not self.kv_dirty_nodes:
            self.sys.schedule(0, self.handle_kv_dirty_nodes)
        self.kv_dirty_nodes.add(n)
    def handle_kv_dirty_nodes(self):
        if not self.kv_dirty_nodes: return
        nodes = set(self.valid_sorted_nodes())
        dn = self.kv_dirty_nodes
        _debug('handle_kv_dirty_nodes %s', dn)
        self.kv_dirty_nodes = set()
        for n in dn:
            od = getattr(n, 'kv_d', {})
            nd = {}
            for t in self.get_node_kv_tlvs(n):
                k = t.json['k']
                v = t.json['v']
                ts = t.json['ts']
                nd[k] = [ts, v]
            n.kv_d = nd
            _debug(' %s: %s => %s', n, od, nd)
            if nd != od:
                self.event('dict_update_event', n, od, nd)
    def get_node_kv_tlvs(self, n):
        if n is self.own_node:
            self._flush_local()
        if self.at is None:
            for t in n.get_tlv_instances(SHSPKV):
                yield t
        else:
            for at in n.get_tlv_instances(SHSPAuth):
                for t in at.get_tlv_instances(SHSPKV):
                    yield t
    def get_dict(self, include_timestamp=False, printable_node=False):
        self.handle_kv_dirty_nodes()
        r = {}
        for n in self.valid_sorted_nodes():
            h = getattr(n, 'kv_d', None)
            if h:
                if printable_node: n = n.get_node_hash_hex()
                if not include_timestamp:
                    h = dict([(k, v) for (k, (ts, v)) in h.items()])
                r[n] = h
        return r
    def update_dict(self, d):
        _debug('%s update_dict %s', self, d)
        tlv_container = self.at or self
        for k, v in d.items():
            ot = self.local_dict.get(k, None)
            if ot:
                if ot.json['v'] == v:
                    continue
                tlv_container.remove_tlv(ot)
            # 'None' value is magical - it clears keys
            if v is None:
                continue
            ts = int(self.sys.time())
            nt = SHSPKV(json=dict(ts=ts, k=k, v=v))
            tlv_container.add_tlv(nt)
            self.local_dict[k] = nt
        self.kv_dirty_nodes.add(self.own_node)
    def set_dict(self, d):
        d = d.copy()
        for k in set(self.local_dict.keys()).difference(set(d.keys())):
            d[k] = None
        self.update_dict(d)

