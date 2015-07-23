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
# Last modified: Thu Jul 23 14:21:18 2015 mstenber
# Edit time:     29 min
#
"""

This module defines SHSP, which is essentially HNCP subclass which
implements it's own (mandatory, lightweight) authentication scheme
based on PSKs and provides a neat distributed key-value store with
last-modified timestamps.

"""

from . import dncp
from pysyma.dncp_tlv import PadBodyTLV, add_tlvs

import json
import binascii

import logging
_logger = logging.getLogger(__name__)
_debug = _logger.debug
_error = _logger.error

JSON_ENCODING='utf-8'

class SHSPKV(PadBodyTLV):
    t = 100
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

add_tlvs(SHSPKV)

class SHSP(dncp.HNCP):
    def __init__(self, *a, **kw):
        dncp.HNCP.__init__(self, *a, **kw)
        self.local_dict = {}
    def get_dict(self, include_timestamp=False):
        r = {}
        for n in self.valid_sorted_nodes():
            h = {}
            for t in n._get_tlv_instances(SHSPKV):
                k = t.json['k']
                v = t.json['v']
                ts = t.json['ts']
                if include_timestamp:
                    h[k] = [ts, v]
                else:
                    h[k] = v
            if h:
                r[n.get_node_hash_hex()] = h
        return r
    def update_dict(self, d):
        for k, v in d.items():
            ot = self.local_dict.get(k, None)
            if ot:
                if ot.json['v'] == v:
                    continue
                self.remove_tlv(ot)
            # 'None' value is magical - it clears keys
            if v is None:
                continue
            ts = int(self.sys.time())
            nt = SHSPKV(json=dict(ts=ts, k=k, v=v))
            self.add_tlv(nt)
            self.local_dict[k] = nt
    def set_dict(self, d):
        d = d.copy()
        for k in set(self.local_dict.keys()).difference(set(d.keys())):
            d[k] = None
        self.update_dict(d)

