#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: dncp_tlv.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Sat Jun 13 12:05:01 2015 mstenber
# Last modified: Thu Jul 23 12:37:32 2015 mstenber
# Edit time:     54 min
#
"""

A lot of this is just cut-n-paste from pybabel project; should
probably make some sort of shared library at some point, or better
yet, find one to reuse.

"""

import struct
import operator
import functools

RID_LEN = 8
MTU_ISH = 1400 # random MTU we use for splitting TLVs when we send stuff

UPDATE_FLAG_SET_DEFAULT_PREFIX=0x80
UPDATE_FLAG_SET_DEFAULT_RID=0x40

class Blob:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)
    @classmethod
    def decode(cls, x, *a, **kwa):
        o = cls()
        o.decode_buffer(x, *a, **kwa)
        return o
    def encode(self):
        raise NotImplementedError
    def decode_buffer(self, x):
        raise NotImplementedError
    def __eq__(self, o):
        return type(self) == type(o) and self.encode() == o.encode()
    def __lt__(self, o):
        return self.encode() < o.encode()
    def __hash__(self):
        return 0

functools.total_ordering(Blob)

class CStruct(Blob):
    format = None # subclass responsibility
    keys = [] # subclass responsibility
    arkeys = None # additional repr-keys
    def __init__(self, **kw):
        Blob.__init__(self, **kw)
    def __hash__(self):
        h = 0
        for key in self.keys:
            h = h ^ hash(getattr(self, key, None))
        return h
    def __repr__(self):
        ark = self.arkeys or []
        return '%s(%s)' % (self.__class__.__name__,
                           ', '.join(['%s=%s' % (k, repr(v)) for k, v in self.__dict__.items() if k in self.keys or k in ark]))
    def copy(self):
        return self.__class__(**self.__dict__)
    def get_format(self):
        # We store this in __class__ instead of self (ugly but fast)
        if '_fmt' not in self.__class__.__dict__:
            self.__class__._fmt = struct.Struct(self.format)
        return self._fmt
    def encode(self):
        fmt = self.get_format()
        return fmt.pack(*[getattr(self, k) for k in self.keys])
    def decode_buffer(self, x, ofs=0):
        fmt = self.get_format()
        for k, v in zip(self.keys, fmt.unpack_from(x, ofs)):
            if hasattr(self, k) and getattr(self, k) == v:
                continue
            setattr(self, k, v)
    def format_size(self):
        return self.get_format().size

# Observe hardcoded lengths (matching HNCP) of hash/node id
# length.. 4s/8s are the fields to replace :)

class TLV(CStruct):
    format = '>HH'
    keys = ['t', 'l']
    def wire_size(self):
        return self.format_size()
    def encode(self):
        self.l = self.wire_size() - TLV_SIZE
        return CStruct.encode(self)

TLV_SIZE=TLV().wire_size()
PAD_TO=4

class PadBodyTLV(TLV):
    arkeys = ['body']
    body = b''
    def decode_buffer(self, x, ofs=0):
        TLV.decode_buffer(self, x, ofs)
        bofs = ofs + self.format_size()
        blen = self.l - self.format_size() + TLV_SIZE
        b = x[bofs:bofs+blen]
        if b != self.body:
            self.body = b
    def pad_size(self):
        return PAD_TO and ((PAD_TO - len(self.body)) % PAD_TO) or 0
    def wire_size(self):
        return TLV.wire_size(self) + len(self.body) + self.pad_size()
    def encode(self):
        self.l = TLV.wire_size(self) + len(self.body) - TLV_SIZE
        return CStruct.encode(self) + self.body + bytearray([0] * self.pad_size())

class ReqNetState(TLV):
    t = 1

class ReqNodeState(TLV):
    t = 2
    format = TLV.format + '4s'
    keys = TLV.keys[:] + ['node_id']

class NodeEP(TLV):
    t = 3
    format = TLV.format + '4sI'
    keys = TLV.keys[:] + ['node_id', 'ep_id']

class NetState(TLV):
    t = 4
    format = TLV.format + '8s'
    keys = TLV.keys[:] + ['hash']

class NodeState(PadBodyTLV):
    t = 5
    format = TLV.format + '4sII8s'
    keys = TLV.keys[:] + ['node_id', 'seqno', 'age', 'hash']

# TBD Custom 6
# TBD Fragment Count 7

class Neighbor(TLV):
    t = 8
    format = TLV.format + '4sII'
    keys = TLV.keys[:] + ['n_node_id', 'n_ep_id', 'ep_id']

class KAInterval(TLV):
    t = 9
    format = TLV.format + 'II'
    keys = TLV.keys[:] + ['ep_id', 'interval']

_tlvlist = []
_tlvs = {}

def add_tlvs(*tlvs):
    for tlv in tlvs:
        _tlvlist.append(tlv)
        _tlvs[tlv.t] = tlv

add_tlvs(ReqNetState, ReqNodeState,
         NodeEP,
         NetState, NodeState,
         Neighbor, KAInterval)



def decode_tlvs(x):
    i = 0
    while i + TLV_SIZE <= len(x):
        t = TLV.decode(x, i).t
        tlv = _tlvs.get(t, PadBodyTLV).decode(x, i)
        yield tlv
        i += tlv.wire_size()

def encode_tlvs(*l):
    assert l
    # TBD: Is there some cross-Python-version 'more efficient' syntax?
    return functools.reduce(operator.add, [x.encode() for x in l])
