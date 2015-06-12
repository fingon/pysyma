#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: test_dncp.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Fri Jun 12 13:25:03 2015 mstenber
# Last modified: Fri Jun 12 13:34:57 2015 mstenber
# Edit time:     1 min
#
"""

"""

import pysyma.dncp

# TBD: Implement something net_sim-ish here
class DummySystem:
    def schedule(self, dt, cb, *a):
        pass
    def time(self):
        return 0

def test_hncp():
    h = pysyma.dncp.HNCP(DummySystem())
