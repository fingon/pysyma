#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: test_shsp.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Thu Jul 23 11:45:29 2015 mstenber
# Last modified: Thu Jul 23 12:44:34 2015 mstenber
# Edit time:     9 min
#
"""

Test code for SHSP

"""

from net_sim import setup_tube
from pysyma.shsp import SHSP

def test_shsp():
    s, nodes = setup_tube(2, proto=SHSP)
    d = {'foo': 1, 'bar': 'baz'}
    nodes[0].h.update_dict(d)
    s.run_until(s.is_converged, time_ceiling=3)
    assert nodes[1].h.get_dict() != {}
    assert nodes[1].h.get_dict() == nodes[0].h.get_dict()

    # Ensure spurious set is spurious
    nodes[0].h.update_dict(d)
    assert s.is_converged()

    # And then clear it -> should propagate
    nodes[0].h.set_dict({})
    s.run_until(s.is_converged, time_ceiling=3)
    assert nodes[1].h.get_dict() == nodes[0].h.get_dict()
    assert nodes[1].h.get_dict() == {}

if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.DEBUG)
    test_shsp()
