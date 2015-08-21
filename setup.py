#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: setup.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2014 Markus Stenberg
#
# Created:       Tue Oct 14 10:46:31 2014 mstenber
# Last modified: Fri Aug 21 11:10:43 2015 mstenber
# Edit time:     1 min
#
"""

Minimalist setup.py

"""

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup

NAME='pysyma'

setup(name=NAME,
      version='0.0.1', # XXXX
      author = 'Markus Stenberg',
      author_email = 'fingon+%s@iki.fi' % NAME,
      packages = find_packages(),
      install_requires=['enum34', 'ipaddress']
      )

