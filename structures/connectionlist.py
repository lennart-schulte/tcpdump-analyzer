#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:softtabstop=4:shiftwidth=4:expandtab

# Script to calculate TCP reordering statistics.
#
# Copyright (C) 2009 - 2011 Lennart Schulte <lennart.schulte@rwth-aachen.de>
# Copyright (C) 2012 - 2014 Lennart Schulte <lennart.schulte@aalto.fi>
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.

from connection import Connection
from packet import Packet

class ConnectionList:
    '''
    Manages a list of connections.
    '''
    def __init__(self):
        self._cons = list()

    # check if connection exists (from a Packet)
    def find(self, p):
        for c in self._cons:
            if ((c.src == p.src) and (c.dst == p.dst) \
             and (c.sport == p.sport) and (c.dport == p.dport)):
                return c # found corresponding connection
        return None

    # find the other half connection
    def findHalf(self, c2):
        for c1 in self._cons:
            if ((c1.src == c2.dst) and (c1.dst == c2.src) \
             and (c1.sport == c2.dport) and (c1.dport == c2.sport)):
                return c1
        return None

    def add(self, c):
        self._cons.append(c)

