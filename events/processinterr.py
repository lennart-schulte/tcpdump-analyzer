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

from datetime import datetime

class Interruption():
    def __init__(self, enable=True):
        self.enable = True

    def detect(self, con, p):
        if not self.enable:
            return

        if not con.rst and not con.fin:
            # if there hasn't been an ACK in some time -> connection interruption
            #print ts - con.last_ts #print every ACK inter arrival time
            spurious = 0
            if con.interr_rto_tsval != 0 and p.opts.tsecr < con.interr_rto_tsval:
                spurious = 1
            con.interruptions.append([con.last_ts, p.ts, con.interr_rexmits, spurious])
            con.interr_rexmits = 0
            con.interr_rto_tsval = 0
            #print datetime.fromtimestamp(con.last_ts),datetime.fromtimestamp(ts),datetime.fromtimestamp(con.istart)
