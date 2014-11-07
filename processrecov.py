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
import logging

from packet import Packet
from connection import Connection

class Recovery():
    def __init__(self, enable=True):
        self.enable = enable

    def checkStart(self, con, p, newly_sacked):
        if len(con.sblocks) > 0:
            con.sacked = newly_sacked
            if con.interr_rexmits == 0: # not in RTO
                # there haven't been any SACK blocks, now there are new incoming -> start of disorder
                con.disorder = p.ts
                if con.half != None and con.half.high > 0:
                    con.recovery_point = con.half.high + con.half.high_len
                    con.flightsize = con.recovery_point - p.ack
                logging.debug("disorder begin (new SACK blocks) %s %s %s %s", p.opts.sack_blocks, datetime.fromtimestamp(p.ts), con.recovery_point, con.flightsize)

    def checkEnd(self, con, p):
        #if con.disorder > 0:
        #    print len(con.sblocks)
        if len(con.sblocks) == 0 and con.disorder > 0:    # it was disorder, now there are no more SACK blocks -> disorder ended
            if p.ack > con.acked: # for RTOs the above is not sufficient
                # begin and end of disorder phase, and number of frets/rtos
                spur = (1 if con.disorder_spurrexmit == con.disorder_fret else 0)

                con.disorder_phases.append([con.disorder, p.ts, con.disorder_fret, con.disorder_rto, spur,  con.disorder_spurrexmit])

                con.disorder = 0
                con.disorder_fret = 0
                con.disorder_rto = 0
                con.sacked = 0
                con.disorder_spurrexmit = 0
                con.flightsize = 0
                con.recovery_point = 0

                logging.debug("disorder end %s", datetime.fromtimestamp(p.ts))

