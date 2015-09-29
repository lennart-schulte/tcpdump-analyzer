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

import logging

class TputSamples():
    def __init__(self, enable=True, interval=0.050):
        self.enable = enable

        self.interval   = interval # in seconds
        self.start_time = 0        # start of interval
        self.start_ack  = 0        # ACK pointer at start of interval

    def check(self, con, p):
        # current timestamp
        ts = p.ts

        # init
        if self.start_time == 0:
            self.start_time = ts
            self.start_ack  = max(con.acked, p.ack)

        # interval finished?
        if ts - self.start_time > self.interval:
            # number of bytes: difference between cumACK + #SACKed
            max_acked = con.acked
            acked = max_acked - self.start_ack

            sacked = 0
            for s in con.sblocks:
                sacked += s[1] - s[0] # add all SACKed bytes

            self.addSample(con, acked+sacked)
            self.start_ack  = max_acked

            while ts - self.start_time > self.interval:
                self.addSample(con, 0)

    def addSample(self, con, acked):
            next_time = self.start_time + self.interval
            #print next_time - self.start_time, acked
                                          #start     end  bytes
            con.tput_samples.append([self.start_time, next_time, acked])

            self.start_time = next_time

