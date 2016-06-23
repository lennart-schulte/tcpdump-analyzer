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

    def check(self, con, p):
        # load con info
        self.start_time = 0        # start of interval
        self.start_ack  = 0        # ACK pointer at start of interval
        self.high_sent  = 0        # highest sent byte at start of interval

        if con.tputinfo.has_key('start_time'):
            self.start_time = con.tputinfo['start_time']
            self.start_ack  = con.tputinfo['start_ack']
        if con.half and con.half.tputinfo.has_key('high_sent'):
            self.high_sent  = con.half.tputinfo['high_sent']

        # current timestamp
        ts = p.ts

        # init
        if self.start_time == 0:
            self.start_time = ts
            self.start_ack  = max(con.acked, p.ack)

            con.tputinfo['start_time'] = self.start_time
            con.tputinfo['start_ack']  = self.start_ack

        if self.high_sent == 0 and con.half != None:
            self.high_sent = con.half.high

            con.half.tputinfo['high_sent']  = self.high_sent

        # interval finished?
        if ts - self.start_time > self.interval:
            # cumulatively ACKed bytes
            max_acked = con.acked
            acked = max(max_acked - self.start_ack, 0) # SACK might move start_ack

            # add SACKed bytes during this interval
            # TODO closing SACK hole
            sacked = 0
            for s in con.sblocks:
                if self.start_ack >= s[1]:
                    continue
                sacked += s[1] - max(self.start_ack, s[0])
                max_acked = max(max_acked, s[1])

            self.start_ack = max_acked

            # number of bytes sent
            sent = 0
            if con.half != None:
                sent = con.half.high - self.high_sent
                self.high_sent = con.half.high


            # add intervals
            self.addSample(con, acked+sacked, sent)

            while ts - self.start_time > self.interval:
                self.addSample(con, 0, 0)

            # update con tput info
            con.tputinfo['start_time'] = self.start_time
            con.tputinfo['start_ack']  = self.start_ack
            if con.half != None:
                con.half.tputinfo['high_sent']  = self.high_sent


    def addSample(self, con, acked, sent):

            next_time = self.start_time + self.interval
            #print next_time - self.start_time, acked
            con.tput_samples.append([self.start_time, next_time, acked, sent])

            self.start_time = next_time

