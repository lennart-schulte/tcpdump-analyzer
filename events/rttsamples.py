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

class RttSamples():
    def __init__(self, enable=True):
        self.enable = enable
        self.pktsent = dict()

    def addPacket(self, p):
        ts = p.ts
        seq = p.seq

        self.pktsent[seq] = ts

    def rexmit(self, p):
        # do not use retransmitted packets
        seq = p.seq
        if seq in self.pktsent:
            del self.pktsent[seq]

    def checkAck(self, con, ack):
        for seq in sorted(self.pktsent):
            if seq > max(con.acked, con.sacked):
                break

            # check SACK scoreboard
            done = False
            for b in con.sblocks:
                if b[0] > seq:
                    break
                if seq >= b[0] and seq < b[1]:
                    #print "SACK RTT", ack.ts, seq, ack.ts - self.pktsent[seq]
                    self.addSample(con, ack.ts, self.pktsent[seq])
                    del self.pktsent[seq]
                    done = True

            # cumulative ACK
	    if seq > ack.ack or done:
                continue

            self.addSample(con, ack.ts, self.pktsent[seq])
            del self.pktsent[seq]

    def addSample(self, con, ack_ts, pkt_ts):
        rtt = ack_ts - pkt_ts

        con.rtt_samples.append([ack_ts, rtt])
        #print ack_ts, rtt

