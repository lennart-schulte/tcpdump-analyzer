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
import socket
import dpkt
import struct

class TcpFlags:
    """
    Manages the TCP flags.
    """
    def __init__(self):
        self.ack = False
        self.syn = False
        self.rst = False
        self.fin = False
        self.urg = False
        self.psh = False

    def load(self, bits):
        flags = [0,0,0,0,0,0]
        for t in reversed(range(6)):
            flags[t] = bits % 2
            bits = bits/2
        (self.urg, self.ack, self.psh, self.rst, self.syn, self.fin) = flags

class TcpOpts:
    """
    Manages TCP options.
    """
    def __init__(self):
        self.wscale      = -1
        self.tsval       = 0
        self.tsecr       = 0

        self.sack_blocks = []
        self.sack        = False
        self.dsack       = False

    def load(self, bits, flags, ack):
        opt = dpkt.tcp.parse_opts(bits)

        for i in opt:
            # window scaling
            if flags.syn:
                if i[0] == 3:
                    self.wscale = ord(i[1])

            # Timestamps
            if i[0] == 8:
                oval = i[1]
                ofmt = "!"
                ofmt += "%iI" % (len(oval)/4)
                if ofmt and struct.calcsize(ofmt) == len(oval):
                    oval = struct.unpack(ofmt, oval)
                    if len(oval) == 1:
                        oval = oval[0]
                if len(oval) == 2:
                    self.tsval = oval[0]
                    self.tsecr = oval[1]

            # SACK and DSACK
            if i[0] == 5:
                oval = i[1]
                ofmt = "!"
                ofmt += "%iI" % (len(oval)/4)
                if ofmt and struct.calcsize(ofmt) == len(oval):
                    oval = struct.unpack(ofmt, oval)
                    if len(oval) == 1:
                        oval = oval[0]
                self.sack_blocks = oval
                self.sack = True

                # check dsack
                if ack >= self.sack_blocks[1]: #1st sack block, right edge
                    self.dsack = True
                if ack <= self.sack_blocks[0] and len(self.sack_blocks) >= 3 \
                 and (self.sack_blocks[0] >= self.sack_blocks[2] and self.sack_blocks[1] <= self.sack_blocks[3]):
                    #ex 2nd sack block, 1st sack block is covered by 2nd
                    self.dsack = True


class Packet:
    """
    This class manages a packet. It loads its content from the header data.
    All necessary information from the headers will then be accessible through
    this data structure.
    """
    def __init__(self, ip_hdr = None, ts = 0):
        self.ts           = 0
        self.carries_data = False

        # IP
        self.src          = None
        self.dst          = None
        self.ip_data_len  = 0

        # TCP
        self.sport        = 0
        self.dport        = 0
        self.tcp_data_len = 0

        self.ack          = 0
        self.seq          = 0
        self.win          = 0
        self.flags        = TcpFlags()
        self.opts         = TcpOpts()

        if ip_hdr != None:
            self.load(ip_hdr, ts)

    def load(self, ip_hdr, ts):
        self.ts = ts

        #try:
        if True:
            self.src          = socket.inet_ntoa(ip_hdr.src)
            self.dst          = socket.inet_ntoa(ip_hdr.dst)
            self.ip_data_len  = ip_hdr.len - (ip_hdr.hl * 4)

            tcp_hdr           = ip_hdr.data
            self.sport        = int(tcp_hdr.sport)
            self.dport        = int(tcp_hdr.dport)
            self.tcp_data_len = self.ip_data_len - (tcp_hdr.off * 4)
            self.ack          = int(tcp_hdr.ack)
            self.seq          = int(tcp_hdr.seq)
            self.win          = int(tcp_hdr.win)
            self.flags.load(tcp_hdr.flags)
            self.opts.load(tcp_hdr.opts, self.flags, self.ack)

            if self.tcp_data_len > 0:
                self.carries_data = True
        #except:
        #    logging.warn("tcp_hdr failed!")
        #    return



