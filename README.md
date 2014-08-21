tcpdump-analyzer
================

usage: pcapstats.py [-h] [-j] [-t TIMELIMIT] [-n] pcapfile

Parses PCAP files and extracts information like connection interruptions,
retransmission phases and unnecessary retransmissions.

positional arguments:
  pcapfile              pcap file to analyse

optional arguments:
  -h, --help            show this help message and exit
  -j, --json            output in JSON format
  -t TIMELIMIT, --timelimit TIMELIMIT
                        analyse only the first <time> seconds of the
                        connection [default: 0 = analyse all]
  -n, --netradar        use Netradar ports to distinguish connections
  
  
Example output:
ip1:por1 - ip2:port2 --> 1280 pkts in 9.8902118206 s, MSS = 40544, 6419.12 kbit/s
Options: SACK = 1, DSACK = 1, TS = 1
Connection Interruption time: 3.01 s ( 19 interruptions, 0 with RTOs, 0 spurious ) --> 9221.09 kbit/s
Fast Recovery time: 4.28 s ( 5 phases, 0 spurious, 1 with RTOs, 48 total frets )
Reorder: W/o retransmit = 0 , Closed SACK holes = 0 , Rexmits (TSval tested) = 19
Reorder extends: [85432, 83984, 82536, 81088, 79640, 78192, 76744, 75296, 73848, 72400, 70952, 68056, 66608, 65160, 63712, 62264, 60816, 59368, 57920]
