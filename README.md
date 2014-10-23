tcpdump-analyzer
================
```
usage: pcapstats.py [-h] [-j] [-t TIMELIMIT] [-n] [-q] [-d] pcapfile

Parses PCAP files and extracts information from TCP connections about
connection interruptions, recovery phases and reordering.

positional arguments:
  pcapfile              pcap file to analyse

optional arguments:
  -h, --help            show this help message and exit
  -j, --json            output in JSON format
  -t TIMELIMIT, --timelimit TIMELIMIT
                        analyse only the first <TIMELIMIT> seconds of the
                        connection [default: 0 = analyse all]
  -n, --netradar        use Netradar ports to distinguish connections
  -q, --quiet           decrease output verbosity
  -d, --debug           debug message output
```

Example output:
```
ip1:port1 - ip2:port2 --> 861 pkts in 9.99 s, MSS = 63848, 16716.59 kbit/s
Options: SACK = 1, DSACK = 1, TS = 1
Connection Interruption time: 0.81 s ( 5 interruptions, 0 with RTOs, 0 spurious ) --> 18201.24 kbit/s
Fast Recovery time: 0.15 s ( 1 phases, 0 spurious, 0 with RTOs, 2 total frets )
Reorder: W/o retransmit = 5 , Closed SACK holes = 6 , Rexmits (TSval tested) = 1 , DSACK+TS = 0
```
Output in JSON format provides more information (each event individually).
