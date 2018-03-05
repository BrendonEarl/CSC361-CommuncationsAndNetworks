- Welcome to my TCP Traffic Analyzer

## A little about me
Name: Brendon Earl  
Student #: V00797149  

## And why I wrote this code
Course: CSC 361 (Communication Networks)  
Assignment: #2 - TCP Traffic Analysis  

## How to use this thing
Ensure you have __python3.6__ installed.  
As this application does have dependencies, 
ensure you install `pcapy` version `0.11` or higher. 
Depending on you environment you can do this using `pip3`, `pypi` or other package managers.  
If your setup uses `pip3` run `pip3 install pcapy`, and you should be good to go.  
Then, depending on your configutation run either:  

`python simulateTCP <pcap_file_location>` or  
`python3 simulateTCP <pcap_file_location>`

where `<pcap_file_location>` is a path like `./pcaps/my_example_pcap_file.pcap` or `my_example_pcap_file.pcap`

## Expected behaviour
This application will parse a pcap file, and do it's best to interpret and analyse 
every transaction. It should create an output according to the assignment spec, noted 
below in the output section.

## Output

```
A) Total number of connections: 48
------------------------------------------------------------------------------------------------------------
B) Connections' details:

(complete connection)
Connection 1:
Source Address: ---.---.---.---
Destination Address: ---.---.---.---
Source Port: --
Destination Port: --
Status: S#F# (+ R)?
Start Time: --
End Time: -.-
Duration: -.-
Number of packets sent from source to destination: --
Number of packets sent from destination to source: --
Total number of packets: --
Number of data bytes sent from source to destination: --
Number of data bytes sent from destination to source: --
Total number of data bytes: --
END
+++++++++++++++++++++++++++++++++
.
.
.
+++++++++++++++++++++++++++++++++
(incomplete connection)
Connection 2:
Source Address: ---.---.---.---
Destination Address: ---.---.---.---
Source Port: --
Destination Port: --
Status: S#F# (+ R)?
END
+++++++++++++++++++++++++++++++++
.
.
.
+++++++++++++++++++++++++++++++++
Connection N:
Source Address: ---.---.---.---
Destination Address: ---.---.---.---
Source Port: --
Destination Port: --
Status: S#F# (+ R)?
Start Time: --
End Time: -.-
Duration: -.-
Number of packets sent from source to destination: --
Number of packets sent from destination to source: --
Total number of packets: --
Number of data bytes sent from source to destination: --
Number of data bytes sent from destination to source: --
Total number of data bytes: --
END
------------------------------------------------------------------------------------------------------------
C) General
Total number of complete TCP connections: --
Number of reset TCP connections: --
Number of TCP connections that were still open when the trace capture ended: --
------------------------------------------------------------------------------------------------------------
D) Complete TCP connections:

Minimum time duration: --
Mean time duration: --
Maximum time duration: --

Minimum RTT value: --
Mean RTT value: --
Maximum RTT value: --

Minimum number of packets including both send/received: --
Mean number of packets including both send/received: --
Maximum number of packets including both send/received: --

Minimum receive window size including both send/received: --
Mean receive window size including both send/received: --
Maximum receive window size including both send/received: --
------------------------------------------------------------------------------------------------------------
```

__Happy Marking!__