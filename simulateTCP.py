import pcapy
import sys

try:
    cap = pcapy.open_offline(sys.argv[1])
except IndexError:
    print("Please include pcap file name")
packet = cap.next()
