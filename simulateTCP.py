# from bitstring import BitArray
import pcapy
import sys


def getBytes(data):
    output = []
    for d in data:
        output.append(d)
    return output


if __name__ == '__main__':
    try:
        cap = pcapy.open_offline(sys.argv[1])
    except IndexError:
        print("Please include pcap file name")

    while True:
        header_info, header_data = cap.next()
        if (header_info is None):
            break
        header = getBytes(header_data)

        ip_header = header[14:34]
        print(ip_header)
        src_ip = ip_header[12:16]
        dest_ip = ip_header[16:20]
        
        tcp_header = header[34:]
        print(tcp_header)
        src_port = tcp_header[0] & 0x10 >> 16
        dest_port = tcp_header[0] & 0x01 >> 16

        print()

    
