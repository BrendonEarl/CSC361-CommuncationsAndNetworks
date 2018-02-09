# from bitstring import BitArray
import pcapy
import sys

class Connection:
    def __init__(self, ip1, ip2, port1, port2, start_time):
        self.ip1 = ip1
        self.ip2 = ip2
        self.port1 = port1
        self.port2 = port2
        self.start_time = start_time
        self.end_time = None
        self.pkts_1 = 0
        self.pkts_2 = 0
        self.syn = 0
        self.fin = 0
        self.rst = 0
    
    def close_connection(end_time):
        if this.end_time is not None:
            print("Connection already closed")
            return
        this.end_time = end_time
    
    def get_duration(close_time):
        if this.close_time is None: return None
        return this.close_time - this.start_time
    
    def add_packet(src_ip):
        if src_ip == self.ip1: self.pkts_1 += 1
        elif src_ip == self.ip2: self.pkts_2 += 1
        else:
            print("Wrong Connection:")
            print("Attempted ip: {}".format(src_ip))
            print("On connection between {} and {}".format(self.ip1, self.ip2))
    
    def check_connection(ip1, ip2):
        if (ip1 == self.ip1 and ip2 == self.ip2) or (ip1 == self.ip2 and ip2 == self.ip1):
            return True
        return False


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

    
