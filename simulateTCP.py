# from bitstring import BitArray
import pcapy
import sys

class Connection:
    def __init__(self, ip1, ip2, port1, port2, start_time):
        self.sig = get_sig(ip1, ip2, port1, port2)
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
        self.packets = []
    
    def close_connection(self, end_time):
        if this.end_time is not None:
            print("Connection already closed")
            return
        this.end_time = end_time
    
    def get_duration(self, close_time):
        if this.close_time is None: return None
        return this.close_time - this.start_time
    
    def add_packet(self, packet):
        if packet.src_ip == self.ip1: self.pkts_1 += 1
        elif packet.src_ip == self.ip2: self.pkts_2 += 1
        else:
            print("Wrong Connection:")
            print("Attempted ip: {}".format(packet.src_ip))
            print("On connection between {} and {}".format(self.ip1, self.ip2))
            return
    
    def check_connection(self, ip1, ip2):
        if (ip1 == self.ip1 and ip2 == self.ip2) or (ip1 == self.ip2 and ip2 == self.ip1):
            return True
        return False

class Packet:
    def __init__(self, header_bstr):
        header = getBytes(header_data)
        ip_header = header[14:34]
        tcp_header = header[34:]

        self.src_ip = ip_header[12:16]
        self.dest_ip = ip_header[16:20]
        self.src_port = tcp_header[0] & 0x10 >> 16
        self.dest_port = tcp_header[0] & 0x01
        self.sig = get_sig(src_ip, dest_ip, src_port, dest_port)
        self.data_len = tcp_header[14:16]
    

def getBytes(data):
    output = []
    for d in data:
        output.append(d)
    return output


def get_sig(ip1, ip2, port1, port2):
    ip1_str = ''.join(str(seg) for seg in ip1)
    ip2_str = ''.join(str(seg) for seg in ip2)
    if ip1_str < ip2_str:
        return "{}{}{}{}".format(ip1_str, ip2_str, port1, port2)
    elif ip1_str > ip2_str:
        return "{}{}{}{}".format(ip2_str, ip1_str, port2, port1)
    elif port1 < port2:
        return "{}{}{}{}".format(ip1_str, ip2_str, port1, port2)
    else:
        return "{}{}{}{}".format(ip2_str, ip1_str, port2, port1)

if __name__ == '__main__':
    try:
        cap = pcapy.open_offline(sys.argv[1])
    except IndexError:
        print("Please include pcap file name")

    while True:
        header_info, header_data = cap.next()
        if (header_info is None):
            break
        
        Packet(header_data)

        print()

    
