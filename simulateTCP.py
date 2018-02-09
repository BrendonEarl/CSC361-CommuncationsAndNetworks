# from bitstring import BitArray
import pcapy
import sys

class Session:
    def __init__(self):
        self.connections = {}
    
    def consume_packet(self, header_bstr, packet_time):
        new_packet = Packet(header_bstr, packet_time)
        if new_packet.sig in self.connections:
            self.connections[new_packet.sig].add_packet(new_packet)
        else:
            self.connections[new_packet.sig] = Connection(new_packet)


class Connection:
    def __init__(self, packet):
        self.sig = get_sig(packet.src_ip, packet.dest_ip, packet.src_port, packet.dest_port)
        self.ip1 = packet.src_ip
        self.ip2 = packet.dest_ip
        self.port1 = packet.src_port
        self.port2 = packet.dest_port
        self.start_time = packet.time
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
        if packet.fin == 1: self.fin += 1
        if packet.syn == 1: self.syn += 1
        if packet.rst == 1: self.rst += 1
    
    def check_connection(self, ip1, ip2):
        if (ip1 == self.ip1 and ip2 == self.ip2) or (ip1 == self.ip2 and ip2 == self.ip1):
            return True
        return False


class Packet:
    def __init__(self, header_bstr, time):
        header = get_bytes(header_data)
        ip_header = header[14:34]
        tcp_header = header[34:]
        flags = tcp_header[12:14]

        self.src_ip = ip_header[12:16]
        self.dest_ip = ip_header[16:20]
        self.src_port = tcp_header[0] & 0x10 >> 16
        self.dest_port = tcp_header[0] & 0x01
        self.fin = flags[1] & 0x01
        self.syn = flags[1] & 0x02 >> 1
        self.rst = flags[1] & 0x04 >> 2
        self.time = time
        self.sig = get_sig(self.src_ip, self.dest_ip, self.src_port, self.dest_port)
        self.data_len = tcp_header[14:16]
    

def get_bytes(data):
    output = []
    for d in data:
        output.append(d)
    return output


def get_sig(ip1, ip2, port1, port2):
    ip1_str = ''.join(str(seg) for seg in ip1)
    ip2_str = ''.join(str(seg) for seg in ip2)
    print("{}:{} -> {}:{}".format(ip1, port1, ip2, port2))
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

    session = Session()

    while True:
        header_info, header_data = cap.next()
        if (header_info is None):
            break
        
        session.consume_packet(header_data, header_info.getts)

    print(session.connections)
    
