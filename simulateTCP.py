"""
This method is to be called as main from the command line,
with a *.pcap file as the first and only argument.
It parses the file, and creates a session (the capture session)
with a series of sessions within, each tracking the packets apart of each
"""
import sys
import pcapy


class Session:
    """Connection session"""

    def __init__(self):
        """Initialize connections dictionary"""
        self.connections = {}

    def consume_packet(self, header_bstr, packet_time):
        """
        Accept new packet and associate it with appropriate connection

        Keyword arguments:
        header_bstr -- binary string of the packet header
        packet_time -- time tuple (sec, ms) since epoch of header
        """
        # Init packet
        new_packet = Packet(header_bstr, packet_time)
        # If connection exists for packet
        if new_packet.sig in self.connections:
            self.connections[new_packet.sig].add_packet(new_packet)
        # If new connection must created
        else:
            self.connections[new_packet.sig] = Connection(new_packet)

        # Archive connection if an end time has been associated
        if self.connections[new_packet.sig].end_time is not None:
            self.connections["{}-c{}".format(new_packet.sig, new_packet.time)] = \
                self.connections.pop(new_packet.sig)


class Connection:
    """Connection between two specific services [ip:port]s"""

    def __init__(self, packet):
        # pylint: disable=too-many-instance-attributes
        # 13 is reasonable without breaking them into dicts
        # TODO: consolodate some of these
        self.sig = get_sig(packet.src_ip, packet.dest_ip,
                           packet.src_port, packet.dest_port)
        # print("{}:{} -> {}:{}".format(src_ip, src_port, dest_ip, dest_port))
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
        """Marks connection as closed by associating an end time"""
        if self.end_time is not None:
            print("Connection already closed")
            return
        self.end_time = end_time

    def get_duration(self):
        """Return duration of connection"""
        if self.end_time is None:
            return None
        return self.end_time - self.start_time

    def add_packet(self, packet):
        """Add packet to connection"""
        # Track direction of packet
        if packet.src_ip == self.ip1:
            self.pkts_1 += 1
        elif packet.src_ip == self.ip2:
            self.pkts_2 += 1
        else:
            print("Wrong Connection:")
            print("Attempted ip: {}".format(packet.src_ip))
            print("On connection between {} and {}".format(self.ip1, self.ip2))
            return
        # Track if flag has been set
        if packet.fin == 1:
            self.fin += 1
        if packet.syn == 1:
            self.syn += 1
        if packet.rst == 1:
            self.rst += 1
        if packet.fin == 2:
            self.close_connection(packet.time)
        self.packets.append(packet)

    def print_state(self):
        """Print state of connection"""
        if self.rst == 1:
            print("R")
        print("S{}F{}".format(self.syn, self.fin))
        if self.syn == 0 and self.fin == 0:
            print(len(self.packets))


class Packet:
    """Parsed packet"""

    def __init__(self, header_bstr, time):
        header = get_bytes(header_bstr)
        ip_header = header[14:34]
        tcp_header = header[34:]
        tcp_flags = tcp_header[12:14]

        self.src_ip = ip_header[12:16]
        self.dest_ip = ip_header[16:20]
        self.src_port = tcp_header[0] * 256 + tcp_header[1]
        self.dest_port = tcp_header[2] * 256 + tcp_header[3]
        self.fin = tcp_flags[1] & 0x01
        self.syn = tcp_flags[1] & 0x02 >> 1
        self.rst = tcp_flags[1] & 0x04 >> 2
        self.time = time
        self.sig = get_sig(self.src_ip, self.dest_ip,
                           self.src_port, self.dest_port)
        self.data_len = tcp_header[14:16]

    def print_packet(self):
        """Print packet info to assignment spec"""
        print('TODO: print packet info {}'.format(self.src_ip))


def get_bytes(bstring):
    """Parse header bstring into list"""
    output = []
    for byte in bstring:
        output.append(byte)
    return output


def get_sig(ip1, ip2, port1, port2):
    """Find unique sig for ip/port combination"""
    ip1_str = ''.join(str(seg) for seg in ip1)
    ip2_str = ''.join(str(seg) for seg in ip2)
    if ip1_str < ip2_str:
        return "{}{}{}{}".format(ip1_str, ip2_str, port1, port2)
    elif ip1_str > ip2_str:
        return "{}{}{}{}".format(ip2_str, ip1_str, port2, port1)
    elif port1 < port2:
        return "{}{}{}{}".format(ip1_str, ip2_str, port1, port2)
    return "{}{}{}{}".format(ip2_str, ip1_str, port2, port1)


if __name__ == '__main__':
    try:
        # pylint: disable=E1101
        # pcapy does have open_offline function
        cap = pcapy.open_offline(sys.argv[1])
    except IndexError:
        print("Please include pcap file name")

    session = Session()

    while True:
        header_info, header_data = cap.next()
        if header_info is None:
            break

        session.consume_packet(header_data, header_info.getts())

    for c in session.connections:
        print(c)
    for c in session.connections:
        session.connections[c].print_state()
