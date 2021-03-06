"""
This script is to be called as main from the command line,
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
        self.conn_order = []
        self.ref_time = None

    def __str__(self):
        """Print session summary"""
        # Calculate and define variables for later use
        c_count_total = len(self.conn_order)
        c_count_fin = sum(
            1 for c_id in self.connections if self.connections[c_id].flags["fin"] > 0)
        c_coutn_rst = sum(
            1 for c_id in self.connections if self.connections[c_id].flags["rst"] > 0)

        # Output part A details
        output = ""
        output += "A) Total number of connections: {}\n".format(c_count_total)
        output += ("----------------------------------------------------" +
                   "--------------------------------------------------------\n")

        # Output aprt B deatils
        output += "B) Connections' details:\n\n"
        for index, c_id in enumerate(self.conn_order[:-1]):
            output += "Connection {}:\n".format(index + 1)
            output += str(self.connections[c_id])
            output += ("+++++++++++++++++++++++++++++++++\n.\n.\n.\n" +
                       "+++++++++++++++++++++++++++++++++\n")
        output += "Connection {}:\n".format(len(self.conn_order))
        output += str(self.connections[self.conn_order[-1]])
        output += ("----------------------------------------------------" +
                   "--------------------------------------------------------\n")

        # Output part C details
        output += "C) General\n"
        output += "Total number of complete TCP connections: {}\n".format(
            c_count_fin)
        output += "Number of reset TCP connections: {}\n".format(c_coutn_rst)
        output += ("Number of TCP connections that were still open when the trace capture " +
                   "ended: {}\n".format(c_count_total - c_count_fin))
        output += ("----------------------------------------------------" +
                   "--------------------------------------------------------\n")

        # Calculate variables for part D
        all_conn_times = [self.connections[c_id].end_time - self.connections[c_id]
                          .start_time for c_id in self.connections
                          if self.connections[c_id].end_time != None]
        all_packet_rtts = [
            rtt for c_id in self.connections for rtt in self.connections[c_id].rtts]
        all_conn_packet_count = [
            len(self.connections[c_id].packets) for c_id in self.connections]
        all_packet_window_size = [
            packet.window for c_id in self.connections for packet in self.connections[c_id].packets]

        # Output part D details
        output += "D) Complete TCP connections:\n\n"
        # Connection durations
        output += "Minimum time duration: {}\n".format(min(all_conn_times))
        output += "Mean time duration: {}\n".format(
            float(sum(all_conn_times) / len(all_conn_times)))
        output += "Maximum time duration: {}\n\n".format(max(all_conn_times))

        # RTT stats
        output += "Minimum RTT value: {}\n".format(min(all_packet_rtts))
        output += "Mean RTT value: {}\n".format(
            float(sum(all_packet_rtts) / len(all_packet_rtts)))
        output += "Maximum RTT value: {}\n\n".format(max(all_packet_rtts))

        # Packet counts
        output += "Minimum number of packets including both send/received: {}\n".format(
            min(all_conn_packet_count))
        output += "Mean number of packets including both send/received: {}\n".format(
            float(sum(all_conn_packet_count) / len(all_conn_packet_count)))
        output += "Maximum number of packets including both send/received: {}\n\n".format(
            max(all_conn_packet_count))

        # Window size stats
        output += "Minimum receive window size including both send/received: {}\n".format(
            min(all_packet_window_size))
        output += "Mean receive window size including both send/received: {}\n".format(
            float(sum(all_packet_window_size) / len(all_packet_window_size)))
        output += "Maximum receive window size including both send/received: {}\n".format(
            max(all_packet_window_size))
        output += ("----------------------------------------------------" +
                   "--------------------------------------------------------\n")
        return output

    def consume_packet(self, header_bstr, packet_time):
        """
        Accept new packet and associate it with appropriate connection

        Keyword arguments:
        header_bstr -- binary string of the packet header
        packet_time -- time tuple (sec, ms) since epoch of header
        """
        # Init packet
        new_packet = Packet(header_bstr, packet_time)

        # Set start time if very first packet
        if self.ref_time is None:
            self.ref_time = new_packet.time

        # If connection exists for packet
        if new_packet.sig in self.connections:
            self.connections[new_packet.sig].add_packet(new_packet)
        # If new connection must created
        else:
            self.connections.update({
                new_packet.sig: Connection(
                    new_packet, self.ref_time)
            })
            self.conn_order.append(new_packet.sig)


class Connection:
    """Connection between two specific services [ip:port]s"""

    def __init__(self, packet, sesh_start):
        self.sig = get_sig(packet.src_ip, packet.dest_ip,
                           packet.src_port, packet.dest_port)
        self.ips = (packet.src_ip, packet.dest_ip)
        self.ports = (packet.src_port, packet.dest_port)
        self.sesh_start = sesh_start
        self.start_time = None
        self.end_time = None
        self.pkts_1 = 0
        self.pkts_2 = 0
        self.flags = {
            "syn": 0,
            "fin": 0,
            "rst": 0,
        }
        self.packets = []
        self.seq_wo_ack = {}
        self.rtts = []

        self.add_packet(packet)

    def __str__(self):
        """Print state of connection"""
        # Calculate and define variables for later use
        src_ip, dest_ip = self.ips
        src_port, dest_port = self.ports
        src_data = sum(
            packet.data_len for packet in self.packets if packet.src_ip == src_ip)
        dest_data = sum(
            packet.data_len for packet in self.packets if packet.src_ip == dest_ip)

        # Detail IP, Port, and Status
        output = ""
        output += "Source Address: {}\n".format(
            ".".join(str(e) for e in src_ip))
        output += "Destination Address: {}\n".format(
            ".".join(str(e) for e in dest_ip))
        output += "Source Port: {}\n".format(src_port)
        output += "Destination Port: {}\n".format(dest_port)
        output += "Status: {}{}\n".format("S{}F{}".format(
            self.flags["syn"], self.flags["fin"]), " + R" if self.flags["rst"] != 0 else "")

        # If connection is parked as finished output connection details
        if self.flags["fin"] > 0:
            output += "Start Time: {}\n".format(self.start_time)
            output += "End Time: {}\n".format(self.end_time)
            output += "Duration: {}\n".format(self.end_time - self.start_time)
            # pylint: disable=E1101
            # ^ (Instance of 'str' has no 'src_ip' member) - Packet(s) do have src_ip members
            output += "Number of packets sent from source to destination: {}\n".format(
                sum(1 for packet in self.packets if packet.src_ip == src_ip))
            output += "Number of packets sent from destination to source: {}\n".format(
                sum(1 for packet in self.packets if packet.src_ip == dest_ip))
            output += "Total number of packets: {}\n".format(len(self.packets))
            output += "Number of data bytes sent from source to destination: {}\n".format(
                src_data)
            output += "Number of data bytes sent from destination to source: {}\n".format(
                dest_data)
            output += "Total number of data bytes: {}\n".format(
                src_data + dest_data)
        output += "END\n"

        return output

    def get_duration(self):
        """Return duration of connection"""
        if self.end_time is None:
            return None
        return self.end_time - self.start_time

    def add_packet(self, packet):
        """Add packet to connection"""
        # Track direction of packet
        if packet.src_ip == self.ips[0]:
            self.pkts_1 += 1
        elif packet.src_ip == self.ips[1]:
            self.pkts_2 += 1
        else:
            print("Wrong Connection:")
            print("Attempted ip: {}".format(packet.src_ip))
            print("On connection between {} and {}".format(
                self.ips[0], self.ips[1]))
            return

        # Track details dependibng on set flags
        if packet.flags["fin"] == 1:
            self.flags["fin"] += 1
            self.end_time = packet.time - self.sesh_start
        if packet.flags["syn"] == 1:
            self.flags["syn"] += 1
            if self.start_time is None:
                self.start_time = packet.time - self.sesh_start
        if packet.flags["rst"] == 1:
            self.flags["rst"] += 1

        self.packets.append(packet)

        # Track acknowledged packets
        self.seq_wo_ack.update(
            {str(packet.seqn + packet.data_len): packet.time})
        if packet.flags["ack"] == 1:
            if str(packet.ackn) in self.seq_wo_ack:
                self.rtts.append(
                    packet.time - self.seq_wo_ack[str(packet.ackn)])
                del self.seq_wo_ack[str(packet.ackn)]


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
        self.seqn = tcp_header[4] * 16777216 + tcp_header[5] * \
            65536 + tcp_header[6] * 256 + tcp_header[7]
        self.ackn = tcp_header[8] * 16777216 + tcp_header[9] * \
            65536 + tcp_header[10] * 256 + tcp_header[11]
        self.flags = {
            "fin": (tcp_flags[1] & 0x01),
            "syn": (tcp_flags[1] & 0x02) >> 1,
            "rst": (tcp_flags[1] & 0x04) >> 2,
            "ack": (tcp_flags[1] & 0x10) >> 4,
        }
        self.data_len = len(tcp_header) - \
            int(((tcp_header[12] & 0xF0) >> 4)) * 4
        self.window = tcp_header[14] * 256 + tcp_header[15]
        self.time = time[0] + time[1] * 0.0000001
        self.sig = get_sig(self.src_ip, self.dest_ip,
                           self.src_port, self.dest_port)


def get_bytes(bstring):
    """Parse header bstring into list"""
    output = []
    for byte in bstring:
        output.append(byte)
    return output


def get_sig(ip1, ip2, port1, port2):
    """Find unique sig for ip/port combination"""
    ip1_str = '.'.join(str(seg) for seg in ip1)
    ip2_str = '.'.join(str(seg) for seg in ip2)
    if ip1_str < ip2_str:
        return "{}:{}->{}:{}".format(ip1_str, port1, ip2_str, port2)
    elif ip1_str > ip2_str:
        return "{}:{}->{}:{}".format(ip2_str, port2, ip1_str, port1)
    elif port1 < port2:
        return "{}:{}->{}:{}".format(ip1_str, port1, ip2_str, port2)
    return "{}:{}->{}:{}".format(ip2_str, port2, ip1_str, port1)


if __name__ == '__main__':
    try:
        # pylint: disable=E1101
        # pcapy does have open_offline function
        CAP = pcapy.open_offline(sys.argv[1])
    except IndexError:
        print("Please include pcap file name")

    SESSION = Session()

    while True:
        HEADER_INFO, HEADER_DATA = CAP.next()
        if HEADER_INFO is None:
            break

        SESSION.consume_packet(HEADER_DATA, HEADER_INFO.getts())

    print(SESSION)
