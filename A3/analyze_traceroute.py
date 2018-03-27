"""
This script is to be called as main from the command line,
with a *.pcap file as the first and only argument.
It parses the file, and creates a session (the capture session)
with a series of sessions within, each tracking the packets apart of each
"""
from enum import Enum
import sys
import pcapy


class PacketError(Exception):
    """Exception raised for errors in the input.

    Attributes:
        packet -- input packet in which the error occurred
        message -- explanation of the error
    """

    def __init__(self, message):
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.message = message


# NOTE code has been copied from my previous assignment as I designed it in a reusable fashion

class Session:
    """Trace session"""

    def __init__(self):
        """Initialize traces dictionary"""
        self.traces = {}
        self.trace_order = []
        self.ref_time = None

    def __str__(self):
        """Print session summary"""

        # Output
        output = ""
        output += "traces: {}\n".format(len(self.trace_order))

        return output

    def consume_packet(self, header_bstr, packet_time):
        """
        Accept new packet and associate it with appropriate trace

        Keyword arguments:
        header_bstr -- binary string of the packet header
        packet_time -- time tuple (sec, ms) since epoch of header
        """
        # Init packet
        new_packet = Packet(header_bstr, packet_time)

        # Set start time if very first packet
        if self.ref_time is None:
            self.ref_time = new_packet.time

        # If trace exists for packet
        if new_packet.protocol == Protocol.UDP:
            if new_packet.sig in self.traces:
                print('Error: duplicate UDP packet probe')
                print(self.traces)
                self.traces[new_packet.sig].add_probe(new_packet)
            # If new trace must created
            else:
                self.traces.update({
                    new_packet.sig: Trace(
                        new_packet, self.ref_time)
                })
                self.trace_order.append(new_packet.sig)

        elif new_packet.protocol == Protocol.ICMP:
            if new_packet.req_sig in self.traces:
                self.traces[new_packet.req_sig].add_resp(new_packet)
            else:
                print("Error: ICMP receieved for nonexistant probe")
                print(self.traces)
                print(new_packet.req_sig)


class Trace:
    """Trace between two specific services [ip:port]s"""

    def __init__(self, packet, sesh_start):
        self.sig = get_sig(packet.src_ip, packet.dest_ip,
                           packet.src_port, packet.dest_port)
        self.ips = (packet.src_ip, packet.dest_ip)
        self.ports = (packet.src_port, packet.dest_port)
        self.sesh_start = sesh_start
        self.start_time = None
        self.end_time = None
        self.probe_packet = None
        self.resp_packet = None
        self.rtts = []

        self.add_probe(packet)

    def __str__(self):
        """Print state of trace"""
        # Calculate and define variables for later use
        src_ip, dest_ip = self.ips
        src_port, dest_port = self.ports

        # Detail IP, Port, and Status
        output = ""
        output += "Source Address: {}\n".format(
            ".".join(str(e) for e in src_ip))
        output += "Destination Address: {}\n".format(
            ".".join(str(e) for e in dest_ip))
        output += "Source Port: {}\n".format(src_port)
        output += "Destination Port: {}\n".format(dest_port)

        # If trace is parked as finished output trace details
        output += "Start Time: {}\n".format(self.start_time)
        output += "End Time: {}\n".format(self.end_time)
        output += "Duration: {}\n".format(self.end_time - self.start_time)
        output += "END\n"

        return output

    def get_duration(self):
        """Return duration of trace"""
        if self.end_time is None:
            return None
        return self.end_time - self.start_time

    def add_probe(self, packet):
        """Add packet as probe"""
        # Add packet as probe
        if packet.protocol != Protocol.UDP:
            print("Error: probe not of protocol UDP")
        elif packet.src_ip not in self.ips:
            print("Wrong Trace:")
            print("Attempted ip: {}".format(packet.src_ip))
            print("On trace between {} and {}".format(
                self.ips[0], self.ips[1]))
            return
        self.probe_packet = packet

    def add_resp(self, packet):
        """Add packet as response"""
        # Add packet as response
        if packet.protocol != Protocol.ICMP:
            print("Error: probe not of protocol ICMP")
        elif packet.req_src_ip not in self.ips:
            print("Wrong Trace:")
            print("Attempted ip: {}".format(packet.req_src_ip))
            print("On trace between {} and {}".format(
                self.ips[0], self.ips[1]))
            return
        self.resp_packet = packet


class Packet:
    """Parsed packet"""

    def __init__(self, header_bstr, time):
        header = get_bytes(header_bstr)
        # eth_header = header[0x00:0x0e]
        ip_header = header[0x0e:0x22]
        self.time = time[0] + time[1] * 0.0000001

        try:
            self.protocol = Protocol(ip_header[9])
        except ValueError:
            raise PacketError('Unexpected packet protocol')

        # if packet is UDP
        if self.protocol == Protocol.UDP:
            udp_header = header[0x22:0x2a]
            self.src_port = udp_header[0x00] * 256 + udp_header[0x01]
            self.dest_port = udp_header[0x02] * 256 + udp_header[0x03]

            if self.dest_port < 33434 or self.dest_port > 33529:
                raise PacketError('Port out of range, undesirable packet')

            self.src_ip = ip_header[0x0c:0x0f]
            self.dest_ip = ip_header[0x0f:0x14]
            self.sig = get_sig(self.src_ip, self.dest_ip,
                               self.src_port, self.dest_port)

        # if packet is ICMP
        elif self.protocol == Protocol.ICMP:
            icmp_header = header[0x22:]

            self.type = Type(icmp_header[0x00])

            req_ip_header = icmp_header[0x08:0x1c]
            req_udp_header = icmp_header[0x1c:0x25]
            self.req_src_ip = req_ip_header[0x0c:0x0f]
            self.req_dest_ip = req_ip_header[0x0f:0x14]

            self.req_src_port = req_udp_header[0x00] * \
                256 + req_udp_header[0x01]
            self.req_dest_port = req_udp_header[0x02] * \
                256 + req_udp_header[0x03]

            self.req_sig = get_sig(self.req_src_ip, self.req_dest_ip,
                                   self.req_src_port, self.req_dest_port)

        # otherwise unrecognized packet
        else:
            raise PacketError('Unanticipated packet protocol')


class Protocol(Enum):
    """Packet Protocol"""
    ICMP = 0x01
    TCP = 0x06
    UDP = 0x11


class Type(Enum):
    """ICMP Type"""
    DESTINATION_UNREACHABLE = 3
    REDIRECT = 5
    TIME_EXCEEDED = 11
    PARAMETER_PROBLEM = 12


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

        try:
            SESSION.consume_packet(HEADER_DATA, HEADER_INFO.getts())
        except PacketError as error:
            print(error.message)

    print(SESSION)
