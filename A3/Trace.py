from utils import Platform, Protocol, Type, get_udp_sig, get_icmp_sig, get_ips_sig


class Trace:
    """Trace between two specific services [ip:port]s"""

    def __init__(self, packet, sesh_start):
        self.sesh_start = sesh_start
        # managed by add_probe function
        self.sig = None
        self.platform = None
        self.start_time = None
        self.probe_packet = None
        # managed by add_resp function
        self.resp_packet = None
        self.end_time = None

        self.add_probe(packet)

    def __str__(self):
        """Print state of trace"""
        # calculate and define variables for later use
        src_ip, dest_ip = self.get_ips()
        src_port, dest_port = self.get_ports()

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
        output += "END\n"

        return output

    def get_ips(self):
        if self.probe_packet is not None and self.resp_packet is not None:
            return (self.probe_packet.src_ip, self.resp_packet.src_ip)
        elif self.probe_packet is not None:
            return (self.probe_packet.src_ip, None)
        return (None, None)

    def get_ports(self):
        if self.platform == Platform.LINUX:
            if self.probe_packet is not None and self.resp_packet is not None:
                return (self.probe_packet.src_port, self.resp_packet.src_port)
            elif self.probe_packet is not None:
                return (self.probe_packet.src_port, None)
            return (None, None)

        elif self.platform == Platform.WIN:
            print("get_ports request made on windows trace, no are set")
            return (None, None)
        else:
            print("get_ports request made on trace without platform set")
            return (None, None)

    def get_sig(self):
        return self.sig

    def get_ips_sig(self):
        return get_ips_sig(self.get_ips())

    def get_duration(self):
        """Return duration of trace"""
        if self.end_time is None:
            return None
        return self.end_time - self.start_time

    def is_complete(self):
        if self.probe_packet is not None and self.resp_packet is not None:
            return True
        return False

    def add_probe(self, packet):
        """Add packet as probe"""
        # check probe follows appropriate protocol
        if packet.protocol != Protocol.UDP and packet.protocol != Protocol.ICMP:
            print("Error: probe of protocols UDP or ICMP")
        if self.probe_packet is None:
            self.start_time = packet.time
            self.probe_packet = packet
            if packet.protocol == Protocol.UDP:
                self.sig = get_udp_sig(packet.src_ip, packet.src_port)
            elif packet.protocol == Protocol.ICMP:
                self.sig = get_icmp_sig(packet.src_ip, packet.seq)
        else:
            self.probe_packet.add_frag(packet)

    def add_resp(self, packet):
        """Add packet as response"""
        # add packet as response
        if packet.protocol != Protocol.ICMP:
            print("Error: probe not of protocol ICMP")
        elif packet.req_src_ip not in self.get_ips():
            print("Wrong Trace:")
            print("Attempted ip: {}".format(packet.req_src_ip))
            print("On trace between {} and {}".format(
                self.get_ips()[0], self.get_ips()[1]))
            return
        self.ips = (packet.req_src_ip, packet.src_ip)
        self.end_time = packet.time
        self.resp_packet = packet
