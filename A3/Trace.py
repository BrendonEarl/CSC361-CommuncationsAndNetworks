from utils import Platform, Protocol, Type, get_sig, get_ips_sig

class Trace:
    """Trace between two specific services [ip:port]s"""

    def __init__(self, packet, sesh_start):
        self.sig = get_sig(packet.src_ip, packet.dest_ip,
                           packet.src_port, packet.dest_port)
        self.ips = (packet.src_ip, packet.dest_ip)
        self.ports = (packet.src_port, packet.dest_port)
        self.sesh_start = sesh_start
        # managed by add_probe function
        self.start_time = None
        self.probe_packet = None
        # managed by add_resp function
        self.resp_packet = None
        self.end_time = None
        # call add_probe
        self.platform = self.add_probe(packet)

    def __str__(self):
        """Print state of trace"""
        # calculate and define variables for later use
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
        output += "END\n"

        return output

    def get_duration(self):
        """Return duration of trace"""
        if self.end_time is None:
            return None
        return self.end_time - self.start_time

    def add_probe(self, packet):
        """Add packet as probe"""
        # add packet as probe
        if packet.protocol != Protocol.UDP:
            print("Error: probe not of protocol UDP")
        elif packet.src_ip not in self.ips:
            print("Wrong Trace:")
            print("Attempted ip: {}".format(packet.src_ip))
            print("On trace between {} and {}".format(
                self.ips[0], self.ips[1]))
            return
        self.start_time = packet.time
        self.probe_packet = packet

    def add_resp(self, packet):
        """Add packet as response"""
        # add packet as response
        if packet.protocol != Protocol.ICMP:
            print("Error: probe not of protocol ICMP")
        elif packet.req_src_ip not in self.ips:
            print("Wrong Trace:")
            print("Attempted ip: {}".format(packet.req_src_ip))
            print("On trace between {} and {}".format(
                self.ips[0], self.ips[1]))
            return
        self.ips = (packet.req_src_ip, packet.src_ip)
        self.end_time = packet.time
        self.resp_packet = packet

