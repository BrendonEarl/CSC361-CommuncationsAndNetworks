import statistics

from utils import Platform, Protocol, Type, get_ips_sig
from Trace import Trace
from Packet import Packet


class Session:
    """Trace session"""

    def __init__(self):
        """Initialize traces dictionary"""
        self.traces = {}
        self.trace_order = []
        self.ref_time = None

    def __str__(self):
        """Print session summary"""

        complete_traces = []
        for trace_id in self.trace_order:
            if (self.traces[trace_id].resp_packet and
                    self.traces[trace_id].resp_packet.type == Type.TIME_EXCEEDED):
                complete_traces.append(self.traces[trace_id])

        complete_trace_ips = []
        complete_trace_rtts = {}
        for trace in complete_traces:
            if trace.get_ips() not in complete_trace_ips:
                complete_trace_ips.append(trace.get_ips())
                complete_trace_rtts[trace.get_ips_sig()] = [
                    trace.get_duration()]
            else:
                complete_trace_rtts[trace.get_ips_sig()].append(
                    trace.get_duration())

        # Output
        # summarize routers
        output = ""
        output += "The IP address of the source node: {}\n".format(
            ".".join(map(str, complete_trace_ips[0][0])))
        output += "The IP address of the ultimate destination: {}\n".format(
            ".".join(map(str, complete_trace_ips[-1][1])))
        output += "The IP addresses of the intermediate destination nodes:\n"
        for index, ips in enumerate(complete_trace_ips):
            output += '\trouter {}: {}'.format(index + 1,
                                               ".".join(map(str, ips[1])))
            if index == len(complete_trace_ips) - 1:
                output += ".\n\n"
            else:
                output += ",\n"

        # summarize protocols seen
        unique_protos = []
        for trace in self.traces.values():
            if trace.probe_packet.protocol not in unique_protos:
                unique_protos.append(
                    trace.probe_packet.protocol)
            if trace.resp_packet is not None:
                if trace.resp_packet.protocol not in unique_protos:
                    unique_protos.append(
                        trace.resp_packet.protocol)

        output += "The values in the protocol field of IP headers:\n"
        for proto in unique_protos:
            output += "\t {}: {}\n".format(proto.value, proto.name)
        output += "\n"

        # summarize rtts
        for ips in complete_trace_ips:
            rtts = complete_trace_rtts[get_ips_sig(ips)]
            output += "The avg RTT between {} and {} is: ".format(
                ".".join(map(str, ips[0])), ".".join(map(str, ips[1])))
            output += "{0:.3f}ms, ".format(statistics.mean(rtts))
            output += "the s.d. is: {0:.1f}ms\n".format(
                0 if len(rtts) < 2 else statistics.stdev(rtts))
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
        if (new_packet.protocol == Protocol.UDP or (
            new_packet.protocol == Protocol.ICMP and new_packet.type == Type.ECHO
        )):
            if new_packet.get_trace_sig() in self.traces:
                print('Error: duplicate UDP packet probe')
                self.traces[new_packet.get_trace_sig()].add_probe(new_packet)
            # If new trace must created
            else:
                self.traces.update({
                    new_packet.get_trace_sig(): Trace(
                        new_packet, self.ref_time)
                })
                self.trace_order.append(new_packet.get_trace_sig())

        elif new_packet.protocol == Protocol.ICMP and new_packet.type == Type.TIME_EXCEEDED:
            if new_packet.get_trace_sig() in [trace.get_sig() for trace in self.traces.values()]:
                self.traces[new_packet.get_trace_sig()].add_resp(new_packet)
            else:
                print("Error: ICMP receieved for nonexistant probe")
                print(new_packet.get_trace_sig())
