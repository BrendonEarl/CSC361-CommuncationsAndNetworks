from utils import PacketError, Platform, Protocol, Type, get_sig, get_ips_sig, get_bytes


class Packet:
    """Parsed packet"""

    def __init__(self, header_bstr, time):
        header = get_bytes(header_bstr)
        ip_header = header[0x0e:0x22]
        self.time = time[0] * 1000 + time[1] * 0.001

        try:
            self.protocol = Protocol(ip_header[9])
        except ValueError:
            raise PacketError('Unexpected packet protocol')

        self.src_ip = ip_header[0x0c:0x10]
        self.dest_ip = ip_header[0x10:0x14]

        # if packet is UDP
        if self.protocol == Protocol.UDP:
            udp_header = header[0x22:0x2a]

            self.src_port = udp_header[0x00] * 256 + udp_header[0x01]
            self.dest_port = udp_header[0x02] * 256 + udp_header[0x03]

            if self.dest_port < 33434 or self.dest_port > 33529:
                raise PacketError('Port out of range, undesirable packet')

            self.sig = get_sig(self.src_ip, self.dest_ip,
                               self.src_port, self.dest_port)

        # if packet is ICMP
        elif self.protocol == Protocol.ICMP:
            icmp_header = header[0x22:]

            self.type = Type(icmp_header[0x00])

            # if type == Type.ECHO:
            #     # self.sig = get_sig(self.src_ip, self.dest_ip, self.seq)
            # if type == Type.TIME_EXCEEDED:
            # break out req headers from icmp response
            req_ip_header = icmp_header[0x08:0x1c]
            req_udp_header = icmp_header[0x1c:0x25]

            # get req ips & ports
            self.req_src_ip = req_ip_header[0x0c:0x10]
            self.req_dest_ip = req_ip_header[0x10:0x14]
            self.req_src_port = req_udp_header[0x00] * \
                256 + req_udp_header[0x01]
            self.req_dest_port = req_udp_header[0x02] * \
                256 + req_udp_header[0x03]

            self.req_sig = get_sig(self.req_src_ip, self.req_dest_ip,
                                   self.req_src_port, self.req_dest_port)
            # else:
            #     print("ICMP type unacounted for: {}".format(type))

        # otherwise unrecognized packet
        else:
            raise PacketError('Unanticipated packet protocol')

    def get_sig(self):
        return self.sig

    def get_req_sig(self):
        return self.req_sig
