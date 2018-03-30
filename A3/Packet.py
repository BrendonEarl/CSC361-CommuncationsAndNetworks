from utils import PacketError, Platform, Protocol, Type, get_udp_sig, get_icmp_sig, get_ips_sig, get_bytes


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

            self.sig = get_udp_sig(self.src_ip, self.dest_ip,
                                   self.src_port, self.dest_port)

        # if packet is ICMP
        elif self.protocol == Protocol.ICMP:
            icmp_header = header[0x22:]

            self.type = Type(icmp_header[0x00])

            req_ip_header = icmp_header[0x08:0x1c]
            self.req_src_ip = req_ip_header[0x0c:0x10]
            self.req_dest_ip = req_ip_header[0x10:0x14]

            req_icmp_header = icmp_header[0x1c:]

            if self.type == Type.ECHO:
                self.seq = icmp_header[0x06] * 256 + icmp_header[0x07]
                self.sig = get_icmp_sig(self.src_ip, self.dest_ip, self.seq)
            elif self.type == Type.TIME_EXCEEDED:
                if req_icmp_header[0x00] == 0x08:
                    # break out req headers from icmp response
                    self.sig = get_ips_sig((self.src_ip, self.dest_ip))
                    self.req_seq = req_icmp_header[-2] * \
                        256 + req_icmp_header[-1]
                    self.req_sig = get_icmp_sig(
                        self.req_src_ip, self.req_dest_ip, self.req_seq)

                else:
                    # break out req headers from icmp response
                    req_udp_header = icmp_header[0x1c:0x25]

                    # get req ips & ports
                    self.req_src_port = req_udp_header[0x00] * \
                        256 + req_udp_header[0x01]
                    self.req_dest_port = req_udp_header[0x02] * \
                        256 + req_udp_header[0x03]

                    self.sig = get_ips_sig((self.src_ip, self.dest_ip))

                    self.req_sig = get_udp_sig(self.req_src_ip, self.req_dest_ip,
                                               self.req_src_port, self.req_dest_port)
            else:
                print("ICMP type unacounted for: {}".format(self.type))

        # otherwise unrecognized packet
        else:
            raise PacketError('Unanticipated packet protocol')

    def get_sig(self):
        return self.sig

    def get_req_sig(self):
        return self.req_sig
