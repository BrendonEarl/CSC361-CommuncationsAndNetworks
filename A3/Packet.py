from utils import PacketError, Platform, Protocol, Type, get_udp_sig, get_icmp_sig, get_ips_sig, get_bytes


class Packet:
    """Parsed packet"""

    def __init__(self, header_bstr, time):
        header = get_bytes(header_bstr)
        ip_header = header[0x0e:0x22]
        self.time = time[0] * 1000 + time[1] * 0.001
        self.id = ip_header[0x04] * 256 + ip_header[0x05]
        self.flags = ip_header[0x06]
        self.frags = []
        self.req_seq = None

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

        # if packet is ICMP
        elif self.protocol == Protocol.ICMP:
            icmp_header = header[0x22:]
            try:
                self.type = Type(icmp_header[0x00])
            except:
                print('oups icmp packet with unexpected type')

            if self.type == Type.ECHO:
                self.seq = icmp_header[0x06] * 256 + icmp_header[0x07]
            elif self.type == Type.TIME_EXCEEDED:
                req_ip_header = icmp_header[0x08:0x1c]
                req_icmp_header = icmp_header[0x1c:]
                self.req_id = req_ip_header[0x04] * 256 + req_ip_header[0x05]
                self.req_src_ip = req_ip_header[0x0c:0x10]
                self.req_dest_ip = req_ip_header[0x10:0x14]
                if req_icmp_header[0x00] == Type.ECHO.value:
                    # break out req headers from icmp response
                    self.req_seq = req_icmp_header[-2] * \
                        256 + req_icmp_header[-1]
                else:
                    # break out req headers from icmp response
                    req_udp_header = icmp_header[0x1c:0x25]

                    # get req ips & ports
                    self.req_src_port = req_udp_header[0x00] * \
                        256 + req_udp_header[0x01]
                    self.req_dest_port = req_udp_header[0x02] * \
                        256 + req_udp_header[0x03]

            else:
                print("ICMP type unacounted for: {}".format(self.type))

        # otherwise unrecognized packet
        else:
            raise PacketError('Unanticipated packet protocol')

    def add_frag(self, frag_packet):
        self.frags.append(frag_packet)

    def get_sig(self):
        return self.id

    def get_req_sig(self):
        return self.req_id

    def get_trace_sig(self):
        if self.protocol == Protocol.UDP:
            return get_udp_sig(self.src_ip, self.src_port)
        elif self.protocol == Protocol.ICMP:
            if self.type == Type.ECHO:
                return get_icmp_sig(self.src_ip, self.seq)
            elif self.type == Type.TIME_EXCEEDED:
                if self.req_seq:
                    return get_icmp_sig(self.req_src_ip, self.req_seq)
                else:
                    return get_udp_sig(self.req_src_ip, self.req_src_port)
