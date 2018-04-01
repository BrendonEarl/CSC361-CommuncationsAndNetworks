"""
Packet class to represent a datagram/packet combined from
one or more fragments found in a pcap or pcapng file
"""

from config import DEV_ENV
from utils import PacketError, Protocol, Type, get_udp_sig, get_icmp_sig


class Packet:
    """Parsed packet"""

    def __init__(self, fragment):
        self.fragments = []
        self.time = fragment.time
        self.id = fragment.id
        self.protocol = None
        self.src_ip = fragment.src_ip
        self.dest_ip = fragment.dest_ip
        self.total_len = None
        # TODO: remove this
        self.req_seq = None

        try:
            self.protocol = Protocol(fragment.proto)
        except ValueError:
            raise PacketError('Unexpected packet protocol')

        self.add_frag(fragment)

    def add_frag(self, fragment):
        """Add fragment to packet & update packet state"""
        self.fragments.append(fragment)
        # if last fragment
        if fragment.flags == 0x00:
            self.total_len = fragment.offset + fragment.len - 20
        if self.is_complete():
            self.assemble_packet()

    def assemble_packet(self):
        """Assemble data from various fragments part of packet"""
        data = []
        for frag in self.fragments:
            data.extend(frag.data)

        # if packet is UDP
        if self.protocol == Protocol.UDP:
            udp_header = data

            self.src_port = udp_header[0x00] * 256 + udp_header[0x01]
            self.dest_port = udp_header[0x02] * 256 + udp_header[0x03]

            if self.dest_port < 33434 or self.dest_port > 33529:
                raise PacketError('Port out of range, undesirable packet')

        # if packet is ICMP
        elif self.protocol == Protocol.ICMP:
            icmp_header = data
            try:
                self.type = Type(icmp_header[0x00])
            except:
                if DEV_ENV:
                    print('oups icmp packet with unexpected type')
                raise PacketError('ICMP packet with unexpected type')

            if self.type == Type.ECHO:
                self.seq = icmp_header[0x06] * 256 + icmp_header[0x07]
            elif self.type == Type.TIME_EXCEEDED:
                req_ip_header = icmp_header[0x08:0x1c]
                req_icmp_header = icmp_header[0x1c:]
                self.req_id = req_ip_header[0x04] * \
                    256 + req_ip_header[0x05]
                self.req_src_ip = req_ip_header[0x0c:0x10]
                self.req_dest_ip = req_ip_header[0x10:0x14]
                if req_icmp_header[0x00] == Type.ECHO.value:
                    # break out req headers from icmp response
                    self.req_seq = req_icmp_header[0x06] * \
                        256 + req_icmp_header[0x07]
                else:
                    # break out req headers from icmp response
                    req_udp_header = icmp_header[0x1c:0x25]

                    # get req ips & ports
                    self.req_src_port = req_udp_header[0x00] * \
                        256 + req_udp_header[0x01]
                    self.req_dest_port = req_udp_header[0x02] * \
                        256 + req_udp_header[0x03]
            else:
                if DEV_ENV:
                    print("ICMP type unacounted for: {}".format(self.type))

        # otherwise unrecognized packet
        else:
            raise PacketError('Unanticipated packet protocol')

    def is_complete(self):
        """Check if packet is considered complete"""
        # if last packet has been recieved
        frags_data_len = sum([len(frag.data)
                              for frag in self.fragments])
        if self.total_len is not None:
            # if all fragments have been gathered
            if frags_data_len == self.total_len:
                return True
        return False

    def get_sig(self):
        """Get packet signature"""
        return self.id

    def get_req_sig(self):
        """Get packet's corresponding request signature"""
        return self.req_id

    def get_trace_sig(self):
        """Get related traces signature given information in the packet"""
        if self.protocol == Protocol.UDP:
            return get_udp_sig(self.src_ip, self.src_port)
        elif self.protocol == Protocol.ICMP:
            if self.type == Type.ECHO:
                return get_icmp_sig(self.src_ip, self.seq)
            elif self.type == Type.TIME_EXCEEDED:
                if self.req_seq is not None:
                    return get_icmp_sig(self.req_src_ip, self.req_seq)
                else:
                    return get_udp_sig(self.req_src_ip, self.req_src_port)
