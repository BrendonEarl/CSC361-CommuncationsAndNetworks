from enum import Enum


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


class Platform(Enum):
    """OS Platform"""
    WIN = 0
    LINUX = 1


class Protocol(Enum):
    """Packet Protocol"""
    ICMP = 0x01
    TCP = 0x06
    UDP = 0x11


class Type(Enum):
    """ICMP Type"""
    INVALID = 0
    DESTINATION_UNREACHABLE = 3
    REDIRECT = 5
    ECHO = 8
    TIME_EXCEEDED = 11
    PARAMETER_PROBLEM = 12


def get_bytes(bstring):
    """Parse header bstring into list"""
    output = []
    for byte in bstring:
        output.append(byte)
    return output


def get_ips_sig(ips):
    """Find unique sig for ip/port combination"""
    ip1_str = '.'.join(str(seg) for seg in ips[0])
    ip2_str = '.'.join(str(seg) for seg in ips[1])

    # Arrange sig according to lex order
    if ip1_str < ip2_str:
        return "{}->{}".format(ip1_str, ip2_str)
    elif ip1_str > ip2_str:
        return "{}->{}".format(ip2_str, ip1_str)
    return "{}->{}".format(ip1_str, ip2_str)


def get_udp_sig(ip1, port1):
    """Find unique sig for ip/port combination"""
    ip1_str = '.'.join(str(seg) for seg in ip1)

    # Arrange sig according to lex order
    return "src-{}:{}".format(ip1_str, port1)


def get_icmp_sig(ip1, seq):
    """Find unique sig for ip/port combination"""
    ip1_str = '.'.join(str(seg) for seg in ip1)

    # Arrange sig according to lex order
    return "src-{}--{}".format(ip1_str, seq)


def is_frag(header_bstr):
    """check if bystream is that of a fragment"""
    if (header_bstr[0x14] & 0xe0) == 0x20:
        return True
    else:
        return False


def get_frag_id(header_bstr):
    """Return id associated with frag"""
    return header_bstr[0x12] * 256 + header_bstr[0x13]
