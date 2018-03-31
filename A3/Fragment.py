class Fragment:
    """Parsed fragment"""

    def __init__(self, header, time):
        self.time = time[0] * 1000 + time[1] * 0.001
        self._eth = header[0x00:0x0e]
        self._ipv4 = header[0x0e:0x22]
        self.data = header[0x22:]

        self.len = self._ipv4[0x02] * 256 + self._ipv4[0x03]
        self.id = self._ipv4[0x04] * 256 + self._ipv4[0x05]
        self.flags = self._ipv4[0x06] & 0xe0
        self.offset = (self._ipv4[0x06] & 0x1f) * 256 + self._ipv4[0x07]
        self.ttl = self._ipv4[0x08]
        self.proto = self._ipv4[0x08]
        self.src_ip = self._ipv4[0x0c:0x10]
        self.dest_ip = self._ipv4[0x10:0x14]
