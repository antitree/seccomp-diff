import struct

TCPDUMP_MAGIC = 0xa1b2c3d4L
TCPDUMP_MAGIC_NANO = 0xa1b23c4d
# Magic backwards
PMUDPCT_MAGIC = 0xd4c3b2a1L
PMUDPCT_MAGIC_NANO = 0x4d3cb2a1

FILEHDR = "IHHIIII"
FILEHDR_SIZE = struct.calcsize("=" + FILEHDR)
PKTHDR = "IIII"
PKTHDR_SIZE = struct.calcsize("=" + PKTHDR)


# Very simple PCAP reader
class PCAPReader(object):
    def __init__(self, fh):
        self.fh = fh
        
        hdr_bytes = fh.read(FILEHDR_SIZE)

        hdr = struct.unpack("<" + FILEHDR, hdr_bytes)
        if hdr[0] in (TCPDUMP_MAGIC, TCPDUMP_MAGIC_NANO):
            self.order = "<"
        elif hdr[0] in (PMUDPCT_MAGIC, PMUDPCT_MAGIC_NANO):
            self.order = ">"
        else:
            raise Exception("Not a tcpdump file")

        self.header = struct.unpack(self.order + FILEHDR, hdr_bytes)

        self.ts_div = 1000000.0 if hdr[0] == TCPDUMP_MAGIC else 1000000000.0

    def __iter__(self):
        return self

    def next(self):
        pkthdr_bytes = self.fh.read(PKTHDR_SIZE)
        if len(pkthdr_bytes) < PKTHDR_SIZE:
            raise StopIteration

        pkthdr = struct.unpack(self.order + PKTHDR, pkthdr_bytes)

        pkt_bytes = self.fh.read(pkthdr[2])
        if len(pkthdr_bytes) < PKTHDR_SIZE:
            raise StopIteration

        return pkthdr[0] + pkthdr[1]/self.ts_div, pkthdr[3], pkt_bytes
