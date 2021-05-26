import struct
import socket
from ctypes import *

class ESPHeader:
    def __init__(self, encrypted_payload):
        spi = socket.inet_aton('0.0.0.0') #4bytes
        seq = 1 #4bytes
        payload = encrypted_payload #size varies
        esp_part1 = struct.pack("4sI", spi, seq)
        esp_payload_part2 = payload
        
        self.payload = esp_part1 + esp_payload_part2 

class IPHeader:
    # https://www.bitforestinfo.com/blog/12/26/code-to-create-ipv4-packet-header-in-python.html
    def __init__(self, dst, src):
        self.dst = dst
        self.src = src
        self.header = None
        self.create_ipv4_feilds_list()

    def assemble_ipv4_feilds(self):
        self.header = struct.pack('!BBHHHBBH4s4s',
                                  self.ip_ver,   # IP Version
                                  self.ip_dfc,   # Differentiate Service Feild
                                  self.ip_tol,   # Total Length
                                  self.ip_idf,   # Identification
                                  self.ip_flg,   # Flags
                                  self.ip_ttl,   # Time to leave
                                  self.ip_proto,  # protocol
                                  self.ip_chksum,   # Checksum
                                  self.ip_saddr,  # Source IP
                                  self.ip_daddr  # Destination IP
                                  )

    def create_ipv4_feilds_list(self):
        ip_ver = 4
        ip_vhl = 5
        self.ip_ver = (ip_ver << 4) + ip_vhl

        ip_dsc = 0
        ip_ecn = 0
        self.ip_dfc = (ip_dsc << 2) + ip_ecn
        self.ip_tol = 0

        # ---- [ Identification ]
        self.ip_idf = 0
        ip_rsv = 0
        ip_dtf = 0
        ip_mrf = 0
        ip_frag_offset = 0

        self.ip_flg = (ip_rsv << 7) + (ip_dtf << 6) + \
            (ip_mrf << 5) + (ip_frag_offset)
        self.ip_ttl = 255
        self.ip_proto = 50
        self.ip_chksum = 0

        self.ip_saddr = socket.inet_aton(str(self.src))
        self.ip_daddr = socket.inet_aton(str(self.dst))

        self.assemble_ipv4_feilds()

def unpack_ipv4(packet):
    iph = struct.unpack('!BBHHHBBH4s4s', packet[:20])

    version_ihl = iph[0]
    version = version_ihl >> 4
    ih_len = (version_ihl & 0xF) * 4
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    return s_addr, d_addr, protocol
