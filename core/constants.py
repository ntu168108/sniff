"""
Constants for SNIFF tool
- Protocol numbers
- TCP flags
- Ethernet types
- Default configurations
"""

# Ethernet Types (EtherType)
ETHERTYPE_IP = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

ETHERTYPE_NAMES = {
    ETHERTYPE_IP: "IPv4",
    ETHERTYPE_ARP: "ARP",
    ETHERTYPE_IPV6: "IPv6",
    ETHERTYPE_VLAN: "VLAN",
}

# IP Protocol Numbers
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

PROTO_NAMES = {
    PROTO_ICMP: "ICMP",
    PROTO_TCP: "TCP",
    PROTO_UDP: "UDP",
    PROTO_ICMPV6: "ICMPv6",
}

# TCP Flags
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80

TCP_FLAG_NAMES = {
    TCP_FIN: "FIN",
    TCP_SYN: "SYN",
    TCP_RST: "RST",
    TCP_PSH: "PSH",
    TCP_ACK: "ACK",
    TCP_URG: "URG",
    TCP_ECE: "ECE",
    TCP_CWR: "CWR",
}

def tcp_flags_str(flags: int) -> str:
    """Convert TCP flags to string like [SYN,ACK]"""
    result = []
    for flag_val, flag_name in TCP_FLAG_NAMES.items():
        if flags & flag_val:
            result.append(flag_name)
    return "[" + ",".join(result) + "]" if result else ""

# ICMP Types
ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACHABLE = 3
ICMP_REDIRECT = 5
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11

ICMP_TYPE_NAMES = {
    ICMP_ECHO_REPLY: "Echo Reply",
    ICMP_DEST_UNREACHABLE: "Destination Unreachable",
    ICMP_REDIRECT: "Redirect",
    ICMP_ECHO_REQUEST: "Echo Request",
    ICMP_TIME_EXCEEDED: "Time Exceeded",
}

# ARP Operations
ARP_REQUEST = 1
ARP_REPLY = 2

ARP_OP_NAMES = {
    ARP_REQUEST: "Request",
    ARP_REPLY: "Reply",
}

# Common ports
WELL_KNOWN_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-S",
    68: "DHCP-C",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}

# Default configurations
DEFAULT_SNAPLEN = 1518          # Capture up to 1518 bytes per packet
DEFAULT_BUFFER_SIZE = 2097152   # 2MB ring buffer
DEFAULT_PROMISC = True          # Promiscuous mode on
DEFAULT_RETENTION_DAYS = 7      # Keep PCAP files for 7 days
DEFAULT_MAX_MEMORY_MB = 500     # Max memory usage
DEFAULT_QUEUE_SIZE = 10000      # Packet queue size
DEFAULT_UI_CACHE_SIZE = 5000    # UI packet cache size

# Snaplen options
SNAPLEN_OPTIONS = {
    64: "64 bytes (headers only)",
    128: "128 bytes (small)",
    256: "256 bytes (medium)",
    512: "512 bytes (large)",
    1518: "1518 bytes (full Ethernet)",
    4096: "4096 bytes (jumbo)",
    65535: "65535 bytes (max)",
}

# Buffer profiles
BUFFER_PROFILES = {
    "low": {
        "buffer_size": 1048576,     # 1MB
        "queue_size": 5000,
        "desc": "Thấp - Tiết kiệm RAM"
    },
    "balanced": {
        "buffer_size": 2097152,     # 2MB
        "queue_size": 10000,
        "desc": "Cân bằng - Mặc định"
    },
    "fast": {
        "buffer_size": 4194304,     # 4MB
        "queue_size": 20000,
        "desc": "Nhanh - Tốc độ cao"
    },
    "max": {
        "buffer_size": 8388608,     # 8MB
        "queue_size": 50000,
        "desc": "Tối đa - Không drop"
    },
}

# PCAP file header constants
PCAP_MAGIC = 0xa1b2c3d4          # Standard pcap magic number
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_LINKTYPE_ETHERNET = 1

# Time constants
STATS_UPDATE_INTERVAL = 2.0     # Update stats every 2 seconds
UI_REFRESH_INTERVAL = 0.1       # UI refresh rate (10 FPS)

