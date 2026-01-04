"""
Packet Decoder - Parse raw bytes into structured data
Supports: Ethernet, IP, IPv6, TCP, UDP, ICMP, ARP
"""

from dataclasses import dataclass, field
from typing import Optional
import struct
import socket

from .constants import (
    ETHERTYPE_IP, ETHERTYPE_ARP, ETHERTYPE_IPV6, ETHERTYPE_VLAN,
    ETHERTYPE_NAMES, PROTO_NAMES, PROTO_TCP, PROTO_UDP, PROTO_ICMP,
    tcp_flags_str, ICMP_TYPE_NAMES, ARP_OP_NAMES, WELL_KNOWN_PORTS
)


@dataclass
class PacketInfo:
    """Basic packet info for queue/display"""
    stt: int                    # Packet sequence number
    ts_sec: int                 # Timestamp seconds
    ts_usec: int                # Timestamp microseconds
    caplen: int = 0             # Captured length
    origlen: int = 0            # Original length
    data: bytes = field(default_factory=bytes)  # Raw packet data


@dataclass
class EthernetHeader:
    dst_mac: str
    src_mac: str
    ethertype: int
    ethertype_name: str = ""


@dataclass
class IPv4Header:
    version: int
    ihl: int                    # Header length
    tos: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    checksum: int
    src_ip: str
    dst_ip: str
    protocol_name: str = ""


@dataclass
class IPv6Header:
    version: int
    traffic_class: int
    flow_label: int
    payload_length: int
    next_header: int
    hop_limit: int
    src_ip: str
    dst_ip: str


@dataclass
class TCPHeader:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    data_offset: int
    reserved: int
    flags: int
    window: int
    checksum: int
    urgent: int
    flags_str: str = ""


@dataclass
class UDPHeader:
    src_port: int
    dst_port: int
    length: int
    checksum: int


@dataclass
class ICMPHeader:
    icmp_type: int
    code: int
    checksum: int
    type_name: str = ""


@dataclass
class ARPHeader:
    hw_type: int
    proto_type: int
    hw_size: int
    proto_size: int
    opcode: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str
    op_name: str = ""


@dataclass
class DecodedPacket:
    """Fully decoded packet with all layers"""
    raw_data: bytes
    ethernet: Optional[EthernetHeader] = None
    ipv4: Optional[IPv4Header] = None
    ipv6: Optional[IPv6Header] = None
    tcp: Optional[TCPHeader] = None
    udp: Optional[UDPHeader] = None
    icmp: Optional[ICMPHeader] = None
    arp: Optional[ARPHeader] = None
    
    # Computed summary fields
    protocol_name: str = "UNKNOWN"
    src_addr: str = ""
    dst_addr: str = ""
    src_port: int = 0
    dst_port: int = 0
    info_str: str = ""
    payload: bytes = field(default_factory=bytes)


def mac_to_str(mac_bytes: bytes) -> str:
    """Convert 6-byte MAC to string"""
    return ':'.join(f'{b:02x}' for b in mac_bytes)


def decode_ethernet(data: bytes) -> tuple[Optional[EthernetHeader], int]:
    """Decode Ethernet header, return (header, offset)"""
    if len(data) < 14:
        return None, 0
    
    dst_mac = mac_to_str(data[0:6])
    src_mac = mac_to_str(data[6:12])
    ethertype = struct.unpack('!H', data[12:14])[0]
    
    offset = 14
    
    # Handle VLAN tag
    if ethertype == ETHERTYPE_VLAN:
        if len(data) < 18:
            return None, 0
        ethertype = struct.unpack('!H', data[16:18])[0]
        offset = 18
    
    return EthernetHeader(
        dst_mac=dst_mac,
        src_mac=src_mac,
        ethertype=ethertype,
        ethertype_name=ETHERTYPE_NAMES.get(ethertype, f"0x{ethertype:04x}")
    ), offset


def decode_ipv4(data: bytes) -> tuple[Optional[IPv4Header], int]:
    """Decode IPv4 header, return (header, header_length)"""
    if len(data) < 20:
        return None, 0
    
    version_ihl = data[0]
    version = (version_ihl >> 4) & 0x0F
    ihl = (version_ihl & 0x0F) * 4
    
    if version != 4 or len(data) < ihl:
        return None, 0
    
    tos = data[1]
    total_length = struct.unpack('!H', data[2:4])[0]
    identification = struct.unpack('!H', data[4:6])[0]
    flags_frag = struct.unpack('!H', data[6:8])[0]
    flags = (flags_frag >> 13) & 0x07
    fragment_offset = flags_frag & 0x1FFF
    ttl = data[8]
    protocol = data[9]
    checksum = struct.unpack('!H', data[10:12])[0]
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])
    
    return IPv4Header(
        version=version,
        ihl=ihl,
        tos=tos,
        total_length=total_length,
        identification=identification,
        flags=flags,
        fragment_offset=fragment_offset,
        ttl=ttl,
        protocol=protocol,
        checksum=checksum,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol_name=PROTO_NAMES.get(protocol, str(protocol))
    ), ihl


def decode_ipv6(data: bytes) -> tuple[Optional[IPv6Header], int]:
    """Decode IPv6 header, return (header, header_length)"""
    if len(data) < 40:
        return None, 0
    
    first_word = struct.unpack('!I', data[0:4])[0]
    version = (first_word >> 28) & 0x0F
    traffic_class = (first_word >> 20) & 0xFF
    flow_label = first_word & 0xFFFFF
    
    if version != 6:
        return None, 0
    
    payload_length = struct.unpack('!H', data[4:6])[0]
    next_header = data[6]
    hop_limit = data[7]
    src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
    
    return IPv6Header(
        version=version,
        traffic_class=traffic_class,
        flow_label=flow_label,
        payload_length=payload_length,
        next_header=next_header,
        hop_limit=hop_limit,
        src_ip=src_ip,
        dst_ip=dst_ip
    ), 40


def decode_tcp(data: bytes) -> tuple[Optional[TCPHeader], int]:
    """Decode TCP header, return (header, header_length)"""
    if len(data) < 20:
        return None, 0
    
    src_port = struct.unpack('!H', data[0:2])[0]
    dst_port = struct.unpack('!H', data[2:4])[0]
    seq = struct.unpack('!I', data[4:8])[0]
    ack = struct.unpack('!I', data[8:12])[0]
    data_offset_reserved = data[12]
    data_offset = ((data_offset_reserved >> 4) & 0x0F) * 4
    reserved = data_offset_reserved & 0x0F
    flags = data[13]
    window = struct.unpack('!H', data[14:16])[0]
    checksum = struct.unpack('!H', data[16:18])[0]
    urgent = struct.unpack('!H', data[18:20])[0]
    
    return TCPHeader(
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        data_offset=data_offset,
        reserved=reserved,
        flags=flags,
        window=window,
        checksum=checksum,
        urgent=urgent,
        flags_str=tcp_flags_str(flags)
    ), data_offset


def decode_udp(data: bytes) -> tuple[Optional[UDPHeader], int]:
    """Decode UDP header, return (header, 8)"""
    if len(data) < 8:
        return None, 0
    
    src_port = struct.unpack('!H', data[0:2])[0]
    dst_port = struct.unpack('!H', data[2:4])[0]
    length = struct.unpack('!H', data[4:6])[0]
    checksum = struct.unpack('!H', data[6:8])[0]
    
    return UDPHeader(
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        checksum=checksum
    ), 8


def decode_icmp(data: bytes) -> tuple[Optional[ICMPHeader], int]:
    """Decode ICMP header, return (header, 8)"""
    if len(data) < 8:
        return None, 0
    
    icmp_type = data[0]
    code = data[1]
    checksum = struct.unpack('!H', data[2:4])[0]
    
    return ICMPHeader(
        icmp_type=icmp_type,
        code=code,
        checksum=checksum,
        type_name=ICMP_TYPE_NAMES.get(icmp_type, f"Type {icmp_type}")
    ), 8


def decode_arp(data: bytes) -> tuple[Optional[ARPHeader], int]:
    """Decode ARP header, return (header, 28)"""
    if len(data) < 28:
        return None, 0
    
    hw_type = struct.unpack('!H', data[0:2])[0]
    proto_type = struct.unpack('!H', data[2:4])[0]
    hw_size = data[4]
    proto_size = data[5]
    opcode = struct.unpack('!H', data[6:8])[0]
    sender_mac = mac_to_str(data[8:14])
    sender_ip = socket.inet_ntoa(data[14:18])
    target_mac = mac_to_str(data[18:24])
    target_ip = socket.inet_ntoa(data[24:28])
    
    return ARPHeader(
        hw_type=hw_type,
        proto_type=proto_type,
        hw_size=hw_size,
        proto_size=proto_size,
        opcode=opcode,
        sender_mac=sender_mac,
        sender_ip=sender_ip,
        target_mac=target_mac,
        target_ip=target_ip,
        op_name=ARP_OP_NAMES.get(opcode, f"Op {opcode}")
    ), 28


def get_port_name(port: int) -> str:
    """Get well-known port name"""
    return WELL_KNOWN_PORTS.get(port, "")


def decode_packet(data: bytes) -> DecodedPacket:
    """Decode raw packet bytes into structured DecodedPacket"""
    result = DecodedPacket(raw_data=data)
    offset = 0
    
    # Layer 2: Ethernet
    eth, eth_len = decode_ethernet(data)
    if not eth:
        return result
    result.ethernet = eth
    offset = eth_len
    
    # Layer 3: Network
    if eth.ethertype == ETHERTYPE_IP:
        ipv4, ip_len = decode_ipv4(data[offset:])
        if ipv4:
            result.ipv4 = ipv4
            result.src_addr = ipv4.src_ip
            result.dst_addr = ipv4.dst_ip
            result.protocol_name = ipv4.protocol_name
            offset += ip_len
            
            # Layer 4: Transport
            if ipv4.protocol == PROTO_TCP:
                tcp, tcp_len = decode_tcp(data[offset:])
                if tcp:
                    result.tcp = tcp
                    result.src_port = tcp.src_port
                    result.dst_port = tcp.dst_port
                    result.payload = data[offset + tcp_len:]
                    
                    # Build info string
                    port_info = ""
                    src_name = get_port_name(tcp.src_port)
                    dst_name = get_port_name(tcp.dst_port)
                    if src_name:
                        port_info = f" ({src_name})"
                    elif dst_name:
                        port_info = f" ({dst_name})"
                    
                    result.info_str = f"{tcp.src_port} → {tcp.dst_port}{port_info} {tcp.flags_str} Seq={tcp.seq}"
            
            elif ipv4.protocol == PROTO_UDP:
                udp, udp_len = decode_udp(data[offset:])
                if udp:
                    result.udp = udp
                    result.src_port = udp.src_port
                    result.dst_port = udp.dst_port
                    result.payload = data[offset + udp_len:]
                    
                    port_info = ""
                    src_name = get_port_name(udp.src_port)
                    dst_name = get_port_name(udp.dst_port)
                    if src_name:
                        port_info = f" ({src_name})"
                    elif dst_name:
                        port_info = f" ({dst_name})"
                    
                    result.info_str = f"{udp.src_port} → {udp.dst_port}{port_info} Len={udp.length}"
            
            elif ipv4.protocol == PROTO_ICMP:
                icmp, icmp_len = decode_icmp(data[offset:])
                if icmp:
                    result.icmp = icmp
                    result.payload = data[offset + icmp_len:]
                    result.info_str = f"{icmp.type_name} (code={icmp.code})"
    
    elif eth.ethertype == ETHERTYPE_IPV6:
        ipv6, ip_len = decode_ipv6(data[offset:])
        if ipv6:
            result.ipv6 = ipv6
            result.src_addr = ipv6.src_ip
            result.dst_addr = ipv6.dst_ip
            result.protocol_name = "IPv6"
            offset += ip_len
            
            # Parse transport layer based on next_header
            if ipv6.next_header == PROTO_TCP:
                tcp, tcp_len = decode_tcp(data[offset:])
                if tcp:
                    result.tcp = tcp
                    result.protocol_name = "TCP"
                    result.src_port = tcp.src_port
                    result.dst_port = tcp.dst_port
                    result.info_str = f"{tcp.src_port} → {tcp.dst_port} {tcp.flags_str}"
            
            elif ipv6.next_header == PROTO_UDP:
                udp, _ = decode_udp(data[offset:])
                if udp:
                    result.udp = udp
                    result.protocol_name = "UDP"
                    result.src_port = udp.src_port
                    result.dst_port = udp.dst_port
                    result.info_str = f"{udp.src_port} → {udp.dst_port}"
    
    elif eth.ethertype == ETHERTYPE_ARP:
        arp, _ = decode_arp(data[offset:])
        if arp:
            result.arp = arp
            result.protocol_name = "ARP"
            result.src_addr = arp.sender_ip
            result.dst_addr = arp.target_ip
            result.info_str = f"{arp.op_name}: {arp.sender_ip} → {arp.target_ip}"
    
    return result


def decode_packet_scapy(pkt) -> DecodedPacket:
    """Decode using Scapy packet object - alternative method"""
    try:
        from scapy.layers.l2 import Ether, ARP
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.inet6 import IPv6
    except ImportError:
        # Fallback to manual decoder
        return decode_packet(bytes(pkt))
    
    data = bytes(pkt)
    result = DecodedPacket(raw_data=data)
    
    # Ethernet
    if Ether in pkt:
        result.ethernet = EthernetHeader(
            dst_mac=pkt[Ether].dst,
            src_mac=pkt[Ether].src,
            ethertype=pkt[Ether].type,
            ethertype_name=ETHERTYPE_NAMES.get(pkt[Ether].type, "")
        )
    
    # IPv4
    if IP in pkt:
        result.ipv4 = IPv4Header(
            version=pkt[IP].version,
            ihl=pkt[IP].ihl * 4,
            tos=pkt[IP].tos,
            total_length=pkt[IP].len,
            identification=pkt[IP].id,
            flags=int(pkt[IP].flags),
            fragment_offset=pkt[IP].frag,
            ttl=pkt[IP].ttl,
            protocol=pkt[IP].proto,
            checksum=pkt[IP].chksum or 0,
            src_ip=pkt[IP].src,
            dst_ip=pkt[IP].dst,
            protocol_name=PROTO_NAMES.get(pkt[IP].proto, str(pkt[IP].proto))
        )
        result.src_addr = pkt[IP].src
        result.dst_addr = pkt[IP].dst
        result.protocol_name = result.ipv4.protocol_name
    
    # IPv6
    if IPv6 in pkt:
        result.ipv6 = IPv6Header(
            version=pkt[IPv6].version,
            traffic_class=pkt[IPv6].tc,
            flow_label=pkt[IPv6].fl,
            payload_length=pkt[IPv6].plen,
            next_header=pkt[IPv6].nh,
            hop_limit=pkt[IPv6].hlim,
            src_ip=pkt[IPv6].src,
            dst_ip=pkt[IPv6].dst
        )
        result.src_addr = pkt[IPv6].src
        result.dst_addr = pkt[IPv6].dst
        result.protocol_name = "IPv6"
    
    # TCP
    if TCP in pkt:
        flags = int(pkt[TCP].flags)
        result.tcp = TCPHeader(
            src_port=pkt[TCP].sport,
            dst_port=pkt[TCP].dport,
            seq=pkt[TCP].seq,
            ack=pkt[TCP].ack,
            data_offset=pkt[TCP].dataofs * 4 if pkt[TCP].dataofs else 20,
            reserved=pkt[TCP].reserved,
            flags=flags,
            window=pkt[TCP].window,
            checksum=pkt[TCP].chksum or 0,
            urgent=pkt[TCP].urgptr,
            flags_str=tcp_flags_str(flags)
        )
        result.protocol_name = "TCP"
        result.src_port = pkt[TCP].sport
        result.dst_port = pkt[TCP].dport
        result.info_str = f"{pkt[TCP].sport} → {pkt[TCP].dport} {result.tcp.flags_str} Seq={pkt[TCP].seq}"
    
    # UDP
    if UDP in pkt:
        result.udp = UDPHeader(
            src_port=pkt[UDP].sport,
            dst_port=pkt[UDP].dport,
            length=pkt[UDP].len,
            checksum=pkt[UDP].chksum or 0
        )
        result.protocol_name = "UDP"
        result.src_port = pkt[UDP].sport
        result.dst_port = pkt[UDP].dport
        result.info_str = f"{pkt[UDP].sport} → {pkt[UDP].dport} Len={pkt[UDP].len}"
    
    # ICMP
    if ICMP in pkt:
        result.icmp = ICMPHeader(
            icmp_type=pkt[ICMP].type,
            code=pkt[ICMP].code,
            checksum=pkt[ICMP].chksum or 0,
            type_name=ICMP_TYPE_NAMES.get(pkt[ICMP].type, f"Type {pkt[ICMP].type}")
        )
        result.protocol_name = "ICMP"
        result.info_str = f"{result.icmp.type_name} (code={pkt[ICMP].code})"
    
    # ARP
    if ARP in pkt:
        result.arp = ARPHeader(
            hw_type=pkt[ARP].hwtype,
            proto_type=pkt[ARP].ptype,
            hw_size=pkt[ARP].hwlen,
            proto_size=pkt[ARP].plen,
            opcode=pkt[ARP].op,
            sender_mac=pkt[ARP].hwsrc,
            sender_ip=pkt[ARP].psrc,
            target_mac=pkt[ARP].hwdst,
            target_ip=pkt[ARP].pdst,
            op_name=ARP_OP_NAMES.get(pkt[ARP].op, f"Op {pkt[ARP].op}")
        )
        result.protocol_name = "ARP"
        result.src_addr = pkt[ARP].psrc
        result.dst_addr = pkt[ARP].pdst
        result.info_str = f"{result.arp.op_name}: {pkt[ARP].psrc} → {pkt[ARP].pdst}"
    
    return result

