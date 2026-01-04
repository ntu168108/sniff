"""
Detail View - Xem chi tiết packet với hexdump
"""

import sys
import os
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.colors import (
    clear_screen, print_header, print_divider, print_menu_item,
    bold, cyan, green, yellow, red, dim, magenta, white,
    get_terminal_size, show_cursor
)
from core.decoder import decode_packet, DecodedPacket, PacketInfo
from core.pcap_writer import PcapWriter


def hexdump(data: bytes, bytes_per_line: int = 16) -> str:
    """
    Tạo hexdump string từ bytes
    Format: offset  hex bytes  |  ASCII
    """
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        
        # Hex phần
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
        
        # ASCII phần  
        ascii_part = ''.join(
            chr(b) if 32 <= b < 127 else '.'
            for b in chunk
        )
        
        lines.append(f'{i:08x}  {hex_part}  |{ascii_part}|')
    
    return '\n'.join(lines)


class PacketDetailView:
    """
    Hiển thị chi tiết một packet
    - Decode các layer
    - Hexdump với ASCII
    """
    
    def __init__(self):
        pass
    
    def show(self, pkt_info: PacketInfo, on_back: callable, save_dir: Optional[str] = None):
        """
        Hiển thị chi tiết packet
        
        Args:
            pkt_info: Thông tin packet
            on_back: Callback khi quay lại
            save_dir: Thư mục để lưu packet riêng (nếu có)
        """
        show_cursor()
        decoded = decode_packet(pkt_info.data)
        
        while True:
            clear_screen()
            print_header(f" CHI TIẾT GÓI #{pkt_info.stt} ", '═')
            print()
            
            # Thông tin cơ bản
            print(bold("═══ THÔNG TIN CHUNG ═══"))
            print(f"  STT:        {cyan(str(pkt_info.stt))}")
            print(f"  Thời gian:  {pkt_info.ts_sec}.{pkt_info.ts_usec:06d}")
            print(f"  Độ dài:     {pkt_info.caplen} bytes (gốc: {pkt_info.origlen} bytes)")
            print()
            
            # Ethernet
            if decoded.ethernet:
                eth = decoded.ethernet
                print(bold("═══ ETHERNET ═══"))
                print(f"  MAC nguồn:  {cyan(eth.src_mac)}")
                print(f"  MAC đích:   {cyan(eth.dst_mac)}")
                print(f"  EtherType:  {hex(eth.ethertype)} ({eth.ethertype_name})")
                print()
            
            # IPv4
            if decoded.ipv4:
                ip = decoded.ipv4
                print(bold("═══ IPv4 ═══"))
                print(f"  Version:    {ip.version}")
                print(f"  IHL:        {ip.ihl} bytes")
                print(f"  ToS:        {ip.tos}")
                print(f"  Length:     {ip.total_length}")
                print(f"  ID:         {ip.identification}")
                print(f"  Flags:      {ip.flags}")
                print(f"  Frag Off:   {ip.fragment_offset}")
                print(f"  TTL:        {ip.ttl}")
                print(f"  Protocol:   {ip.protocol} ({ip.protocol_name})")
                print(f"  Checksum:   {hex(ip.checksum)}")
                print(f"  Nguồn:      {green(ip.src_ip)}")
                print(f"  Đích:       {green(ip.dst_ip)}")
                print()
            
            # IPv6
            if decoded.ipv6:
                ip6 = decoded.ipv6
                print(bold("═══ IPv6 ═══"))
                print(f"  Version:      {ip6.version}")
                print(f"  Traffic Cls:  {ip6.traffic_class}")
                print(f"  Flow Label:   {ip6.flow_label}")
                print(f"  Payload Len:  {ip6.payload_length}")
                print(f"  Next Header:  {ip6.next_header}")
                print(f"  Hop Limit:    {ip6.hop_limit}")
                print(f"  Nguồn:        {green(ip6.src_ip)}")
                print(f"  Đích:         {green(ip6.dst_ip)}")
                print()
            
            # TCP
            if decoded.tcp:
                tcp = decoded.tcp
                print(bold("═══ TCP ═══"))
                print(f"  Port nguồn: {yellow(str(tcp.src_port))}")
                print(f"  Port đích:  {yellow(str(tcp.dst_port))}")
                print(f"  Seq:        {tcp.seq}")
                print(f"  Ack:        {tcp.ack}")
                print(f"  Data Off:   {tcp.data_offset} ({tcp.data_offset * 4} bytes)")
                print(f"  Flags:      {magenta(tcp.flags_str)} ({hex(tcp.flags)})")
                print(f"  Window:     {tcp.window}")
                print(f"  Checksum:   {hex(tcp.checksum)}")
                print(f"  Urgent:     {tcp.urgent}")
                print()
            
            # UDP
            if decoded.udp:
                udp = decoded.udp
                print(bold("═══ UDP ═══"))
                print(f"  Port nguồn: {yellow(str(udp.src_port))}")
                print(f"  Port đích:  {yellow(str(udp.dst_port))}")
                print(f"  Length:     {udp.length}")
                print(f"  Checksum:   {hex(udp.checksum)}")
                print()
            
            # ICMP
            if decoded.icmp:
                icmp = decoded.icmp
                print(bold("═══ ICMP ═══"))
                print(f"  Type:       {magenta(icmp.type_name)} ({icmp.icmp_type})")
                print(f"  Code:       {icmp.code}")
                print(f"  Checksum:   {hex(icmp.checksum)}")
                print()
            
            # ARP
            if decoded.arp:
                arp = decoded.arp
                print(bold("═══ ARP ═══"))
                print(f"  Operation:    {magenta(arp.op_name)} ({arp.opcode})")
                print(f"  Sender MAC:   {cyan(arp.sender_mac)}")
                print(f"  Sender IP:    {green(arp.sender_ip)}")
                print(f"  Target MAC:   {cyan(arp.target_mac)}")
                print(f"  Target IP:    {green(arp.target_ip)}")
                print()
            
            # Payload hexdump
            print(bold("═══ PAYLOAD / HEXDUMP ═══"))
            if decoded.payload:
                print(f"  Payload size: {len(decoded.payload)} bytes")
                print()
                # Hiển thị tối đa 256 bytes
                display_data = pkt_info.data[:256]
                hex_output = hexdump(display_data)
                for line in hex_output.split('\n'):
                    print(f"  {dim(line)}")
                
                if len(pkt_info.data) > 256:
                    print(dim(f"  ... còn {len(pkt_info.data) - 256} bytes ..."))
            else:
                print(dim("  (Không có payload)"))
            
            print()
            print_divider()
            print()
            
            # Menu
            print_menu_item('1', 'Quay lại danh sách')
            if save_dir:
                print_menu_item('2', 'Lưu gói này ra file PCAP riêng')
            print_menu_item('0', 'Thoát về menu chính')
            print()
            
            try:
                choice = input(f"{cyan('Chọn')} [0-2]: ").strip()
            except (EOFError, KeyboardInterrupt):
                return
            
            if choice == '1':
                # Quay lại danh sách - gọi callback
                if on_back:
                    on_back()
                return
            elif choice == '2' and save_dir:
                self._save_single_packet(pkt_info, save_dir)
            elif choice == '0':
                # Thoát hẳn - không gọi on_back
                return
    
    def _save_single_packet(self, pkt_info: PacketInfo, save_dir: str):
        """Lưu một packet ra file riêng"""
        from datetime import datetime
        
        os.makedirs(save_dir, exist_ok=True)
        
        filename = f"packet_{pkt_info.stt}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        filepath = os.path.join(save_dir, filename)
        
        try:
            writer = PcapWriter(filepath, snaplen=65535)
            writer.open()
            writer.write_packet(
                pkt_info.ts_sec,
                pkt_info.ts_usec,
                pkt_info.data,
                pkt_info.origlen,
            )
            writer.close()
            print(green(f"Đã lưu: {filepath}"))
        except Exception as e:
            print(red(f"Lỗi lưu file: {e}"))
        
        input("Nhấn Enter để tiếp tục...")
