"""
List View - Hiển thị danh sách packets kiểu Wireshark
Fixed: Memory leak, CPU optimization
"""

import sys
import threading
import queue
import time
import select
import termios
import tty
import gc
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable
from collections import deque, OrderedDict

import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.colors import (
    clear_screen, print_header, print_divider,
    bold, cyan, green, yellow, red, dim, white, magenta,
    get_terminal_size, hide_cursor, show_cursor, clear_line,
    format_bytes, format_number, format_rate, format_duration,
    Colors, color
)
from core.decoder import decode_packet, DecodedPacket, PacketInfo


class LimitedDict:
    """
    Dict với giới hạn kích thước - tự động xóa entries cũ nhất
    Giải quyết memory leak của packet_map
    """
    def __init__(self, maxsize: int = 10000):
        self.maxsize = maxsize
        self._data = OrderedDict()
        self._lock = threading.Lock()
    
    def __setitem__(self, key, value):
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
            self._data[key] = value
            # Xóa entries cũ nếu vượt quá limit
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)
    
    def __getitem__(self, key):
        with self._lock:
            return self._data[key]
    
    def __contains__(self, key):
        with self._lock:
            return key in self._data
    
    def get(self, key, default=None):
        with self._lock:
            return self._data.get(key, default)
    
    def clear(self):
        with self._lock:
            self._data.clear()
    
    def __len__(self):
        with self._lock:
            return len(self._data)


class PacketListView:
    """
    Hiển thị danh sách packets theo dạng bảng
    Auto-scroll và hỗ trợ tạm dừng
    
    Fixed:
    - Memory leak: packet_map giờ có giới hạn kích thước
    - CPU usage: Giảm decode overhead, batch processing
    - Queue overflow: Drop packets cũ thay vì block
    """
    
    # Column widths
    COL_STT = 8
    COL_TIME = 12
    COL_SRC = 32
    COL_DST = 32
    COL_PROTO = 8
    COL_LEN = 7
    COL_INFO = 35
    
    # Protocol colors
    PROTO_COLORS = {
        'TCP': Colors.GREEN,
        'UDP': Colors.BLUE,
        'ICMP': Colors.MAGENTA,
        'ARP': Colors.YELLOW,
        'IPv4': Colors.CYAN,
        'IPv6': Colors.CYAN,
    }
    
    def __init__(
        self,
        packet_queue: queue.Queue,
        on_quit: Callable,
        stats_callback: Callable[[], Dict[str, Any]],
        file_info_callback: Callable[[], Dict[str, Any]],
        on_pause: Optional[Callable[[bool], None]] = None,  # Callback khi pause/resume
        on_save_exit: Optional[Callable[[], None]] = None,  # Callback lưu file và thoát
        cache_size: int = 5000,  # Giảm xuống để tiết kiệm RAM
    ):
        self.packet_queue = packet_queue
        self.on_quit = on_quit
        self.stats_callback = stats_callback
        self.file_info_callback = file_info_callback
        self.on_pause = on_pause  # Callback để pause capture engine
        self.on_save_exit = on_save_exit  # Callback lưu file và thoát
        
        # Packet cache - giới hạn cả deque và map
        self.cache_size = cache_size
        self.packets: deque = deque(maxlen=cache_size)
        self.packet_map = LimitedDict(maxsize=cache_size)  # Fixed memory leak!
        
        # Display state
        self.paused = False
        self.running = False
        self.start_time = time.time()
        
        # Threading
        self._display_thread: Optional[threading.Thread] = None
        self._input_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Terminal state
        self._old_settings = None
        self._terminal_restored = False  # Track if terminal already restored
        
        # Performance counters
        self._packets_processed = 0
        self._last_gc = time.time()
    
    def _setup_terminal(self):
        """Setup terminal cho non-blocking input"""
        try:
            self._old_settings = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())
        except Exception:
            self._old_settings = None
    
    def _restore_terminal(self):
        """Restore terminal settings"""
        if self._old_settings and not self._terminal_restored:
            try:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self._old_settings)
                self._terminal_restored = True
            except Exception:
                pass
    
    def _truncate_ipv6(self, addr: str, max_len: int) -> str:
        """Intelligently truncate IPv6 address"""
        if len(addr) <= max_len:
            return addr
        
        # Check if it's IPv6 (contains multiple colons)
        if addr.count(':') < 2:
            return addr[:max_len]
        
        # For IPv6, show first part and last segment
        # fe80:1c4f:3f2a:28b9:a:b:c:d -> fe80:1c4f:...:d
        parts = addr.split(':')
        if len(parts) >= 4:
            # Keep first 2-3 segments and last segment
            keep_first = 2
            last_seg = parts[-1] if parts[-1] else parts[-2]
            truncated = ':'.join(parts[:keep_first]) + ':...:' + last_seg
            if len(truncated) <= max_len:
                return truncated
        
        # Fallback: simple truncation
        return addr[:max_len-3] + '...'
    
    def _get_header_line(self) -> str:
        """Tạo header line"""
        cols = [
            ("STT", self.COL_STT),
            ("Thời gian", self.COL_TIME),
            ("Nguồn", self.COL_SRC),
            ("Đích", self.COL_DST),
            ("Proto", self.COL_PROTO),
            ("Dài", self.COL_LEN),
            ("Thông tin", self.COL_INFO),
        ]
        
        parts = []
        for name, width in cols:
            parts.append(bold(name.ljust(width)))
        
        return ' '.join(parts)
    
    def _format_packet_row(self, pkt_info: PacketInfo, decoded: DecodedPacket) -> str:
        """Format một dòng packet"""
        try:
            # Time relative
            elapsed = pkt_info.ts_sec - int(self.start_time)
            time_str = f"{elapsed:>8}.{pkt_info.ts_usec // 1000:03d}"
            
            # Protocol color
            proto = decoded.protocol_name if decoded else 'UNKNOWN'
            proto_color = self.PROTO_COLORS.get(proto, Colors.WHITE)
            
            # Source/Dest
            src = decoded.src_addr if decoded else ''
            dst = decoded.dst_addr if decoded else ''
            
            if decoded and decoded.src_port:
                src = f"{src}:{decoded.src_port}"
            if decoded and decoded.dst_port:
                dst = f"{dst}:{decoded.dst_port}"
            
            # Truncate if needed with smart IPv6 handling
            src = self._truncate_ipv6(src or '-', self.COL_SRC - 1).ljust(self.COL_SRC)
            dst = self._truncate_ipv6(dst or '-', self.COL_DST - 1).ljust(self.COL_DST)
            
            # Info - sniff uses info_str as attribute, not method
            info_str = (decoded.info_str if decoded else '')[:self.COL_INFO - 1]
            
            # Build row
            row = ' '.join([
                str(pkt_info.stt).rjust(self.COL_STT),
                time_str.ljust(self.COL_TIME),
                src,
                dst,
                color(proto.ljust(self.COL_PROTO), proto_color),
                str(pkt_info.origlen).rjust(self.COL_LEN),
                info_str,
            ])
            
            return row
        except Exception:
            return f"{pkt_info.stt:>8} [Error formatting packet]"
    
    def _draw_stats_bar(self) -> str:
        """Vẽ thanh thống kê"""
        try:
            stats = self.stats_callback()
            
            parts = [
                f"Nhận: {format_number(stats.get('packets', 0))}",
                f"Rớt: {format_number(stats.get('dropped', 0))}",
                f"Tốc độ: {format_rate(stats.get('pps', 0), ' pkt/s')}",
                f"Băng thông: {format_rate(stats.get('bps', 0) * 8, 'bps')}",
                f"Cache: {len(self.packets)}/{self.cache_size}",
            ]
            
            return dim(' | '.join(parts))
        except Exception:
            return dim("Stats: N/A")
    
    def _draw_file_info(self) -> str:
        """Vẽ thông tin file"""
        try:
            file_info = self.file_info_callback()
            
            current_file = file_info.get('current_file', 'N/A')
            next_rotate = file_info.get('next_rotate', 'N/A')
            retention = file_info.get('retention_days', 7)
            
            # Shorten path
            if current_file and len(current_file) > 50:
                current_file = '...' + current_file[-47:]
            
            return dim(f"File: {current_file} | Cắt: {next_rotate} | Giữ: {retention} ngày")
        except Exception:
            return dim("File: N/A")
    
    def _draw_screen(self, new_packets: List[tuple]):
        """Vẽ màn hình"""
        try:
            term_width, term_height = get_terminal_size()
            
            # Số dòng cho packets (trừ header, stats, controls)
            available_lines = term_height - 8
            
            # Header
            lines = []
            lines.append(bold(" SNIFF - Đang bắt gói tin ") + (yellow(" [TẠM DỪNG]") if self.paused else green(" [ĐANG CHẠY]")))
            lines.append(self._draw_file_info())
            lines.append('')
            lines.append(self._get_header_line())
            lines.append(dim('─' * min(term_width, 120)))
            
            # Packets
            with self._lock:
                # Lấy packets mới nhất để hiển thị
                display_packets = list(self.packets)[-available_lines:]
            
            for pkt_info, decoded in display_packets:
                row = self._format_packet_row(pkt_info, decoded)
                lines.append(row)
            
            # Padding
            while len(lines) < term_height - 3:
                lines.append('')
            
            # Stats and controls
            lines.append(dim('─' * min(term_width, 120)))
            lines.append(self._draw_stats_bar())
            
            # Control hints
            lines.append(cyan("[Space] Dừng/Chạy, [S] Lưu & Thoát, [Q] Thoát"))
            
            # Clear and draw
            sys.stdout.write('\033[H')  # Home
            for i, line in enumerate(lines[:term_height]):
                # Clear line và in
                sys.stdout.write(f'\033[{i + 1};1H\033[2K{line}')
            sys.stdout.flush()
        except Exception:
            pass  # Không để lỗi UI crash chương trình
    
    def _display_loop(self):
        """Vòng lặp hiển thị - tối ưu CPU"""
        hide_cursor()
        clear_screen()
        
        last_draw = 0
        new_packets = []
        batch_size = 100  # Xử lý batch để giảm overhead
        
        while self.running:
            try:
                # Khi PAUSED: drain TOÀN BỘ queue (discard tất cả)
                if self.paused:
                    discarded = 0
                    try:
                        while True:
                            self.packet_queue.get_nowait()
                            discarded += 1
                    except queue.Empty:
                        pass
                    # Sleep ngắn khi paused
                    time.sleep(0.05)
                    continue
                
                # Khi RUNNING: đọc batch và xử lý
                packets_read = 0
                while packets_read < batch_size:
                    try:
                        pkt_info = self.packet_queue.get_nowait()
                        
                        # Decode với error handling
                        try:
                            decoded = decode_packet(pkt_info.data)
                        except Exception:
                            decoded = None
                        
                        with self._lock:
                            self.packets.append((pkt_info, decoded))
                            self.packet_map[pkt_info.stt] = pkt_info
                        
                        new_packets.append((pkt_info, decoded))
                        packets_read += 1
                        self._packets_processed += 1
                        
                    except queue.Empty:
                        break
                
                # Vẽ lại màn hình (max 10 FPS)
                now = time.time()
                if now - last_draw >= 0.1:
                    self._draw_screen(new_packets)
                    new_packets.clear()
                    last_draw = now
                
                # Periodic garbage collection (mỗi 30 giây)
                if now - self._last_gc >= 30.0:
                    gc.collect()
                    self._last_gc = now
                
                # Sleep ngắn để không chiếm CPU
                time.sleep(0.01)
                
            except Exception:
                time.sleep(0.1)  # Sleep dài hơn nếu có lỗi
        
        show_cursor()
    
    def _input_loop(self):
        """Vòng lặp xử lý input - đơn giản hóa"""
        while self.running:
            try:
                # Check if input available
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    ch = sys.stdin.read(1)
                    
                    if ch == ' ':
                        # Toggle pause - THỰC SỰ tạm dừng capture
                        self.paused = not self.paused
                        
                        # Gọi callback để pause/resume capture engine
                        if self.on_pause:
                            try:
                                self.on_pause(self.paused)
                            except Exception:
                                pass
                        
                        # Khi RESUME: clear queue để không hiển thị packets cũ tích lũy
                        if not self.paused:
                            # Clear queue - loại bỏ packets cũ tích lũy trong kernel buffer
                            cleared = 0
                            try:
                                while True:
                                    self.packet_queue.get_nowait()
                                    cleared += 1
                            except queue.Empty:
                                pass
                    elif ch.lower() == 's':
                        # Save và Exit - lưu file hiện tại và thoát
                        # QUAN TRỌNG: Dừng display loop TRƯỚC để messages hiển thị đúng
                        self.running = False
                        
                        # Đợi display thread dừng để không ghi đè messages
                        if self._display_thread:
                            self._display_thread.join(timeout=0.5)
                        
                        # Restore terminal TRƯỚC khi callback
                        self._restore_terminal()
                        show_cursor()
                        
                        # Giờ gọi callback - messages sẽ hiển thị đúng
                        if self.on_save_exit:
                            try:
                                self.on_save_exit()
                            except Exception:
                                pass
                        # running đã = False, thoát vòng lặp
                    elif ch.lower() == 'q':
                        # Quit
                        self.running = False
                        self.on_quit()
            except Exception:
                pass
    
    def start(self):
        """Bắt đầu hiển thị"""
        self.running = True
        self.start_time = time.time()
        self.packets.clear()
        self.packet_map.clear()
        self.paused = False
        self._packets_processed = 0
        self._last_gc = time.time()
        self._terminal_restored = False
        
        self._setup_terminal()
        
        self._display_thread = threading.Thread(
            target=self._display_loop,
            daemon=True,
        )
        self._input_thread = threading.Thread(
            target=self._input_loop,
            daemon=True,
        )
        
        self._display_thread.start()
        self._input_thread.start()
    
    def stop(self):
        """Dừng hiển thị"""
        self.running = False
        
        if self._display_thread:
            self._display_thread.join(timeout=1.0)
        if self._input_thread:
            self._input_thread.join(timeout=1.0)
        
        # Chỉ restore terminal nếu chưa restore
        if not self._terminal_restored:
            self._restore_terminal()
            show_cursor()
        
        # Clear memory
        self.packets.clear()
        self.packet_map.clear()
        gc.collect()
    
    def wait(self):
        """Chờ cho đến khi dừng"""
        while self.running:
            time.sleep(0.1)
