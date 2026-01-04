"""
Capture Engine using Scapy AsyncSniffer
- libpcap backend for performance
- Statistics tracking
- Pause/Resume support
- Thread-safe packet queue
"""

import time
import threading
import queue
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional
from pathlib import Path

from .decoder import PacketInfo, decode_packet_scapy
from .rotator import HourlyRotator
from .constants import (
    DEFAULT_SNAPLEN, DEFAULT_BUFFER_SIZE, DEFAULT_PROMISC,
    DEFAULT_QUEUE_SIZE, STATS_UPDATE_INTERVAL
)

logger = logging.getLogger(__name__)


@dataclass
class CaptureStats:
    """Capture statistics"""
    packets: int = 0
    bytes: int = 0
    dropped: int = 0           # Drops since capture started
    queue_dropped: int = 0
    start_time: float = 0.0
    last_update: float = 0.0
    
    # Rate calculations
    pps: float = 0.0          # Packets per second
    bps: float = 0.0          # Bytes per second
    
    # Previous values for rate calc
    _prev_packets: int = 0
    _prev_bytes: int = 0
    _prev_time: float = 0.0
    
    # Baseline for kernel drops (set at capture start)
    _initial_kernel_drops: int = 0
    _current_kernel_drops: int = 0
    
    def update_rates(self):
        """Update PPS and BPS rates"""
        now = time.time()
        elapsed = now - self._prev_time
        
        if elapsed > 0:
            self.pps = (self.packets - self._prev_packets) / elapsed
            self.bps = (self.bytes - self._prev_bytes) / elapsed
            
            self._prev_packets = self.packets
            self._prev_bytes = self.bytes
            self._prev_time = now
        
        self.last_update = now
        
        # Update dropped = kernel drops since start + queue drops
        self.dropped = max(0, self._current_kernel_drops - self._initial_kernel_drops)
    
    def reset(self):
        """Reset all stats"""
        self.packets = 0
        self.bytes = 0
        self.dropped = 0
        self.queue_dropped = 0
        self.start_time = time.time()
        self.last_update = self.start_time
        self.pps = 0.0
        self.bps = 0.0
        self._prev_packets = 0
        self._prev_bytes = 0
        self._prev_time = self.start_time
        # Will be set by _update_drop_stats on first call
        self._initial_kernel_drops = -1  # -1 = not set yet
        self._current_kernel_drops = 0


class CaptureEngine:
    """
    Packet capture engine using Scapy
    Manages capture lifecycle, stats, and packet routing
    """
    
    def __init__(
        self,
        interface: str,
        bpf_filter: str = "",
        snaplen: int = DEFAULT_SNAPLEN,
        promisc: bool = DEFAULT_PROMISC,
        buffer_size: int = DEFAULT_BUFFER_SIZE,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        packet_callback: Optional[Callable[[PacketInfo], None]] = None,
        rotator: Optional[HourlyRotator] = None,
    ):
        """
        Args:
            interface: Network interface to capture on
            bpf_filter: BPF filter string (e.g., "tcp port 80")
            snaplen: Max bytes to capture per packet
            promisc: Enable promiscuous mode
            buffer_size: Kernel buffer size
            queue_size: Packet queue size for UI
            packet_callback: Callback for each packet (for UI)
            rotator: HourlyRotator for file writing
        """
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.snaplen = snaplen
        self.promisc = promisc
        self.buffer_size = buffer_size
        self.queue_size = queue_size
        self.packet_callback = packet_callback
        self.rotator = rotator
        
        self._sniffer = None
        self._packet_queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._stats = CaptureStats()
        self._packet_stt = 0
        
        self._running = False
        self._paused = False
        self._stop_event = threading.Event()
        self._stats_thread: Optional[threading.Thread] = None
        
        self._lock = threading.Lock()
    
    def setup(self):
        """Initialize Scapy sniffer"""
        try:
            from scapy.all import AsyncSniffer, conf
            
            # Use libpcap backend if available
            try:
                conf.use_pcap = True
            except Exception:
                pass
            
            # Create AsyncSniffer
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._on_packet,
                store=False,
                promisc=self.promisc,
                filter=self.bpf_filter if self.bpf_filter else None,
            )
            logger.info(f"Capture engine setup on {self.interface}")
            
        except ImportError:
            raise ImportError("Scapy is required. Install with: pip install scapy")
    
    def _on_packet(self, pkt):
        """Callback for each captured packet"""
        if self._paused:
            return
        
        try:
            # Get packet info
            ts = float(pkt.time)
            ts_sec = int(ts)
            ts_usec = int((ts % 1) * 1e6)
            data = bytes(pkt)
            
            with self._lock:
                self._packet_stt += 1
                stt = self._packet_stt
            
            pkt_info = PacketInfo(
                stt=stt,
                ts_sec=ts_sec,
                ts_usec=ts_usec,
                caplen=len(data),
                origlen=len(data),
                data=data
            )
            
            # Update stats
            self._stats.packets += 1
            self._stats.bytes += len(data)
            
            # Write to rotator (PCAP file)
            if self.rotator:
                try:
                    self.rotator.write_packet_info(pkt_info)
                except Exception as e:
                    logger.error(f"Rotator write error: {e}")
            
            # Call packet callback (for UI)
            if self.packet_callback:
                try:
                    self.packet_callback(pkt_info)
                except Exception:
                    pass  # Don't let callback errors crash capture
            
            # Add to queue (for UI display)
            try:
                self._packet_queue.put_nowait(pkt_info)
            except queue.Full:
                self._stats.queue_dropped += 1
        
        except Exception as e:
            logger.error(f"Packet processing error: {e}")
    
    def _stats_loop(self):
        """Background thread for updating stats"""
        while not self._stop_event.is_set():
            self._stats.update_rates()
            self._update_drop_stats()
            time.sleep(STATS_UPDATE_INTERVAL)
    
    def _update_drop_stats(self):
        """Read drop stats from /proc/net/dev"""
        try:
            with open('/proc/net/dev', 'r') as f:
                for line in f:
                    if self.interface in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            # Column 4 is rx_drop (absolute from kernel)
                            kernel_drops = int(parts[4])
                            
                            # Set initial baseline on first read
                            if self._stats._initial_kernel_drops < 0:
                                self._stats._initial_kernel_drops = kernel_drops
                            
                            self._stats._current_kernel_drops = kernel_drops
                        break
        except Exception:
            pass
    
    def start(self):
        """Start capturing"""
        if self._running:
            return
        
        if self._sniffer is None:
            self.setup()
        
        self._running = True
        self._paused = False
        self._stop_event.clear()
        self._stats.reset()
        
        # Start stats thread
        self._stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
        self._stats_thread.start()
        
        # Start sniffer
        self._sniffer.start()
        logger.info(f"Capture started on {self.interface}")
    
    def stop(self):
        """Stop capturing"""
        if not self._running:
            return
        
        self._running = False
        self._stop_event.set()
        
        # Stop sniffer
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception as e:
                logger.error(f"Error stopping sniffer: {e}")
        
        # Wait for stats thread
        if self._stats_thread and self._stats_thread.is_alive():
            self._stats_thread.join(timeout=2.0)
        
        # Flush rotator
        if self.rotator:
            self.rotator.flush()
        
        logger.info("Capture stopped")
    
    def pause(self):
        """Pause capturing (packets still captured but not processed)"""
        self._paused = True
        logger.info("Capture paused")
    
    def resume(self):
        """Resume capturing"""
        self._paused = False
        logger.info("Capture resumed")
    
    def toggle_pause(self) -> bool:
        """Toggle pause state, return new state"""
        if self._paused:
            self.resume()
        else:
            self.pause()
        return self._paused
    
    @property
    def is_running(self) -> bool:
        return self._running
    
    @property
    def is_paused(self) -> bool:
        return self._paused
    
    @property
    def stats(self) -> CaptureStats:
        return self._stats
    
    @property
    def packet_queue(self) -> queue.Queue:
        return self._packet_queue
    
    def get_packet(self, timeout: float = 0.1) -> Optional[PacketInfo]:
        """Get packet from queue"""
        try:
            return self._packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def clear_queue(self):
        """Clear packet queue"""
        while not self._packet_queue.empty():
            try:
                self._packet_queue.get_nowait()
            except queue.Empty:
                break
    
    def get_status(self) -> dict:
        """Get capture status"""
        uptime = time.time() - self._stats.start_time if self._stats.start_time else 0
        
        return {
            "interface": self.interface,
            "running": self._running,
            "paused": self._paused,
            "uptime": uptime,
            "packets": self._stats.packets,
            "bytes": self._stats.bytes,
            "dropped": self._stats.dropped,
            "queue_dropped": self._stats.queue_dropped,
            "pps": self._stats.pps,
            "bps": self._stats.bps,
            "queue_size": self._packet_queue.qsize(),
        }


def get_interfaces() -> list:
    """Get list of available network interfaces - FAST version using /sys"""
    interfaces = []
    
    # Use /sys/class/net directly (fast, no scapy import)
    try:
        net_path = Path('/sys/class/net')
        if net_path.exists():
            interfaces = [d.name for d in net_path.iterdir() if d.is_dir()]
    except Exception:
        pass
    
    # Filter out loopback if others available
    if len(interfaces) > 1 and 'lo' in interfaces:
        interfaces = [i for i in interfaces if i != 'lo']
    
    return sorted(interfaces)


def validate_interface(interface: str) -> bool:
    """Check if interface exists"""
    return interface in get_interfaces() or interface == 'any'


def get_interface_info(interface: str) -> dict:
    """Get interface information - FAST version using /sys only"""
    info = {
        "name": interface,
        "exists": False,
        "ipv4": None,
        "mac": None,
        "up": False,
    }
    
    try:
        net_path = Path(f'/sys/class/net/{interface}')
        if not net_path.exists():
            return info
        
        info["exists"] = True
        
        # Get state from /sys (fast)
        state_file = net_path / 'operstate'
        if state_file.exists():
            state = state_file.read_text().strip()
            info["up"] = state in ('up', 'unknown')  # unknown = usually up
        
        # Get MAC from /sys (fast)
        addr_file = net_path / 'address'
        if addr_file.exists():
            info["mac"] = addr_file.read_text().strip()
        
        # Get IPv4 from /proc/net/fib_trie or socket (fast, no subprocess)
        try:
            import socket
            import fcntl
            import struct
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip_bytes = fcntl.ioctl(
                sock.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', interface.encode('utf-8')[:15])
            )[20:24]
            info["ipv4"] = socket.inet_ntoa(ip_bytes)
            sock.close()
        except Exception:
            info["ipv4"] = None
    
    except Exception as e:
        logger.error(f"Error getting interface info: {e}")
    
    return info

