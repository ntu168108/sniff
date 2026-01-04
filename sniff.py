#!/usr/bin/env python3
"""
SNIFF - Network Packet Capture Tool
Main entry point with CLI args and daemon mode

Usage:
    sudo python3 sniff.py                    # Interactive menu
    sudo python3 sniff.py -i eth0            # Quick capture on eth0
    sudo python3 sniff.py -i eth0 -d         # Daemon mode
    sudo python3 sniff.py --status           # Check daemon status
    sudo python3 sniff.py --stop             # Stop daemon
"""

import os
import sys
import argparse
import signal
import logging
import time
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.capture import CaptureEngine, get_interfaces, validate_interface
from core.rotator import HourlyRotator
from core.constants import BUFFER_PROFILES, DEFAULT_SNAPLEN, DEFAULT_PROMISC, DEFAULT_RETENTION_DAYS
from ui.menu import MainMenu
from ui.list_view import PacketListView
from ui.colors import green, red, yellow, bold, show_cursor, clear_screen, success, error, info
from modules.runner import create_runner

# Default paths
DEFAULT_DATA_DIR = Path(__file__).parent / "sniff_data"
DEFAULT_PID_FILE = "/tmp/sniff.pid"
DEFAULT_LOG_FILE = "/tmp/sniff.log"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger('sniff')


class SniffApp:
    """Main application class"""
    
    def __init__(
        self,
        data_dir: str = None,
        interface: str = None,
        bpf_filter: str = "",
        snaplen: int = DEFAULT_SNAPLEN,
        promisc: bool = DEFAULT_PROMISC,
        buffer_profile: str = "balanced",
        retention_days: int = DEFAULT_RETENTION_DAYS,
        daemon: bool = False,
        enable_modules: bool = True,
    ):
        self.data_dir = Path(data_dir) if data_dir else DEFAULT_DATA_DIR
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.snaplen = snaplen
        self.promisc = promisc
        self.buffer_profile = buffer_profile
        self.retention_days = retention_days
        self.daemon = daemon
        self.enable_modules = enable_modules
        
        # Components
        self.capture: CaptureEngine = None
        self.rotator: HourlyRotator = None
        self.module_runner = None
        self.list_view: PacketListView = None
        
        # State
        self._running = False
        self._shutdown_requested = False
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        self._shutdown_requested = True
        self.stop()
    
    def _on_rotate(self, pcap_path: str, interface: str, time_window: str):
        """Callback when file rotates - queue for analysis"""
        if self.module_runner:
            self.module_runner.queue_analysis(pcap_path, interface, time_window)
    
    def setup(self):
        """Setup all components"""
        # Create directories
        self.data_dir.mkdir(parents=True, exist_ok=True)
        raw_dir = self.data_dir / "raw"
        raw_dir.mkdir(exist_ok=True)
        modules_dir = self.data_dir / "modules"
        modules_dir.mkdir(exist_ok=True)
        
        # Get buffer profile
        profile = BUFFER_PROFILES.get(self.buffer_profile, BUFFER_PROFILES['balanced'])
        
        # Setup module runner
        if self.enable_modules:
            self.module_runner = create_runner(
                output_dir=str(modules_dir),
                auto_discover=True
            )
        
        # Setup rotator
        self.rotator = HourlyRotator(
            base_dir=str(raw_dir),
            interface=self.interface,
            snaplen=self.snaplen,
            retention_days=self.retention_days,
            on_rotate=self._on_rotate if self.module_runner else None,
        )
        
        # Setup capture engine
        self.capture = CaptureEngine(
            interface=self.interface,
            bpf_filter=self.bpf_filter,
            snaplen=self.snaplen,
            promisc=self.promisc,
            buffer_size=profile['buffer_size'],
            queue_size=profile['queue_size'],
            rotator=self.rotator,
        )
        
        # Setup capture engine
        self.capture.setup()
        
        logger.info(f"Setup complete - Interface: {self.interface}, Data dir: {self.data_dir}")
    
    def start(self):
        """Start capture"""
        if self._running:
            return
        
        self._running = True
        self._setup_signal_handlers()
        
        # Start module runner
        if self.module_runner:
            self.module_runner.start()
        
        # Start capture
        self.capture.start()
        
        logger.info("Capture started")
    
    def stop(self):
        """Stop capture and cleanup"""
        if not self._running:
            return
        
        self._running = False
        
        # Stop list view first
        if self.list_view:
            self.list_view.stop()
        
        # Stop capture
        if self.capture:
            self.capture.stop()
        
        # Flush and close rotator
        if self.rotator:
            self.rotator.close()
        
        # Stop module runner
        if self.module_runner:
            self.module_runner.stop(wait=True)
        
        logger.info("Capture stopped")
    
    def _get_stats(self) -> dict:
        """Wrapper để trả về stats dict tương thích với UI mới"""
        if self.capture:
            stats = self.capture.stats
            return {
                'packets': stats.packets,
                'dropped': stats.dropped + stats.queue_dropped,
                'bytes': stats.bytes,
                'pps': stats.pps,
                'bps': stats.bps,
                'paused': self.capture.is_paused,
            }
        return {}
    
    def _get_file_info(self) -> dict:
        """Wrapper để trả về file info tương thích với UI mới"""
        if self.rotator:
            return {
                'current_file': self.rotator.current_filepath,
                'next_rotate': self.rotator.next_rotate_time.strftime('%H:%M:%S') if self.rotator.next_rotate_time else 'N/A',
                'retention_days': self.retention_days,
            }
        return {}
    
    def _on_pause(self, paused: bool):
        """Callback khi UI pause/resume"""
        if self.capture:
            if paused:
                self.capture.pause()
            else:
                self.capture.resume()
    
    def _on_save_exit(self):
        """Callback khi nhấn S (save & exit)"""
        clear_screen()
        print()
        print(success("Đang lưu file..."))
        
        if self.rotator:
            self.rotator.flush()
            current_file = self.rotator.current_filepath
            if current_file:
                print(info(f"File đã lưu: {current_file}"))
        
        print()
        print(bold("Thống kê phiên capture:"))
        if self.capture:
            stats = self.capture.stats
            print(f"  Tổng gói:    {stats.packets:,}")
            print(f"  Tổng bytes:  {stats.bytes:,}")
            print(f"  Rớt:         {stats.dropped + stats.queue_dropped:,}")
        
        print()
        print(info("Tạm biệt!"))
        time.sleep(1)
    
    def _on_quit(self):
        """Callback khi nhấn Q (quit)"""
        self.stop()
    
    def run_interactive(self):
        """Run with interactive UI"""
        self.setup()
        self.start()
        
        # Create and start list view with new API
        self.list_view = PacketListView(
            packet_queue=self.capture.packet_queue,
            on_quit=self._on_quit,
            stats_callback=self._get_stats,
            file_info_callback=self._get_file_info,
            on_pause=self._on_pause,
            on_save_exit=self._on_save_exit,
        )
        
        try:
            self.list_view.start()
            self.list_view.wait()
        finally:
            show_cursor()
            self.stop()
    
    def run_daemon(self):
        """Run as daemon (headless)"""
        self.setup()
        self.start()
        
        logger.info("Running in daemon mode (headless)")
        
        # Main loop - just wait for shutdown
        while not self._shutdown_requested:
            time.sleep(1)
            
            # Log stats periodically
            stats = self.capture.stats
            if stats.packets > 0 and stats.packets % 10000 == 0:
                logger.info(
                    f"Stats: {stats.packets} pkts, {stats.bytes} bytes, "
                    f"PPS: {stats.pps:.1f}, Dropped: {stats.dropped}"
                )
        
        self.stop()


def daemonize(pid_file: str):
    """
    Daemonize the process using double-fork technique
    """
    # First fork
    try:
        pid = os.fork()
        if pid > 0:
            # Parent exits
            sys.exit(0)
    except OSError as e:
        logger.error(f"Fork #1 failed: {e}")
        sys.exit(1)
    
    # Decouple from parent
    os.chdir('/')
    os.setsid()
    os.umask(0)
    
    # Second fork
    try:
        pid = os.fork()
        if pid > 0:
            # Parent exits
            sys.exit(0)
    except OSError as e:
        logger.error(f"Fork #2 failed: {e}")
        sys.exit(1)
    
    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    
    with open('/dev/null', 'r') as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
    
    with open(DEFAULT_LOG_FILE, 'a') as log:
        os.dup2(log.fileno(), sys.stdout.fileno())
        os.dup2(log.fileno(), sys.stderr.fileno())
    
    # Write PID file
    with open(pid_file, 'w') as f:
        f.write(str(os.getpid()))
    
    logger.info(f"Daemon started with PID {os.getpid()}")


def get_daemon_status(pid_file: str) -> dict:
    """Check daemon status"""
    result = {
        "running": False,
        "pid": None,
    }
    
    if not os.path.exists(pid_file):
        return result
    
    try:
        with open(pid_file, 'r') as f:
            pid = int(f.read().strip())
        
        # Check if process exists
        os.kill(pid, 0)
        result["running"] = True
        result["pid"] = pid
        
    except (ValueError, ProcessLookupError, PermissionError):
        # PID file exists but process doesn't
        pass
    
    return result


def stop_daemon(pid_file: str) -> bool:
    """Stop daemon process"""
    status = get_daemon_status(pid_file)
    
    if not status["running"]:
        print(yellow("Daemon is not running"))
        return False
    
    try:
        os.kill(status["pid"], signal.SIGTERM)
        print(green(f"Sent SIGTERM to PID {status['pid']}"))
        
        # Wait for process to exit
        for _ in range(10):
            time.sleep(0.5)
            try:
                os.kill(status["pid"], 0)
            except ProcessLookupError:
                print(green("Daemon stopped"))
                # Clean up PID file
                if os.path.exists(pid_file):
                    os.remove(pid_file)
                return True
        
        print(yellow("Daemon still running, sending SIGKILL"))
        os.kill(status["pid"], signal.SIGKILL)
        return True
        
    except Exception as e:
        print(red(f"Error stopping daemon: {e}"))
        return False


def print_status(pid_file: str):
    """Print daemon status"""
    status = get_daemon_status(pid_file)
    
    print(f"\n{bold('SNIFF Daemon Status')}")
    print("-" * 30)
    
    if status["running"]:
        print(f"Status: {green('Running')}")
        print(f"PID:    {status['pid']}")
        print(f"Log:    {DEFAULT_LOG_FILE}")
    else:
        print(f"Status: {red('Not running')}")
    
    print()


def run_menu_mode(data_dir: str):
    """Run interactive menu mode"""
    app_instance = [None]  # Use list to allow modification in nested functions
    
    def on_quick_capture(interface: str, settings: dict):
        """Callback khi chọn quick capture"""
        app = SniffApp(
            data_dir=settings.get('base_dir', data_dir),
            interface=interface,
            snaplen=settings.get('snaplen', DEFAULT_SNAPLEN),
            promisc=settings.get('promisc', DEFAULT_PROMISC),
            buffer_profile=settings.get('buffer_profile', 'balanced'),
            retention_days=settings.get('retention_days', DEFAULT_RETENTION_DAYS),
        )
        app_instance[0] = app
        app.run_interactive()
    
    def on_advanced_capture(interface: str, settings: dict):
        """Callback khi chọn advanced capture"""
        app = SniffApp(
            data_dir=settings.get('base_dir', data_dir),
            interface=interface,
            snaplen=settings.get('snaplen', DEFAULT_SNAPLEN),
            promisc=settings.get('promisc', DEFAULT_PROMISC),
            buffer_profile=settings.get('buffer_profile', 'balanced'),
            retention_days=settings.get('retention_days', DEFAULT_RETENTION_DAYS),
            enable_modules=len(settings.get('modules', [])) > 0,
        )
        app_instance[0] = app
        app.run_interactive()
    
    def on_open_pcap(base_dir: str):
        """Callback khi chọn mở file PCAP"""
        from ui.colors import print_header, print_menu_item, cyan, dim
        from core.pcap_writer import PcapReader
        from ui.detail_view import PacketDetailView
        
        raw_dir = Path(base_dir) / "raw"
        
        if not raw_dir.exists():
            print(red("Chưa có file PCAP nào!"))
            input("Nhấn Enter để tiếp tục...")
            return
        
        # Find PCAP files
        pcap_files = list(raw_dir.rglob("*.pcap"))
        if not pcap_files:
            print(red("Không tìm thấy file PCAP nào!"))
            input("Nhấn Enter để tiếp tục...")
            return
        
        # Sort by modification time (newest first)
        pcap_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
        
        print(bold("Danh sách file PCAP (mới nhất trước):"))
        print()
        for i, f in enumerate(pcap_files[:20], 1):
            size = f.stat().st_size
            mtime = time.strftime('%Y-%m-%d %H:%M', time.localtime(f.stat().st_mtime))
            print(f"  [{i}] {f.name} ({size:,} bytes) - {mtime}")
        
        if len(pcap_files) > 20:
            print(dim(f"  ... và {len(pcap_files) - 20} file khác"))
        
        print()
        print_menu_item('0', 'Quay lại')
        print()
        
        choice = input(f"{cyan('Chọn file')} [0-{min(20, len(pcap_files))}]: ").strip()
        
        if choice == '0' or not choice:
            return
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < min(20, len(pcap_files)):
                filepath = pcap_files[idx]
                
                # Read and display packets
                print(info(f"Đang đọc {filepath.name}..."))
                
                with PcapReader(str(filepath)) as reader:
                    packets = list(reader)
                
                if not packets:
                    print(red("File rỗng!"))
                    input("Nhấn Enter để tiếp tục...")
                    return
                
                print(success(f"Đọc được {len(packets)} gói"))
                print()
                
                # Show first 20 packets with details
                print(bold("Các gói trong file:"))
                print()
                
                from core.decoder import decode_packet
                
                for i, pkt in enumerate(packets[:20], 1):
                    # Decode packet to get protocol and addresses
                    try:
                        decoded = decode_packet(pkt.data)
                        proto = decoded.protocol_name if decoded else 'UNKNOWN'
                        src = decoded.src_addr or '-'
                        dst = decoded.dst_addr or '-'
                        
                        if decoded and decoded.src_port:
                            src = f"{src}:{decoded.src_port}"
                        if decoded and decoded.dst_port:
                            dst = f"{dst}:{decoded.dst_port}"
                        
                        # Truncate long addresses
                        if len(src) > 25:
                            src = src[:22] + '...'
                        if len(dst) > 25:
                            dst = dst[:22] + '...'
                        
                        # Format nicely
                        print(f"  [{i:2}] {proto:8} {src:25} -> {dst:25} ({pkt.caplen} bytes)")
                    except:
                        # Fallback if decode fails
                        print(f"  [{i:2}] #{pkt.stt} - {pkt.caplen} bytes")
                
                print()
                detail_choice = input(f"{cyan('Xem chi tiết gói')} [1-{min(20, len(packets))}] hoặc Enter để quay lại: ").strip()
                
                if detail_choice:
                    try:
                        pkt_idx = int(detail_choice) - 1
                        if 0 <= pkt_idx < min(20, len(packets)):
                            detail_view = PacketDetailView()
                            detail_view.show(packets[pkt_idx], on_back=None)
                    except ValueError:
                        pass
        except ValueError:
            pass
    
    def on_settings():
        """Callback cho settings - được xử lý trong MainMenu"""
        pass
    
    # Create and show menu
    menu = MainMenu(
        on_quick_capture=on_quick_capture,
        on_advanced_capture=on_advanced_capture,
        on_open_pcap=on_open_pcap,
        on_settings=on_settings,
    )
    menu.show()


def main():
    parser = argparse.ArgumentParser(
        description='SNIFF - Network Packet Capture Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    sudo python3 sniff.py                    # Interactive menu
    sudo python3 sniff.py -i eth0            # Quick capture on eth0
    sudo python3 sniff.py -i eth0 -d         # Daemon mode
    sudo python3 sniff.py -i eth0 -f "tcp port 80"   # With BPF filter
    sudo python3 sniff.py --status           # Check daemon status
    sudo python3 sniff.py --stop             # Stop daemon
        """
    )
    
    parser.add_argument('-i', '--interface', help='Network interface to capture on')
    parser.add_argument('-f', '--filter', default='', help='BPF filter')
    parser.add_argument('-s', '--snaplen', type=int, default=DEFAULT_SNAPLEN,
                        help=f'Capture length (default: {DEFAULT_SNAPLEN})')
    parser.add_argument('-p', '--no-promisc', action='store_true',
                        help='Disable promiscuous mode')
    parser.add_argument('-b', '--buffer', choices=['low', 'balanced', 'fast', 'max'],
                        default='balanced', help='Buffer profile')
    parser.add_argument('-o', '--output', default=str(DEFAULT_DATA_DIR),
                        help='Output directory')
    parser.add_argument('-r', '--retention', type=int, default=DEFAULT_RETENTION_DAYS,
                        help=f'Days to keep files (default: {DEFAULT_RETENTION_DAYS})')
    
    parser.add_argument('-d', '--daemon', action='store_true',
                        help='Run as daemon (background)')
    parser.add_argument('--status', action='store_true',
                        help='Show daemon status')
    parser.add_argument('--stop', action='store_true',
                        help='Stop daemon')
    parser.add_argument('--list-interfaces', action='store_true',
                        help='List available interfaces')
    
    args = parser.parse_args()
    
    # Handle special commands
    if args.status:
        print_status(DEFAULT_PID_FILE)
        return
    
    if args.stop:
        stop_daemon(DEFAULT_PID_FILE)
        return
    
    if args.list_interfaces:
        print(f"\n{bold('Available Interfaces:')}")
        for iface in get_interfaces():
            print(f"  - {iface}")
        print()
        return
    
    # Check root
    if os.geteuid() != 0:
        print(red("Error: Root privileges required for packet capture"))
        print(f"Run with: sudo python3 {sys.argv[0]} ...")
        sys.exit(1)
    
    # No interface specified - run menu mode
    if not args.interface:
        run_menu_mode(args.output)
        return
    
    # Validate interface
    if not validate_interface(args.interface):
        print(red(f"Error: Interface '{args.interface}' not found"))
        print(f"Available: {', '.join(get_interfaces())}")
        sys.exit(1)
    
    # Check if daemon already running
    if args.daemon:
        status = get_daemon_status(DEFAULT_PID_FILE)
        if status["running"]:
            print(yellow(f"Daemon already running (PID: {status['pid']})"))
            sys.exit(1)
    
    # Create app
    app = SniffApp(
        data_dir=args.output,
        interface=args.interface,
        bpf_filter=args.filter,
        snaplen=args.snaplen,
        promisc=not args.no_promisc,
        buffer_profile=args.buffer,
        retention_days=args.retention,
        daemon=args.daemon,
    )
    
    # Run
    if args.daemon:
        daemonize(DEFAULT_PID_FILE)
        app.run_daemon()
    else:
        app.run_interactive()


if __name__ == '__main__':
    main()
