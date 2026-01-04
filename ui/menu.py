"""
Menu system tiếng Việt cho sniff tool
"""

import sys
import os
from typing import Optional, List, Dict, Any, Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.colors import (
    clear_screen, print_header, print_divider, print_menu_item,
    print_status, bold, cyan, green, yellow, red, dim, info,
    highlight, get_terminal_size, show_cursor, hide_cursor,
    success, error, warning
)
from core.capture import get_interfaces, get_interface_info
from core.constants import BUFFER_PROFILES, SNAPLEN_OPTIONS, DEFAULT_SNAPLEN


# ============================================================
# Text constants
# ============================================================

BANNER = r"""
   _____ _   _ _____ ______ ______ 
  / ____| \ | |_   _|  ____|  ____|
 | (___ |  \| | | | | |__  | |__   
  \___ \| . ` | | | |  __| |  __|  
  ____) | |\  |_| |_| |    | |     
 |_____/|_| \_|_____|_|    |_|     
                                   
    Công cụ thu thập gói tin
"""

HELP_TEXT = """
╔══════════════════════════════════════════════════════════════════╗
║                      HƯỚNG DẪN SỬ DỤNG                           ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  1. BẮT GÓI NHANH                                                ║
║     - Chọn card mạng và bắt đầu ngay                             ║
║     - File PCAP lưu vào ./sniff_data/raw/YYYY-MM-DD/             ║
║     - Tên file: <iface>_YYYY-MM-DD_HH.pcap                       ║
║     - Cắt file theo giờ (HH:00:00), giữ 7 ngày                   ║
║                                                                  ║
║  2. BẮT GÓI NÂNG CAO                                             ║
║     - Tùy chỉnh snaplen, promisc, buffer profile                 ║
║     - Chọn module phân loại tấn công                             ║
║     - Thay đổi thư mục lưu và số ngày giữ                        ║
║                                                                  ║
║  3. MỞ FILE PCAP                                                 ║
║     - Xem nội dung file PCAP đã lưu                              ║
║     - Xem kết quả phân loại từ các module                        ║
║                                                                  ║
║  TRONG KHI BẮT GÓI:                                              ║
║     - Space : Tạm dừng/Tiếp tục capture                          ║
║     - S     : Lưu file hiện tại và thoát                         ║
║     - Q     : Thoát về menu chính                                ║
║                                                                  ║
║  CHẠY NỀN (DAEMON):                                              ║
║     - sudo python3 sniff.py -i eth0 -d   # Chạy daemon           ║
║     - python3 sniff.py --status          # Xem trạng thái        ║
║     - sudo python3 sniff.py --stop       # Dừng daemon           ║
║                                                                  ║
║  SYSTEMD SERVICE:                                                ║
║     - sudo ./install-service.sh eth0     # Cài đặt service       ║
║     - sudo systemctl start sniff         # Khởi động             ║
║     - sudo systemctl status sniff        # Xem trạng thái        ║
║                                                                  ║
║  YÊU CẦU:                                                        ║
║     - Chạy với quyền root                                        ║
║     - sudo python3 sniff.py                                      ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""


def get_interfaces_with_info() -> List[Dict[str, Any]]:

    interfaces = []
    for iface in get_interfaces():
        info = get_interface_info(iface)
        interfaces.append({
            'name': iface,
            'up': info.get('up', False),
            'ip': info.get('ipv4')
        })
    return interfaces


def input_with_default(prompt: str, default: str = '') -> str:
    """Input với giá trị mặc định"""
    if default:
        prompt = f"{prompt} [{default}]: "
    else:
        prompt = f"{prompt}: "
    
    result = input(prompt).strip()
    return result if result else default


def input_choice(prompt: str, choices: List[str], default: str = '') -> str:
    """Input với các lựa chọn"""
    while True:
        result = input_with_default(prompt, default).upper()
        if result in [c.upper() for c in choices]:
            return result
        print(error(f"Lựa chọn không hợp lệ! Chọn: {', '.join(choices)}"))


def confirm(prompt: str, default: bool = True) -> bool:
    """Xác nhận yes/no"""
    suffix = "[Y/n]" if default else "[y/N]"
    result = input(f"{prompt} {suffix}: ").strip().lower()
    
    if not result:
        return default
    return result in ('y', 'yes', 'có', 'co')


def wait_for_key(prompt: str = "Nhấn Enter để tiếp tục..."):
    """Chờ người dùng nhấn phím"""
    input(prompt)


class MainMenu:
    """Menu chính"""
    
    def __init__(
        self,
        on_quick_capture: Callable,
        on_advanced_capture: Callable,
        on_open_pcap: Callable,
        on_settings: Callable,
    ):
        self.on_quick_capture = on_quick_capture
        self.on_advanced_capture = on_advanced_capture
        self.on_open_pcap = on_open_pcap
        self.on_settings = on_settings
        
        self.settings = {
            'base_dir': './sniff_data',
            'retention_days': 7,
            'snaplen': DEFAULT_SNAPLEN,
            'promisc': True,
            'buffer_profile': 'balanced',
            'stats_interval': 2.0,
            'modules': [],
        }
    
    def show(self):
        """Hiển thị menu chính"""
        while True:
            clear_screen()
            print(cyan(BANNER))
            print()
            print_header(" MENU CHÍNH ", '═')
            print()
            print_menu_item('1', 'Bắt gói nhanh (Khuyến nghị)')
            print_menu_item('2', 'Bắt gói (Nâng cao)')
            print_menu_item('3', 'Mở file PCAP')
            print_menu_item('4', 'Cài đặt mặc định')
            print_menu_item('5', 'Hướng dẫn')
            print_menu_item('0', 'Thoát')
            print()
            print_divider()
            
            choice = input(f"\n{cyan('Chọn')} [0-5]: ").strip()
            
            if choice == '1':
                self.quick_capture_menu()
            elif choice == '2':
                self.advanced_capture_menu()
            elif choice == '3':
                self.open_pcap_menu()
            elif choice == '4':
                self.settings_menu()
            elif choice == '5':
                self.show_help()
            elif choice == '0':
                if self.exit_confirm():
                    break  # Chỉ thoát nếu user xác nhận Y
            else:
                print(error("Lựa chọn không hợp lệ!"))
                wait_for_key()
    
    def quick_capture_menu(self):
        """Menu bắt gói nhanh"""
        clear_screen()
        print_header(" BẮT GÓI NHANH ", '═')
        print()
        
        # Bước 1: Chọn interface
        print(bold("Bước 1: Chọn card mạng"))
        print()
        
        interfaces = get_interfaces_with_info()
        if not interfaces:
            print(error("Không tìm thấy card mạng nào!"))
            wait_for_key()
            return
        
        for i, iface in enumerate(interfaces, 1):
            status = green("UP") if iface['up'] else red("DOWN")
            ip = iface['ip'] if iface['ip'] else dim("Không có IP")
            print(f"  [{i}] {bold(iface['name'])} - {status} - {ip}")
        
        print()
        choice = input(f"{cyan('Chọn card')} [1-{len(interfaces)}]: ").strip()
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(interfaces):
                selected_iface = interfaces[idx]['name']
            else:
                print(error("Lựa chọn không hợp lệ!"))
                wait_for_key()
                return
        except ValueError:
            print(error("Vui lòng nhập số!"))
            wait_for_key()
            return
        
        # Bước 2: Xác nhận
        print()
        print_divider()
        print()
        print(bold("Bước 2: Xác nhận cấu hình"))
        print()
        print_status("Card mạng", selected_iface)
        print_status("Thư mục lưu", f"{self.settings['base_dir']}/raw/")
        print_status("Cắt file", "Theo giờ (đúng mốc HH:00:00)")
        print_status("Giữ file", f"{self.settings['retention_days']} ngày")
        print_status("Snaplen", str(self.settings['snaplen']))
        print_status("Promiscuous", "Bật" if self.settings['promisc'] else "Tắt")
        print()
        
        print_menu_item('1', 'Bắt đầu')
        print_menu_item('0', 'Quay lại')
        print()
        
        choice = input(f"{cyan('Chọn')} [0-1]: ").strip()
        
        if choice == '1':
            self.on_quick_capture(
                interface=selected_iface,
                settings=self.settings,
            )
    
    def advanced_capture_menu(self):
        """Menu bắt gói nâng cao"""
        clear_screen()
        print_header(" BẮT GÓI NÂNG CAO ", '═')
        print()
        
        # Bước 1: Chọn interface
        print(bold("Bước 1: Chọn card mạng"))
        print()
        
        interfaces = get_interfaces_with_info()
        if not interfaces:
            print(error("Không tìm thấy card mạng nào!"))
            wait_for_key()
            return
        
        for i, iface in enumerate(interfaces, 1):
            status = green("UP") if iface['up'] else red("DOWN")
            ip = iface['ip'] if iface['ip'] else dim("Không có IP")
            print(f"  [{i}] {bold(iface['name'])} - {status} - {ip}")
        
        print()
        choice = input(f"{cyan('Chọn card')} [1-{len(interfaces)}]: ").strip()
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(interfaces):
                selected_iface = interfaces[idx]['name']
            else:
                print(error("Lựa chọn không hợp lệ!"))
                wait_for_key()
                return
        except ValueError:
            print(error("Vui lòng nhập số!"))
            wait_for_key()
            return
        
        # Bước 2: Cấu hình capture
        print()
        print_divider()
        print()
        print(bold("Bước 2: Cấu hình capture"))
        print()
        
        # Snaplen - SNAPLEN_OPTIONS is a dict
        snaplen_list = list(SNAPLEN_OPTIONS.items())
        print(dim("Snaplen (bytes để lưu mỗi gói):"))
        for i, (snap_val, snap_desc) in enumerate(snaplen_list, 1):
            default_mark = " (mặc định)" if snap_val == DEFAULT_SNAPLEN else ""
            print(f"  [{i}] {snap_val} - {snap_desc}{default_mark}")
        
        snap_choice = input(f"{cyan('Chọn snaplen')} [1-{len(snaplen_list)}] (Enter = mặc định): ").strip()
        if snap_choice:
            try:
                snap_idx = int(snap_choice) - 1
                if 0 <= snap_idx < len(snaplen_list):
                    self.settings['snaplen'] = snaplen_list[snap_idx][0]
            except ValueError:
                pass
        
        print()
        
        # Promisc
        promisc = confirm("Bật Promiscuous mode?", default=True)
        self.settings['promisc'] = promisc
        
        print()
        
        # Buffer profile
        print(dim("Buffer profile:"))
        profiles = list(BUFFER_PROFILES.keys())
        for i, profile in enumerate(profiles, 1):
            desc = BUFFER_PROFILES[profile].get('desc', profile)
            print(f"  [{i}] {profile} - {desc}")
        
        profile_choice = input(f"{cyan('Chọn profile')} [1-{len(profiles)}] (Enter = balanced): ").strip()
        if profile_choice:
            try:
                profile_idx = int(profile_choice) - 1
                if 0 <= profile_idx < len(profiles):
                    self.settings['buffer_profile'] = profiles[profile_idx]
            except ValueError:
                pass
        
        print()
        
        # Stats interval
        print(dim("Interval cập nhật thống kê:"))
        intervals = [1, 2, 5, 10]
        for i, interval in enumerate(intervals, 1):
            print(f"  [{i}] {interval}s")
        
        interval_choice = input(f"{cyan('Chọn interval')} [1-4] (Enter = 2s): ").strip()
        if interval_choice:
            try:
                interval_idx = int(interval_choice) - 1
                if 0 <= interval_idx < len(intervals):
                    self.settings['stats_interval'] = float(intervals[interval_idx])
            except ValueError:
                pass
        
        # Bước 3: Thiết lập lưu PCAP
        print()
        print_divider()
        print()
        print(bold("Bước 3: Thiết lập lưu PCAP"))
        print()
        
        base_dir = input_with_default("Thư mục gốc", self.settings['base_dir'])
        self.settings['base_dir'] = base_dir
        
        retention = input_with_default("Số ngày giữ file", str(self.settings['retention_days']))
        try:
            self.settings['retention_days'] = int(retention)
        except ValueError:
            pass
        
        # Bước 4: Chọn module
        print()
        print_divider()
        print()
        print(bold("Bước 4: Chọn module phân loại (tùy chọn)"))
        print()
        
        available_modules = ['port_scan', 'syn_flood', 'dns_amplification', 'brute_force', 'dummy']
        
        for i, mod in enumerate(available_modules, 1):
            status = green("✓") if mod in self.settings['modules'] else dim("○")
            print(f"  [{i}] {status} {mod}")
        
        print()
        print_menu_item('A', 'Bật TẤT CẢ')
        print_menu_item('N', 'Tắt hết')
        print_menu_item('9', 'Bắt đầu')
        print()
        
        while True:
            choice = input(f"{cyan('Chọn')} [1-{len(available_modules)}/A/N/9]: ").strip().upper()
            
            if choice == 'A':
                self.settings['modules'] = available_modules.copy()
                print(success("Đã bật tất cả module"))
            elif choice == 'N':
                self.settings['modules'] = []
                print(info("Đã tắt tất cả module"))
            elif choice == '9':
                break
            elif choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(available_modules):
                    mod = available_modules[idx]
                    if mod in self.settings['modules']:
                        self.settings['modules'].remove(mod)
                        print(info(f"Đã tắt {mod}"))
                    else:
                        self.settings['modules'].append(mod)
                        print(success(f"Đã bật {mod}"))
            else:
                print(error("Lựa chọn không hợp lệ!"))
        
        # Bắt đầu capture
        self.on_advanced_capture(
            interface=selected_iface,
            settings=self.settings,
        )
    
    def open_pcap_menu(self):
        """Menu mở file PCAP"""
        clear_screen()
        print_header(" MỞ FILE PCAP ", '═')
        print()
        
        self.on_open_pcap(base_dir=self.settings['base_dir'])
    
    def settings_menu(self):
        """Menu cài đặt"""
        while True:
            clear_screen()
            print_header(" CÀI ĐẶT MẶC ĐỊNH ", '═')
            print()
            
            print_status("1. Thư mục gốc", self.settings['base_dir'])
            print_status("2. Số ngày giữ", str(self.settings['retention_days']))
            print_status("3. Snaplen", str(self.settings['snaplen']))
            print_status("4. Promiscuous", "Bật" if self.settings['promisc'] else "Tắt")
            print_status("5. Buffer profile", self.settings['buffer_profile'])
            print_status("6. Stats interval", f"{self.settings['stats_interval']}s")
            print()
            print_menu_item('0', 'Quay lại')
            print()
            
            choice = input(f"{cyan('Chọn để thay đổi')} [0-6]: ").strip()
            
            if choice == '0':
                break
            elif choice == '1':
                self.settings['base_dir'] = input_with_default("Thư mục gốc", self.settings['base_dir'])
            elif choice == '2':
                val = input_with_default("Số ngày giữ", str(self.settings['retention_days']))
                try:
                    self.settings['retention_days'] = int(val)
                except ValueError:
                    pass
            elif choice == '3':
                snaplen_list = list(SNAPLEN_OPTIONS.items())
                print(dim("Snaplen options:"))
                for i, (snap_val, snap_desc) in enumerate(snaplen_list, 1):
                    print(f"  [{i}] {snap_val} - {snap_desc}")
                val = input(f"{cyan('Chọn')} [1-{len(snaplen_list)}]: ").strip()
                try:
                    idx = int(val) - 1
                    if 0 <= idx < len(snaplen_list):
                        self.settings['snaplen'] = snaplen_list[idx][0]
                except ValueError:
                    pass
            elif choice == '4':
                self.settings['promisc'] = not self.settings['promisc']
            elif choice == '5':
                profiles = list(BUFFER_PROFILES.keys())
                for i, p in enumerate(profiles, 1):
                    desc = BUFFER_PROFILES[p].get('desc', p)
                    print(f"  [{i}] {p} - {desc}")
                val = input(f"{cyan('Chọn')} [1-{len(profiles)}]: ").strip()
                try:
                    idx = int(val) - 1
                    if 0 <= idx < len(profiles):
                        self.settings['buffer_profile'] = profiles[idx]
                except ValueError:
                    pass
            elif choice == '6':
                intervals = [1, 2, 5, 10]
                for i, interval in enumerate(intervals, 1):
                    print(f"  [{i}] {interval}s")
                val = input(f"{cyan('Chọn')} [1-4]: ").strip()
                try:
                    idx = int(val) - 1
                    if 0 <= idx < len(intervals):
                        self.settings['stats_interval'] = float(intervals[idx])
                except ValueError:
                    pass
    
    def show_help(self):
        """Hiển thị hướng dẫn"""
        clear_screen()
        print(cyan(HELP_TEXT))
        print()
        wait_for_key()
    
    def exit_confirm(self) -> bool:
        """Xác nhận thoát - return True nếu user muốn thoát"""
        result = confirm("\nBạn có chắc muốn thoát?", default=False)
        if result:
            print(info("\nTạm biệt!"))
            return True
        return False
