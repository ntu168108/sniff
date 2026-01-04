# SNIFF - Công Cụ Bắt Gói Tin Mạng

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)

Công cụ bắt gói tin mạng mạnh mẽ và modular cho Linux với giao diện TUI real-time và hệ thống module phân tích mở rộng.

**English** | **Tiếng Việt**

## Tính Năng

- **Bắt Gói Tin Real-time** - Hiệu suất cao sử dụng Scapy/libpcap
- **Giao Diện TUI Tương Tác** - Giao diện text đẹp mắt để giám sát gói tin trực tiếp
- **Tự Động Quay Vòng Theo Giờ** - Tự động xoay file PCAP với cấu hình lưu trữ linh hoạt
- **Hệ Thống Plugin** - Kiến trúc module mở rộng cho phân tích gói tin tùy chỉnh
- **Chế Độ Daemon** - Chạy như systemd service để giám sát 24/7
- **Bộ Giải Mã Nâng Cao** - Hỗ trợ sẵn Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP
- **Tạm Dừng/Tiếp Tục** - Điều khiển capture mà không mất dữ liệu
- **BPF Filters** - Hỗ trợ Berkeley Packet Filter để capture có mục tiêu

## Cài Đặt Nhanh (Một Lệnh)

```bash
sudo apt update
sudo apt install git -y
curl -sSL https://raw.githubusercontent.com/ntu168108/sniff/main/scripts/install.sh | sudo bash
```

Xong! Sau đó chạy:
```bash
sudo sniff
```

## Bắt Đầu Nhanh

### Yêu Cầu Hệ Thống

- Linux OS (đã test trên Ubuntu 20.04+, Debian 11+)
- Python 3.8 trở lên
- Quyền root/sudo (cần thiết để bắt gói tin)

### Cài Đặt

**Phương Pháp 1: Tự Động Cài Đặt (Khuyến Nghị)**

Một lệnh cài đặt Python, dependencies và SNIFF:

```bash
curl -sSL https://raw.githubusercontent.com/ntu168108/sniff/main/scripts/install.sh | sudo bash
```

**Phương Pháp 2: Cài Đặt Thủ Công với pip**

```bash
# Cài từ GitHub repo
sudo pip3 install git+https://github.com/ntu168108/sniff.git
```

**Phương Pháp 3: Clone và Cài Đặt**

```bash
git clone https://github.com/ntu168108/sniff.git
cd sniff
sudo pip3 install .
```

### Sử Dụng Cơ Bản

```bash
# Chế độ menu tương tác
sudo sniff

# Capture nhanh trên interface cụ thể
sudo sniff -i eth0

# Capture với BPF filter
sudo sniff -i eth0 -f "tcp port 80"

# Chạy như daemon
sudo sniff -i eth0 -d

# Kiểm tra trạng thái daemon
sudo sniff --status

# Dừng daemon
sudo sniff --stop

# Liệt kê các interface có sẵn
sudo sniff --list-interfaces
```

## Ví Dụ Sử Dụng

### Chế Độ Tương Tác

Cách dễ nhất để sử dụng SNIFF là menu tương tác:

```bash
sudo sniff
```

Menu sẽ hiển thị:
- Quick capture trên bất kỳ interface nào
- Advanced capture với cài đặt tùy chỉnh
- Duyệt các file PCAP đã capture
- Cấu hình settings

### Tùy Chọn Command Line

```bash
sniff [-h] [-i INTERFACE] [-f FILTER] [-s SNAPLEN] [-p] 
      [-b {low,balanced,fast,max}] [-o OUTPUT] [-r RETENTION]
      [-d] [--status] [--stop] [--list-interfaces]

Tùy chọn:
  -i, --interface INTERFACE  Interface mạng để capture
  -f, --filter FILTER        BPF filter (ví dụ: "tcp port 80")
  -s, --snaplen SNAPLEN      Độ dài capture (mặc định: 65535)
  -p, --no-promisc          Tắt chế độ promiscuous
  -b, --buffer PROFILE      Profile buffer: low, balanced, fast, max
  -o, --output OUTPUT       Thư mục output (mặc định: ./sniff_data)
  -r, --retention DAYS      Số ngày lưu file (mặc định: 7)
  -d, --daemon              Chạy như daemon (background)
  --status                  Hiển thị trạng thái daemon
  --stop                    Dừng daemon
  --list-interfaces         Liệt kê interfaces có sẵn
```

### Ví Dụ Thực Tế

**Giám sát traffic web:**
```bash
sudo sniff -i eth0 -f "port 80 or port 443"
```

**Capture DNS queries:**
```bash
sudo sniff -i eth0 -f "port 53"
```

**Debug traffic từ host cụ thể:**
```bash
sudo sniff -i eth0 -f "host 192.168.1.100"
```

**Giám sát 24/7 với daemon:**
```bash
sudo sniff -i eth0 -d -b fast -r 30
```

### Cài Đặt như Systemd Service

Để giám sát production 24/7:

```bash
# Dùng script cài đặt có sẵn
sudo ./scripts/install-service.sh eth0

# Hoặc thủ công:
sudo cp scripts/sniff.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sniff
sudo systemctl start sniff

# Kiểm tra trạng thái
sudo systemctl status sniff

# Xem logs
sudo journalctl -u sniff -f
```

## Cấu Trúc Dự Án

```
sniff/
├── core/               # Core capture engine
│   ├── capture.py     # Packet capture với Scapy
│   ├── decoder.py     # Bộ giải mã gói tin
│   ├── pcap_writer.py # PCAP file I/O
│   ├── rotator.py     # Tự động xoay file theo giờ
│   └── constants.py   # Constants và configs
├── modules/           # Các module phân tích
│   ├── base.py        # Module base class
│   ├── runner.py      # Module executor
│   └── dummy/         # Module mẫu
├── ui/                # Giao diện Text
│   ├── menu.py        # Menu chính
│   ├── list_view.py   # Hiển thị danh sách gói tin
│   ├── detail_view.py # Xem chi tiết gói tin
│   └── colors.py      # Màu terminal
├── sniff.py           # Entry point chính
├── setup.py           # Package setup
└── requirements.txt   # Dependencies
```

## Phát Triển Plugin

Tạo module phân tích tùy chỉnh dễ dàng:

```python
from modules.base import BaseModule, Summary, Detection

class MyModule(BaseModule):
    @property
    def name(self) -> str:
        return "my_module"
    
    def analyze(self, pcap_path, output_dir, interface, time_window) -> Summary:
        # Logic phân tích của bạn ở đây
        detections = []
        # ... phân tích packets ...
        
        summary = Summary(
            module_name=self.name,
            total_hits=len(detections),
            # ...
        )
        
        self.write_output(output_dir, interface, time_window, summary, detections)
        return summary
```

## Lưu Trữ Dữ Liệu

Mặc định, SNIFF lưu dữ liệu trong `./sniff_data/`:

```
sniff_data/
├── raw/                    # File PCAP thô
│   └── YYYY-MM-DD/
│       └── interface_YYYY-MM-DD_HH.pcap
└── modules/                # Kết quả phân tích
    └── module_name/
        └── YYYY-MM-DD/
            ├── interface_YYYY-MM-DD_HH.summary.json
            └── interface_YYYY-MM-DD_HH.index.jsonl
```

## Cấu Hình

### Buffer Profiles

- `low` - Tối thiểu bộ nhớ (1MB buffer, 100 queue)
- `balanced` - Mặc định (4MB buffer, 500 queue)
- `fast` - Hiệu suất cao (16MB buffer, 2000 queue)
- `max` - Throughput tối đa (64MB buffer, 10000 queue)

### File Retention (Lưu Trữ)

Cấu hình tự động xóa file cũ:

```bash
sudo sniff -i eth0 -r 30  # Giữ file trong 30 ngày
```

## Cân Nhắc Bảo Mật

- SNIFF yêu cầu quyền root để truy cập raw socket
- Systemd service bao gồm security hardening (`ProtectSystem`, `ProtectHome`)
- BPF filters giúp giảm bề mặt tấn công
- Dữ liệu capture có thể chứa thông tin nhạy cảm - bảo mật phù hợp

## Khắc Phục Sự Cố

### Lỗi Permission Denied

```bash
# Đảm bảo chạy với sudo
sudo sniff -i eth0
```

### Không Tìm Thấy Interface

```bash
# Liệt kê các interface có sẵn
sudo sniff --list-interfaces

# Kiểm tra interface đang up
ip link show
```

### Lỗi Import Scapy

```bash
# Cài đặt Scapy
sudo pip3 install scapy>=2.5.0
```

### CPU Cao

```bash
# Giảm buffer size
sudo sniff -i eth0 -b low

# Hoặc filter traffic cụ thể
sudo sniff -i eth0 -f "host 192.168.1.100"
```

## Tài Liệu

- [Hướng Dẫn Đầy Đủ](docs/USER_GUIDE.md) - Documentation chi tiết
- [Quick Start](docs/QUICKSTART.md) - Bắt đầu trong 2 phút
- [Project Files](docs/PROJECT_FILES.md) - Danh sách files trong project

## License

MIT License - xem file LICENSE để biết chi tiết

## Đóng Góp

Contributions được hoan nghênh! Vui lòng submit Pull Request.

## Tác Giả

TuEx3

## Cảm Ơn

- Được xây dựng với [Scapy](https://scapy.net/) - thư viện xử lý gói tin mạnh mẽ
- Lấy cảm hứng từ tcpdump, Wireshark và các công cụ phân tích mạng khác

---

## Bắt Đầu Ngay

```bash
# Cài đặt
curl -sSL https://raw.githubusercontent.com/ntu168108/sniff/main/scripts/install.sh | sudo bash

# Chạy
sudo sniff

# Enjoy!
```

**Star repo nếu bạn thấy hữu ích!**
