# SNIFF - Hướng Dẫn Sử Dụng Đầy Đủ

![SNIFF Banner](https://img.shields.io/badge/SNIFF-C%C3%B4ng_C%E1%BB%A5_B%E1%BA%AFt_G%C3%B3i_Tin-blue?style=for-the-badge)

**Hướng dẫn hoàn chỉnh để cài đặt và sử dụng SNIFF**

> **SNIFF**: Công cụ bắt và phân tích gói tin mạng (packet sniffer) cho Linux

---

## 📖 Mục Lục

1. [Cài Đặt](#-cài-đặt)
2. [Bắt Đầu Nhanh](#-bắt-đầu-nhanh)
3. [Các Chế Độ Sử Dụng](#-các-chế-độ-sử-dụng)
4. [Tùy Chọn Command-Line](#-tùy-chọn-command-line)
5. [Menu Tương Tác](#️-menu-tương-tác)
6. [Chế Độ Daemon](#-chế-độ-daemon)
7. [Sử Dụng Nâng Cao](#-sử-dụng-nâng-cao)
8. [Files Kết Quả](#-files-kết-quả)  
9. [Khắc Phục Sự Cố](#-khắc-phục-sự-cố)
10. [Gỡ Cài Đặt](#️-gỡ-cài-đặt)

---

## 🚀 Cài Đặt

### Cài Đặt Tự Động (Khuyến Nghị)

Một lệnh cài mọi thứ (Python + dependencies + SNIFF):

```bash
curl -sSL https://raw.githubusercontent.com/ntu168108/sniff/main/scripts/install.sh | sudo bash
```

**Script tự động làm:**
- ✅ Phát hiện hệ điều hành (Ubuntu, Debian, CentOS, Fedora)
- ✅ Cài Python 3.8+ (nếu chưa có)
- ✅ Cài pip3 (trình quản lý package Python)
- ✅ Cài scapy (thư viện bắt gói tin)
- ✅ Cài SNIFF
- ✅ Tùy chọn cài đặt systemd service (chạy tự động)

**Yêu cầu:**
- Linux OS (Ubuntu, Debian, CentOS, Fedora)
- Quyền root/sudo
- Kết nối Internet

---

## ⚡ Bắt Đầu Nhanh

Sau khi cài xong, chạy SNIFF ở chế độ menu tương tác:

```bash
sudo sniff
```

Bạn sẽ thấy menu như này:

```
╔═══════════════════════════════════════╗
║           SNIFF v1.0.0                ║
║   Công Cụ Bắt Gói Tin Mạng           ║
╚═══════════════════════════════════════╝

Menu Chính:
  [1] Quick Capture    - Bắt nhanh trên một interface
  [2] Advanced Capture - Cài đặt tùy chỉnh và filters
  [3] Open PCAP File   - Xem file đã bắt
  [4] Settings         - Cấu hình mặc định
  [Q] Quit             - Thoát

Chọn [1-4, Q]:
```

**Để bắt nhanh:**
1. Nhấn `1` → Quick Capture
2. Chọn interface mạng (ví dụ: eth0, wlan0)
3. Nhấn Enter để bắt đầu
4. Xem gói tin real-time!

**Dừng capture:**
- `S` → Lưu và thoát
- `Q` → Thoát không lưu
- `SPACE` → Tạm dừng/Tiếp tục

---

## 🎯 Các Chế Độ Sử Dụng

SNIFF có 3 chế độ chính:

### 1. Menu Tương Tác

```bash
sudo sniff
```

**Phù hợp:** Người mới, khám phá tính năng

**Tính năng:**
- Menu dễ dùng
- Setup nhanh
- Wizard cấu hình nâng cao
- Xem file PCAP đã bắt
- Xem chi tiết từng gói tin

### 2. Command Line

```bash
# Bắt cơ bản trên interface eth0
sudo sniff -i eth0

# Với BPF filter (bộ lọc)
sudo sniff -i eth0 -f "tcp port 80"

# Với custom buffer size
sudo sniff -i eth0 -b fast

# Custom thư mục lưu
sudo sniff -i eth0 -o /data/captures
```

**Phù hợp:** Tự động hóa, scripts, bắt nhanh

### 3. Daemon Mode (Chạy Ngầm)

```bash
# Chạy như daemon background
sudo sniff -i eth0 -d

# Kiểm tra trạng thái
sudo sniff --status

# Dừng daemon
sudo sniff --stop
```

**Phù hợp:** Giám sát 24/7, môi trường production

---

## 📋 Tùy Chọn Command-Line

### Các Tùy Chọn Cơ Bản

```bash
sniff [OPTIONS]

Bắt buộc:
  -i, --interface INTERFACE    Interface mạng để bắt gói tin
                               Ví dụ: eth0, wlan0, ens33

Tùy chọn:
  -f, --filter FILTER          Biểu thức BPF filter
                               Ví dụ: "tcp port 80"
                                      "host 192.168.1.1"
                                      "not port 22"

  -s, --snaplen SIZE          Max bytes mỗi gói tin (mặc định: 65535)
                               Ví dụ: -s 1500

  -p, --no-promisc            Tắt promiscuous mode
                               (chỉ bắt gói tin cho máy này)

  -b, --buffer PROFILE        Buffer profile
                               Options: low, balanced, fast, max
                               Mặc định: balanced

  -o, --output DIR            Thư mục output
                               Mặc định: ./sniff_data

  -r, --retention DAYS        Giữ file N ngày (mặc định: 7)
                               Ví dụ: -r 30

Daemon Mode:
  -d, --daemon                Chạy như daemon(background)
  --status                    Hiển thị trạng thái daemon
  --stop                      Dừng daemon

Tiện ích:
  --list-interfaces           Liệt kê interfaces mạng có sẵn
  -h, --help                  Hiển thị help
```

### Buffer Profiles (Cấu Hình Bộ Nhớ Đệm)

Chọn dựa trên tốc độ mạng và RAM có sẵn:

| Profile | Kích Thước Buffer | Kích Thước Queue | Phù Hợp Cho |
|---------|-------------------|------------------|-------------|
| `low` | 1 MB | 100 | Traffic thấp, RAM hạn chế |
| `balanced` | 4 MB | 500 | Sử dụng bình thường (mặc định) |
| `fast` | 16 MB | 2000 | Mạng traffic cao |
| `max` | 64 MB | 10000 | Enterprise, capture tốc độ cao |

> **Buffer**: Vùng nhớ tạm lưu dữ liệu trước khi ghi vào file  
> **Queue**: Hàng đợi, lưu gói tin chờ xử lý  
> **Profile**: Cấu hình sẵn tùy theo nhu cầu

---

## 🖥️ Menu Tương Tác

### Quick Capture (Bắt Nhanh)

1. Chạy `sudo sniff`
2. Chọn `[1] Quick Capture`
3. Chọn interface từ danh sách
4. Capture bắt đầu ngay!

**Hiển thị real-time:**
```
╔══════════════════════════════════════════════════════════════╗
║ SNIFF - Đang bắt trên eth0                [SPACE] Tạm dừng  ║
╠══════════════════════════════════════════════════════════════╣
║ Thống kê: 1,234 gói | 567 KB | 45 pps | 0 drops  [Q] Thoát ║
║ File: eth0_2026-01-04_22.pcap                    [S] Lưu    ║
╠══════════════════════════════════════════════════════════════╣
  #    Thời gian    IP Nguồn:Port       IP Đích:Port       Proto
  1    0.000        192.168.1.100:52341  1.1.1.1:443       TCP
  2    0.001        1.1.1.1:443          192.168.1.100:52341 TCP
  ...
```

> **pps**: packets per second - số gói tin mỗi giây  
> **drops**: gói tin bị drop (mất) vì buffer đầy

**Phím điều khiển:**
- `SPACE` - Tạm dừng/Tiếp tục
- `Q` - Thoát không lưu
- `S` - Lưu và thoát
- `↑/↓` - Cuộn danh sách
- `Enter` - Xem chi tiết gói tin

### Advanced Capture (Bắt Nâng Cao)

Để cấu hình tùy chỉnh:

1. Chọn `[2] Advanced Capture`
2. Cấu hình:
   - Interface
   - BPF filter (tùy chọn)
   - Snaplen (độ dài capture)
   - Buffer profile
   - Thư mục output
   - Retention days (số ngày giữ file)
   - Enable analysis modules
3. Bắt đầu capture

### Browse PCAP Files (Xem File Đã Bắt)

1. Chọn `[3] Open PCAP File`
2. Xem danh sách file (mới nhất trước)
3. Chọn file để xem
4. Duyệt gói tin và xem chi tiết

---

## 🔧 Chế Độ Daemon

### Cài Đặt như Systemd Service

Trong quá trình cài đặt, script sẽ hỏi có muốn setup systemd service không.

Hoặc cài thủ công:

```bash
# Dùng script tự động
sudo ./scripts/install-service.sh eth0

# Hoặc cài thủ công
sudo cp scripts/sniff.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sniff
sudo systemctl start sniff
```

### Quản Lý Service

```bash
# Khởi động service
sudo systemctl start sniff

# Dừng service
sudo systemctl stop sniff

# Khởi động lại
sudo systemctl restart sniff

# Kiểm tra trạng thái
sudo systemctl status sniff

# Xem logs real-time
sudo journalctl -u sniff -f

# Xem 100 dòng log cuối
sudo journalctl -u sniff -n 100

# Tự động chạy khi boot
sudo systemctl enable sniff

# Tắt tự động chạy
sudo systemctl disable sniff
```

> **systemd service**: Dịch vụ chạy ngầm trên Linux, tự động restart khi crash  
> **journalctl**: Công cụ xem log của systemd

### Daemon CLI Mode

Thay thế cho systemd service:

```bash
# Khởi động daemon
sudo sniff -i eth0 -d

# Kiểm tra xem đang chạy không
sudo sniff --status
# Output:
# Trạng thái SNIFF Daemon
# ------------------------------
# Status: Running
# PID:    12345
# Log:    /tmp/sniff.log

# Dừng daemon
sudo sniff --stop
```

---

## 🎓 Sử Dụng Nâng Cao

### Ví Dụ BPF Filters (Bộ Lọc)

Chỉ bắt traffic cụ thể:

```bash
# Chỉ HTTP traffic
sudo sniff -i eth0 -f "tcp port 80"

# HTTPS traffic (web bảo mật)
sudo sniff -i eth0 -f "tcp port 443"

# DNS traffic (tra cứu tên miền)
sudo sniff -i eth0 -f "udp port 53"

# Traffic từ host cụ thể
sudo sniff -i eth0 -f "host 192.168.1.100"

# Traffic tới mạng cụ thể
sudo sniff -i eth0 -f "dst net 10.0.0.0/8"

# Loại trừ SSH traffic (tránh capture SSH của chính mình)
sudo sniff -i eth0 -f "not port 22"

# Nhiều điều kiện (HTTP hoặc HTTPS)
sudo sniff -i eth0 -f "tcp port 80 or tcp port 443"

# Chỉ TCP SYN packets (gói tin khởi tạo kết nối)
sudo sniff -i eth0 -f "tcp[tcpflags] & tcp-syn != 0"

# ICMP packets (ping)
sudo sniff -i eth0 -f "icmp"

# Chỉ gói tin lớn (> 1000 bytes)
sudo sniff -i eth0 -f "greater 1000"
```

> **BPF**: Berkeley Packet Filter - ngôn ngữ lọc gói tin  
> **port**: cổng, số định danh dịch vụ (80=HTTP, 443=HTTPS, 53=DNS)  
> **host**: máy tính/thiết bị mạng  
> **SYN packet**: gói tin bắt đầu kết nối TCP

### Custom Output Directory (Thư Mục Lưu Tùy Chỉnh)

```bash
# Lưu vào vị trí cụ thể
sudo sniff -i eth0 -o /data/network-captures

# Tổ chức theo mục đích
sudo sniff -i eth0 -o /var/log/sniff/web-traffic -f "port 80 or port 443"
sudo sniff -i eth0 -o /var/log/sniff/dns-traffic -f "port 53"
```

### File Retention (Lưu Trữ)

```bash
# Giữ file 30 ngày
sudo sniff -i eth0 -r 30

# Giữ 1 năm
sudo sniff -i eth0 -r 365

# Giữ mãi mãi
sudo sniff -i eth0 -r 9999
```

### Capture Hiệu Suất Cao

Cho mạng gigabit:

```bash
sudo sniff -i eth0 -b max -s 1500 -f "not port 22"
```

**Giải thích:**
- `-b max` - Buffer tối đa (64MB, 10K queue)
- `-s 1500` - Snaplen 1500 (không cần full packet để phân tích)
- `-f "not port 22"` - Bỏ qua SSH để giảm dung lượng

---

## 📁 Files Kết Quả

### Cấu Trúc Thư Mục

Vị trí mặc định: `./sniff_data/`

```
sniff_data/
├── raw/                           # File PCAP thô
│   └── 2026-01-04/
│       ├── eth0_2026-01-04_00.pcap  # 00:00-00:59
│       ├── eth0_2026-01-04_01.pcap  # 01:00-01:59
│       ├── eth0_2026-01-04_22.pcap  # 22:00-22:59
│       └── ...
└── modules/                       # Kết quả phân tích
    └── dummy/                     # Tên module
        └── 2026-01-04/
            ├── eth0_2026-01-04_22.summary.json
            └── eth0_2026-01-04_22.index.jsonl
```

### Files PCAP

- **Format:** PCAP chuẩn (mở được bằng Wireshark, tcpdump)
- **Tên file:** `{interface}_{ngày}_{giờ}.pcap`
- **Rotation:** Tự động xoay mỗi giờ
- **Retention:** Tự động xóa sau số ngày cấu hình

**Mở bằng Wireshark:**
```bash
wireshark sniff_data/raw/2026-01-04/eth0_2026-01-04_22.pcap
```

**Phân tích bằng tcpdump:**
```bash
tcpdump -r sniff_data/raw/2026-01-04/eth0_2026-01-04_22.pcap
```

> **Wireshark**: Công cụ phân tích gói tin GUI nổi tiếng  
> **tcpdump**: Công cụ phân tích gói tin dòng lệnh

### Module Output (Kết Quả Phân Tích)

Modules tạo ra:

**Summary JSON (`*.summary.json`):**
```json
{
  "module_name": "dummy",
  "interface": "eth0",
  "time_window": "2026-01-04_22",
  "total_packets": 10000,
  "total_hits": 5,
  "labels": {
    "port-scan": 2,
    "high-rate-source": 3
  }
}
```

**Detection Index (`*.index.jsonl`):**
```json
{"stt": 1234, "label": "port-scan", "src": "192.168.1.100", "unique_ports": 50}
{"stt": 5678, "label": "high-rate-source", "src": "10.0.0.5", "packet_count": 5000}
```

> **port-scan**: Quét port, hành vi dò tìm cổng mở  
> **high-rate-source**: Nguồn gửi gói tin với tần suất cao bất thường

---

## 🐛 Khắc Phục Sự Cố

### Lỗi "Permission denied"

**Nguyên nhân:** Chạy không dùng sudo

**Giải pháp:**
```bash
# Luôn dùng sudo để bắt gói tin
sudo sniff -i eth0
```

### Lỗi "Interface not found"

**Nguyên nhân:** Tên interface không đúng

**Giải pháp:**
```bash
# Liệt kê interfaces có sẵn
sudo sniff --list-interfaces

# Hoặc dùng lệnh hệ thống
ip link show
```

### Lỗi "Scapy not found"

**Giải pháp:**
```bash
# Cài thủ công
sudo pip3 install scapy>=2.5.0

# Hoặc cài lại SNIFF (bao gồm dependencies)
curl -sSL https://raw.githubusercontent.com/ntu168108/sniff/main/scripts/install.sh | sudo bash
```

### Không Bắt Được Gói Tin / 0 gói tin

**Nguyên nhân có thể:**
1. Interface sai → Kiểm tra `ip link show`
2. Không có traffic → Dùng `ping` để tạo traffic
3. Firewall chặn → Kiểm tra iptables/firewalld
4. BPF filter quá chặt → Thử không dùng `-f` trước

**Debug:**
```bash
# Test với tcpdump (nếu work thì hệ thống OK)
sudo tcpdump -i eth0 -c 10

# tcpdump work mà SNIFF không → báo issue GitHub
```

### CPU Cao

**Giải pháp:**
```bash
# Giảm buffer
sudo sniff -i eth0 -b low

# Filter traffic cụ thể
sudo sniff -i eth0 -f "host 192.168.1.100"
```

### Disk Đầy

**Giải pháp:**
```bash
# Giảm retention days
sudo sniff -i eth0 -r 1

# Xóa file cũ thủ công
rm -rf sniff_data/raw/2026-01-01/
```

---

## 🗑️ Gỡ Cài Đặt

### Gỡ Hoàn Toàn

```bash
# Một lệnh gỡ toàn bộ
curl -sSL https://raw.githubusercontent.com/ntu168108/sniff/main/scripts/uninstall.sh | sudo bash
```

Script xóa:
- ✅ SNIFF package
- ✅ Systemd service
- ✅ Service files

**Lưu ý:** Dữ liệu đã capture (`sniff_data/`) KHÔNG tự động xóa.

### Gỡ Thủ Công

```bash
# Dừng và disable service
sudo systemctl stop sniff
sudo systemctl disable sniff

# Xóa service file
sudo rm /etc/systemd/system/sniff.service
sudo systemctl daemon-reload

# Gỡ package
sudo pip3 uninstall -y sniff-pcap

# Xóa dữ liệu (tùy chọn)
rm -rf ./sniff_data
```

---

## 📚 Tài Nguyên Thêm

### Ví Dụ Use Cases

**1. Giám Sát Web Traffic**
```bash
sudo sniff -i eth0 -f "port 80 or port 443" -o /var/log/web-traffic -r 30
```

**2. Bắt DNS Queries**
```bash
sudo sniff -i eth0 -f "port 53" -o /var/log/dns-queries
```

**3. Debug Host Cụ Thể**
```bash
sudo sniff -i eth0 -f "host 192.168.1.100"
```

**4. Giám Sát Production 24/7**
```bash
# Setup như service
sudo ./scripts/install-service.sh eth0

# Hoặc daemon thủ công
sudo sniff -i eth0 -d -b fast -r 90
```

---

## ✅ Bảng Tra Cứu Nhanh

```bash
# Cài đặt
curl -sSL https://raw.githubusercontent.com/ntu168108/sniff/main/scripts/install.sh | sudo bash

# Menu tương tác
sudo sniff

# Bắt nhanh
sudo sniff -i eth0

# Với filter
sudo sniff -i eth0 -f "tcp port 80"

# Daemon mode
sudo sniff -i eth0 -d
sudo sniff --status
sudo sniff --stop

# Systemd Service
sudo systemctl start sniff
sudo systemctl status sniff
sudo journalctl -u sniff -f

# Liệt kê interfaces
sudo sniff --list-interfaces

# Gỡ cài đặt
curl -sSL https://raw.githubusercontent.com/ntu168108/sniff/main/scripts/uninstall.sh | sudo bash
```

---

## 📚 Bảng Thuật Ngữ Chuyên Ngành

| Thuật Ngữ | Tiếng Việt | Giải Thích Chi Tiết |
|-----------|------------|---------------------|
| **Packet** | Gói tin | Đơn vị dữ liệu nhỏ được truyền qua mạng |
| **Interface** | Card mạng | Kết nối mạng: eth0 (dây), wlan0 (wifi), lo (loopback) |
| **Port** | Cổng | Số định danh dịch vụ: 80 (HTTP), 443 (HTTPS), 22 (SSH) |
| **Filter** | Bộ lọc | Điều kiện chọn lọc gói tin muốn xem |
| **BPF** | Berkeley Packet Filter | Ngôn ngữ lọc gói tin mạnh mẽ |
| **Daemon** | Tiến trình ngầm | Chương trình chạy background, không hiển thị UI |
| **PCAP** | Packet Capture | Định dạng file lưu gói tin chuẩn |
| **Snapshot length** | Độ dài snapshot | Số bytes tối đa capture từ mỗi gói tin |
| **Promiscuous mode** | Chế độ promiscuous | Bắt TẤT CẢ gói tin trên mạng, không chỉ gói tới máy này |
| **Buffer** | Bộ đệm | Vùng nhớ tạm lưu dữ liệu trước khi ghi file |
| **Queue** | Hàng đợi | Danh sách gói tin chờ xử lý |
| **TUI** | Giao diện text | Text User Interface - giao diện dạng text, không phải GUI |
| **Real-time** | Thời gian thực | Hiển thị ngay lập tức khi có dữ liệu |
| **Retention** | Lưu giữ | Số ngày lưu file trước khi tự động xóa |
| **Rotation** | Xoay vòng | Tự động tạo file mới theo chu kỳ (mỗi giờ) |
| **Systemd** | Systemd | Hệ thống quản lý service trên Linux hiện đại |
| **Module** | Module/Plugin | Thành phần mở rộng để phân tích gói tin |
| **Drop** | Rơi/Mất | Gói tin bị mất do buffer đầy |
| **pps** | Gói tin/giây | Packets per second - số gói tin mỗi giây |
| **bps** | Bytes/giây | Bytes per second - tốc độ dữ liệu |

---

**Phiên bản:** 1.0.0  
**Cập nhật:** 2026-01-04  
**Giấy phép:** MIT

**Chúc bắt gói tin vui vẻ! 🚀**
