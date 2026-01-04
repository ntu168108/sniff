# SNIFF - Hướng Dẫn Bắt Đầu Nhanh

**Bắt đầu với SNIFF trong 2 phút!**

---

## 📦 Cài Đặt (30 giây)

Chạy MỘT lệnh này:

```bash
curl -sSL https://raw.githubusercontent.com/ntu168108/sniff/main/scripts/install.sh | sudo bash
```

**Xong!** Script tự động cài đặt:
- ✅ Python 3.8+ (ngôn ngữ lập trình)
- ✅ pip3 (trình quản lý package của Python)
- ✅ scapy (thư viện bắt gói tin)
- ✅ SNIFF (công cụ này)

---

## ⚡ Bắt Đầu Nhanh (1 phút)

### Cách 1: Menu Tương Tác (Dễ nhất)

```bash
sudo sniff
```

Sau đó:
1. Nhấn `1` để quick capture (bắt nhanh)
2. Chọn **interface mạng** của bạn (ví dụ: `eth0`, `wlan0`)
   - *Interface mạng: card mạng/kết nối mạng trên máy tính*
3. Xem gói tin **real-time** (trực tiếp)! 🎉
   - *Gói tin (packet): đơn vị dữ liệu được truyền qua mạng*

**Phím điều khiển:**
- `SPACE` - Tạm dừng/Tiếp tục
- `S` - Lưu và thoát
- `Q` - Thoát

### Cách 2: Command Line (Nhanh)

```bash
# Bắt gói tin trên eth0
sudo sniff -i eth0

# Chỉ bắt traffic HTTP (web)
sudo sniff -i eth0 -f "tcp port 80"
# -f: filter (bộ lọc), chỉ bắt từ cổng 80 (HTTP)

# Chạy ở chế độ daemon (background)
sudo sniff -i eth0 -d
# daemon: chạy ngầm, không hiển thị giao diện
```

---

## 🎯 Các Trường Hợp Sử Dụng Thường Gặp

### Giám Sát Toàn Bộ Traffic (Dữ Liệu Mạng)
```bash
sudo sniff -i eth0
```

### Giám Sát Web Traffic (HTTP/HTTPS)
```bash
sudo sniff -i eth0 -f "port 80 or port 443"
# port 80: HTTP (web thường)
# port 443: HTTPS (web bảo mật)
```

### Giám Sát Host (Máy) Cụ Thể
```bash
sudo sniff -i eth0 -f "host 192.168.1.100"
# Chỉ bắt traffic đến/đi từ IP 192.168.1.100
```

### Giám Sát 24/7 Chạy Ngầm
```bash
sudo sniff -i eth0 -d
```

Kiểm tra trạng thái:
```bash
sudo sniff --status
```

Dừng:
```bash
sudo sniff --stop
```

---

## 📁 File Được Lưu Ở Đâu?

Vị trí mặc định: `./sniff_data/raw/`

```
sniff_data/
└── raw/                        # File PCAP thô
    └── 2026-01-04/             # Theo ngày
        ├── eth0_2026-01-04_00.pcap  # Theo giờ (00:00)
        ├── eth0_2026-01-04_01.pcap  # 01:00
        └── ...
```

> **PCAP**: Packet Capture - định dạng file lưu trữ gói tin mạng, có thể mở bằng Wireshark

**Mở bằng Wireshark:**
```bash
wireshark sniff_data/raw/2026-01-04/eth0_2026-01-04_22.pcap
```

---

## 🛠️ Cần Giúp Đỡ?

### Liệt Kê Các Interface Mạng
```bash
sudo sniff --list-interfaces
# Xem các kết nối mạng: eth0, wlan0, lo, etc.
```

### Xem Tất Cả Tùy Chọn
```bash
sudo sniff --help
```

### Đọc Hướng Dẫn Đầy Đủ
Xem [USER_GUIDE.md](USER_GUIDE.md) để biết chi tiết.

---

## 🗑️ Gỡ Cài Đặt

```bash
curl -sSL https://raw.githubusercontent.com/ntu168108/sniff/main/scripts/uninstall.sh | sudo bash
```

---

## 📚 Giải Thích Thuật Ngữ

| Thuật Ngữ | Giải Thích |
|-----------|------------|
| **Packet (Gói tin)** | Đơn vị dữ liệu nhỏ được truyền qua mạng, giống như "bức thư" điện tử |
| **Interface** | Card mạng/kết nối mạng (eth0: dây mạng, wlan0: wifi) |
| **Port (Cổng)** | Số định danh dịch vụ (80: web, 22: SSH, 443: HTTPS) |
| **Traffic** | Lưu lượng dữ liệu mạng đi qua |
| **Daemon** | Chương trình chạy ngầm, không hiển thị giao diện |
| **Filter (Bộ lọc)** | Điều kiện để chọn lọc gói tin muốn xem |
| **PCAP** | File lưu gói tin, mở được bằng Wireshark |
| **BPF** | Berkeley Packet Filter - ngôn ngữ lọc gói tin |
| **Real-time** | Trực tiếp, ngay lập tức |
| **TUI** | Text User Interface - giao diện text |

---

**Vậy thôi! Chúc bắt gói tin vui vẻ! 🚀**
