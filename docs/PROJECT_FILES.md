# SNIFF - Danh Sách Files Trong Dự Án

## 📦 Files Package Chính (Python)

| File | Dòng | Mục Đích | Trạng Thái |
|------|------|----------|------------|
| `sniff.py` | 662 | File chính, phân tích command line, khởi chạy app | ✅ Sẵn sàng |
| `setup.py` | 70 | Cấu hình package để cài bằng pip | ✅ Sẵn sàng |
| `requirements.txt` | 1 | Danh sách thư viện cần: scapy>=2.5.0 | ✅ Sạch |

> **pip**: công cụ cài đặt thư viện Python, giống App Store cho Python

## 🔧 Core Module (`core/`) - Xử Lý Chính

| File | Dòng | Mục Đích | Trạng Thái |
|------|------|----------|------------|
| `capture.py` | 434 | Bắt gói tin (dùng Scapy AsyncSniffer) | ✅ Đã xóa debug code |
| `decoder.py` | 569 | Giải mã gói tin (Ethernet/IP/TCP/UDP/etc) | ✅ Hoàn hảo |
| `pcap_writer.py` | ~300 | Đọc/ghi file PCAP | ✅ Tốt |
| `rotator.py` | ~400 | Tự động xoay file theo giờ | ✅ Tốt |
| `constants.py` | ~120 | Các hằng số protocol, buffer profiles | ✅ Tốt |

> **Decoder**: Bộ giải mã, chuyển dữ liệu thô thành dạng đọc được  
> **PCAP**: Packet Capture - định dạng file lưu gói tin  
> **Buffer**: Vùng nhớ tạm để lưu dữ liệu

## 🔌 Modules System (`modules/`) - Hệ Thống Plugin

| File | Dòng | Mục Đích | Trạng Thái |
|------|------|----------|------------|
| `base.py` | 282 | Class cơ sở cho plugins phân tích | ✅ Xuất sắc |
| `runner.py` | 319 | Chạy nhiều module song song (multi-thread) | ✅ Tốt |
| `dummy/analyze.py` | 167 | Module phân tích mẫu | ✅ Ví dụ tốt |

> **Plugin**: Thành phần mở rộng, có thể thêm vào dễ dàng  
> **Multi-thread**: Chạy nhiều tác vụ đồng thời  
> **Base class**: Lớp cha, các lớp con kế thừa

## 🎨 UI Module (`ui/`) - Giao Diện

| File | Dòng | Mục Đích | Trạng Thái |
|------|------|----------|------------|
| `menu.py` | ~650 | Menu chính TUI | ✅ Giàu tính năng |
| `list_view.py` | ~550 | Hiển thị danh sách gói tin real-time | ✅ Tốt |
| `detail_view.py` | ~280 | Xem chi tiết gói tin | ✅ Tốt |
| `colors.py` | ~250 | Màu sắc terminal & format | ✅ Tốt |

> **TUI**: Text User Interface - giao diện dạng text (không phải GUI với chuột)  
> **Real-time**: Hiển thị trực tiếp, ngay lập tức

## 📜 Scripts Cài Đặt (`scripts/`)

| File | Dòng | Mục Đích | Trạng Thái |
|------|------|----------|------------|
| `install.sh` | 220 | Script tự động cài đặt | ✅ Sẵn sàng |
| `uninstall.sh` | 50 | Script gỡ cài đặt | ✅ Sẵn sàng |
| `install-service.sh` | 144 | Cài đặt systemd service | ✅ Sẵn sàng |

> **Script**: File chứa các lệnh tự động  
> **Systemd service**: Dịch vụ chạy ngầm trên Linux

## 🐧 Service Files

| File | Dòng | Mục Đích | Trạng Thái |
|------|------|----------|------------|
| `sniff.service` | 29 | Template systemd service | ✅ Sẵn sàng |

> **Template**: Mẫu, file cấu hình mẫu

## 📖 Files Tài Liệu (`docs/`)

| File | Sections | Mục Đích | Trạng Thái |
|------|----------|----------|------------|
| `README.md` | 15 | Tổng quan dự án, tính năng, cách cài | ✅ Đầy đủ |
| `USER_GUIDE.md` | 15 | Hướng dẫn sử dụng chi tiết | ✅ Chi tiết |
| `QUICKSTART.md` | 7 | Bắt đầu nhanh 2 phút | ✅ Ngắn gọn |
| `LICENSE` | - | Giấy phép MIT | ✅ Chuẩn |

## ⚙️ Files Cấu Hình

| File | Mục Đích | Trạng Thái |
|------|----------|------------|
| `.gitignore` | Liệt kê file git bỏ qua | ✅ Đầy đủ |
| `MANIFEST.in` | File nào sẽ được đóng gói | ✅ Đã cập nhật |

> **Git**: Hệ thống quản lý phiên bản code  
> **.gitignore**: File liệt kê những gì git không theo dõi  
> **MANIFEST**: Danh sách file được include khi đóng gói

## 📊 Thống Kê Tổng Thể

```
Tổng số files: 25+ files
Tổng số dòng code: ~5,500+ dòng
Ngôn ngữ: Python (95%), Bash (5%)
Tài liệu: 3 hướng dẫn đầy đủ
```

## 🎯 Chất Lượng Code

| Tiêu Chí | Điểm | Ghi Chú |
|----------|------|---------|
| **Tài liệu** | ⭐⭐⭐⭐⭐ | Docstrings, README, USER_GUIDE, QUICKSTART |
| **Cấu trúc code** | ⭐⭐⭐⭐⭐ | Tách biệt rõ ràng (core/modules/ui) |
| **Xử lý lỗi** | ⭐⭐⭐⭐ | Try-except blocks, logging đầy đủ |
| **Thread-safe** | ⭐⭐⭐⭐⭐ | Locks, queues, events |
| **Mở rộng** | ⭐⭐⭐⭐⭐ | Hệ thống module plugin |
| **Trải nghiệm** | ⭐⭐⭐⭐⭐ | Cài 1 lệnh, TUI tương tác |

> **Thread-safe**: An toàn khi chạy đa luồng  
> **Locks**: Khóa, đảm bảo 1 thread 1 lúc  
> **Queues**: Hàng đợi dữ liệu  
> **Logging**: Ghi log lỗi/thông tin

## ✅ Checklist Cuối

- [x] Code chính đã dọn sạch (đã xóa debug code)
- [x] Requirements.txt tối thiểu và sạch
- [x] Setup.py đã cấu hình cho pip install
- [x] Đã tạo one-line installer
- [x] Tài liệu đầy đủ (3 guides)
- [x] Service files cho daemon mode
- [x] .gitignore cho repo sạch
- [x] LICENSE (MIT)
- [x] Đã update username GitHub
- [x] Đã test install.sh
- [ ] **Push lên GitHub** ← Việc cuối cùng!

## 🚀 Sẵn Sàng Deploy!

**Bước tiếp theo:** Push code lên GitHub và chia sẻ!

---

## 📚 Giải Thích Thuật Ngữ Kỹ Thuật

| Thuật Ngữ | Giải Thích | Ví Dụ |
|-----------|------------|-------|
| **Module** | Thành phần chức năng riêng biệt | `core/`, `ui/` |
| **Package** | Tập hợp code có thể cài đặt | SNIFF package |
| **Dependencies** | Thư viện cần thiết | scapy |
| **CLI** | Command Line Interface - giao diện dòng lệnh | `sniff -i eth0` |
| **Parser** | Bộ phân tích cú pháp | Phân tích `-i eth0` |
| **AsyncSniffer** | Bắt gói tin không đồng bộ | Không block chương trình |
| **Buffer profile** | Cấu hình vùng nhớ tạm | low/balanced/fast/max |
| **Systemd** | Hệ thống quản lý service Linux | Auto-start khi boot |
| **Daemon** | Chương trình chạy ngầm | Chạy background 24/7 |
| **PCAP** | Packet Capture file format | File lưu gói tin |
