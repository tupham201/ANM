# TÀI LIỆU SẢN PHẨM: SECURE HYBRID EMAIL LAB
> **Phòng Lab Mô Phỏng Thư Điện Tử An Toàn Bằng Mã Hóa Lai & Chữ Ký Số**  
> *Đồ án môn An toàn Thông tin — Nhóm 14*

---

## 📖 MỤC LỤC
1. [Giới thiệu & Vấn đề giải quyết](#1-giới-thiệu--vấn-đề-giải-quyết)
2. [Mô hình Kiến trúc & Công nghệ](#2-mô-hình-kiến-trúc--công-nghệ)
3. [Pipeline Mật mã từ đầu đến cuối (Core Cryptographic Flow)](#3-pipeline-mật-mã-từ-đầu-đến-cuối-core-cryptographic-flow)
4. [Cấu trúc Thư mục & Chức năng từng file](#4-cấu-trúc-thư-mục--chức-năng-từng-file)
5. [Hướng dẫn Cài đặt & Khởi chạy (Step-by-Step cho người mới)](#5-hướng-dẫn-cài-đặt--khởi-chạy-step-by-step-cho-người-mới)
6. [Hướng dẫn Sử dụng & Kịch bản Demo thực tế](#6-hướng-dẫn-sử-dụng--kịch-bản-demo-thực-tế)
7. [Giải quyết Sự cố thường gặp (Troubleshooting FAQ)](#7-giải-quyết-sự-cố-thường-gặp-troubleshooting-faq)

---

## 1. GIỚI THIỆU & VẤN ĐỀ GIẢI QUYẾT

### 1.1. Vấn đề thực tế của Email truyền thống
Email ban đầu được thiết kế theo cơ chế văn bản rõ (plaintext). Khi gửi thư qua Internet:
- **Nguy cơ nghe lén (Eavesdropping / Sniffing)**: Các router trung gian hoặc tin tặc trên đường truyền có thể đọc trộm toàn bộ nội dung và tệp đính kèm.
- **Nguy cơ giả mạo dữ liệu (Tampering / MITM)**: Kẻ tấn công đứng giữa có thể sửa đổi nội dung thư (ví dụ: thay đổi số tài khoản ngân hàng trong hợp đồng) mà người nhận không hề hay biết.
- **Nguy cơ mạo danh (Spoofing / Impersonation)**: Bất kỳ ai cũng có thể giả mạo địa chỉ người gửi (Header `From`) để gửi thư lừa đảo.

### 1.2. Giải pháp của dự án: Secure Hybrid Email Lab
Dự án cung cấp một **phòng lab tương tác trực quan**, tích hợp đầy đủ 3 trụ cột bảo mật thông tin (CIA Traid + Non-repudiation):
1. **Tính bí mật (Confidentiality)**: Chỉ người nhận đích danh (Bob) mới giải mã và đọc được thư.
2. **Tính toàn vẹn (Integrity)**: Bất kỳ sự thay đổi dù chỉ **1 bit** trên đường truyền cũng bị phát hiện và từ chối ngay lập tức.
3. **Tính xác thực & Chống chối bỏ (Authenticity & Non-repudiation)**: Người nhận xác thực được chắc chắn thư do chính người gửi (Alice) ký và phát hành.

---

## 2. MÔ HÌNH KIẾN TRÚC & CÔNG NGHỆ

### 2.1. Tại sao phải sử dụng "Mã hóa lai" (Hybrid Encryption)?
Trong mật mã học:
- **Mã hóa đối xứng (Symmetric - ví dụ: AES)**: Tốc độ cực nhanh, mã hóa được file dung lượng lớn. Nhưng có điểm yếu chí mạng: *Làm sao chia sẻ khóa bí mật giữa Alice và Bob qua Internet một cách an toàn?*
- **Mã hóa bất đối xứng (Asymmetric - ví dụ: RSA)**: Giải quyết hoàn hảo bài toán trao đổi khóa (dùng khóa công khai - Public Key). Nhưng điểm yếu là *tốc độ xử lý rất chậm và bị giới hạn độ dài dữ liệu mã hóa* (khóa RSA-2048 không thể mã hóa trực tiếp file lớn hơn ~214 bytes).

👉 **MÃ HÓA LAI = Kết hợp ưu điểm của cả hai**:
Dùng **AES** để mã hóa dữ liệu lớn với tốc độ cao, sau đó dùng **RSA** để "bọc" (mã hóa) chiếc chìa khóa AES nhỏ bé đó lại.

### 2.2. Bảng công nghệ & Thuật toán sử dụng

| Hạng mục | Công nghệ / Thuật toán | Vai trò trong hệ thống | Lý do lựa chọn |
| :--- | :--- | :--- | :--- |
| **Giao diện Web** | [Streamlit](https://streamlit.io/) (Python) | UI tương tác, hiển thị trực quan các bước | Dựng giao diện nhanh, tương tác trực tiếp với logic Python |
| **Thư viện Mật mã** | `cryptography` (hazmat) | Cung cấp các hàm mật mã học tiêu chuẩn | Thư viện mật mã chuẩn công nghiệp của Python, an toàn cao |
| **Mã hóa Nội dung** | **AES-256-GCM** | Mã hóa nội dung thư và tệp đính kèm | Chuẩn AEAD (vừa mã hóa vừa xác thực toàn vẹn bằng Auth Tag) |
| **Bọc Khóa Phiên** | **RSA-2048-OAEP (SHA-256)** | Mã hóa khóa đối xứng AES | Đệm OAEP ngăn chặn tấn công chọn bản mã (CCA) |
| **Chữ ký số** | **RSA-2048-PSS (SHA-256)** | Ký và xác thực danh tính người gửi | Chuẩn PSS an toàn vượt trội hơn đệm PKCS#1 v1.5 cũ |
| **Hàm băm** | **SHA-256** | Băm dữ liệu phục vụ ký và tạo đệm | Chống va chạm mạnh mẽ (Cryptographic hash) |
| **Vận chuyển thư** | **SMTP STARTTLS & IMAP SSL** | Gửi/nhận thư qua Gmail thật | Tương thích chuẩn thư điện tử quốc tế |

---

## 3. PIPELINE MẬT MÃ TỪ ĐẦU ĐẾN CUỐI (CORE CRYPTOGRAPHIC FLOW)

### 3.1. Sơ đồ tổng thể

```text
======================================================================================
PHÍA GỬI (ALICE)
======================================================================================
1. Soạn thư (Subject, Body, Attachment)
   │
   ▼
2. [RSA-PSS + SHA-256]: Alice dùng Khóa riêng (Alice Private Key) để ký số lên thông điệp.
   │  └──> Tạo ra: Signature (Chữ ký số)
   ▼
3. Đóng gói {Thông điệp + Signature} thành một khối dữ liệu gốc.
   │
   ▼
4. [CSPRNG]: Sinh ngẫu nhiên một Khóa phiên (Session Key) AES-256 (32 bytes).
   │
   ▼
5. [AES-256-GCM]: Mã hóa khối dữ liệu gốc bằng Session Key.
   │  └──> Tạo ra: Ciphertext (Bản mã) + Nonce (12 bytes) + Auth Tag (16 bytes)
   ▼
6. [RSA-OAEP + SHA-256]: Dùng Khóa công khai của Bob (Bob Public Key) để mã hóa Session Key.
   │  └──> Tạo ra: Wrapped Key (Khóa phiên đã bọc)
   ▼
7. Đóng gói tất cả thành Phong bì JSON: [SECURE-HYBRID-MAIL v1.0]
   └──> Chuyển qua kênh vận chuyển: Hộp thư cục bộ HOẶC Gmail SMTP

======================================================================================
KÊNH TRUYỀN DẪN (Internet / Hộp thư mô phỏng)
======================================================================================
Kẻ tấn công nghe lén trên đường truyền chỉ thấy:
- Địa chỉ người gửi & nhận (Metadata).
- Một phong bì JSON chứa toàn chuỗi mã hóa vô nghĩa (Ciphertext Base64).
* Kẻ tấn công KHÔNG CÓ Khóa riêng của Bob nên KHÔNG THỂ mở được Session Key.
* Nếu Kẻ tấn công cố tình sửa đổi dù chỉ 1 bit của Ciphertext, Auth Tag sẽ phát hiện ngay.

======================================================================================
PHÍA NHẬN (BOB)
======================================================================================
1. Bob nhận phong bì JSON (từ Gmail IMAP hoặc Hộp thư cục bộ).
   │
   ▼
2. [RSA-OAEP Giải mã]: Bob dùng Khóa riêng của mình (Bob Private Key) giải mã Wrapped Key.
   │  └──> Khôi phục lại: Khóa phiên (Session Key) AES-256 ban đầu.
   ▼
3. [AES-256-GCM Giải mã]: Dùng Session Key + Nonce + Auth Tag để giải mã Ciphertext.
   │  ├──> NẾU Auth Tag KHÔNG KHỚP: Báo lỗi "Dữ liệu bị can thiệp (Tampered)!" -> HỦY BỎ.
   │  └──> NẾU Auth Tag KHỚP: Dữ liệu toàn vẹn -> Thu được {Thông điệp + Signature}.
   ▼
4. [RSA-PSS Xác minh]: Dùng Khóa công khai của Alice (Alice Public Key) kiểm tra Signature.
   │  ├──> NẾU Hợp lệ: "Xác thực thành công! Thư chính xác từ Alice và không bị sửa đổi".
   │  └──> NẾU Không hợp lệ: "Cảnh báo mạo danh người gửi!".
   ▼
5. Hiển thị nội dung thư và cho phép tải tệp đính kèm đã giải mã.
```

### 3.2. Cấu trúc Phong bì Dữ liệu Mã hóa (`secure-envelope.json`)
Dữ liệu truyền trên mạng được chuẩn hóa thành cấu trúc JSON độc lập:
```json
{
  "protocol": "SECURE-HYBRID-MAIL",
  "version": "1.0",
  "sender": "alice@example.com",
  "recipient": "bob@example.com",
  "timestamp": "2026-11-03T08:00:00Z",
  "crypto_metadata": {
    "asym_algo": "RSA-2048-OAEP-SHA256",
    "sym_algo": "AES-256-GCM",
    "hash_algo": "SHA-256",
    "sig_algo": "RSA-2048-PSS-SHA256"
  },
  "payload": {
    "wrapped_key": "...",
    "nonce": "...",
    "tag": "...",
    "ciphertext": "..."
  }
}
```

---

## 4. CẤU TRÚC THƯ MỤC & CHỨC NĂNG TỪNG FILE

```text
ANM/
├── app.py                      # Ứng dụng Web Streamlit (Giao diện 3 tab)
├── src/                        # Mã nguồn logic cốt lõi (Core Business Logic)
│   ├── __init__.py
│   ├── config.py               # Quản lý cấu hình môi trường, đọc file .env
│   ├── crypto_engine.py        # Động cơ mật mã: AES-GCM, RSA-OAEP, RSA-PSS, Envelope
│   ├── key_manager.py          # Quản lý khóa RSA: sinh khóa, lưu/đọc PEM, mật khẩu bảo vệ
│   └── mail_service.py         # Dịch vụ thư điện tử: Gửi SMTP và nhận IMAP Gmail
├── tests/                      # Bộ kiểm thử tự động (Unit Test & Smoke Test)
│   ├── test_flow.py            # Kiểm thử toàn vẹn quy trình mã hóa & bắt lỗi sửa bit
│   ├── test_mail_service.py    # Kiểm thử logic phân tích cú pháp email
│   └── test_app_smoke.py       # Kiểm thử giao diện Streamlit khởi động không lỗi
├── .streamlit/
│   └── config.toml             # Tùy biến giao diện (Màu sắc, Font chữ, kích thước upload)
├── .env.example                # File mẫu cấu hình biến môi trường
├── requirements.txt            # Danh sách thư viện Python cần cài đặt
├── README.md                   # Tài liệu kỹ thuật
└── PRODUCT.md                  # Hướng dẫn sản phẩm và kiến trúc (File này)
```

---

## 5. HƯỚNG DẪN CÀI ĐẶT & KHỞI CHẠY (STEP-BY-STEP CHO NGƯỜI MỚI)

### Bước 1: Mở Terminal tại thư mục dự án
Mở cửa sổ **PowerShell** (hoặc Terminal trong VS Code / Antigravity) tại thư mục chứa dự án: `C:\Users\Admin\ANM`.

### Bước 2: Tạo môi trường ảo (Virtual Environment)
Môi trường ảo giúp cô lập thư viện của dự án, không làm xung đột với Python trên máy:
```powershell
python -m venv .venv
```

### Bước 3: Cài đặt các thư viện phụ thuộc
Do chính sách bảo mật PowerShell của Windows thường chặn kích hoạt script (`Restricted`), **bạn chỉ cần gọi trực tiếp file python trong `.venv`** để cài đặt an toàn:
```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Bước 4: Kiểm tra nhanh hệ thống (Chạy Test)
Trước khi mở giao diện, hãy chạy thử bộ kiểm thử tự động để chắc chắn mọi hàm mật mã hoạt động trơn tru:
```powershell
.\.venv\Scripts\python.exe -m pytest
```
> Khi màn hình báo xanh (ví dụ: `8 passed`), toàn bộ logic mật mã đã sẵn sàng!

### Bước 5: Cấu hình gửi qua Gmail thật (Tùy chọn)
- **Nếu chỉ muốn chạy thử cục bộ (Offline)**: Bỏ qua bước này, bạn có thể dùng ngay "Hộp thư mô phỏng cục bộ" mà không cần làm gì thêm!
- **Nếu muốn gửi Gmail thật**:
  1. Tạo file `.env` tại thư mục gốc (bằng cách nhân bản từ `.env.example`).
  2. Bật Xác minh 2 bước trên tài khoản Google $\rightarrow$ Truy cập: [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords) $\rightarrow$ Tạo mật khẩu ứng dụng (App Password) 16 chữ cái.
  3. Điền vào `.env`:
     ```dotenv
     GMAIL_USER=your_email@gmail.com
     GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
     SMTP_HOST=smtp.gmail.com
     SMTP_PORT=587
     IMAP_HOST=imap.gmail.com
     IMAP_PORT=993
     ```

### Bước 6: Khởi chạy ứng dụng Web
Chạy lệnh sau:
```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```
Trình duyệt sẽ tự động mở trang web tại địa chỉ: **`http://localhost:8501`**.

---

## 6. HƯỚNG DẪN SỬ DỤNG & KỊCH BẢN DEMO THỰC TẾ

Giao diện ứng dụng được chia thành **3 Tab** tuần tự theo đúng quy trình nghiệp vụ:

### 🎯 Kịch bản 1: Luồng chuẩn Happy Path (Alice gửi cho Bob)
1. **Tại Tab `01 · Khóa`**:
   - Nhập mật khẩu bảo vệ nếu muốn mã hóa khóa riêng.
   - Nhấn nút **Tạo cặp khóa Alice & Bob**.
   - Quan sát Fingerprint (Mã vân tay SHA-256) của hai cặp khóa được sinh ngẫu nhiên.
2. **Tại Tab `02 · Gửi thư`**:
   - Nhập thông tin người gửi, người nhận, tiêu đề, nội dung và đính kèm tệp nếu thích.
   - Chọn Kênh vận chuyển: **Hộp thư mô phỏng cục bộ** (hoặc **Gmail** nếu đã cấu hình `.env`).
   - Nhấn **Ký, mã hóa và gửi**.
   - Quan sát thanh trạng thái chạy qua từng thuật toán:
     * `SHA-256 + RSA-PSS`: Đang ký thông điệp bằng Alice Private Key.
     * `AES-256-GCM`: Đang mã hóa nội dung bằng Khóa phiên ngẫu nhiên.
     * `RSA-OAEP`: Đang bọc khóa phiên bằng Bob Public Key.
3. **Tại Tab `03 · Thẩm định`**:
   - Chọn bức thư vừa nhận trong danh sách.
   - Nhấn **Giải mã và thẩm định**.
   - Kết quả: Hiện banner xanh lá **CHỮ KÝ SỐ HỢP LỆ**, nội dung thư bản rõ và tệp đính kèm xuất hiện nguyên vẹn.

---

### 🛡️ Kịch bản 2: Mô phỏng Tấn công Kẻ đứng giữa (MITM Tampering Attack)
*Kịch bản này là điểm nhấn đắt giá nhất khi thuyết trình đồ án để chứng minh sức mạnh của AES-GCM.*

1. Sau khi gửi thư ở Tab 02, chuyển sang Tab **`03 · Thẩm định`**.
2. Thay vì bấm giải mã bình thường, hãy nhấn nút: **"Mô phỏng sửa 1 bit (MITM)"**.
3. **Hiện tượng xảy ra**:
   - Hệ thống cố tình đảo một bit duy nhất trong chuỗi Ciphertext của phong bì.
   - Khi giải mã, khối AES-GCM tính lại Auth Tag và phát hiện sự sai lệch.
   - Thư viện lập tức ném ngoại lệ `InvalidTag` và từ chối xuất ra dữ liệu bản rõ.
   - Màn hình hiện banner đỏ cảnh báo:  
     **"AES-GCM ĐÃ CHẶN CUỘC TẤN CÔNG — Bản mã bị thay đổi 1 bit nên Auth Tag không còn hợp lệ. Toàn bộ bản rõ đã bị từ chối."**

---

### 👤 Kịch bản 3: Tấn công Mạo danh người gửi (Chữ ký không hợp lệ)
1. Trong Tab **`03 · Thẩm định`**, mở mục **Sử dụng khóa PEM tùy chỉnh**.
2. Tải lên một Public Key của một người khác (không phải Alice).
3. Bấm **Giải mã và thẩm định**.
4. Bản mã AES vẫn giải mã được (nếu Bob dùng đúng Private Key), nhưng bước xác minh chữ ký RSA-PSS sẽ thất bại.
5. Ứng dụng hiện cảnh báo đỏ: **"CHỮ KÝ KHÔNG HỢP LỆ — Không tin cậy nội dung đã giải mã."**

---

## 7. GIẢI QUYẾT SỰ CỐ THƯỜNG GẶP (TROUBLESHOOTING FAQ)

### Q1: Lỗi `File ... Activate.ps1 cannot be loaded because running scripts is disabled`?
* **Nguyên nhân**: Chính sách `ExecutionPolicy` mặc định của Windows PowerShell là `Restricted`.
* **Cách khắc phục**: Không cần sửa cài đặt Windows, bạn chỉ cần gọi trực tiếp:
  ```powershell
  .\.venv\Scripts\python.exe -m streamlit run app.py
  ```

### Q2: Ứng dụng báo "Gmail chưa cấu hình"?
* **Nguyên nhân**: Chưa có file `.env` hoặc thiếu biến `GMAIL_USER` / `GMAIL_APP_PASSWORD`.
* **Cách khắc phục**: Kiểm tra xem file `.env` đã nằm đúng tại thư mục gốc chưa. Nếu chưa có tài khoản Gmail, bạn hãy chọn kênh **Hộp thư mô phỏng cục bộ** để chạy hoàn toàn bình thường mà không cần Gmail.

### Q3: Báo lỗi "Không thể kết nối Gmail SMTP / IMAP"?
* **Nguyên nhân**: Bạn đang dùng mật khẩu đăng nhập Gmail thông thường thay vì **Mật khẩu ứng dụng (App Password 16 chữ cái)**.
* **Cách khắc phục**: Vào [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords), tạo mật khẩu ứng dụng mới và copy mã 16 ký tự vào file `.env`, sau đó khởi động lại Streamlit.

### Q4: Đóng trình duyệt xong mở lại có bị mất khóa không?
* **Trả lời**: Mặc định khóa được lưu trong Session RAM của trình duyệt. Nếu muốn lưu lại để lần sau dùng tiếp, tại Tab 01 bạn hãy tích chọn ô: **"Lưu khóa vào thư mục keys/ để dùng sau khi tải lại trang"**.

---
*Tài liệu được biên soạn phục vụ học tập, nghiên cứu và bảo vệ đồ án An toàn Thông tin.*
---

## 4. CẤU TRÚC THƯ MỤC & CHỨC NĂNG TỪNG FILE

```text
ANM/
├── app.py                      # Ứng dụng Web Streamlit (Giao diện 3 tab)
├── src/                        # Mã nguồn logic cốt lõi (Core Business Logic)
│   ├── __init__.py
│   ├── config.py               # Quản lý cấu hình môi trường, đọc file .env
│   ├── crypto_engine.py        # Động cơ mật mã: AES-GCM, RSA-OAEP, RSA-PSS, Envelope
│   ├── key_manager.py          # Quản lý khóa RSA: sinh khóa, lưu/đọc PEM, mật khẩu bảo vệ
│   └── mail_service.py         # Dịch vụ thư điện tử: Gửi SMTP và nhận IMAP Gmail
├── tests/                      # Bộ kiểm thử tự động (Unit Test & Smoke Test)
│   ├── test_flow.py            # Kiểm thử toàn vẹn quy trình mã hóa & bắt lỗi sửa bit
│   ├── test_mail_service.py    # Kiểm thử logic phân tích cú pháp email
│   └── test_app_smoke.py       # Kiểm thử giao diện Streamlit khởi động không lỗi
├── .streamlit/
│   └── config.toml             # Tùy biến giao diện (Màu sắc, Font chữ, kích thước upload)
├── .env.example                # File mẫu cấu hình biến môi trường
├── requirements.txt            # Danh sách thư viện Python cần cài đặt
├── README.md                   # Tài liệu kỹ thuật
└── PRODUCT.md                  # Hướng dẫn sản phẩm và kiến trúc (File này)
```

---

## 5. HƯỚNG DẪN CÀI ĐẶT & KHỞI CHẠY (STEP-BY-STEP CHO NGƯỜI MỚI)

### Bước 1: Mở Terminal tại thư mục dự án
Mở cửa sổ **PowerShell** (hoặc Terminal trong VS Code / Antigravity) tại thư mục chứa dự án: `C:\Users\Admin\ANM`.

### Bước 2: Tạo môi trường ảo (Virtual Environment)
Môi trường ảo giúp cô lập thư viện của dự án, không làm xung đột với Python trên máy:
```powershell
python -m venv .venv
```

### Bước 3: Cài đặt các thư viện phụ thuộc
Do chính sách bảo mật PowerShell của Windows thường chặn kích hoạt script (`Restricted`), **bạn chỉ cần gọi trực tiếp file python trong `.venv`** để cài đặt an toàn:
```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Bước 4: Kiểm tra nhanh hệ thống (Chạy Test)
Trước khi mở giao diện, hãy chạy thử bộ kiểm thử tự động để chắc chắn mọi hàm mật mã hoạt động trơn tru:
```powershell
.\.venv\Scripts\python.exe -m pytest
```
> Khi màn hình báo xanh (ví dụ: `8 passed`), toàn bộ logic mật mã đã sẵn sàng!

### Bước 5: Cấu hình gửi qua Gmail thật (Tùy chọn)
- **Nếu chỉ muốn chạy thử cục bộ (Offline)**: Bỏ qua bước này, bạn có thể dùng ngay "Hộp thư mô phỏng cục bộ" mà không cần làm gì thêm!
- **Nếu muốn gửi Gmail thật**:
  1. Tạo file `.env` tại thư mục gốc (bằng cách nhân bản từ `.env.example`).
  2. Bật Xác minh 2 bước trên tài khoản Google $\rightarrow$ Truy cập: [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords) $\rightarrow$ Tạo mật khẩu ứng dụng (App Password) 16 chữ cái.
  3. Điền vào `.env`:
     ```dotenv
     GMAIL_USER=your_email@gmail.com
     GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
     SMTP_HOST=smtp.gmail.com
     SMTP_PORT=587
     IMAP_HOST=imap.gmail.com
     IMAP_PORT=993
     ```

### Bước 6: Khởi chạy ứng dụng Web
Chạy lệnh sau:
```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```
Trình duyệt sẽ tự động mở trang web tại địa chỉ: **`http://localhost:8501`**.

---

## 6. HƯỚNG DẪN SỬ DỤNG & KỊCH BẢN DEMO THỰC TẾ

Giao diện ứng dụng được chia thành **3 Tab** tuần tự theo đúng quy trình nghiệp vụ:

### 🎯 Kịch bản 1: Luồng chuẩn Happy Path (Alice gửi cho Bob)
1. **Tại Tab `01 · Khóa`**:
   - Nhập mật khẩu bảo vệ nếu muốn mã hóa khóa riêng.
   - Nhấn nút **Tạo cặp khóa Alice & Bob**.
   - Quan sát Fingerprint (Mã vân tay SHA-256) của hai cặp khóa được sinh ngẫu nhiên.
2. **Tại Tab `02 · Gửi thư`**:
   - Nhập thông tin người gửi, người nhận, tiêu đề, nội dung và đính kèm tệp nếu thích.
   - Chọn Kênh vận chuyển: **Hộp thư mô phỏng cục bộ** (hoặc **Gmail** nếu đã cấu hình `.env`).
   - Nhấn **Ký, mã hóa và gửi**.
   - Quan sát thanh trạng thái chạy qua từng thuật toán:
     * `SHA-256 + RSA-PSS`: Đang ký thông điệp bằng Alice Private Key.
     * `AES-256-GCM`: Đang mã hóa nội dung bằng Khóa phiên ngẫu nhiên.
     * `RSA-OAEP`: Đang bọc khóa phiên bằng Bob Public Key.
3. **Tại Tab `03 · Thẩm định`**:
   - Chọn bức thư vừa nhận trong danh sách.
   - Nhấn **Giải mã và thẩm định**.
   - Kết quả: Hiện banner xanh lá **CHỮ KÝ SỐ HỢP LỆ**, nội dung thư bản rõ và tệp đính kèm xuất hiện nguyên vẹn.

---

### 🛡️ Kịch bản 2: Mô phỏng Tấn công Kẻ đứng giữa (MITM Tampering Attack)
*Kịch bản này là điểm nhấn đắt giá nhất khi thuyết trình đồ án để chứng minh sức mạnh của AES-GCM.*

1. Sau khi gửi thư ở Tab 02, chuyển sang Tab **`03 · Thẩm định`**.
2. Thay vì bấm giải mã bình thường, hãy nhấn nút: **"Mô phỏng sửa 1 bit (MITM)"**.
3. **Hiện tượng xảy ra**:
   - Hệ thống cố tình đảo một bit duy nhất trong chuỗi Ciphertext của phong bì.
   - Khi giải mã, khối AES-GCM tính lại Auth Tag và phát hiện sự sai lệch.
   - Thư viện lập tức ném ngoại lệ `InvalidTag` và từ chối xuất ra dữ liệu bản rõ.
   - Màn hình hiện banner đỏ cảnh báo:  
     **"AES-GCM ĐÃ CHẶN CUỘC TẤN CÔNG — Bản mã bị thay đổi 1 bit nên Auth Tag không còn hợp lệ. Toàn bộ bản rõ đã bị từ chối."**

---

### 👤 Kịch bản 3: Tấn công Mạo danh người gửi (Chữ ký không hợp lệ)
1. Trong Tab **`03 · Thẩm định`**, mở mục **Sử dụng khóa PEM tùy chỉnh**.
2. Tải lên một Public Key của một người khác (không phải Alice).
3. Bấm **Giải mã và thẩm định**.
4. Bản mã AES vẫn giải mã được (nếu Bob dùng đúng Private Key), nhưng bước xác minh chữ ký RSA-PSS sẽ thất bại.
5. Ứng dụng hiện cảnh báo đỏ: **"CHỮ KÝ KHÔNG HỢP LỆ — Không tin cậy nội dung đã giải mã."**

---

## 7. GIẢI QUYẾT SỰ CỐ THƯỜNG GẶP (TROUBLESHOOTING FAQ)

### Q1: Lỗi `File ... Activate.ps1 cannot be loaded because running scripts is disabled`?
* **Nguyên nhân**: Chính sách `ExecutionPolicy` mặc định của Windows PowerShell là `Restricted`.
* **Cách khắc phục**: Không cần sửa cài đặt Windows, bạn chỉ cần gọi trực tiếp:
  ```powershell
  .\.venv\Scripts\python.exe -m streamlit run app.py
  ```

### Q2: Ứng dụng báo "Gmail chưa cấu hình"?
* **Nguyên nhân**: Chưa có file `.env` hoặc thiếu biến `GMAIL_USER` / `GMAIL_APP_PASSWORD`.
* **Cách khắc phục**: Kiểm tra xem file `.env` đã nằm đúng tại thư mục gốc chưa. Nếu chưa có tài khoản Gmail, bạn hãy chọn kênh **Hộp thư mô phỏng cục bộ** để chạy hoàn toàn bình thường mà không cần Gmail.

### Q3: Báo lỗi "Không thể kết nối Gmail SMTP / IMAP"?
* **Nguyên nhân**: Bạn đang dùng mật khẩu đăng nhập Gmail thông thường thay vì **Mật khẩu ứng dụng (App Password 16 chữ cái)**.
* **Cách khắc phục**: Vào [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords), tạo mật khẩu ứng dụng mới và copy mã 16 ký tự vào file `.env`, sau đó khởi động lại Streamlit.

### Q4: Đóng trình duyệt xong mở lại có bị mất khóa không?
* **Trả lời**: Mặc định khóa được lưu trong Session RAM của trình duyệt. Nếu muốn lưu lại để lần sau dùng tiếp, tại Tab 01 bạn hãy tích chọn ô: **"Lưu khóa vào thư mục keys/ để dùng sau khi tải lại trang"**.

---
*Tài liệu được biên soạn phục vụ học tập, nghiên cứu và bảo vệ đồ án An toàn Thông tin.*
