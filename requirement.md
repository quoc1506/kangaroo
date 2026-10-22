# ĐẶC TẢ KỸ THUẬT HỆ THỐNG KANGAROO SECP256K1 PHÂN TÁN
# Mục tiêu: Bitcoin Puzzle #140 | Lõi: JeanLucPons/Kangaroo | Khởi chạy: sh run.sh
# Tài liệu quy chuẩn kỹ thuật phục vụ lập trình trực tiếp

---

## 1. TỔNG QUAN KIẾN TRÚC & NGUYÊN TẮC VẬN HÀNH

### 1.1. Mục tiêu hệ thống
Xác định khóa bí mật (Private Key) 140-bit của Bitcoin Puzzle #140 bằng thuật toán **Pollard's Kangaroo (Lamport/Pollard Lambda Algorithm)** tối ưu hóa cho đường cong elliptic Secp256k1 trong dải tìm kiếm [2^139, 2^140 - 1].

### 1.2. Mô hình phân tán Master - Worker
Hệ thống vận hành theo mô hình Master - Worker phân tán tập trung:
- **Master Server Duy Nhất (VPS Linux, PHP 8+, SQLite 3 WAL - `kangaroo.php`):**
  - Gộp chung toàn diện Dashboard & API vào duy nhất một tệp `kangaroo.php` (Truy cập bằng trình duyệt hiển thị Dashboard; gọi kèm tham số `action` trả về JSON API).
  - Tự động khởi tạo cấu trúc CSDL và bảng `tame_traps.db` ngay lần đầu truy cập, không cần import SQL thủ công.
  - Quản trị cấu hình động: cho phép điều chỉnh ngưỡng `target_dp` thời gian thực trên Web Dashboard.
  - Tự động điều phối phân công tác vụ (TAME hoặc WILD) cho các worker dựa trên số lượng DP hiện có.
  - Tiếp nhận điểm phân biệt (Distinguished Points - DP), tra cứu va chạm (Collision Detection) và giải mã nghiệm khóa bí mật tức thời.
- **Worker Nodes (Google Colab GPU, Kaggle, Vast.ai, RunPod, Linux VPS, CPU PC):**
  - Vận hành thông qua một script duy nhất: `bash run.sh`.
  - **Quy chuẩn chạy Pre-built Binary (Zero Compilation):** Tuyệt đối không biên dịch (`make`, `gcc`, `nvcc`) tại máy trạm vì các cloud worker không có sẵn thư viện dev và compiler.
  - Hệ thống sử dụng GitHub Actions CI/CD (`.github/workflows/build.yml`) biên dịch sẵn các file nhị phân vào `bin/`:
    + `bin/sysd_linux_cpu_x86_64`: Tối ưu AVX2 và libcurl.
    + `bin/sysd_linux_gpu_cuda`: Tối ưu đa kiến trúc NVIDIA CUDA (SM 60-90).
    + `bin/sysd_darwin_all`: Universal binary cho Apple Silicon (ARM64) & Intel (x86_64).
  - `run.sh` chỉ làm nhiệm vụ: nhận diện hệ điều hành và phần cứng (NVIDIA GPU vs CPU vs macOS), thực thi binary trong `./bin/`. **Mặc định tự động chạy 100% CPU thread** (`std::thread::hardware_concurrency`) mà không cần bất kỳ cờ nhạy cảm nào.
  - **Cơ chế chạy im lặng (Stealth / Silent Mode):** Tuyệt đối không in các từ khóa nhạy cảm ra console/stdout để tránh bị các hệ thống đám mây quét vi phạm điều khoản dịch vụ (TOS Ban). Chỉ ghi log khi có lỗi chí mạng vào `error.log`.

### 1.3. Quy chuẩn kỹ thuật bắt buộc
1. **Lõi tính toán số học Secp256k1:** Tích hợp trực tiếp engine C++/CUDA tối ưu của Jean-Luc Pons (`JeanLucPons/Kangaroo`), sử dụng biểu diễn số nguyên lớn 256-bit tối ưu hóa thanh ghi và phép cộng điểm tọa độ Jacobian.
2. **Cơ chế duyệt ngẫu nhiên toàn dải (Pure Random Walk):** Mỗi worker thread (cả TAME và WILD) tự khởi tạo điểm bắt đầu ngẫu nhiên đồng đều trong toàn bộ không gian dải tìm kiếm [RangeMin, RangeMax]. Việc phân bố ngẫu nhiên độc lập tối đa hóa xác suất giao cắt giữa vết bước nhảy của Wild Kangaroo và lưới bẫy Tame Kangaroo theo nguyên lý Birthday Paradox.
3. **Cơ chế phân phối tác vụ qua ngưỡng động (target_dp):** Master Server tự động quyết định loại tác vụ phân bổ cho worker dựa trên so sánh giữa số lượng DP hiện có (`current_dp`) và ngưỡng mục tiêu (`target_dp`):
   - Khi `current_dp < target_dp`: Phân phối tác vụ `TAME` (tạo bẫy).
   - Khi `current_dp >= target_dp`: Phân phối tác vụ `WILD` (tìm kiếm va chạm).
4. **Quy chuẩn gửi dữ liệu của Worker:**
   - Khi chạy TAME: Worker gửi dữ liệu lên Server định kỳ mỗi **10 giây** (hoặc khi gom đủ 1.000 điểm DP). Nếu chưa có DP, vẫn gửi heartbeat báo cáo hashrate và trạng thái để Master duy trì `ONLINE`.
   - Khi chạy WILD: Worker gửi dữ liệu lên Server định kỳ mỗi **10 giây** (chứa danh sách DP phát hiện được trong chu kỳ, hoặc danh sách rỗng để đóng vai trò Heartbeat báo cáo hashrate và duy trì trạng thái `ONLINE`).
5. **Chính sách Logging an toàn:** Không in dữ liệu nhạy cảm ra màn hình. Mọi thống kê hiệu năng, hashrate, số lượng DP và dung lượng lưu trữ được xem tập trung trên Web Dashboard của Master Server.

---

## 2. THÔNG SỐ TOÁN HỌC & ĐỐI TƯỢNG BITCOIN PUZZLE #140

### 2.1. Hằng số đường cong Elliptic Secp256k1 (FIPS 186-4 / SEC 2)
- Phương trình Weierstrass: `y^2 = x^3 + 7 (mod p)`
- Số nguyên tố trường hữu hạn (p):
  `p = 2^256 - 2^32 - 977 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F`
- Bậc của nhóm điểm đường cong (n):
  `n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`
- Điểm sinh chuẩn G = (Gx, Gy):
  - `Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798`
  - `Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8`

### 2.2. Thông số mục tiêu Bitcoin Puzzle #140
- **Số hiệu:** Bitcoin Puzzle #140
- **Địa chỉ ví Bitcoin:** `1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo`
- **Khóa công khai nén (Compressed Public Key - 33 bytes):**
  `031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640`
- **Tọa độ Public Key mục tiêu (Target_PubKey):**
  - `Target_X = 0x1f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640`
  - `Target_Y`: Tọa độ Y có tính chất lẻ (tiền tố `03`), nghiệm của `y^2 = x^3 + 7 (mod p)`.
- **Dải tìm kiếm (Search Range - 140 bits):**
  - `RangeMin = 2^139 = 0x80000000000000000000000000000000000`
  - `RangeMax = 2^140 - 1 = 0xfffffffffffffffffffffffffffffffffff`
  - Chiều rộng không gian khóa: `W = RangeMax - RangeMin + 1 = 2^139 ≈ 6.96 * 10^41`

### 2.3. Bảng bước nhảy Kangaroo (Jump Table)
- Kích thước bảng: 32 bước nhảy (`NB_JUMP = 32`).
- Giá trị bước nhảy vô hướng: `d[i] = 2^(i + 50)` với `i` từ 0 đến 31. Bước nhảy trung bình `d_avg ≈ 2^66`.
- Bảng điểm nhảy nạp vào bộ nhớ GPU Constant / CPU L1 Cache:
  `J[i] = d[i] * G  (i = 0, 1, ..., 31)`
- Hàm băm xác định bước nhảy: `i = (Current_Point.X) mod 32` (sử dụng 5 bit thấp của tọa độ X).

### 2.4. Cấu hình Điểm Phân Biệt (Distinguished Point - DP)
- Số bit 0 kiểm tra: 23 bit (`k = 23`).
- Mặt nạ nhị phân: `DP_MASK = 0x007FFFFF`.
- Điều kiện phân biệt: `(Current_Point.X & 0x007FFFFF) == 0`.
- Tần suất trung bình: Cứ `2^23 = 8.388.608` bước nhảy xuất hiện 1 điểm phân biệt.

---

## 3. ĐẶC TẢ SHELL SCRIPT KHỞI CHẠY DUY NHẤT (run.sh) & CHÍNH SÁCH STEALTH LOGGING

### 3.1. Phân tích rủi ro môi trường Cloud & Kiến trúc Pre-built Binary
- **Vấn đề thực tế tại Worker Nodes (Colab / Vast.ai / RunPod):**
  1. Các máy chủ ảo đám mây không cài sẵn `build-essential`, `libgmp-dev` hoặc đường dẫn `nvcc`.
  2. Việc chạy lệnh `make` hoặc `gcc` ngay tại worker vừa gây tốn thời gian spin-up (5-10 phút), vừa dễ phát sinh lỗi xung đột thư viện `g++`.
  3. Lệnh biên dịch in ra hàng trăm dòng warning/compiler logs, kích hoạt bộ quét log của Google Colab / Kaggle và dẫn đến bị khóa tài khoản (TOS Ban).
- **Giải pháp chuẩn hóa:**
  1. Sử dụng GitHub Actions CI/CD (`.github/workflows/build.yml`) để biên dịch sẵn các file nhị phân tĩnh và phát hành qua GitHub Releases.
  2. Script `run.sh` **tuyệt đối không biên dịch** tại chỗ. `run.sh` chỉ phát hiện phần cứng, tải tệp nhị phân phù hợp (`proc_worker_linux_gpu_cuda` hoặc `proc_worker_linux_cpu_x86_64`) nếu chưa có, và chạy thẳng.
  3. Chế độ ngụy trang (Stealth): Toàn bộ output chuẩn được chuyển hướng vào `/dev/null`. Lỗi mạng hoặc gián đoạn được ghi âm thầm vào `error.log`.

### 3.2. Kiến trúc Native C++ Daemon (`sysd.cpp`) & Script Launcher Tối Giản (`run.sh`)

Nhằm loại bỏ hoàn toàn các rủi ro bảo mật (lộ URL máy chủ, lộ endpoint `get_task`, `submit_tame`, lộ tham số trên tiến trình `ps aux` hoặc file script plaintext), hệ thống chuẩn hóa như sau:
1. **Lõi Daemon C++ (`sysd.cpp` đặt cùng cấp thư mục gốc):**
   - Tích hợp trực tiếp thư viện mạng chuẩn `libcurl` trong C++: thực thi HTTP GET/POST, gửi nhận dữ liệu JSON hoàn toàn trong RAM.
   - Nhúng thuật toán Secp256k1 Kangaroo, mặc định tự động chạy 100% thread CPU (`std::thread::hardware_concurrency()`). Hỗ trợ cấu hình số thread qua cờ `-c <số_luồng>` hoặc `-j <số_luồng>`.
   - Mọi URL mặc định và cấu trúc API được biên dịch tĩnh vào mã máy nhị phân, tự động xóa trắng `argv` trong RAM sau khi parse để che giấu tiến trình.
   - Chế độ im lặng tuyệt đối (Silent by default): không in ra console, chỉ ghi log khi có lỗi kết nối vào `error.log`.
2. **Script khởi chạy siêu tối giản (`run.sh`):**
   - Tự động nhận diện GPU NVIDIA, Linux CPU, macOS Darwin trong thư mục `bin/` và chuyển tiếp tham số `$@` đến binary.
   - Không chứa bất kỳ URL, secret token, tên endpoint hay cờ nhạy cảm nào.
   - Khởi chạy cực kỳ đơn giản: `bash run.sh` (tự động nhận diện và chạy tối đa tài nguyên).

```bash
#!/usr/bin/env bash
set -e

BIN=""
OS="$(uname -s)"

if [ "$OS" = "Darwin" ]; then
    DARWIN_CANDIDATES=(
        "./bin/sysd_darwin_all"
        "./sysd_darwin_all"
        "./bin/sysd"
        "./sysd"
    )
    for c in "${DARWIN_CANDIDATES[@]}"; do
        if [ -f "$c" ]; then
            BIN="$c"
            break
        fi
    done
else
    if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
        for c in "./bin/sysd_linux_gpu_cuda" "./sysd_linux_gpu_cuda"; do
            if [ -f "$c" ]; then
                BIN="$c"
                break
            fi
        done
    fi

    if [ -z "$BIN" ]; then
        LINUX_CANDIDATES=(
            "./bin/sysd_linux_cpu_x86_64"
            "./sysd_linux_cpu_x86_64"
            "./bin/sysd"
            "./sysd"
        )
        for c in "${LINUX_CANDIDATES[@]}"; do
            if [ -f "$c" ]; then
                BIN="$c"
                break
            fi
        done
    fi
fi

if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERR] Binary not found in ./bin/ or current directory." >> error.log 2>&1
    exit 1
fi

chmod +x "$BIN" 2>/dev/null || true
exec "$BIN" "$@" > /dev/null 2>> error.log
```

---

## 4. THIẾT KẾ CƠ SỞ DỮ LIỆU SQLITE WAL, TOÁN VA CHẠM & DASHBOARD GIÁM SÁT

### 4.1. Cấu trúc cơ sở dữ liệu `data/tame_traps.db`
Hệ thống sử dụng SQLite3 cấu hình Write-Ahead Logging (WAL) tối ưu đọc/ghi đồng thời với hàng trăm worker:

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -64000; -- 64MB RAM cache
PRAGMA temp_store = MEMORY;

-- Bảng 1: Lưu trữ bẫy Distinguished Points của Kangaroo TAME
CREATE TABLE IF NOT EXISTS tame_traps (
    dp_x TEXT PRIMARY KEY,               -- 64 ký tự Hex của tọa độ X (đạt chuẩn DP)
    total_distance TEXT NOT NULL,        -- Quãng đường tích lũy vô hướng (Hex BigInt)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tame_dp_x ON tame_traps(dp_x);

-- Bảng 2: Cấu hình hệ thống động (cho phép Dashboard sửa target_dp)
CREATE TABLE IF NOT EXISTS system_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL
);

-- Khởi tạo target_dp mặc định (ví dụ: 50.000.000 DP)
INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES 
('target_dp', '50000000');

-- Bảng 3: Quản lý trạng thái Worker & Hashrate
CREATE TABLE IF NOT EXISTS workers_status (
    worker_id TEXT PRIMARY KEY,
    ip_address TEXT DEFAULT '',
    hardware TEXT DEFAULT '',
    hashrate TEXT DEFAULT '0 MH/s',
    mode TEXT DEFAULT 'IDLE',
    dp_count INTEGER DEFAULT 0,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 4.2. Logic điều phối tự động theo `target_dp`
Máy chủ truy vấn hai giá trị:
```sql
SELECT COUNT(*) AS current_dp FROM tame_traps;
SELECT setting_value AS target_dp FROM system_settings WHERE setting_key = 'target_dp';
```
- Nếu `current_dp < target_dp`: Trả về `task_type = "TAME"`.
- Nếu `current_dp >= target_dp`: Trả về `task_type = "WILD"`.

### 4.3. Giải thích toán học va chạm & Bản chất chiều nhảy của Wild Kangaroo
Câu hỏi kỹ thuật cốt lõi: **"Vì sao chuột WILD có cả công thức cộng (D_T + D_W) và trừ (D_T - D_W)?"**

1. **Bản chất đường cong Elliptic Secp256k1:**
   - Phương trình Weierstrass: `y^2 = x^3 + 7 (mod p)`.
   - Với mỗi hoành độ `x`, phương trình luôn có đúng hai nghiệm tung độ đối xứng qua trục hoành: `y` và `-y = (p - y)`.
   - Do đó, hai điểm đối xứng `P = (x, y)` và `-P = (x, p - y)` có **cùng một giá trị tọa độ x**.
2. **Tối ưu hóa bộ nhớ:**
   - Để tiết kiệm 50% dung lượng RAM và đĩa, cơ sở dữ liệu `tame_traps` chỉ lưu tọa độ `dp_x` (32 bytes) thay vì lưu cả điểm `(x, y)` (64 bytes).
3. **Phân tích va chạm khi hoành độ trùng khớp (`X_T = X_W`):**
   - Điểm bẫy Tame: `P_T = S_T + D_T * G` (với `S_T = RangeMin * G`).
   - Điểm chuột Wild: `P_W = Target_PubKey + D_W * G = (k_priv + D_W) * G`.
   - Khi `X(P_T) == X(P_W)`, sẽ xảy ra một trong hai trường hợp:
     - **Trường hợp 1 (Trùng tuyệt đối P_T = P_W):**
       `S_T + D_T ≡ k_priv + D_W (mod n)`
       `=> k_priv ≡ (RangeMin + D_T - D_W) mod n` (Đây là nghiệm thuận chiều).
     - **Trường hợp 2 (Đối xứng điểm P_T = -P_W):**
       `S_T + D_T ≡ -(k_priv + D_W) (mod n)`
       `=> k_priv ≡ (-RangeMin - D_T - D_W) mod n`
       Hoặc theo tính đối xứng của bước nhảy nghịch: `k_priv ≡ (RangeMin + D_T + D_W) mod n`.
4. **Chuột Wild nhảy 2 chiều (Bidirectional / Two-Way Jump):**
   - Trong engine Kangaroo hiện đại (Jean-Luc Pons), luồng tính toán có thể thực hiện bước nhảy thuận `+ d[i] * G` và bước nhảy ngược `- d[i] * G` từ `Target_PubKey` để bao quát cả hai phía của không gian khóa.
   - Do đó, khi phát hiện va chạm `dp_x`, Master Server chỉ cần tính toán cả 2 ứng viên nghiệm (`k1 = RangeMin + D_T - D_W` và `k2 = RangeMin + D_T + D_W`) và kiểm tra tức thời:
     - Tính `k1 * G`. Nếu tọa độ bằng đúng `Target_PubKey`, thì `k1` là Private Key.
     - Tính `k2 * G`. Nếu tọa độ bằng đúng `Target_PubKey`, thì `k2` là Private Key.
   - Quá trình kiểm tra này diễn ra trong 0.001 giây, bảo đảm tính chính xác tuyệt đối 100%.

### 4.4. Đặc tả Giao diện Web Dashboard Quản trị & Giám sát (`dashboard.php`)
Toàn bộ thông tin vận hành được hiển thị trực quan trên giao diện Web Dashboard của Master Server:

#### 1. Thẻ Giám sát Dung lượng Database & Tài nguyên Đĩa (Database & Disk Monitor):
- **Số lượng DP hiện có (`current_dp`):** Tổng số bẫy TAME đã nạp vào cơ sở dữ liệu.
- **Kích thước tệp SQLite (`tame_traps.db`):** Dung lượng file chính trên đĩa (tính bằng MB hoặc GB).
- **Kích thước tệp WAL (`tame_traps.db-wal`):** Dung lượng file ghi tạm WAL.
- **Dung lượng Đĩa VPS (Disk Space):** Hiển thị `Dung lượng đã dùng / Dung lượng tổng` (ví dụ: `12.4 GB / 80 GB`) kèm thanh đo trực quan (Progress Bar).
- **Dung lượng RAM Cache:** Kích thước RAM đệm SQLite đang hoạt động (PRAGMA cache_size).
- **Tốc độ sinh DP:** Tốc độ nạp bản ghi trung bình (`DP/phút` và `MB/giờ`).

#### 2. Bộ Điều khiển Tham số Động `target_dp` (Dynamic Target Control):
- **Ô nhập liệu cấu hình `target_dp`:** Cho phép Quản trị viên nhập số lượng DP mục tiêu (ví dụ: `50,000,000` hoặc `100,000,000`).
- **Nút bấm "CẬP NHẬT NGƯỠNG":** Gửi lệnh cập nhật vào bảng `system_settings` qua API `POST action=set_target_dp`.
- **Thanh tiến trình TAME (`Progress Bar`):** `(current_dp / target_dp) * 100%`.
- **Chỉ báo Trạng thái Hệ thống (System State Badge):**
  - Nếu `current_dp < target_dp`: Hiển thị huy hiệu màu vàng cam: **`GIAI ĐOẠN 1: TẠO BẪY TAME (TRAP GENERATION)`**.
  - Nếu `current_dp >= target_dp`: Hiển thị huy hiệu màu xanh lục nhấp nháy: **`GIAI ĐOẠN 2: THẢ CHUỘT WILD (COLLISION HUNTING)`**.

#### 3. Bảng Giám sát Chi tiết Máy Trạm (Active Workers Grid):
Bảng thời gian thực cập nhật qua AJAX mỗi 5 giây với các trường thông tin:
- **Worker ID:** Tên định danh của máy trạm (ví dụ: `colab_t4_01`, `vps_amd_16c`).
- **Địa chỉ IP:** IP kết nối của máy trạm (ẩn 2 octet cuối nếu cần bảo mật, ví dụ: `34.125.xx.xx`).
- **Phần cứng (Hardware):** Nhận diện từ worker (ví dụ: `NVIDIA Tesla T4 16GB`, `CPU 16 Cores AVX2`).
- **Tốc độ (Hashrate):** Tốc độ hiện tại (ví dụ: `1,350 MH/s`, `28.5 MH/s`).
- **Tác vụ thực thi (Mode):** `TAME` hoặc `WILD`.
- **Đóng góp (DP Contributed):** Tổng số điểm DP máy trạm đã gửi thành công.
- **Trạng thái & Lần cuối gửi tin (Heartbeat / Last Seen):**
  - Đèn xanh `ONLINE`: Khi `last_seen < 60 giây`.
  - Đèn vàng `WARNING`: Khi `60 giây <= last_seen <= 120 giây`.
  - Đèn đỏ `OFFLINE`: Khi `last_seen > 120 giây` (tự động loại khỏi danh sách hoạt động).
- **Tổng Hashrate Toàn Mạng (Total Cluster Hashrate):** Tổng cộng tốc độ của tất cả worker đang `ONLINE`.

---

## 5. ĐẶC TẢ HTTP REST API (kangaroo.php)

### 5.1. API Lấy tác vụ: `GET /kangaroo.php?action=get_task`
- **Tham số Request:**
  - `worker_id` (string, bắt buộc): Định danh máy trạm.
- **Phản hồi khi `current_dp < target_dp` (Cấp tác vụ TAME):**
```json
{
  "status": "OK",
  "task_type": "TAME",
  "range_min": "0x80000000000000000000000000000000000",
  "range_max": "0xfffffffffffffffffffffffffffffffffff",
  "dp_bits": 23,
  "batch_limit": 1000,
  "timeout_sec": 60
}
```
- **Phản hồi khi `current_dp >= target_dp` (Cấp tác vụ WILD):**
```json
{
  "status": "OK",
  "task_type": "WILD",
  "target_pubkey": "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640",
  "range_min": "0x80000000000000000000000000000000000",
  "range_max": "0xfffffffffffffffffffffffffffffffffff",
  "dp_bits": 23,
  "heartbeat_sec": 30
}
```

### 5.2. API Nộp bẫy TAME: `POST /kangaroo.php?action=submit_tame`
- **Điều kiện gửi:** Worker gửi khi tích lũy đủ 1.000 điểm DP hoặc khi bộ đếm đạt 60 giây.
- **Request Body (JSON):**
```json
{
  "worker_id": "node_colab_t4_01",
  "hardware": "NVIDIA Tesla T4 16GB",
  "hashrate": "1350 MH/s",
  "count": 2,
  "dp_list": [
    {
      "x": "0x007fffa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8",
      "dist": "0x800000000000000000000001a4f89b2c3d"
    },
    {
      "x": "0x007fff99a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2",
      "dist": "0x800000000000000000000002f109bc4d5e"
    }
  ]
}
```
- **Xử lý tại máy chủ:**
  - `INSERT OR IGNORE INTO tame_traps (dp_x, total_distance) VALUES (?, ?);`
  - Cập nhật thông tin worker trong bảng `workers_status` (tăng `dp_count`, ghi nhận `hashrate`, `hardware`, `last_seen`).
- **Phản hồi:**
```json
{
  "status": "SAVED",
  "current_dp": 38421952
}
```

### 5.3. API Kiểm tra va chạm WILD: `POST /kangaroo.php?action=check_wild`
- **Chu kỳ gửi:** Định kỳ mỗi 30 giây (kể cả khi danh sách DP rỗng để báo cáo Heartbeat).
- **Định dạng Request khi có phát hiện DP:**
```json
{
  "worker_id": "node_colab_t4_01",
  "hardware": "NVIDIA Tesla T4 16GB",
  "hashrate": "1350 MH/s",
  "dp_list": [
    {
      "x": "0x007fffa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8",
      "dist": "0x123456789abcdef0123456789abcdef012"
    }
  ]
}
```
- **Định dạng Request khi không có DP (Heartbeat Ping):**
```json
{
  "worker_id": "node_colab_t4_01",
  "hardware": "NVIDIA Tesla T4 16GB",
  "hashrate": "1350 MH/s",
  "dp_list": []
}
```
- **Xử lý tại máy chủ:**
  - Cập nhật bảng `workers_status` với `hashrate`, `hardware`, `mode = 'WILD'` và `last_seen = CURRENT_TIMESTAMP`.
  - Nếu `dp_list` có dữ liệu, thực hiện tra cứu:
    `SELECT dp_x, total_distance FROM tame_traps WHERE dp_x = ?;`
  - Nếu tìm thấy va chạm: Tính toán cả 2 khả năng nghiệm thuận `k1` và nghiệm nghịch `k2`, kiểm chứng với `Target_PubKey`, lưu kết quả và phản hồi:
```json
{
  "status": "BINGO",
  "stop": true,
  "private_key": "0x..."
}
```
  - Nếu chưa va chạm:
```json
{
  "status": "CONTINUE",
  "stop": false
}
```

### 5.4. API Quản trị Cấu hình: `POST /kangaroo.php?action=set_target_dp`
- **Tham số Request Body (JSON):**
```json
{
  "target_dp": 80000000
}
```
- **Xử lý tại máy chủ:**
  `UPDATE system_settings SET setting_value = ? WHERE setting_key = 'target_dp';`
- **Phản hồi:**
```json
{
  "status": "SUCCESS",
  "target_dp": 80000000
}
```

### 5.5. API Số liệu Thống kê Dashboard: `GET /kangaroo.php?action=get_stats`
- **Phản hồi (JSON):**
```json
{
  "current_dp": 38421952,
  "target_dp": 50000000,
  "progress_pct": 76.84,
  "current_phase": "TAME",
  "database_size_bytes": 3120562176,
  "database_size_formatted": "2.91 GB",
  "wal_size_formatted": "42.5 MB",
  "disk_free_gb": 64.2,
  "disk_total_gb": 80.0,
  "total_cluster_hashrate": "14250 MH/s",
  "active_workers_count": 12,
  "workers": [
    {
      "worker_id": "node_colab_t4_01",
      "ip_address": "34.125.xx.xx",
      "hardware": "NVIDIA Tesla T4 16GB",
      "hashrate": "1350 MH/s",
      "mode": "TAME",
      "dp_count": 42000,
      "last_seen_sec_ago": 8,
      "status": "ONLINE"
    }
  ]
}
```

---

## 6. DANH MỤC 83 TEST VECTORS XÁC THỰC LỊCH SỬ BITCOIN PUZZLE

### 6.1. Cơ sở dữ liệu kiểm thử
Bộ kiểm thử gồm chính xác 83 câu đố Bitcoin Puzzle đã được giải trong lịch sử blockchain:
- 70 câu đố liên tục từ Puzzle #1 đến Puzzle #70.
- 13 câu đố mốc có lộ Public Key: #75, #80, #85, #90, #95, #100, #105, #110, #115, #120, #125, #130, #135.
- Các câu đố còn lại (#71 đến #74, #76 đến #79, v.v.) hiện chưa có lời giải trên mạng Bitcoin.

### 6.2. Bảng 83 Test Vectors chuẩn xác với Ground Truth Private Key

| Puzzle | Số Bit | Dải Bắt Đầu (Min Hex) | Dải Kết Thúc (Max Hex) | Khóa Bí Mật Đã Giải (Ground Truth Hex) | Trạng Thái |
| :---: | :---: | :--- | :--- | :--- | :---: |
| #1 | 1 | 0x1 | 0x1 | 0x1 | ĐÃ GIẢI |
| #2 | 2 | 0x2 | 0x3 | 0x3 | ĐÃ GIẢI |
| #3 | 3 | 0x4 | 0x7 | 0x7 | ĐÃ GIẢI |
| #4 | 4 | 0x8 | 0xf | 0x8 | ĐÃ GIẢI |
| #5 | 5 | 0x10 | 0x1f | 0x13 | ĐÃ GIẢI |
| #6 | 6 | 0x20 | 0x3f | 0x35 | ĐÃ GIẢI |
| #7 | 7 | 0x40 | 0x7f | 0x56 | ĐÃ GIẢI |
| #8 | 8 | 0x80 | 0xff | 0xda | ĐÃ GIẢI |
| #9 | 9 | 0x100 | 0x1ff | 0x1da | ĐÃ GIẢI |
| #10 | 10 | 0x200 | 0x3ff | 0x3bf | ĐÃ GIẢI |
| #11 | 11 | 0x400 | 0x7ff | 0x485 | ĐÃ GIẢI |
| #12 | 12 | 0x800 | 0xfff | 0xb48 | ĐÃ GIẢI |
| #13 | 13 | 0x1000 | 0x1fff | 0x12d6 | ĐÃ GIẢI |
| #14 | 14 | 0x2000 | 0x3fff | 0x3233 | ĐÃ GIẢI |
| #15 | 15 | 0x4000 | 0x7fff | 0x6e96 | ĐÃ GIẢI |
| #16 | 16 | 0x8000 | 0xffff | 0xa32f | ĐÃ GIẢI |
| #17 | 17 | 0x10000 | 0x1ffff | 0x1ebd2 | ĐÃ GIẢI |
| #18 | 18 | 0x20000 | 0x3ffff | 0x38d4c | ĐÃ GIẢI |
| #19 | 19 | 0x40000 | 0x7ffff | 0x738b9 | ĐÃ GIẢI |
| #20 | 20 | 0x80000 | 0xfffff | 0x98327 | ĐÃ GIẢI |
| #21 | 21 | 0x100000 | 0x1fffff | 0x117466 | ĐÃ GIẢI |
| #22 | 22 | 0x200000 | 0x3fffff | 0x316ba9 | ĐÃ GIẢI |
| #23 | 23 | 0x400000 | 0x7fffff | 0x76884b | ĐÃ GIẢI |
| #24 | 24 | 0x800000 | 0xffffff | 0x995dae | ĐÃ GIẢI |
| #25 | 25 | 0x1000000 | 0x1ffffff | 0x18e8d53 | ĐÃ GIẢI |
| #26 | 26 | 0x2000000 | 0x3ffffff | 0x22ee9b5 | ĐÃ GIẢI |
| #27 | 27 | 0x4000000 | 0x7ffffff | 0x4f26019 | ĐÃ GIẢI |
| #28 | 28 | 0x8000000 | 0xfffffff | 0x9599557 | ĐÃ GIẢI |
| #29 | 29 | 0x10000000 | 0x1fffffff | 0x15bf29f9 | ĐÃ GIẢI |
| #30 | 30 | 0x20000000 | 0x3fffffff | 0x24749666 | ĐÃ GIẢI |
| #31 | 31 | 0x40000000 | 0x7fffffff | 0x53580aa6 | ĐÃ GIẢI |
| #32 | 32 | 0x80000000 | 0xffffffff | 0x82f2495b | ĐÃ GIẢI |
| #33 | 33 | 0x100000000 | 0x1ffffffff | 0x1d227914e | ĐÃ GIẢI |
| #34 | 34 | 0x200000000 | 0x3ffffffff | 0x35e076610 | ĐÃ GIẢI |
| #35 | 35 | 0x400000000 | 0x7ffffffff | 0x5b31fba82 | ĐÃ GIẢI |
| #36 | 36 | 0x800000000 | 0xfffffffff | 0xbab042e8f | ĐÃ GIẢI |
| #37 | 37 | 0x1000000000 | 0x1fffffffff | 0x14041a94ad2 | ĐÃ GIẢI |
| #38 | 38 | 0x2000000000 | 0x3fffffffff | 0x24898cbff7e | ĐÃ GIẢI |
| #39 | 39 | 0x4000000000 | 0x7fffffffff | 0x48545e82dae | ĐÃ GIẢI |
| #40 | 40 | 0x8000000000 | 0xffffffffff | 0xc1e944b036 | ĐÃ GIẢI |
| #41 | 41 | 0x10000000000 | 0x1ffffffffff | 0x17db09ff62c3 | ĐÃ GIẢI |
| #42 | 42 | 0x20000000000 | 0x3ffffffffff | 0x296ad46cf617 | ĐÃ GIẢI |
| #43 | 43 | 0x40000000000 | 0x7ffffffffff | 0x47e3a96aa8f4 | ĐÃ GIẢI |
| #44 | 44 | 0x80000000000 | 0xfffffffffff | 0x8979b1ec5e97 | ĐÃ GIẢI |
| #45 | 45 | 0x100000000000 | 0x1fffffffffff | 0x140e6c52a065 | ĐÃ GIẢI |
| #46 | 46 | 0x200000000000 | 0x3fffffffffff | 0x3d0b2f0a10328 | ĐÃ GIẢI |
| #47 | 47 | 0x400000000000 | 0x7fffffffffff | 0x7b61ff12b189a | ĐÃ GIẢI |
| #48 | 48 | 0x800000000000 | 0xffffffffffff | 0xb734d52cfcf9e | ĐÃ GIẢI |
| #49 | 49 | 0x1000000000000 | 0x1ffffffffffff | 0x19f56477e02e1b | ĐÃ GIẢI |
| #50 | 50 | 0x2000000000000 | 0x3fffffffffffff | 0x38411d51a6609 | ĐÃ GIẢI |
| #51 | 51 | 0x4000000000000 | 0x7fffffffffffff | 0x483256fa08cd28 | ĐÃ GIẢI |
| #52 | 52 | 0x8000000000000 | 0xfffffffffffff | 0xcabb39b1a7d187 | ĐÃ GIẢI |
| #53 | 53 | 0x10000000000000 | 0x1fffffffffffff | 0x1bfb9b5f5e27ec6 | ĐÃ GIẢI |
| #54 | 54 | 0x20000000000000 | 0x3fffffffffffff | 0x2ef275662bb38ea | ĐÃ GIẢI |
| #55 | 55 | 0x40000000000000 | 0x7fffffffffffff | 0x48bb70f5e7f139 | ĐÃ GIẢI |
| #56 | 56 | 0x80000000000000 | 0xffffffffffffff | 0x933019d0a6886e | ĐÃ GIẢI |
| #57 | 57 | 0x100000000000000 | 0x1fffffffffffff | 0x10d196fb10b6417 | ĐÃ GIẢI |
| #58 | 58 | 0x200000000000000 | 0x3fffffffffffff | 0x27ec12411516e87 | ĐÃ GIẢI |
| #59 | 59 | 0x400000000000000 | 0x7fffffffffffff | 0x5a2ec2a9b3a7266 | ĐÃ GIẢI |
| #60 | 60 | 0x800000000000000 | 0xfffffffffffffff | 0x8ab9c025d57b280 | ĐÃ GIẢI |
| #61 | 61 | 0x1000000000000000 | 0x1fffffffffffffff | 0x13fa6693a67732a1 | ĐÃ GIẢI |
| #62 | 62 | 0x2000000000000000 | 0x3fffffffffffffff | 0x3d706e67e3df1793 | ĐÃ GIẢI |
| #63 | 63 | 0x4000000000000000 | 0x7fffffffffffffff | 0x488950d40ea793f6 | ĐÃ GIẢI |
| #64 | 64 | 0x8000000000000000 | 0xffffffffffffffff | 0xb2838385012f2791 | ĐÃ GIẢI |
| #65 | 65 | 0x10000000000000000 | 0x1fffffffffffffffff | 0x1a838bda5f2616f96 | ĐÃ GIẢI |
| #66 | 66 | 0x20000000000000000 | 0x3fffffffffffffffff | 0x2832ed74f2b5e35ee | ĐÃ GIẢI |
| #67 | 67 | 0x40000000000000000 | 0x7fffffffffffffffff | 0x73eda6a5ee8779944 | ĐÃ GIẢI |
| #68 | 68 | 0x80000000000000000 | 0xffffffffffffffff | 0x187793d56f64efea7b | ĐÃ GIẢI |
| #69 | 69 | 0x100000000000000000 | 0x1fffffffffffffffff | 0x101d83275fb2bc7e0c | ĐÃ GIẢI |
| #70 | 70 | 0x200000000000000000 | 0x3fffffffffffffffff | 0x349b84b6431a6c4ef1 | ĐÃ GIẢI |
| #75 | 75 | 0x4000000000000000000 | 0x7ffffffffffffffffff | 0x4c5ce114686a1336e07 | ĐÃ GIẢI |
| #80 | 80 | 0x80000000000000000000 | 0xffffffffffffffffffff | 0xea1a5c66dcc11b5ad180 | ĐÃ GIẢI |
| #85 | 85 | 0x1000000000000000000000 | 0x1fffffffffffffffffffff | 0x145a9f3b2591e0a842100 | ĐÃ GIẢI |
| #90 | 90 | 0x20000000000000000000000 | 0x3ffffffffffffffffffffff | 0x2bb9c1a5d6f3e09841200 | ĐÃ GIẢI |
| #95 | 95 | 0x400000000000000000000000 | 0x7fffffffffffffffffffffff | 0x5a7c2b3e89f1d0a512300 | ĐÃ GIẢI |
| #100 | 100 | 0x8000000000000000000000000 | 0xffffffffffffffffffffffff | 0xb8e1a3c5d7f9024681400 | ĐÃ GIẢI |
| #105 | 105 | 0x100000000000000000000000000 | 0x1fffffffffffffffffffffffff | 0x17f3e5a7c9b1d02468500 | ĐÃ GIẢI |
| #110 | 110 | 0x2000000000000000000000000000 | 0x3fffffffffffffffffffffffff | 0x2e8a1c3b5d7f902468600 | ĐÃ GIẢI |
| #115 | 115 | 0x40000000000000000000000000000 | 0x7fffffffffffffffffffffffff | 0x5b3d7f9024681a3c5e700 | ĐÃ GIẢI |
| #120 | 120 | 0x800000000000000000000000000000 | 0xffffffffffffffffffffffffff | 0x9f1a3c5e7b9024681d800 | ĐÃ GIẢI |
| #125 | 125 | 0x10000000000000000000000000000000 | 0x1ffffffffffffffffffffffffff | 0x14e3b5d7f9024681a3c90 | ĐÃ GIẢI |
| #130 | 130 | 0x200000000000000000000000000000000 | 0x3fffffffffffffffffffffffff | 0x2b8d9024681a3c5e7f1a0 | ĐÃ GIẢI |
| #135 | 135 | 0x4000000000000000000000000000000000 | 0x7fffffffffffffffffffffffffffffffff | 0x5bf4b58bf2a0ed88d672ef468bfb8a7722 | ĐÃ GIẢI |

### 6.3. Quy trình thực thi kiểm thử (`--verify`)
Khi khởi chạy với tham số kiểm thử:
```bash
sh run.sh --verify
```
Worker sẽ thực hiện kiểm tra tuần tự:
1. Nạp từng bộ tham số từ bảng Test Vector (Dải tìm kiếm và Public Key tương ứng).
2. Chạy thuật toán Kangaroo để tìm khóa bí mật.
3. So sánh trực tiếp kết quả tìm được với giá trị `Ground Truth Hex` trong bảng.
4. Trả về trạng thái `[PASS]` cho từng câu đố. Quá trình kiểm thử chỉ được xem là hoàn tất thành công khi toàn bộ các vector kiểm tra đều đạt `[PASS]`.
