# DATA MASKING SYSTEM
## Chương trình Quản lý Dữ liệu An toàn dưới dạng Mặt nạ Dữ liệu
**Ngôn ngữ:** JavaScript (Node.js)  
**Database:** MySQL  
**Không dùng thư viện ngoài** – toàn bộ thuật toán tự implement

---

## Cấu trúc Project
```
data-masking/
├── config/
│   └── database.js          # Cấu hình kết nối MySQL
├── sql/
│   └── setup.sql            # Script tạo database và dữ liệu mẫu
├── src/
│   ├── masking.js           # Các thuật toán masking TỰ VIẾT
│   ├── mysql_connector.js   # Kết nối MySQL TỰ VIẾT (TCP socket thuần)
│   └── main.js              # Chương trình chính
├── package.json
└── README.md
```

---

## Các Kỹ thuật Data Masking Đã Implement

### 1. Static Masking (Che giấu tĩnh)
- `maskPhone("0912345678")` → `"091*****78"`
- `maskEmail("user@gmail.com")` → `"us*****@gmail.com"`
- `maskName("Nguyễn Văn An")` → `"N****** V** A*"`
- `maskBirthDate("1990-05-15")` → `"1990-**-**"`
- `maskAddress("123 Lê Lợi, Q1, TP.HCM")` → `"***, ***, TP.HCM"`

### 2. XOR Cipher (Tự viết)
- Mã hóa từng byte với key stream
- Key stretching dùng LCG để tránh pattern lặp
- Output dạng HEX string
- Có thể giải mã với key bí mật

### 3. AES-128 (Tự implement hoàn toàn)
- Đầy đủ 10 rounds: SubBytes, ShiftRows, MixColumns, AddRoundKey
- Key Expansion chuẩn FIPS-197
- GF(2^8) multiplication tự viết
- ECB mode + PKCS#7 padding
- Có thể giải mã với key bí mật

### 4. Tokenization
- Thay thế CCCD bằng token ngẫu nhiên
- Token map lưu bí mật server-side (MySQL)
- Deterministic: cùng giá trị → cùng token
- LCG random generator tự viết

### 5. Format-Preserving Masking
- SĐT: giữ đầu số mạng, sinh 8 số ngẫu nhiên → vẫn là SĐT hợp lệ
- Lương: giữ số chữ số, thay giá trị → cùng bậc độ lớn
- CCCD: giữ mã tỉnh 3 chữ số đầu

---

## Hướng dẫn Cài đặt và Chạy

### Yêu cầu
- Node.js >= 14.x
- MySQL >= 5.7 hoặc MySQL 8.x

### Bước 1: Tạo Database
```bash
mysql -u root -p < sql/setup.sql
```

### Bước 2: Cấu hình kết nối
Chỉnh file `config/database.js`:
```javascript
const DB_CONFIG = {
    host:     'localhost',
    port:     3306,
    user:     'root',         // ← Thay username
    password: '123456',       // ← Thay password
    database: 'data_masking_db'
};
```

### Bước 3: Chạy chương trình
```bash
node src/main.js
```

### Output mẫu
```
*********************************************************************
  CHƯƠNG TRÌNH QUẢN LÝ DỮ LIỆU AN TOÀN - DATA MASKING
  Ngôn ngữ: JavaScript (Node.js)  |  Database: MySQL
*********************************************************************

BƯỚC 1: DEMO CÁC KỸ THUẬT DATA MASKING
  SĐT gốc   : 0912345678  →  Sau mask: 091*****78
  Email gốc : nguyenvanan@gmail.com  →  Sau mask: ng*******@gmail.com
  XOR Cipher: [ciphertext hex] → [plaintext khôi phục]
  AES-128   : [ciphertext hex] → [plaintext khôi phục]
  ...

BƯỚC 6: KIỂM TRA TÍNH ĐÚNG ĐẮN
  ✓ PASS: XOR encrypt/decrypt round-trip
  ✓ PASS: AES-128 round-trip: "15000000.00"
  ...
  🎉 Tất cả test đều PASS!
```

---

## Lưu ý Kỹ thuật

### Không dùng thư viện ngoài
- **Không** dùng `crypto` module (built-in Node.js)
- **Không** dùng `mysql2`, `mysql` npm package
- Kết nối MySQL: tự implement MySQL Client/Server Protocol v10 qua `net` module
- SHA1: tự viết cho MySQL authentication
- AES-128: tự viết đầy đủ theo FIPS-197
- Encoding: tự viết UTF-8 encode/decode

### Bảo mật
- Key AES và XOR lưu ở environment variable trong thực tế
- Token map chỉ server mới được đọc
- Kênh truyền công khai chỉ thấy dữ liệu đã mask
# baomat
