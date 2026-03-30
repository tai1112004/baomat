-- ============================================================
-- DATA MASKING SYSTEM - Database Setup
-- ============================================================

CREATE DATABASE IF NOT EXISTS data_masking_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE data_masking_db;

-- Bảng dữ liệu GỐC (nhạy cảm - không được truyền công khai)
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id          INT PRIMARY KEY AUTO_INCREMENT,
    full_name   TEXT NOT NULL,
    email       TEXT NOT NULL,
    phone       TEXT NOT NULL,
    cccd        TEXT NOT NULL,
    salary      TEXT NOT NULL,
    birth_date  TEXT NOT NULL,
    address     TEXT NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Bảng dữ liệu ĐÃ MASK (an toàn để truyền qua kênh công khai)
DROP TABLE IF EXISTS masked_users;
CREATE TABLE masked_users (
    id                  INT PRIMARY KEY,
    full_name_masked    VARCHAR(100),
    email_static        VARCHAR(100),   -- Static masking
    email_xor           VARCHAR(200),   -- XOR cipher (hex encoded)
    phone_static        VARCHAR(20),    -- Static masking
    phone_fpmasked      VARCHAR(20),    -- Format-preserving masking
    cccd_token          VARCHAR(64),    -- Tokenization
    salary_xor          VARCHAR(200),   -- AES cipher
    birth_date_masked   VARCHAR(20),    -- Partial masking
    address_masked      VARCHAR(200),   -- Static masking
    mask_method         VARCHAR(50),
    masked_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Bảng lưu TOKEN MAP (server-side, bí mật)
DROP TABLE IF EXISTS token_map;
CREATE TABLE token_map (
    token       VARCHAR(64) PRIMARY KEY,
    original    VARCHAR(500) NOT NULL,
    field_type  VARCHAR(50),
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Bảng Chat Nội Bộ (Chỉ lưu Ciphertext E2EE)
DROP TABLE IF EXISTS secure_chat;
CREATE TABLE secure_chat (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender VARCHAR(50),
    receiver VARCHAR(50),
    encrypted_msg TEXT,
    demo_plaintext TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Chèn dữ liệu mẫu
INSERT INTO users (full_name, email, phone, cccd, salary, birth_date, address) VALUES
('Nguyễn Văn An',    'nguyenvanan@gmail.com',    '0912345678', '012345678901', 15000000.00, '1990-05-15', '123 Nguyễn Huệ, Q1, TP.HCM'),
('Trần Thị Bình',    'tranthibinh@yahoo.com',    '0987654321', '098765432109', 22500000.50, '1985-08-22', '45 Lê Lợi, Q3, TP.HCM'),
('Lê Hoàng Cường',   'lehoangcuong@outlook.com', '0901122334', '001234567890', 8750000.00,  '1995-12-01', '78 Trần Phú, Hà Đông, Hà Nội'),
('Phạm Minh Dũng',   'phamminhd@company.vn',     '0978123456', '036789012345', 35000000.00, '1988-03-30', '12 Hoàng Diệu, Hải Châu, Đà Nẵng'),
('Hoàng Thị Lan',    'hoanglan99@gmail.com',     '0965432187', '079123456789', 18900000.75, '1999-07-14', '56 Bạch Đằng, Hải Phòng');

SELECT 'Database setup completed!' AS status;
SELECT COUNT(*) AS total_users FROM users;
