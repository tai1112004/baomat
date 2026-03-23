// ============================================================
// config/database.js - Cấu hình kết nối MySQL
// ============================================================

const DB_CONFIG = {
    host:     'localhost',
    port:     3306,
    user:     'root',         // Thay bằng username MySQL của bạn
    password: '01112004',       // Thay bằng password MySQL của bạn
    database: 'data_masking_db',
    charset:  'utf8mb4'
};

module.exports = DB_CONFIG;
