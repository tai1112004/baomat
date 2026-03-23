// ============================================================
// src/mysql_connector.js
// Kết nối MySQL dùng thư viện mysql2 (hỗ trợ MySQL 5.7, 8.0+)
// API tương thích với phiên bản tự viết trước đó
// ============================================================

const mysql = require('mysql2/promise');

class MySQLConnection {
    constructor(config) {
        this._config = {
            host: config.host || 'localhost',
            port: config.port || 3306,
            user: config.user || 'root',
            password: config.password || '',
            database: config.database || '',
            charset: config.charset || 'utf8mb4',
            // Hỗ trợ cả mysql_native_password và caching_sha2_password (MySQL 8+)
            authPlugins: undefined,
        };
        this._conn = null;
        this.connected = false;
    }

    // ============================================================
    // Kết nối tới MySQL server
    // ============================================================
    async connect() {
        this._conn = await mysql.createConnection(this._config);
        this.connected = true;
        return this;
    }

    // ============================================================
    // Escape giá trị để chống SQL injection
    // ============================================================
    escape(val) {
        if (val === null || val === undefined) return 'NULL';
        // Dùng mysql2's escape
        return mysql.escape(val);
    }

    // ============================================================
    // Thực thi SQL, trả về kết quả dạng thô (tương thích cũ)
    // - INSERT/UPDATE/DELETE → { type: 'ok', affectedRows, insertId }
    // - SELECT              → { type: 'result', columns, rows }
    // ============================================================
    async query(sql) {
        const [rows, fields] = await this._conn.execute(sql);

        // Nếu là ResultSet (SELECT)
        if (Array.isArray(rows)) {
            const columns = fields
                ? fields.map(f => ({ name: f.name, table: f.table }))
                : [];
            return { type: 'result', columns, rows };
        }

        // Nếu là OkPacket (INSERT/UPDATE/DELETE/CREATE...)
        return {
            type: 'ok',
            affectedRows: rows.affectedRows,
            insertId: rows.insertId,
        };
    }

    // ============================================================
    // Query trả về mảng object thuần { columnName: value, ... }
    // ============================================================
    async queryRows(sql) {
        const [rows] = await this._conn.execute(sql);
        return Array.isArray(rows) ? rows : [];
    }

    // ============================================================
    // Thực thi nhiều câu lệnh (split theo ';')
    // ============================================================
    async execute(sql) {
        const statements = sql
            .split(';')
            .map(s => s.trim())
            .filter(s => s.length > 0);

        const results = [];
        for (const stmt of statements) {
            const r = await this.query(stmt);
            results.push(r);
        }
        return results;
    }

    // ============================================================
    // Đóng kết nối
    // ============================================================
    async close() {
        if (this._conn) {
            await this._conn.end();
            this._conn = null;
            this.connected = false;
        }
    }
}

module.exports = { MySQLConnection };
