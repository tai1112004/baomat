// ============================================================
// src/server.js - Web Server TỰ VIẾT (dùng http built-in)
// ============================================================

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { MySQLConnection } = require('./mysql_connector');
const DB_CONFIG = require('../config/database');
const masking = require('./masking');

const PORT = 3000;
const XOR_KEY = 'DataMask@SecretKey#2024!VietNam';
const AES_KEY = 'AESKey_DataMask16';
const DB_KEY = 'AES_DB_SECRET_KEY!'; // Khoá cấp cơ sở dữ liệu (tầng 1)

// ============================================================
// HELPER: Giải mã 1 user (vì DB lưu AES-128 hex string)
// ============================================================
function decryptUser(u) {
    if (!u) return u;
    try {
        // Chỉ giải mã nếu nó trông giống chuỗi HEX
        const dec = (val) => (val && val.match(/^[0-9a-fA-F]{32,}$/)) ? masking.aesDecrypt(val, DB_KEY) : val;
        return {
            id: u.id,
            full_name: dec(u.full_name),
            email: dec(u.email),
            phone: dec(u.phone),
            cccd: dec(u.cccd),
            salary: parseFloat(dec(String(u.salary))) || 0,
            birth_date: dec(u.birth_date),
            address: dec(u.address),
            created_at: u.created_at
        };
    } catch (e) {
        console.error("Lỗi decrypt DB user:", e);
        return u;
    }
}

// ============================================================
// HELPER: Đọc body từ request
// ============================================================
function readBody(req) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', () => resolve(body));
    });
}

// ============================================================
// HELPER: Gửi JSON response
// ============================================================
function sendJSON(res, statusCode, data) {
    const json = JSON.stringify(data);
    res.writeHead(statusCode, {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
        'Content-Length': Buffer.byteLength(json)
    });
    res.end(json);
}

// ============================================================
// HELPER: Gửi HTML file
// ============================================================
function sendHTML(res, filePath) {
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.writeHead(404);
            res.end('Not Found');
            return;
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(data);
    });
}

// ============================================================
// DATABASE CONNECTION POOL (đơn giản - tạo mới mỗi request)
// ============================================================
async function withDB(fn) {
    const conn = new MySQLConnection(DB_CONFIG);
    try {
        await conn.connect();
        const result = await fn(conn);
        return result;
    } finally {
        await conn.close();
    }
}

// ============================================================
// HELPER: Ghi Audit Log
// ============================================================
async function writeLog(conn, username, action, target_id, details) {
    try {
        await conn.query(`INSERT INTO access_log (username, action, target_id, details) VALUES (${conn.escape(username)}, ${conn.escape(action)}, ${conn.escape(target_id)}, ${conn.escape(details)})`);
    } catch (e) { console.error("Audit log error:", e); }
}

const sessions = new Map();
const SESSION_DURATION_MS = 1000 * 60 * 30; // 30 phút

function createSession(username, role) {
    const token = crypto.randomBytes(24).toString('hex');
    sessions.set(token, { username, role, createdAt: Date.now() });
    return token;
}

function getSession(req) {
    const authHeader = req.headers['authorization'];
    const token = req.headers['x-auth-token'] || (authHeader && authHeader.replace(/^Bearer\s+/i, ''));
    if (!token) return null;
    const session = sessions.get(token);
    if (!session) return null;
    if (Date.now() - session.createdAt > SESSION_DURATION_MS) {
        sessions.delete(token);
        return null;
    }
    return session;
}

function requireSession(req, res) {
    const session = getSession(req);
    if (!session) {
        sendJSON(res, 401, { ok: false, error: 'Unauthorized: Thiếu phiên đăng nhập hoặc phiên hết hạn' });
        return null;
    }
    return session;
}

function requireAdmin(req, res) {
    const session = requireSession(req, res);
    if (!session) return null;
    if (session.role !== 'Admin') {
        sendJSON(res, 403, { ok: false, error: 'Forbidden: chỉ Admin mới được truy cập' });
        return null;
    }
    return session;
}

function requireRole(req, res, allowedRoles) {
    const session = requireSession(req, res);
    if (!session) return null;
    if (!allowedRoles.includes(session.role)) {
        sendJSON(res, 403, { ok: false, error: `Forbidden: chỉ ${allowedRoles.join(' hoặc ')} mới được truy cập` });
        return null;
    }
    return session;
}

// ============================================================
// SYSTEM: Init DB Accounts
// ============================================================
async function initAccountsDB() {
    await withDB(async (conn) => {
        await conn.query(`
            CREATE TABLE IF NOT EXISTS accounts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE,
                password_hash VARCHAR(64),
                role VARCHAR(50)
            )
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS secure_chat (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sender VARCHAR(50),
                receiver VARCHAR(50),
                encrypted_msg TEXT,
                demo_plaintext TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS access_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50),
                action VARCHAR(50),
                target_id VARCHAR(50),
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT NOT NULL,
                cccd TEXT NOT NULL,
                salary TEXT NOT NULL,
                birth_date TEXT NOT NULL,
                address TEXT NOT NULL,
                owner_username VARCHAR(50) NULL DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS masked_users (
                id INT PRIMARY KEY,
                full_name_masked VARCHAR(100),
                email_static VARCHAR(100),
                email_xor VARCHAR(200),
                phone_static VARCHAR(20),
                phone_fpmasked VARCHAR(20),
                cccd_token VARCHAR(64),
                salary_xor VARCHAR(200),
                birth_date_masked VARCHAR(20),
                address_masked VARCHAR(200),
                mask_method VARCHAR(50),
                masked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS token_map (
                token VARCHAR(64) PRIMARY KEY,
                original VARCHAR(500) NOT NULL,
                field_type VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        try {
            await conn.query(`ALTER TABLE users
                MODIFY full_name TEXT NOT NULL,
                MODIFY email TEXT NOT NULL,
                MODIFY phone TEXT NOT NULL,
                MODIFY cccd TEXT NOT NULL,
                MODIFY salary TEXT NOT NULL,
                MODIFY birth_date TEXT NOT NULL,
                MODIFY address TEXT NOT NULL`);
            const cols = await conn.queryRows("SHOW COLUMNS FROM users LIKE 'owner_username'");
            if (cols.length === 0) {
                await conn.query(`ALTER TABLE users ADD COLUMN owner_username VARCHAR(50) NULL DEFAULT NULL`);
            }
        } catch (e) { }

        const h = (pw) => crypto.createHash('sha256').update(pw).digest('hex');
        const users = [
            ['admin', h('admin'), 'Admin'],
            ['nhanvien', h('nhanvien'), 'Nhân viên'],
            ['khachhang', h('khachhang'), 'Khách hàng']
        ];
        for (const [u, p, r] of users) {
            await conn.query(`INSERT IGNORE INTO accounts (username, password_hash, role) VALUES (${conn.escape(u)}, ${conn.escape(p)}, ${conn.escape(r)})`);
        }
    });
}

// GET /api/logs - Đọc audit log
async function handleGetLogs(req, res) {
    const session = requireAdmin(req, res);
    if (!session) return;
    try {
        const logs = await withDB(conn => conn.queryRows('SELECT * FROM access_log ORDER BY timestamp DESC LIMIT 100'));
        sendJSON(res, 200, { ok: true, data: logs });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// ============================================================
// API HANDLERS
// ============================================================

// GET /api/users - Dữ liệu gốc
async function handleGetUsers(req, res) {
    try {
        const session = requireSession(req, res);
        if (!session) return;

        const { username, role } = session;
        const normalizedRole = (role || '').toString().trim().toLowerCase();
        if (normalizedRole === 'khách hàng') {
            const usersRaw = await withDB(conn => conn.queryRows(`SELECT * FROM users WHERE owner_username = ${conn.escape(username)} ORDER BY id`));
            const custData = usersRaw.map(decryptUser);
            await withDB(conn => writeLog(conn, username, 'VIEW_OWN_DATA', username, `Khách hàng ${username} xem dữ liệu của chính mình`));
            sendJSON(res, 200, { ok: true, data: custData });
            return;
        }

        const usersRaw = await withDB(async (conn) => {
            await writeLog(conn, username, 'VIEW_RAW_DATA', 'ALL', `User ${username} with role ${role} accessed user data`);
            return conn.queryRows('SELECT * FROM users ORDER BY id');
        });
        const users = usersRaw.map(decryptUser);

        if (role === 'Nhân viên') {
            const empData = users.map(u => ({
                id: u.id,
                full_name: masking.maskName(u.full_name),
                email: masking.maskEmail(u.email),
                phone: masking.maskPhone(u.phone),
                cccd: '(ẩn)',
                salary: '*** VNĐ',
                birth_date: masking.maskBirthDate(u.birth_date),
                address: masking.maskAddress(u.address),
                created_at: u.created_at
            }));
            sendJSON(res, 200, { ok: true, data: empData });
            return;
        }

        if (role !== 'Admin') {
            return sendJSON(res, 403, { ok: false, error: 'Forbidden: role không được phép truy cập' });
        }

        sendJSON(res, 200, { ok: true, data: users });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// GET /api/masked - Dữ liệu đã mask
async function handleGetMasked(req, res) {
    const session = requireSession(req, res);
    if (!session) return;
    if (session.role === 'Khách hàng') {
        return sendJSON(res, 403, { ok: false, error: 'Forbidden: Khách hàng không được truy cập dữ liệu đã mask của toàn bộ hệ thống' });
    }
    try {
        const masked = await withDB(conn =>
            conn.queryRows('SELECT * FROM masked_users ORDER BY id')
        );
        sendJSON(res, 200, { ok: true, data: masked });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// POST /api/users/add - Thêm user mới
async function handleAddUser(req, res) {
    const body = await readBody(req);
    try {
        const { full_name, email, phone, cccd, salary, birth_date, address } = JSON.parse(body);
        if (!full_name || !email || !phone || !cccd || !salary || !birth_date || !address) {
            return sendJSON(res, 400, { ok: false, error: 'Vui lòng điền đầy đủ tất cả các trường!' });
        }

        const session = requireSession(req, res);
        if (!session) return;
        const normalizedRole = (session.role || '').toString().trim().toLowerCase();
        if (!['admin', 'nhân viên', 'khách hàng'].includes(normalizedRole)) {
            return sendJSON(res, 403, { ok: false, error: 'Forbidden: role không được phép thêm dữ liệu' });
        }

        // MÃ HÓA AES-128 TẦNG DATABASE
        const eName = masking.aesEncrypt(full_name, DB_KEY);
        const eEmail = masking.aesEncrypt(email, DB_KEY);
        const ePhone = masking.aesEncrypt(phone, DB_KEY);
        const eCccd = masking.aesEncrypt(cccd, DB_KEY);
        const eSalary = masking.aesEncrypt(String(salary), DB_KEY);
        const eBirth = masking.aesEncrypt(String(birth_date), DB_KEY);
        const eAddress = masking.aesEncrypt(address, DB_KEY);
        const owner = session.username;

        await withDB(async (conn) => {
            const sql = `INSERT INTO users (full_name, email, phone, cccd, salary, birth_date, address, owner_username)
                VALUES (${conn.escape(eName)}, ${conn.escape(eEmail)}, ${conn.escape(ePhone)},
                        ${conn.escape(eCccd)}, ${conn.escape(eSalary)}, ${conn.escape(eBirth)}, ${conn.escape(eAddress)}, ${conn.escape(owner)})`;
            const dbRes = await conn.query(sql);
            await writeLog(conn, session.username, 'ADD_USER', dbRes.insertId, `Added new user: ${full_name} (owner=${owner})`);
        });
        sendJSON(res, 200, { ok: true, message: `Đã thêm người dùng "${full_name}" thành công!` });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// POST /api/users/delete - Xóa user
async function handleDeleteUser(req, res) {
    const session = requireAdmin(req, res);
    if (!session) return;

    const body = await readBody(req);
    try {
        const { id } = JSON.parse(body);
        if (!id) return sendJSON(res, 400, { ok: false, error: 'Thiếu ID!' });
        await withDB(async (conn) => {
            await conn.query(`DELETE FROM users WHERE id = ${conn.escape(id)}`);
            await writeLog(conn, session.username, 'DELETE_USER', id, `Deleted user ID=${id}`);
        });
        sendJSON(res, 200, { ok: true, message: `Đã xóa user ID=${id}` });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// GET /api/stats - Thống kê tổng quan
async function handleStats(req, res) {
    const session = requireAdmin(req, res);
    if (!session) return;
    try {
        const stats = await withDB(async (conn) => {
            const [users] = await conn.queryRows('SELECT COUNT(*) as cnt FROM users');
            const [masked] = await conn.queryRows('SELECT COUNT(*) as cnt FROM masked_users');
            const [tokens] = await conn.queryRows('SELECT COUNT(*) as cnt FROM token_map');

            // Tính thống kê lương trên dữ liệu gốc (phải giải mã trước)
            const allUsersRaw = await conn.queryRows('SELECT salary FROM users');
            const allSals = allUsersRaw.map(u =>
                parseFloat((u.salary && u.salary.match(/^[0-9a-fA-F]{32,}$/)) ? masking.aesDecrypt(u.salary, DB_KEY) : u.salary) || 0
            );

            let mn = 0, mx = 0, avg = 0;
            if (allSals.length > 0) {
                mn = Math.min(...allSals);
                mx = Math.max(...allSals);
                avg = allSals.reduce((a, b) => a + b, 0) / allSals.length;
            }
            const salaryRows = [{ mx, mn, avg }];

            // Lấy 5 record mask gần nhất
            const recent = await conn.queryRows(
                'SELECT id, full_name_masked, mask_method, masked_at FROM masked_users ORDER BY masked_at DESC LIMIT 5'
            );

            // Phân loại kỹ thuật (mỗi record dùng 9 fields = 4 Static + 1 XOR + 1 AES + 1 Token + 2 FP)
            const maskedCount = parseInt(masked.cnt) || 0;
            const techniques = {
                'Static Masking': maskedCount * 4,   // name, email, phone, address, birth
                'XOR Cipher': maskedCount * 1,   // email_xor
                'AES-128': maskedCount * 1,   // salary
                'Tokenization': maskedCount * 1,   // cccd
                'Format-Preserving': maskedCount * 2,   // phone_fp
            };

            return {
                users: parseInt(users.cnt) || 0,
                masked: maskedCount,
                tokens: parseInt(tokens.cnt) || 0,
                salary: salaryRows[0] || { mn: 0, mx: 0, avg: 0 },
                recent,
                techniques,
            };
        });
        sendJSON(res, 200, { ok: true, data: stats });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// POST /api/mask - Chạy masking toàn bộ users
async function handleRunMask(req, res) {
    const session = requireRole(req, res, ['Nhân viên', 'Admin']);
    if (!session) return;
    try {
        const result = await withDB(async (conn) => {
            const usersRaw = await conn.queryRows('SELECT * FROM users ORDER BY id');
            if (usersRaw.length === 0) return { count: 0 };

            const users = usersRaw.map(decryptUser);

            await conn.query('DELETE FROM masked_users');
            await conn.query('DELETE FROM token_map');

            const maskedList = [];
            const tokenMapEntries = {};
            for (const user of users) {
                const cccdToken = masking.tokenize(user.cccd, 'cccd');
                tokenMapEntries[cccdToken] = { original: user.cccd, fieldType: 'cccd' };

                const masked = {
                    id: user.id,
                    full_name_masked: masking.maskName(user.full_name),
                    email_static: masking.maskEmail(user.email),
                    email_xor: masking.xorEncrypt(user.email, XOR_KEY),
                    phone_static: masking.maskPhone(user.phone),
                    phone_fpmasked: masking.fpMaskPhone(user.phone),
                    cccd_token: cccdToken,
                    salary_aes: masking.aesEncrypt(String(user.salary), AES_KEY),
                    birth_date_masked: masking.maskBirthDate(user.birth_date),
                    address_masked: masking.maskAddress(user.address),
                    mask_method: 'STATIC+XOR+AES+TOKEN+FP'
                };
                maskedList.push(masked);

                const sql = `INSERT INTO masked_users
                    (id, full_name_masked, email_static, email_xor, phone_static, phone_fpmasked,
                     cccd_token, salary_xor, birth_date_masked, address_masked, mask_method)
                    VALUES (
                        ${conn.escape(masked.id)},
                        ${conn.escape(masked.full_name_masked)},
                        ${conn.escape(masked.email_static)},
                        ${conn.escape(masked.email_xor)},
                        ${conn.escape(masked.phone_static)},
                        ${conn.escape(masked.phone_fpmasked)},
                        ${conn.escape(masked.cccd_token)},
                        ${conn.escape(masked.salary_aes)},
                        ${conn.escape(masked.birth_date_masked)},
                        ${conn.escape(masked.address_masked)},
                        ${conn.escape(masked.mask_method)}
                    )`;
                await conn.query(sql);
            }

            // Lưu token map cccd vào database
            for (const [token, info] of Object.entries(tokenMapEntries)) {
                const sql = `INSERT INTO token_map (token, original, field_type)
                    VALUES (${conn.escape(token)}, ${conn.escape(info.original)}, ${conn.escape(info.fieldType)})
                    ON DUPLICATE KEY UPDATE original=VALUES(original), field_type=VALUES(field_type)`;
                await conn.query(sql);
            }

            await writeLog(conn, 'System', 'RUN_MASKING', 'ALL', `Xác thực và tạo lớp mask cho ${users.length} bản ghi`);

            return { count: users.length, masked: maskedList };
        });
        sendJSON(res, 200, { ok: true, ...result });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// POST /api/decrypt - Giải mã 1 record
async function handleDecrypt(req, res) {
    const body = await readBody(req);
    try {
        const session = getSession(req);
        if (!session) {
            return sendJSON(res, 401, { ok: false, error: 'Unauthorized: Thiếu phiên đăng nhập hoặc phiên hết hạn' });
        }
        const { username, role } = session;
        if (role !== 'Admin') {
            return sendJSON(res, 403, { ok: false, error: 'Forbidden: chỉ Admin mới được giải mã dữ liệu' });
        }

        const { email_xor, salary_aes, cccd_token, id } = JSON.parse(body);
        const result = {};
        if (email_xor) result.email = masking.xorDecrypt(email_xor, XOR_KEY);
        if (salary_aes) result.salary = masking.aesDecrypt(salary_aes, AES_KEY);

        await withDB(async (conn) => {
            if (cccd_token) {
                const orig = await conn.queryRows(`SELECT original FROM token_map WHERE token = ${conn.escape(cccd_token)}`);
                result.cccd = orig.length > 0 ? orig[0].original : '(không tìm thấy)';
            }
            await writeLog(conn, username, 'DECRYPT', id || 'UNKNOWN', 'Giải mã thông tin nhạy cảm (Email, Lương, CCCD)');
        });

        sendJSON(res, 200, { ok: true, data: result });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// POST /api/demo - Demo masking không cần DB
async function handleDemo(req, res) {
    const body = await readBody(req);
    try {
        const { text, type, key } = JSON.parse(body);
        let result = {};

        if (type === 'phone') result = { masked: masking.maskPhone(text), fp: masking.fpMaskPhone(text) };
        else if (type === 'email') result = { masked: masking.maskEmail(text) };
        else if (type === 'name') result = { masked: masking.maskName(text) };
        else if (type === 'address') result = { masked: masking.maskAddress(text) };
        else if (type === 'date') result = { masked: masking.maskBirthDate(text) };
        else if (type === 'xor') {
            const useKey = key || XOR_KEY;
            const enc = masking.xorEncrypt(text, useKey);
            result = { encrypted: enc, decrypted: masking.xorDecrypt(enc, useKey) };
        } else if (type === 'aes') {
            const useKey = key || AES_KEY;
            const enc = masking.aesEncrypt(text, useKey);
            result = { encrypted: enc, decrypted: masking.aesDecrypt(enc, useKey) };
        } else if (type === 'aes_encrypt') {
            const useKey = key || AES_KEY;
            result = { encrypted: masking.aesEncrypt(text, useKey) };
        } else if (type === 'aes_decrypt') {
            const useKey = key || AES_KEY;
            let dec = '';
            try { dec = masking.aesDecrypt(text, useKey); } catch (e) { dec = '(Lỗi giải mã: ' + e.message + ')'; }
            result = { decrypted: dec };
        } else if (type === 'token') {
            const tok = masking.tokenize(text, 'demo');
            result = { token: tok, detokenized: masking.detokenize(tok) };
        }
        sendJSON(res, 200, { ok: true, data: result });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// POST /api/attack - Giả mạo dữ liệu trong DB để test HMAC
async function handleAttack(req, res) {
    const session = requireAdmin(req, res);
    if (!session) return;

    const body = await readBody(req);
    try {
        const { id } = JSON.parse(body);
        if (!id) return sendJSON(res, 400, { ok: false, error: 'Thiếu ID!' });

        await withDB(async (conn) => {
            const users = await conn.queryRows(`SELECT phone FROM users WHERE id = ${conn.escape(id)}`);
            if (users.length > 0) {
                let badPhone = users[0].phone;
                if (badPhone && badPhone.length > 0) {
                    // Cố tình thay đổi 1 ký tự hex cuối cùng để phá vỡ toàn vẹn HMAC
                    let lastChar = badPhone[badPhone.length - 1];
                    let newChar = lastChar === '0' ? '1' : '0';
                    badPhone = badPhone.substring(0, badPhone.length - 1) + newChar;
                    await conn.query(`UPDATE users SET phone = ${conn.escape(badPhone)} WHERE id = ${conn.escape(id)}`);
                    await writeLog(conn, 'Hacker', 'ATTACK_DATA', id, 'Sửa lén lút chuỗi mã hoá trong CSDL để phá vỡ Integrity');
                }
            }
        });
        sendJSON(res, 200, { ok: true, message: `Đã tấn công (đảo ký tự cipher text) điện thoại user ID=${id}` });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// POST /api/hacker/tamper_chat - Giả mạo tin nhắn E2EE (Hacker sửa Cipher/IV)
async function handleTamperChat(req, res) {
    const body = await readBody(req);
    try {
        const { id } = JSON.parse(body);
        if (!id) return sendJSON(res, 400, { ok: false, error: 'Thiếu ID!' });

        await withDB(async (conn) => {
            const msgs = await conn.queryRows(`SELECT encrypted_msg FROM secure_chat WHERE id = ${conn.escape(id)}`);
            if (msgs.length > 0) {
                let badMsg = msgs[0].encrypted_msg;
                if (badMsg && badMsg.length > 70) {
                    let lastChar = badMsg[badMsg.length - 1];
                    let newChar = (lastChar === '0') ? '1' : '0';
                    badMsg = badMsg.substring(0, badMsg.length - 1) + newChar;
                    await conn.query(`UPDATE secure_chat SET encrypted_msg = ${conn.escape(badMsg)} WHERE id = ${conn.escape(id)}`);
                    await writeLog(conn, 'Hacker', 'TAMPER_CHAT', id, 'Sửa lén chuỗi mã hoá (E2EE) của tin nhắn trên đường truyền');
                }
            }
        });
        sendJSON(res, 200, { ok: true, message: `Đã can thiệp thành công vào gói tin ID=${id}` });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// ============================================================
// CHAT API HANDLERS (E2EE)
// ============================================================

// GET /api/chat - Lấy danh sách tin nhắn chat
async function handleGetChat(req, res) {
    try {
        const session = requireSession(req, res);
        if (!session) return;
        const { username, role } = session;
        const urlObj = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
        const peer = (urlObj.searchParams.get('peer') || '').trim();

        const msgs = await withDB(conn => {
            if (peer) {
                return conn.queryRows(`SELECT * FROM secure_chat WHERE ((sender = ${conn.escape(username)} AND receiver = ${conn.escape(peer)}) OR (sender = ${conn.escape(peer)} AND receiver = ${conn.escape(username)})) ORDER BY timestamp ASC`);
            }
            if (role === 'Admin') {
                return conn.queryRows(`SELECT * FROM secure_chat ORDER BY timestamp ASC`);
            }
            return conn.queryRows(`SELECT * FROM secure_chat WHERE sender = ${conn.escape(username)} OR receiver = ${conn.escape(username)} ORDER BY timestamp ASC`);
        });
        sendJSON(res, 200, { ok: true, data: msgs, current_user: username });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

async function handleGetChatUsers(req, res) {
    const session = requireSession(req, res);
    if (!session) return;
    try {
        const rows = await withDB(conn =>
            conn.queryRows(`SELECT username, role FROM accounts ORDER BY FIELD(role, 'Admin', 'Nhân viên', 'Khách hàng'), username`)
        );
        sendJSON(res, 200, { ok: true, data: rows, current_user: session.username });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// POST /api/chat - Gửi tin nhắn mới (Ciphertext)
async function handlePostChat(req, res) {
    const session = requireSession(req, res);
    if (!session) return;

    const body = await readBody(req);
    try {
        const { sender, receiver, encrypted_msg } = JSON.parse(body);
        if (!sender || !receiver || !encrypted_msg) {
            return sendJSON(res, 400, { ok: false, error: 'Thiếu thông tin người gửi/nhận/mã hoá' });
        }
        if (sender !== session.username) {
            return sendJSON(res, 403, { ok: false, error: 'Forbidden: sender phải khớp với phiên đăng nhập' });
        }
        await withDB(async (conn) => {
            await conn.query(`INSERT INTO secure_chat (sender, receiver, encrypted_msg) 
                              VALUES (${conn.escape(sender)}, ${conn.escape(receiver)}, ${conn.escape(encrypted_msg)})`);
            await writeLog(conn, sender, 'SEND_SECURE_CHAT', receiver, 'Gửi tin nhắn được mã hoá End-to-End');
        });
        sendJSON(res, 200, { ok: true, message: 'Đã gửi' });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// ============================================================
// AUTH API
// ============================================================
async function handleLogin(req, res) {
    const body = await readBody(req);
    try {
        const { username, password } = JSON.parse(body);
        if (!username || !password) return sendJSON(res, 400, { ok: false, error: 'Thiếu thông tin' });

        await withDB(async (conn) => {
            const h = crypto.createHash('sha256').update(password).digest('hex');
            const rows = await conn.queryRows(`SELECT role FROM accounts WHERE username = ${conn.escape(username)} AND password_hash = ${conn.escape(h)}`);
            if (rows.length > 0) {
                const role = rows[0].role;
                const token = createSession(username, role);
                await writeLog(conn, username, 'LOGIN', 'SYSTEM', `Đăng nhập thành công với vai trò ${role}`);
                sendJSON(res, 200, { ok: true, role: role, username: username, token });
            } else {
                await writeLog(conn, username, 'LOGIN_FAIL', 'SYSTEM', `Đăng nhập thất bại (Sai MK)`);
                sendJSON(res, 401, { ok: false, error: 'Sai tài khoản hoặc mật khẩu!' });
            }
        });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

async function handleRegister(req, res) {
    const body = await readBody(req);
    try {
        const { username, password } = JSON.parse(body);
        if (!username || !password) return sendJSON(res, 400, { ok: false, error: 'Thiếu thông tin' });

        await withDB(async (conn) => {
            const exist = await conn.queryRows(`SELECT id FROM accounts WHERE username = ${conn.escape(username)}`);
            if (exist.length > 0) return sendJSON(res, 400, { ok: false, error: 'Tài khoản đã tồn tại!' });

            const h = crypto.createHash('sha256').update(password).digest('hex');
            const chosenRole = 'Khách hàng';
            await conn.query(`INSERT INTO accounts (username, password_hash, role) VALUES (${conn.escape(username)}, ${conn.escape(h)}, ${conn.escape(chosenRole)})`);
            await writeLog(conn, username, 'REGISTER', 'SYSTEM', `Đăng ký tài khoản mới với vai trò ${chosenRole}`);

            sendJSON(res, 200, { ok: true, message: 'Đăng ký thành công' });
        });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// ============================================================
// MAIN HTTP SERVER
// ============================================================
const server = http.createServer(async (req, res) => {
    const url = req.url;
    const method = req.method;

    // CORS preflight
    if (method === 'OPTIONS') {
        res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST', 'Access-Control-Allow-Headers': 'Content-Type' });
        res.end();
        return;
    }

    // Serve HTML
    if (method === 'GET' && (url === '/' || url === '/index.html' || url.split('?')[0] === '/' || url.split('?')[0] === '/index.html')) {
        sendHTML(res, path.join(__dirname, '../public/index.html'));
        return;
    }

    if (method === 'GET' && (url === '/hacker' || url === '/hacker.html' || url.split('?')[0] === '/hacker')) {
        sendHTML(res, path.join(__dirname, '../public/hacker.html'));
        return;
    }

    // API Routes
    const pathOnly = url.split('?')[0];

    if (pathOnly === '/api/users' && method === 'GET') { await handleGetUsers(req, res); return; }
    if (pathOnly === '/api/users/add' && method === 'POST') { await handleAddUser(req, res); return; }
    if (pathOnly === '/api/users/delete' && method === 'POST') { await handleDeleteUser(req, res); return; }
    if (pathOnly === '/api/masked' && method === 'GET') { await handleGetMasked(req, res); return; }
    if (pathOnly === '/api/mask' && method === 'POST') { await handleRunMask(req, res); return; }
    if (pathOnly === '/api/decrypt' && method === 'POST') { await handleDecrypt(req, res); return; }
    if (pathOnly === '/api/demo' && method === 'POST') { await handleDemo(req, res); return; }
    if (pathOnly === '/api/stats' && method === 'GET') { await handleStats(req, res); return; }
    if (pathOnly === '/api/logs' && method === 'GET') { await handleGetLogs(req, res); return; }
    if (pathOnly === '/api/attack' && method === 'POST') { await handleAttack(req, res); return; }
    if (pathOnly === '/api/hacker/tamper_chat' && method === 'POST') { await handleTamperChat(req, res); return; }
    if (pathOnly === '/api/chat/users' && method === 'GET') { await handleGetChatUsers(req, res); return; }
    if (pathOnly === '/api/chat' && method === 'GET') { await handleGetChat(req, res); return; }
    if (pathOnly === '/api/chat' && method === 'POST') { await handlePostChat(req, res); return; }
    if (pathOnly === '/api/login' && method === 'POST') { await handleLogin(req, res); return; }
    if (pathOnly === '/api/register' && method === 'POST') { await handleRegister(req, res); return; }

    res.writeHead(404);
    res.end('Not Found');
});

server.listen(PORT, async () => {
    try { await initAccountsDB(); } catch (e) { }
    console.log('');
    console.log('  ╔══════════════════════════════════════════════╗');
    console.log('  ║      DATA MASKING SYSTEM - WEB SERVER        ║');
    console.log('  ╠══════════════════════════════════════════════╣');
    console.log(`  ║  🌐 Mở trình duyệt: http://localhost:${PORT}    ║`);
    console.log('  ║  📦 Database: MySQL - data_masking_db        ║');
    console.log('  ║  ⌨️  Nhấn Ctrl+C để dừng server              ║');
    console.log('  ╚══════════════════════════════════════════════╝');
    console.log('');
});
