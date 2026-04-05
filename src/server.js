// ============================================================
// src/server.js - Web Server Tá»° VIáº¾T (dÃ¹ng http built-in)
// ============================================================

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const { MySQLConnection } = require('./mysql_connector');
const DB_CONFIG = require('../config/database');
const masking = require('./masking');

const PORT = 3000;
const XOR_KEY = 'DataMask@SecretKey#2024!VietNam';
const AES_KEY = 'AESKey_DataMask16';
const DB_KEY = 'AES_DB_SECRET_KEY!'; // KhoÃ¡ cáº¥p cÆ¡ sá»Ÿ dá»¯ liá»‡u (táº§ng 1)
const JWT_SECRET = 'JWTSecret_DataMasking_VietNam2026!';
const JWT_EXPIRY = '30m';
const DEFAULT_RECORD_KEYS = {
    128: 'UserDefault_AES128_Key@2026',
    192: 'UserDefault_AES192_Key@2026__VN',
    256: 'UserDefault_AES256_Key@2026__VietNam'
};

function normalizeAesBits(modeOrBits) {
    const val = String(modeOrBits || '').trim().toUpperCase();
    if (val === '256' || val === 'AES-256' || val === 'AES256') return 256;
    if (val === '192' || val === 'AES-192' || val === 'AES192') return 192;
    return 128;
}

function getAesModeLabel(modeOrBits) {
    return `AES-${normalizeAesBits(modeOrBits)}`;
}

function getRoleCode(role) {
    const raw = String(role || '').toLowerCase();
    if (raw.includes('admin')) return 'admin';
    if (raw.includes('nh') || raw.includes('vi')) return 'employee';
    if (raw.includes('kh') || raw.includes('ch')) return 'customer';
    return raw;
}

function getDefaultRecordKey(modeOrBits) {
    return DEFAULT_RECORD_KEYS[normalizeAesBits(modeOrBits)];
}

function isCipherText(val) {
    return !!(val && String(val).match(/^[0-9a-fA-F]{32,}$/));
}

function unwrapRecordKey(record) {
    if (!record || !record.data_key_wrap) return DB_KEY;
    return masking.aesDecrypt(record.data_key_wrap, DB_KEY);
}

function decryptRecordField(record, fieldName, suppliedKey) {
    const val = record[fieldName];
    if (!isCipherText(val)) return val;
    if (!record.data_key_wrap) return masking.aesDecrypt(val, DB_KEY);
    const bits = normalizeAesBits(record.data_cipher_mode);
    const key = suppliedKey || unwrapRecordKey(record);
    return masking.aesDecryptAdvanced(val, key, bits);
}

function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
}

function stringToBytes(str) {
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
        const code = str.charCodeAt(i);
        if (code < 0x80) {
            bytes.push(code);
        } else if (code < 0x800) {
            bytes.push(0xc0 | (code >> 6));
            bytes.push(0x80 | (code & 0x3f));
        } else if (code < 0xd800 || code >= 0xe000) {
            bytes.push(0xe0 | (code >> 12));
            bytes.push(0x80 | ((code >> 6) & 0x3f));
            bytes.push(0x80 | (code & 0x3f));
        } else {
            i++;
            const codePoint = 0x10000 + (((code & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
            bytes.push(0xf0 | (codePoint >> 18));
            bytes.push(0x80 | ((codePoint >> 12) & 0x3f));
            bytes.push(0x80 | ((codePoint >> 6) & 0x3f));
            bytes.push(0x80 | (codePoint & 0x3f));
        }
    }
    return bytes;
}

function bytesToHex(bytes) {
    const hex = [];
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        hex.push((b >>> 4).toString(16));
        hex.push((b & 0x0f).toString(16));
    }
    return hex.join('');
}

function sha256(message) {
    const K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    const bytes = stringToBytes(message);
    const bitLen = bytes.length * 8;
    bytes.push(0x80);
    while ((bytes.length % 64) !== 56) bytes.push(0x00);
    for (let i = 7; i >= 0; i--) {
        bytes.push((bitLen >>> (i * 8)) & 0xff);
    }
    let H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];
    for (let i = 0; i < bytes.length; i += 64) {
        const chunk = bytes.slice(i, i + 64);
        const w = new Array(64);
        for (let j = 0; j < 16; j++) {
            const idx = j * 4;
            w[j] = (chunk[idx] << 24) | (chunk[idx + 1] << 16) | (chunk[idx + 2] << 8) | chunk[idx + 3];
        }
        for (let j = 16; j < 64; j++) {
            const s0 = rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3);
            const s1 = rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10);
            w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
        }
        let [a, b, c, d, e, f, g, h] = H;
        for (let j = 0; j < 64; j++) {
            const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (h + S1 + ch + K[j] + w[j]) >>> 0;
            const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) >>> 0;
            h = g;
            g = f;
            f = e;
            e = (d + temp1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) >>> 0;
        }
        H = [
            (H[0] + a) >>> 0,
            (H[1] + b) >>> 0,
            (H[2] + c) >>> 0,
            (H[3] + d) >>> 0,
            (H[4] + e) >>> 0,
            (H[5] + f) >>> 0,
            (H[6] + g) >>> 0,
            (H[7] + h) >>> 0
        ];
    }
    const hash = [];
    for (let i = 0; i < H.length; i++) {
        hash.push((H[i] >>> 24) & 0xff);
        hash.push((H[i] >>> 16) & 0xff);
        hash.push((H[i] >>> 8) & 0xff);
        hash.push(H[i] & 0xff);
    }
    return bytesToHex(hash);
}

// ============================================================
// HELPER: Giáº£i mÃ£ 1 user (vÃ¬ DB lÆ°u AES-128 hex string)
// ============================================================
function decryptUser(u) {
    if (!u) return u;
    try {
        const salaryValue = decryptRecordField(u, 'salary');
        return {
            id: u.id,
            full_name: decryptRecordField(u, 'full_name'),
            email: decryptRecordField(u, 'email'),
            phone: decryptRecordField(u, 'phone'),
            cccd: decryptRecordField(u, 'cccd'),
            salary: parseFloat(String(salaryValue)) || 0,
            birth_date: decryptRecordField(u, 'birth_date'),
            address: decryptRecordField(u, 'address'),
            owner_username: u.owner_username,
            data_cipher_mode: u.data_cipher_mode || 'AES-128',
            created_at: u.created_at
        };
    } catch (e) {
        console.error("L?i decrypt DB user:", e);
        return u;
    }
}

function readBody(req) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', () => resolve(body));
    });
}

// ============================================================
// HELPER: Gá»­i JSON response
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
// HELPER: Gá»­i HTML file
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
// DATABASE CONNECTION POOL (Ä‘Æ¡n giáº£n - táº¡o má»›i má»—i request)
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

function getTokenFromReq(req) {
    const authHeader = req.headers['authorization'];
    return req.headers['x-auth-token'] || (authHeader && authHeader.replace(/^Bearer\s+/i, '')) || null;
}

function createSession(username, role) {
    return jwt.sign({ username, role }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
}

function getSession(req) {
    const token = getTokenFromReq(req);
    if (!token) return null;
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (e) {
        return null;
    }
}

function requireSession(req, res) {
    const session = getSession(req);
    if (!session) {
        sendJSON(res, 401, { ok: false, error: 'Unauthorized: Thiáº¿u phiÃªn Ä‘Äƒng nháº­p hoáº·c phiÃªn háº¿t háº¡n' });
        return null;
    }
    return session;
}

function requireAdmin(req, res) {
    const session = requireSession(req, res);
    if (!session) return null;
    if (getRoleCode(session.role) !== 'admin') {
        sendJSON(res, 403, { ok: false, error: 'Forbidden: chá»‰ Admin má»›i Ä‘Æ°á»£c truy cáº­p' });
        return null;
    }
    return session;
}

function requireRole(req, res, allowedRoles) {
    const session = requireSession(req, res);
    if (!session) return null;
    const allowed = (allowedRoles || []).map(getRoleCode);
    if (!allowed.includes(getRoleCode(session.role))) {
        sendJSON(res, 403, { ok: false, error: `Forbidden: chá»‰ ${allowedRoles.join(' hoáº·c ')} má»›i Ä‘Æ°á»£c truy cáº­p` });
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
                data_cipher_mode VARCHAR(20) NOT NULL DEFAULT 'AES-128',
                data_key_wrap TEXT NULL,
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
            const cipherModeCols = await conn.queryRows("SHOW COLUMNS FROM users LIKE 'data_cipher_mode'");
            if (cipherModeCols.length === 0) {
                await conn.query(`ALTER TABLE users ADD COLUMN data_cipher_mode VARCHAR(20) NOT NULL DEFAULT 'AES-128'`);
            }
            const dataKeyWrapCols = await conn.queryRows("SHOW COLUMNS FROM users LIKE 'data_key_wrap'");
            if (dataKeyWrapCols.length === 0) {
                await conn.query(`ALTER TABLE users ADD COLUMN data_key_wrap TEXT NULL`);
            }
        } catch (e) { }

        const h = (pw) => sha256(pw);
        const users = [
            ['admin', h('admin'), 'Admin'],
            ['nhanvien', h('nhanvien'), 'NhÃ¢n viÃªn'],
            ['khachhang', h('khachhang'), 'KhÃ¡ch hÃ ng']
        ];
        for (const [u, p, r] of users) {
            await conn.query(`INSERT IGNORE INTO accounts (username, password_hash, role) VALUES (${conn.escape(u)}, ${conn.escape(p)}, ${conn.escape(r)})`);
        }
    });
}

// GET /api/logs - Äá»c audit log
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

// GET /api/users - Dá»¯ liá»‡u gá»‘c
async function handleGetUsers(req, res) {
    try {
        const session = requireSession(req, res);
        if (!session) return;

        const { username, role } = session;
        const normalizedRole = getRoleCode(role);
        if (normalizedRole === 'customer') {
            const usersRaw = await withDB(conn => conn.queryRows(`SELECT * FROM users WHERE owner_username = ${conn.escape(username)} ORDER BY id`));
            const custData = usersRaw.map(decryptUser);
            await withDB(conn => writeLog(conn, username, 'VIEW_OWN_DATA', username, `KhÃ¡ch hÃ ng ${username} xem dá»¯ liá»‡u cá»§a chÃ­nh mÃ¬nh`));
            sendJSON(res, 200, { ok: true, data: custData });
            return;
        }

        const usersRaw = await withDB(async (conn) => {
            await writeLog(conn, username, 'VIEW_RAW_DATA', 'ALL', `User ${username} with role ${role} accessed user data`);
            return conn.queryRows('SELECT * FROM users ORDER BY id');
        });
        const users = usersRaw.map(decryptUser);

        if (normalizedRole === 'employee') {
            const empData = users.map(u => ({
                id: u.id,
                full_name: masking.maskName(u.full_name),
                email: masking.maskEmail(u.email),
                phone: masking.maskPhone(u.phone),
                cccd: '(áº©n)',
                salary: '*** VNÄ',
                birth_date: masking.maskBirthDate(u.birth_date),
                address: masking.maskAddress(u.address),
                created_at: u.created_at
            }));
            sendJSON(res, 200, { ok: true, data: empData });
            return;
        }

        if (normalizedRole !== 'admin') {
            return sendJSON(res, 403, { ok: false, error: 'Forbidden: role khÃ´ng Ä‘Æ°á»£c phÃ©p truy cáº­p' });
        }

        sendJSON(res, 200, { ok: true, data: users });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// GET /api/masked - Dá»¯ liá»‡u Ä‘Ã£ mask
async function handleGetMasked(req, res) {
    const session = requireSession(req, res);
    if (!session) return;
    if (getRoleCode(session.role) === 'customer') {
        return sendJSON(res, 403, { ok: false, error: 'Forbidden: KhÃ¡ch hÃ ng khÃ´ng Ä‘Æ°á»£c truy cáº­p dá»¯ liá»‡u Ä‘Ã£ mask cá»§a toÃ n bá»™ há»‡ thá»‘ng' });
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

// POST /api/users/add - ThÃªm user má»›i
async function handleAddUser(req, res) {
    const body = await readBody(req);
    try {
        const { full_name, email, phone, cccd, salary, birth_date, address, aes_mode, encryption_key } = JSON.parse(body);
        if (!full_name || !email || !phone || !cccd || !salary || !birth_date || !address) {
            return sendJSON(res, 400, { ok: false, error: 'Vui l?ng ?i?n ??y ?? t?t c? c?c tr??ng!' });
        }

        const session = requireSession(req, res);
        if (!session) return;
        const normalizedRole = getRoleCode(session.role);
        if (!['admin', 'employee', 'customer'].includes(normalizedRole)) {
            return sendJSON(res, 403, { ok: false, error: 'Forbidden: role khong duoc phep them du lieu' });
        }

        const aesBits = normalizeAesBits(aes_mode);
        const aesModeLabel = getAesModeLabel(aesBits);
        const recordKey = (encryption_key || '').trim() || getDefaultRecordKey(aesBits);
        const wrappedRecordKey = masking.aesEncrypt(recordKey, DB_KEY);

        const eName = masking.aesEncryptAdvanced(full_name, recordKey, aesBits);
        const eEmail = masking.aesEncryptAdvanced(email, recordKey, aesBits);
        const ePhone = masking.aesEncryptAdvanced(phone, recordKey, aesBits);
        const eCccd = masking.aesEncryptAdvanced(cccd, recordKey, aesBits);
        const eSalary = masking.aesEncryptAdvanced(String(salary), recordKey, aesBits);
        const eBirth = masking.aesEncryptAdvanced(String(birth_date), recordKey, aesBits);
        const eAddress = masking.aesEncryptAdvanced(address, recordKey, aesBits);
        const owner = session.username;

        await withDB(async (conn) => {
            const sql = `INSERT INTO users (full_name, email, phone, cccd, salary, birth_date, address, data_cipher_mode, data_key_wrap, owner_username)
                VALUES (${conn.escape(eName)}, ${conn.escape(eEmail)}, ${conn.escape(ePhone)},
                        ${conn.escape(eCccd)}, ${conn.escape(eSalary)}, ${conn.escape(eBirth)}, ${conn.escape(eAddress)},
                        ${conn.escape(aesModeLabel)}, ${conn.escape(wrappedRecordKey)}, ${conn.escape(owner)})`;
            const dbRes = await conn.query(sql);
            await writeLog(conn, session.username, 'ADD_USER', dbRes.insertId, `Added new user: ${full_name} (owner=${owner}, mode=${aesModeLabel}, customKey=${(encryption_key || '').trim() ? 'YES' : 'NO'})`);
        });
        sendJSON(res, 200, { ok: true, message: `Da them nguoi dung "${full_name}" thanh cong voi ${aesModeLabel}!`, encryption_mode: aesModeLabel, used_default_key: !(encryption_key || '').trim() });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}
// POST /api/users/delete - XÃ³a user
async function handleDeleteUser(req, res) {
    const session = requireAdmin(req, res);
    if (!session) return;

    const body = await readBody(req);
    try {
        const { id } = JSON.parse(body);
        if (!id) return sendJSON(res, 400, { ok: false, error: 'Thiáº¿u ID!' });
        await withDB(async (conn) => {
            await conn.query(`DELETE FROM users WHERE id = ${conn.escape(id)}`);
            await writeLog(conn, session.username, 'DELETE_USER', id, `Deleted user ID=${id}`);
        });
        sendJSON(res, 200, { ok: true, message: `ÄÃ£ xÃ³a user ID=${id}` });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// GET /api/stats - Thá»‘ng kÃª tá»•ng quan
async function handleStats(req, res) {
    const session = requireAdmin(req, res);
    if (!session) return;
    try {
        const stats = await withDB(async (conn) => {
            const [users] = await conn.queryRows('SELECT COUNT(*) as cnt FROM users');
            const [masked] = await conn.queryRows('SELECT COUNT(*) as cnt FROM masked_users');
            const [tokens] = await conn.queryRows('SELECT COUNT(*) as cnt FROM token_map');

            // TÃ­nh thá»‘ng kÃª lÆ°Æ¡ng trÃªn dá»¯ liá»‡u gá»‘c (pháº£i giáº£i mÃ£ trÆ°á»›c)
            const allUsersRaw = await conn.queryRows('SELECT * FROM users');
            const allSals = allUsersRaw.map(u => decryptUser(u).salary || 0);

            let mn = 0, mx = 0, avg = 0;
            if (allSals.length > 0) {
                mn = Math.min(...allSals);
                mx = Math.max(...allSals);
                avg = allSals.reduce((a, b) => a + b, 0) / allSals.length;
            }
            const salaryRows = [{ mx, mn, avg }];

            // Láº¥y 5 record mask gáº§n nháº¥t
            const recent = await conn.queryRows(
                'SELECT id, full_name_masked, mask_method, masked_at FROM masked_users ORDER BY masked_at DESC LIMIT 5'
            );

            // PhÃ¢n loáº¡i ká»¹ thuáº­t (má»—i record dÃ¹ng 9 fields = 4 Static + 1 XOR + 1 AES + 1 Token + 2 FP)
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

// POST /api/mask - Cháº¡y masking toÃ n bá»™ users
async function handleRunMask(req, res) {
    const session = requireRole(req, res, ['NhÃ¢n viÃªn', 'Admin']);
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

            // LÆ°u token map cccd vÃ o database
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

// POST /api/decrypt - Giáº£i mÃ£ 1 record
async function handleDecrypt(req, res) {
    const body = await readBody(req);
    try {
        const session = getSession(req);
        if (!session) {
            return sendJSON(res, 401, { ok: false, error: 'Unauthorized: thieu phien dang nhap hoac phien het han' });
        }
        const { username, role } = session;
        const roleCode = getRoleCode(role);
        if (!['admin', 'employee'].includes(roleCode)) {
            return sendJSON(res, 403, { ok: false, error: 'Forbidden: chi Admin hoac Nhan vien moi duoc giai ma du lieu' });
        }

        const { id, decrypt_key } = JSON.parse(body);
        if (!id) return sendJSON(res, 400, { ok: false, error: 'Thieu ID ban ghi can giai ma' });
        if (roleCode === 'employee' && !(decrypt_key || '').trim()) {
            return sendJSON(res, 400, { ok: false, error: 'Nhan vien phai nhap dung key da dung khi ma hoa' });
        }

        const result = await withDB(async (conn) => {
            const rows = await conn.queryRows(`SELECT * FROM users WHERE id = ${conn.escape(id)} LIMIT 1`);
            if (rows.length === 0) return null;
            const record = rows[0];
            const suppliedKey = roleCode === 'employee' ? String(decrypt_key || '').trim() : null;
            const fullName = decryptRecordField(record, 'full_name', suppliedKey);
            if (String(fullName).includes('HMAC verification failed') || String(fullName).includes('Decrypt/Unpad')) {
                return { error: roleCode === 'employee' ? 'Key khong dung hoac du lieu da bi gia mao' : 'Khong the giai ma ban ghi' };
            }

            await writeLog(conn, username, 'DECRYPT_RECORD', id, `Decrypt source record with role=${role} mode=${record.data_cipher_mode || 'AES-128'}`);

            return {
                id: record.id,
                full_name: fullName,
                email: decryptRecordField(record, 'email', suppliedKey),
                phone: decryptRecordField(record, 'phone', suppliedKey),
                cccd: decryptRecordField(record, 'cccd', suppliedKey),
                salary: decryptRecordField(record, 'salary', suppliedKey),
                birth_date: decryptRecordField(record, 'birth_date', suppliedKey),
                address: decryptRecordField(record, 'address', suppliedKey),
                data_cipher_mode: record.data_cipher_mode || 'AES-128'
            };
        });

        if (!result) return sendJSON(res, 404, { ok: false, error: 'Khong tim thay ban ghi' });
        if (result.error) return sendJSON(res, 400, { ok: false, error: result.error });
        sendJSON(res, 200, { ok: true, data: result });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}
// POST /api/demo - Demo masking khÃ´ng cáº§n DB
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
            try { dec = masking.aesDecrypt(text, useKey); } catch (e) { dec = '(Lá»—i giáº£i mÃ£: ' + e.message + ')'; }
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

// POST /api/attack - Giáº£ máº¡o dá»¯ liá»‡u trong DB Ä‘á»ƒ test HMAC
async function handleAttack(req, res) {
    const session = requireAdmin(req, res);
    if (!session) return;

    const body = await readBody(req);
    try {
        const { id } = JSON.parse(body);
        if (!id) return sendJSON(res, 400, { ok: false, error: 'Thiáº¿u ID!' });

        await withDB(async (conn) => {
            const users = await conn.queryRows(`SELECT phone FROM users WHERE id = ${conn.escape(id)}`);
            if (users.length > 0) {
                let badPhone = users[0].phone;
                if (badPhone && badPhone.length > 0) {
                    // Cá»‘ tÃ¬nh thay Ä‘á»•i 1 kÃ½ tá»± hex cuá»‘i cÃ¹ng Ä‘á»ƒ phÃ¡ vá»¡ toÃ n váº¹n HMAC
                    let lastChar = badPhone[badPhone.length - 1];
                    let newChar = lastChar === '0' ? '1' : '0';
                    badPhone = badPhone.substring(0, badPhone.length - 1) + newChar;
                    await conn.query(`UPDATE users SET phone = ${conn.escape(badPhone)} WHERE id = ${conn.escape(id)}`);
                    await writeLog(conn, 'Hacker', 'ATTACK_DATA', id, 'Sá»­a lÃ©n lÃºt chuá»—i mÃ£ hoÃ¡ trong CSDL Ä‘á»ƒ phÃ¡ vá»¡ Integrity');
                }
            }
        });
        sendJSON(res, 200, { ok: true, message: `ÄÃ£ táº¥n cÃ´ng (Ä‘áº£o kÃ½ tá»± cipher text) Ä‘iá»‡n thoáº¡i user ID=${id}` });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// POST /api/hacker/tamper_chat - Giáº£ máº¡o tin nháº¯n E2EE (Hacker sá»­a Cipher/IV)
async function handleTamperChat(req, res) {
    const body = await readBody(req);
    try {
        const { id } = JSON.parse(body);
        if (!id) return sendJSON(res, 400, { ok: false, error: 'Thiáº¿u ID!' });

        await withDB(async (conn) => {
            const msgs = await conn.queryRows(`SELECT encrypted_msg FROM secure_chat WHERE id = ${conn.escape(id)}`);
            if (msgs.length > 0) {
                let badMsg = msgs[0].encrypted_msg;
                if (badMsg && badMsg.length > 70) {
                    let lastChar = badMsg[badMsg.length - 1];
                    let newChar = (lastChar === '0') ? '1' : '0';
                    badMsg = badMsg.substring(0, badMsg.length - 1) + newChar;
                    await conn.query(`UPDATE secure_chat SET encrypted_msg = ${conn.escape(badMsg)} WHERE id = ${conn.escape(id)}`);
                    await writeLog(conn, 'Hacker', 'TAMPER_CHAT', id, 'Sá»­a lÃ©n chuá»—i mÃ£ hoÃ¡ (E2EE) cá»§a tin nháº¯n trÃªn Ä‘Æ°á»ng truyá»n');
                }
            }
        });
        sendJSON(res, 200, { ok: true, message: `ÄÃ£ can thiá»‡p thÃ nh cÃ´ng vÃ o gÃ³i tin ID=${id}` });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// ============================================================
// CHAT API HANDLERS (E2EE)
// ============================================================

// GET /api/chat - Láº¥y danh sÃ¡ch tin nháº¯n chat
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
            conn.queryRows(`SELECT username, role FROM accounts ORDER BY FIELD(role, 'Admin', 'NhÃ¢n viÃªn', 'KhÃ¡ch hÃ ng'), username`)
        );
        sendJSON(res, 200, { ok: true, data: rows, current_user: session.username });
    } catch (e) {
        sendJSON(res, 500, { ok: false, error: e.message });
    }
}

// POST /api/chat - Gá»­i tin nháº¯n má»›i (Ciphertext)
async function handlePostChat(req, res) {
    const session = requireSession(req, res);
    if (!session) return;

    const body = await readBody(req);
    try {
        const { sender, receiver, encrypted_msg } = JSON.parse(body);
        if (!sender || !receiver || !encrypted_msg) {
            return sendJSON(res, 400, { ok: false, error: 'Thiáº¿u thÃ´ng tin ngÆ°á»i gá»­i/nháº­n/mÃ£ hoÃ¡' });
        }
        if (sender !== session.username) {
            return sendJSON(res, 403, { ok: false, error: 'Forbidden: sender pháº£i khá»›p vá»›i phiÃªn Ä‘Äƒng nháº­p' });
        }
        await withDB(async (conn) => {
            await conn.query(`INSERT INTO secure_chat (sender, receiver, encrypted_msg) 
                              VALUES (${conn.escape(sender)}, ${conn.escape(receiver)}, ${conn.escape(encrypted_msg)})`);
            await writeLog(conn, sender, 'SEND_SECURE_CHAT', receiver, 'Gửi tin nhắn được mã hóa End-to-End');
        });
        sendJSON(res, 200, { ok: true, message: 'ÄÃ£ gá»­i' });
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
        if (!username || !password) return sendJSON(res, 400, { ok: false, error: 'Thiáº¿u thÃ´ng tin' });

        await withDB(async (conn) => {
            const h = sha256(password);
            const rows = await conn.queryRows(`SELECT role FROM accounts WHERE username = ${conn.escape(username)} AND password_hash = ${conn.escape(h)}`);
            if (rows.length > 0) {
                const role = rows[0].role;
                const token = createSession(username, role);
                await writeLog(conn, username, 'LOGIN', 'SYSTEM', `Đăng nhập thành công với vai trò ${role}`);
                sendJSON(res, 200, { ok: true, role: role, username: username, token });
            } else {
                await writeLog(conn, username, 'LOGIN_FAIL', 'SYSTEM', `Đăng nhập thất bại (Sai MK)`);
                sendJSON(res, 401, { ok: false, error: 'Sai tÃ i khoáº£n hoáº·c máº­t kháº©u!' });
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
        if (!username || !password) return sendJSON(res, 400, { ok: false, error: 'Thiáº¿u thÃ´ng tin' });

        await withDB(async (conn) => {
            const exist = await conn.queryRows(`SELECT id FROM accounts WHERE username = ${conn.escape(username)}`);
            if (exist.length > 0) return sendJSON(res, 400, { ok: false, error: 'TÃ i khoáº£n Ä‘Ã£ tá»“n táº¡i!' });

            const h = sha256(password);
            const chosenRole = 'Khách hàng';
            await conn.query(`INSERT INTO accounts (username, password_hash, role) VALUES (${conn.escape(username)}, ${conn.escape(h)}, ${conn.escape(chosenRole)})`);
            await writeLog(conn, username, 'REGISTER', 'SYSTEM', `Đăng ký tài khoản mới với vai trò ${chosenRole}`);

            sendJSON(res, 200, { ok: true, message: 'ÄÄƒng kÃ½ thÃ nh cÃ´ng' });
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
    console.log('================================================');
    console.log(' DATA MASKING SYSTEM - WEB SERVER');
    console.log('================================================');
    console.log(` Open browser: http://localhost:${PORT}`);
    console.log(' Database: MySQL - data_masking_db');
    console.log(' Press Ctrl+C to stop server');
    console.log('================================================');
    console.log('');
});

