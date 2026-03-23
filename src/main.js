// ============================================================
// src/main.js
// CHƯƠNG TRÌNH QUẢN LÝ DỮ LIỆU AN TOÀN - DATA MASKING SYSTEM
// Ngôn ngữ: JavaScript (Node.js)
// Database: MySQL
// ============================================================

const { MySQLConnection } = require('./mysql_connector');
const DB_CONFIG = require('../config/database');
const masking = require('./masking');

// ============================================================
// KHÓA BÍ MẬT (trong thực tế lưu ở environment variable)
// ============================================================
const XOR_KEY = 'DataMask@SecretKey#2024!VietNam';
const AES_KEY = 'AESKey_DataMask16';  // 16 bytes cho AES-128

// ============================================================
// TIỆN ÍCH HIỂN THỊ
// ============================================================

function printSeparator(char = '=', len = 70) {
    let line = '';
    for (let i = 0; i < len; i++) line += char;
    console.log(line);
}

function printHeader(title) {
    printSeparator();
    console.log(`  ${title}`);
    printSeparator();
}

function printTable(headers, rows, colWidths) {
    // In header
    let headerRow = '| ';
    let divider = '+-';
    for (let i = 0; i < headers.length; i++) {
        const w = colWidths[i];
        headerRow += headers[i].padEnd(w) + ' | ';
        divider += '-'.repeat(w) + '-+-';
    }
    console.log(divider);
    console.log(headerRow);
    console.log(divider);

    // In rows
    for (const row of rows) {
        let rowStr = '| ';
        for (let i = 0; i < row.length; i++) {
            const w = colWidths[i];
            let cell = String(row[i] !== null && row[i] !== undefined ? row[i] : 'NULL');
            if (cell.length > w) cell = cell.substring(0, w - 3) + '...';
            rowStr += cell.padEnd(w) + ' | ';
        }
        console.log(rowStr);
    }
    console.log(divider);
}

// ============================================================
// BƯỚC 1: KIỂM TRA & DEMO CÁC THUẬT TOÁN MASKING
// ============================================================

function demoMaskingAlgorithms() {
    printHeader('BƯỚC 1: DEMO CÁC KỸ THUẬT DATA MASKING');

    // --- Static Masking ---
    console.log('\n[1.1] STATIC MASKING (Che giấu tĩnh)');
    printSeparator('-', 60);
    const testPhone = '0912345678';
    const testEmail = 'nguyenvanan@gmail.com';
    const testName = 'Nguyễn Văn An';
    const testAddr = '123 Nguyễn Huệ, Q1, TP.HCM';
    const testDate = '1990-05-15';

    console.log(`  SĐT gốc   : ${testPhone}  →  Sau mask: ${masking.maskPhone(testPhone)}`);
    console.log(`  Email gốc : ${testEmail}  →  Sau mask: ${masking.maskEmail(testEmail)}`);
    console.log(`  Tên gốc   : ${testName}  →  Sau mask: ${masking.maskName(testName)}`);
    console.log(`  Địa chỉ   : ${testAddr}  →  Sau mask: ${masking.maskAddress(testAddr)}`);
    console.log(`  Ngày sinh  : ${testDate}  →  Sau mask: ${masking.maskBirthDate(testDate)}`);

    // --- XOR Cipher ---
    console.log('\n[1.2] XOR CIPHER (Mã hóa XOR tự viết)');
    printSeparator('-', 60);
    const xorPlaintext = 'nguyenvanan@gmail.com';
    const xorCipher = masking.xorEncrypt(xorPlaintext, XOR_KEY);
    const xorDecrypted = masking.xorDecrypt(xorCipher, XOR_KEY);
    console.log(`  Plaintext  : ${xorPlaintext}`);
    console.log(`  Key        : ${XOR_KEY}`);
    console.log(`  Ciphertext : ${xorCipher}`);
    console.log(`  Decrypted  : ${xorDecrypted}`);
    console.log(`  Khớp?      : ${xorPlaintext === xorDecrypted ? '✓ ĐÚNG' : '✗ SAI'}`);

    // --- AES-128 ---
    console.log('\n[1.3] AES-128 TỰ VIẾT (ECB mode, PKCS#7 padding)');
    printSeparator('-', 60);
    const aesSalary = '35000000.00';
    const aesCipher = masking.aesEncrypt(aesSalary, AES_KEY);
    const aesDecrypted = masking.aesDecrypt(aesCipher, AES_KEY);
    console.log(`  Plaintext  : ${aesSalary}`);
    console.log(`  Key        : ${AES_KEY}`);
    console.log(`  AES Cipher : ${aesCipher}`);
    console.log(`  Decrypted  : ${aesDecrypted}`);
    console.log(`  Khớp?      : ${aesSalary === aesDecrypted ? '✓ ĐÚNG' : '✗ SAI'}`);

    // --- Tokenization ---
    console.log('\n[1.4] TOKENIZATION (Thay thế bằng token ngẫu nhiên)');
    printSeparator('-', 60);
    const cccd1 = '012345678901';
    const cccd2 = '098765432109';
    const token1 = masking.tokenize(cccd1, 'cccd');
    const token2 = masking.tokenize(cccd2, 'cccd');
    const token1Again = masking.tokenize(cccd1, 'cccd');
    console.log(`  CCCD gốc 1 : ${cccd1}  →  Token: ${token1}`);
    console.log(`  CCCD gốc 2 : ${cccd2}  →  Token: ${token2}`);
    console.log(`  CCCD gốc 1 (lần 2): ${cccd1}  →  Token: ${token1Again} (deterministic? ${token1 === token1Again ? '✓' : '✗'})`);
    console.log(`  Detokenize  : ${token1}  →  ${masking.detokenize(token1)}`);

    // --- Format-Preserving Masking ---
    console.log('\n[1.5] FORMAT-PRESERVING MASKING (Giữ định dạng)');
    printSeparator('-', 60);
    const origPhone = '0912345678';
    const origSalary = 15000000.00;
    const origCCCD = '012345678901';
    console.log(`  SĐT gốc    : ${origPhone}  →  FP Mask: ${masking.fpMaskPhone(origPhone)}   (vẫn là SĐT hợp lệ)`);
    console.log(`  Lương gốc  : ${origSalary}  →  FP Mask: ${masking.fpMaskSalary(origSalary)} (cùng số chữ số)`);
    console.log(`  CCCD gốc   : ${origCCCD}  →  FP Mask: ${masking.fpMaskCCCD(origCCCD)}   (giữ mã tỉnh)`);
}

// ============================================================
// BƯỚC 2: ÁP DỤNG MASKING VÀO DATABASE MYSQL
// ============================================================

async function applyMaskingToDatabase(conn) {
    printHeader('BƯỚC 2: ÁP DỤNG DATA MASKING VÀO DATABASE MYSQL');

    console.log('\n[2.1] Đọc dữ liệu gốc từ bảng USERS...');
    const users = await conn.queryRows('SELECT * FROM users ORDER BY id');

    if (users.length === 0) {
        console.log('  ⚠️  Không có dữ liệu! Hãy chạy sql/setup.sql trước.');
        return;
    }

    console.log(`\n  Tìm thấy ${users.length} bản ghi. Dữ liệu GỐC (NHẠY CẢM):`);
    printTable(
        ['ID', 'Họ tên', 'Email', 'SĐT', 'CCCD', 'Lương'],
        users.map(u => [u.id, u.full_name, u.email, u.phone, u.cccd, u.salary]),
        [4, 18, 28, 12, 14, 14]
    );

    await conn.query('DELETE FROM masked_users');
    await conn.query('DELETE FROM token_map');

    console.log('\n[2.2] Áp dụng các kỹ thuật masking...');
    const maskedUsers = [];

    for (const user of users) {
        const masked = {
            id: user.id,
            full_name_masked: masking.maskName(user.full_name),
            email_static: masking.maskEmail(user.email),
            email_xor: masking.xorEncrypt(user.email, XOR_KEY),
            phone_static: masking.maskPhone(user.phone),
            phone_fpmasked: masking.fpMaskPhone(user.phone),
            cccd_token: masking.tokenize(user.cccd, 'cccd'),
            salary_xor: masking.aesEncrypt(String(user.salary), AES_KEY),
            birth_date_masked: masking.maskBirthDate(user.birth_date),
            address_masked: masking.maskAddress(user.address),
            mask_method: 'STATIC+XOR+AES+TOKEN+FP'
        };
        maskedUsers.push(masked);

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
                ${conn.escape(masked.salary_xor)},
                ${conn.escape(masked.birth_date_masked)},
                ${conn.escape(masked.address_masked)},
                ${conn.escape(masked.mask_method)}
            )`;
        await conn.query(sql);
        console.log(`  ✓ Đã mask user ID=${user.id} (${user.full_name})`);
    }

    console.log('\n[2.3] Lưu Token Map vào database (bí mật - server side)...');
    const tokenMap = masking.getTokenMap();
    for (const [token, info] of Object.entries(tokenMap)) {
        const sql = `INSERT INTO token_map (token, original, field_type)
                     VALUES (${conn.escape(token)}, ${conn.escape(info.original)}, ${conn.escape(info.fieldType)})
                     ON DUPLICATE KEY UPDATE original=VALUES(original)`;
        await conn.query(sql);
    }
    console.log(`  ✓ Đã lưu ${Object.keys(tokenMap).length} token(s)`);

    return maskedUsers;
}

// ============================================================
// BƯỚC 3: HIỂN THỊ DỮ LIỆU ĐÃ MASK (an toàn để truyền công khai)
// ============================================================

async function displayMaskedData(conn) {
    printHeader('BƯỚC 3: DỮ LIỆU SAU KHI MASK (AN TOÀN KHI TRUYỀN CÔNG KHAI)');

    const masked = await conn.queryRows('SELECT * FROM masked_users ORDER BY id');

    console.log('\n[3.1] Static Masking - Che giấu tĩnh:');
    printTable(
        ['ID', 'Tên (masked)', 'Email (static)', 'SĐT (static)', 'Ngày sinh (masked)'],
        masked.map(m => [m.id, m.full_name_masked, m.email_static, m.phone_static, m.birth_date_masked]),
        [4, 18, 25, 14, 18]
    );

    console.log('\n[3.2] XOR + AES Encryption - Dữ liệu mã hóa (có thể giải mã với key):');
    printTable(
        ['ID', 'Email XOR (hex)', 'Salary AES (hex, truncated)'],
        masked.map(m => [m.id, m.email_xor.substring(0, 40) + '...', m.salary_xor.substring(0, 35) + '...']),
        [4, 45, 40]
    );

    console.log('\n[3.3] Tokenization + Format-Preserving:');
    printTable(
        ['ID', 'CCCD Token', 'SĐT FP-Masked', 'Địa chỉ (masked)'],
        masked.map(m => [m.id, m.cccd_token, m.phone_fpmasked, m.address_masked]),
        [4, 30, 14, 20]
    );
}

// ============================================================
// BƯỚC 4: GIẢI MÃ DỮ LIỆU (phía nhận với key bí mật)
// ============================================================

async function decryptData(conn) {
    printHeader('BƯỚC 4: GIẢI MÃ DỮ LIỆU (PHÍA NHẬN CÓ KEY BÍ MẬT)');

    const masked = await conn.queryRows('SELECT * FROM masked_users ORDER BY id LIMIT 3');

    console.log('\n[4.1] Giải mã XOR (khôi phục Email gốc):');
    for (const m of masked) {
        const decryptedEmail = masking.xorDecrypt(m.email_xor, XOR_KEY);
        console.log(`  User ID ${m.id}: ${m.email_xor.substring(0, 25)}...  →  ${decryptedEmail}`);
    }

    console.log('\n[4.2] Giải mã AES (khôi phục Lương gốc):');
    for (const m of masked) {
        const decryptedSalary = masking.aesDecrypt(m.salary_xor, AES_KEY);
        console.log(`  User ID ${m.id}: AES[${m.salary_xor.substring(0, 20)}...]  →  ${decryptedSalary} VNĐ`);
    }

    console.log('\n[4.3] Detokenize (khôi phục CCCD từ token):');
    const tokens = await conn.queryRows("SELECT * FROM token_map WHERE field_type = 'cccd'");
    for (const t of tokens) {
        console.log(`  Token: ${t.token}  →  CCCD gốc: ${t.original}`);
    }

    console.log('\n[4.4] Static Masking - KHÔNG THỂ khôi phục (one-way, by design):');
    console.log('  Email static mask (***) → Không thể giải mã - đây là hành vi đúng');
    console.log('  Mục đích: dùng cho hiển thị UI, không cần dữ liệu gốc');
}

// ============================================================
// BƯỚC 5: MÔ PHỎNG TRUYỀN DỮ LIỆU QUA KÊNH CÔNG KHAI
// ============================================================

function simulatePublicChannelTransmission(maskedUsers) {
    printHeader('BƯỚC 5: MÔ PHỎNG TRUYỀN DỮ LIỆU QUA KÊNH CÔNG KHAI');

    console.log('\n[5.1] Dữ liệu được đóng gói JSON để truyền...');

    const payload = {
        timestamp: new Date().toISOString(),
        sender: 'DataMaskingServer_v1.0',
        recipient: 'PublicAPIClient',
        encryption: 'XOR+AES128+TOKEN+STATIC',
        data_note: 'Dữ liệu nhạy cảm đã được che giấu - an toàn để truyền công khai',
        records: maskedUsers ? maskedUsers.map(m => ({
            id: m.id,
            full_name: m.full_name_masked,
            email_display: m.email_static,
            email_encrypted: m.email_xor,
            phone_display: m.phone_static,
            phone_synthetic: m.phone_fpmasked,
            cccd_ref: m.cccd_token,
            salary_encrypted: m.salary_xor,
            birth_year: m.birth_date_masked,
            location: m.address_masked
        })) : []
    };

    const jsonPayload = JSON.stringify(payload, null, 2);

    console.log('\n  === PAYLOAD GỬI QUA KÊNH CÔNG KHAI ===');
    const samplePayload = {
        ...payload,
        records: payload.records.slice(0, 1)
    };
    console.log(JSON.stringify(samplePayload, null, 2));

    console.log(`\n  ✓ Tổng kích thước payload: ${jsonPayload.length} bytes`);
    console.log('  ✓ Không có dữ liệu nhạy cảm nào lộ ra trong payload!');
    console.log('  ✓ Kẻ tấn công chặn được payload vẫn KHÔNG đọc được dữ liệu thật');
}

// ============================================================
// BƯỚC 6: KIỂM TRA TÍNH ĐÚNG ĐẮN (Test Suite)
// ============================================================

function runTests() {
    printHeader('BƯỚC 6: KIỂM TRA TÍNH ĐÚNG ĐẮN CÁC THUẬT TOÁN');

    let passed = 0, failed = 0;

    function test(name, actual, expected) {
        if (actual === expected) {
            console.log(`  ✓ PASS: ${name}`);
            passed++;
        } else {
            console.log(`  ✗ FAIL: ${name}`);
            console.log(`    Expected: ${expected}`);
            console.log(`    Actual  : ${actual}`);
            failed++;
        }
    }

    // Test XOR
    const xorMsg = 'Hello, World! Xin chào Việt Nam 123';
    test('XOR encrypt/decrypt round-trip',
        masking.xorDecrypt(masking.xorEncrypt(xorMsg, XOR_KEY), XOR_KEY),
        xorMsg
    );

    // Test AES
    const aesMsgs = ['15000000.00', 'test@email.com', 'Short', 'ExactlyXXXXXXXXX'];
    for (const msg of aesMsgs) {
        test(`AES-128 round-trip: "${msg}"`,
            masking.aesDecrypt(masking.aesEncrypt(msg, AES_KEY), AES_KEY),
            msg
        );
    }

    // Test Static Masking
    test('maskPhone length preserved',
        masking.maskPhone('0912345678').length,
        10
    );
    test('maskPhone keeps first 3 digits',
        masking.maskPhone('0912345678').substring(0, 3),
        '091'
    );
    test('maskEmail preserves domain',
        masking.maskEmail('user@domain.com').includes('@domain.com'),
        true
    );

    // Test Tokenization
    const tok = masking.tokenize('SECRET_VALUE', 'test');
    test('tokenize deterministic',
        masking.tokenize('SECRET_VALUE', 'test'),
        tok
    );
    test('detokenize returns original',
        masking.detokenize(tok),
        'SECRET_VALUE'
    );

    // Test FP Masking
    const fpPhone = masking.fpMaskPhone('0912345678');
    test('fpMaskPhone preserves length',
        fpPhone.length,
        10
    );
    test('fpMaskPhone keeps network prefix',
        fpPhone.substring(0, 2),
        '09'
    );

    // Test Bytes utilities
    const testStr = 'Xin chào! Hello 123';
    const bytes = masking.stringToBytes(testStr);
    test('stringToBytes/bytesToString round-trip',
        masking.bytesToString(bytes),
        testStr
    );

    printSeparator('-', 60);
    console.log(`  Kết quả: ${passed} PASS, ${failed} FAIL`);
    if (failed === 0) console.log('  🎉 Tất cả test đều PASS!');
}

// ============================================================
// MAIN
// ============================================================

async function main() {
    console.log('\n');
    printSeparator('*');
    console.log('  CHƯƠNG TRÌNH QUẢN LÝ DỮ LIỆU AN TOÀN - DATA MASKING');
    console.log('  Ngôn ngữ: JavaScript (Node.js)  |  Database: MySQL');
    console.log('  Các kỹ thuật: Static | XOR | AES-128 | Token | FP-Mask');
    printSeparator('*');
    console.log('');

    // Bước 1: Demo thuật toán (không cần DB)
    demoMaskingAlgorithms();

    // Bước 6: Chạy test suite
    runTests();

    // Bước 2-5: Kết nối DB và thực hiện masking
    printHeader('KẾT NỐI MYSQL DATABASE');
    console.log(`\n  → Đang kết nối ${DB_CONFIG.host}:${DB_CONFIG.port}/${DB_CONFIG.database}...`);

    let conn = null;
    try {
        conn = new MySQLConnection(DB_CONFIG);
        await conn.connect();
        console.log('  ✓ Kết nối MySQL thành công!\n');

        const maskedUsers = await applyMaskingToDatabase(conn);
        await displayMaskedData(conn);
        await decryptData(conn);
        simulatePublicChannelTransmission(maskedUsers);

        printHeader('TỔNG KẾT');
        console.log('  ✓ Static Masking   : Che email, SĐT, tên, địa chỉ bằng *** (một chiều)');
        console.log('  ✓ XOR Cipher       : Mã hóa email có thể khôi phục (tự viết)');
        console.log('  ✓ AES-128          : Mã hóa lương 10 rounds (tự viết từ đầu)');
        console.log('  ✓ Tokenization     : CCCD → token ngẫu nhiên, lưu map bí mật');
        console.log('  ✓ FP Masking       : SĐT giả hợp lệ, CCCD giữ mã tỉnh');
        console.log('\n  Dữ liệu an toàn khi truyền qua kênh công khai!');
        printSeparator('*');

    } catch (err) {
        console.error('\n  ✗ Lỗi kết nối MySQL:', err.message);
        console.log('\n  → Hướng dẫn khắc phục:');
        console.log('    1. Kiểm tra MySQL đang chạy');
        console.log('    2. Chỉnh config/database.js (user, password, database)');
        console.log('    3. Chạy SQL setup: mysql -u root -p < sql/setup.sql');
        console.log('\n  → Các bước Demo (không cần DB) vẫn hoạt động bình thường ở trên.');
    } finally {
        if (conn) await conn.close();
    }
}

main().catch(console.error);
