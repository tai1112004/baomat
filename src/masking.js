// ============================================================
// src/masking.js
// Các thuật toán Data Masking TỰ VIẾT - KHÔNG dùng thư viện
// ============================================================

// ============================================================
// PHẦN 1: TIỆN ÍCH CƠ BẢN (tự implement)
// ============================================================

/**
 * Chuyển chuỗi sang mảng byte UTF-8 (tự viết, không dùng Buffer lib)
 * Mỗi ký tự ASCII = 1 byte, ký tự Unicode dùng encoding thủ công
 */
function stringToBytes(str) {
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
        const code = str.charCodeAt(i);
        if (code < 0x80) {
            // ASCII: 1 byte
            bytes.push(code);
        } else if (code < 0x800) {
            // 2 bytes
            bytes.push(0xC0 | (code >> 6));
            bytes.push(0x80 | (code & 0x3F));
        } else {
            // 3 bytes
            bytes.push(0xE0 | (code >> 12));
            bytes.push(0x80 | ((code >> 6) & 0x3F));
            bytes.push(0x80 | (code & 0x3F));
        }
    }
    return bytes;
}

/**
 * Chuyển mảng byte UTF-8 về chuỗi (tự viết)
 */
function bytesToString(bytes) {
    let str = '';
    let i = 0;
    while (i < bytes.length) {
        const byte = bytes[i];
        if ((byte & 0x80) === 0) {
            // 1 byte ASCII
            str += String.fromCharCode(byte);
            i += 1;
        } else if ((byte & 0xE0) === 0xC0) {
            // 2 bytes
            const code = ((byte & 0x1F) << 6) | (bytes[i + 1] & 0x3F);
            str += String.fromCharCode(code);
            i += 2;
        } else {
            // 3 bytes
            const code = ((byte & 0x0F) << 12) | ((bytes[i + 1] & 0x3F) << 6) | (bytes[i + 2] & 0x3F);
            str += String.fromCharCode(code);
            i += 3;
        }
    }
    return str;
}

/**
 * Chuyển số thành chuỗi HEX 2 ký tự (tự viết, không dùng toString(16))
 */
function byteToHex(byte) {
    const HEX_CHARS = '0123456789ABCDEF';
    return HEX_CHARS[(byte >> 4) & 0x0F] + HEX_CHARS[byte & 0x0F];
}

/**
 * Chuyển chuỗi HEX về số (tự viết)
 */
function hexToByte(hex) {
    const h = hex.toUpperCase();
    const high = h.charCodeAt(0) <= 57 ? h.charCodeAt(0) - 48 : h.charCodeAt(0) - 55;
    const low = h.charCodeAt(1) <= 57 ? h.charCodeAt(1) - 48 : h.charCodeAt(1) - 55;
    return (high << 4) | low;
}

/**
 * Chuyển mảng byte thành chuỗi HEX (tự viết)
 */
function bytesToHex(bytes) {
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += byteToHex(bytes[i]);
    }
    return hex;
}

/**
 * Chuyển chuỗi HEX về mảng byte (tự viết)
 */
function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(hexToByte(hex.substring(i, i + 2)));
    }
    return bytes;
}

/**
 * Sinh số ngẫu nhiên trong khoảng [min, max) (tự viết LCG - Linear Congruential Generator)
 */
let _lcgSeed = Date.now() % 2147483647;
function lcgRandom() {
    _lcgSeed = (_lcgSeed * 1103515245 + 12345) & 0x7FFFFFFF;
    return _lcgSeed / 0x7FFFFFFF;
}
function randInt(min, max) {
    return min + Math.floor(lcgRandom() * (max - min));
}

// ============================================================
// PHẦN 2: STATIC MASKING (Che giấu tĩnh)
// ============================================================

/**
 * Static Masking cho SỐ ĐIỆN THOẠI
 * Giữ 3 số đầu và 2 số cuối, che phần giữa bằng ***
 * VD: "0912345678" → "091*****78"
 */
function maskPhone(phone) {
    if (!phone || phone.length < 6) return '***';
    const cleaned = phone.trim();
    const len = cleaned.length;
    const keepStart = 3;
    const keepEnd = 2;
    const maskLen = len - keepStart - keepEnd;

    let result = '';
    for (let i = 0; i < keepStart; i++) result += cleaned[i];
    for (let i = 0; i < maskLen; i++) result += '*';
    for (let i = len - keepEnd; i < len; i++) result += cleaned[i];
    return result;
}

/**
 * Static Masking cho EMAIL
 * Che phần local, giữ ký tự đầu và domain
 * VD: "nguyenvanan@gmail.com" → "ng*******@gmail.com"
 */
function maskEmail(email) {
    if (!email || !email.includes('@')) return '***@***.***';

    let atPos = -1;
    for (let i = 0; i < email.length; i++) {
        if (email[i] === '@') { atPos = i; break; }
    }

    const local = email.substring(0, atPos);
    const domain = email.substring(atPos); // "@gmail.com"

    if (local.length <= 2) return local[0] + '*' + domain;

    let masked = local[0] + local[1];
    for (let i = 2; i < local.length; i++) masked += '*';
    return masked + domain;
}

/**
 * Static Masking cho HỌ TÊN
 * Giữ ký tự đầu mỗi từ, che phần còn lại
 * VD: "Nguyễn Văn An" → "N****** V** A*"
 */
function maskName(name) {
    if (!name) return '***';
    const words = [];
    let word = '';
    for (let i = 0; i <= name.length; i++) {
        const ch = i < name.length ? name[i] : ' ';
        if (ch === ' ') {
            if (word.length > 0) words.push(word);
            word = '';
        } else {
            word += ch;
        }
    }

    const maskedWords = [];
    for (let w = 0; w < words.length; w++) {
        let m = words[w][0];
        for (let i = 1; i < words[w].length; i++) m += '*';
        maskedWords.push(m);
    }

    return maskedWords.join(' ');
}

/**
 * Static Masking cho ĐỊA CHỈ
 * Che toàn bộ số nhà và tên đường, giữ quận/tỉnh
 * VD: "123 Nguyễn Huệ, Q1, TP.HCM" → "***, ***, TP.HCM"
 */
function maskAddress(address) {
    if (!address) return '***';
    const parts = [];
    let part = '';
    for (let i = 0; i <= address.length; i++) {
        const ch = i < address.length ? address[i] : ',';
        if (ch === ',') {
            parts.push(part.trim());
            part = '';
        } else {
            part += ch;
        }
    }

    const maskedParts = [];
    for (let i = 0; i < parts.length; i++) {
        // Giữ phần tỉnh/thành phố (phần cuối)
        if (i === parts.length - 1) {
            maskedParts.push(parts[i]);
        } else {
            maskedParts.push('***');
        }
    }
    return maskedParts.join(', ');
}

/**
 * Static Masking cho NGÀY SINH
 * Giữ năm, che tháng và ngày
 * VD: "1990-05-15" → "1990-**-**"
 */
function maskBirthDate(dateStr) {
    if (!dateStr) return '****-**-**';
    const str = typeof dateStr === 'object' ? dateStr.toISOString().substring(0, 10) : dateStr.toString().substring(0, 10);
    // Giữ năm, ẩn tháng và ngày
    const year = str.substring(0, 4);
    return year + '-**-**';
}

// ============================================================
// PHẦN 3: XOR CIPHER (Mã hóa XOR tự viết)
// ============================================================

/**
 * Mở rộng key để khớp độ dài plaintext (Key Stretching đơn giản)
 * Lặp lại key và trộn với vị trí để tăng độ phức tạp
 */
function stretchKey(keyBytes, targetLen) {
    const stretched = [];
    for (let i = 0; i < targetLen; i++) {
        // Kết hợp key byte + vị trí + byte kế tiếp để tránh pattern lặp
        const k1 = keyBytes[i % keyBytes.length];
        const k2 = keyBytes[(i + 1) % keyBytes.length];
        stretched.push((k1 ^ (i & 0xFF) ^ (k2 >> 1)) & 0xFF);
    }
    return stretched;
}

/**
 * XOR Encrypt: text XOR key → chuỗi HEX
 * @param {string} plaintext  - Văn bản gốc
 * @param {string} key        - Khóa bí mật
 * @returns {string}          - Ciphertext dạng HEX
 */
function xorEncrypt(plaintext, key) {
    const ptBytes = stringToBytes(plaintext);
    const keyBytes = stringToBytes(key);
    const keyStream = stretchKey(keyBytes, ptBytes.length);

    const cipherBytes = [];
    for (let i = 0; i < ptBytes.length; i++) {
        cipherBytes.push(ptBytes[i] ^ keyStream[i]);
    }
    return bytesToHex(cipherBytes);
}

/**
 * XOR Decrypt: chuỗi HEX → text gốc
 * @param {string} cipherHex  - Ciphertext dạng HEX
 * @param {string} key        - Khóa bí mật (phải trùng với lúc mã hóa)
 * @returns {string}          - Plaintext gốc
 */
function xorDecrypt(cipherHex, key) {
    const cipherBytes = hexToBytes(cipherHex);
    const keyBytes = stringToBytes(key);
    const keyStream = stretchKey(keyBytes, cipherBytes.length);

    const ptBytes = [];
    for (let i = 0; i < cipherBytes.length; i++) {
        ptBytes.push(cipherBytes[i] ^ keyStream[i]);
    }
    return bytesToString(ptBytes);
}

// ============================================================
// PHẦN 4: AES-128 TỰ VIẾT (ECB mode)
// ============================================================

// S-Box chuẩn AES (256 giá trị cố định theo đặc tả AES/FIPS-197)
const AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

// Inverse S-Box (dùng cho giải mã)
const AES_INV_SBOX = (function () {
    const inv = new Array(256);
    for (let i = 0; i < 256; i++) inv[AES_SBOX[i]] = i;
    return inv;
})();

// Round constants cho Key Expansion
const AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/**
 * GF(2^8) multiplication - nhân trong trường Galois (phép XOR + shift)
 * Đây là phép nhân modulo đa thức bất khả quy x^8 + x^4 + x^3 + x + 1
 */
function gfMul(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        const hiBit = a & 0x80;
        a = (a << 1) & 0xFF;
        if (hiBit) a ^= 0x1B; // polynomial reduction
        b >>= 1;
    }
    return p;
}

/**
 * AES Key Expansion: từ 16-byte key → 11 round keys (176 bytes)
 */
function aesKeyExpansion(key16) {
    const w = []; // 44 words (4 bytes each)

    // 4 words đầu = key gốc
    for (let i = 0; i < 4; i++) {
        w.push([key16[4 * i], key16[4 * i + 1], key16[4 * i + 2], key16[4 * i + 3]]);
    }

    for (let i = 4; i < 44; i++) {
        let temp = [...w[i - 1]];
        if (i % 4 === 0) {
            // RotWord: xoay trái 1 byte
            temp = [temp[1], temp[2], temp[3], temp[0]];
            // SubWord: áp dụng S-Box
            temp = temp.map(b => AES_SBOX[b]);
            // XOR với Rcon
            temp[0] ^= AES_RCON[i / 4 - 1];
        }
        w.push(w[i - 4].map((b, j) => b ^ temp[j]));
    }

    // Chuyển thành 11 round keys, mỗi key 16 bytes
    
    const roundKeys = [];
    for (let r = 0; r < 11; r++) {
        const rk = [];
        for (let c = 0; c < 4; c++) {
            for (let b = 0; b < 4; b++) rk.push(w[r * 4 + c][b]);
        }
        roundKeys.push(rk);
    }
    return roundKeys;
}

/**
 * AES SubBytes: thay thế từng byte qua S-Box
 */
function aesSubBytes(state) {
    return state.map(b => AES_SBOX[b]);
}

/**
 * AES InvSubBytes: thay thế ngược
 */
function aesInvSubBytes(state) {
    return state.map(b => AES_INV_SBOX[b]);
}

/**
 * AES ShiftRows: dịch vòng các hàng trong state 4x4
 * Hàng 0: không dịch, Hàng 1: dịch 1, Hàng 2: dịch 2, Hàng 3: dịch 3
 */
function aesShiftRows(state) {
    const s = [...state];
    // Hàng 1: dịch trái 1
    let tmp = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = tmp;
    // Hàng 2: dịch trái 2
    tmp = s[2]; s[2] = s[10]; s[10] = tmp;
    tmp = s[6]; s[6] = s[14]; s[14] = tmp;
    // Hàng 3: dịch trái 3 (= phải 1)
    tmp = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = tmp;
    return s;
}

/**
 * AES InvShiftRows: dịch ngược
 */
function aesInvShiftRows(state) {
    const s = [...state];
    let tmp = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = tmp;
    tmp = s[2]; s[2] = s[10]; s[10] = tmp;
    tmp = s[6]; s[6] = s[14]; s[14] = tmp;
    tmp = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = tmp;
    return s;
}

/**
 * AES MixColumns: trộn từng cột sử dụng phép nhân GF(2^8)
 */
function aesMixColumns(state) {
    const result = new Array(16);
    for (let c = 0; c < 4; c++) {
        const i = c * 4;
        const r0 = state[i], r1 = state[i + 1], r2 = state[i + 2], r3 = state[i + 3];
        result[i] = gfMul(0x02, r0) ^ gfMul(0x03, r1) ^ r2 ^ r3;
        result[i + 1] = r0 ^ gfMul(0x02, r1) ^ gfMul(0x03, r2) ^ r3;
        result[i + 2] = r0 ^ r1 ^ gfMul(0x02, r2) ^ gfMul(0x03, r3);
        result[i + 3] = gfMul(0x03, r0) ^ r1 ^ r2 ^ gfMul(0x02, r3);
    }
    return result;
}

/**
 * AES InvMixColumns
 */
function aesInvMixColumns(state) {
    const result = new Array(16);
    for (let c = 0; c < 4; c++) {
        const i = c * 4;
        const r0 = state[i], r1 = state[i + 1], r2 = state[i + 2], r3 = state[i + 3];
        result[i] = gfMul(0x0e, r0) ^ gfMul(0x0b, r1) ^ gfMul(0x0d, r2) ^ gfMul(0x09, r3);
        result[i + 1] = gfMul(0x09, r0) ^ gfMul(0x0e, r1) ^ gfMul(0x0b, r2) ^ gfMul(0x0d, r3);
        result[i + 2] = gfMul(0x0d, r0) ^ gfMul(0x09, r1) ^ gfMul(0x0e, r2) ^ gfMul(0x0b, r3);
        result[i + 3] = gfMul(0x0b, r0) ^ gfMul(0x0d, r1) ^ gfMul(0x09, r2) ^ gfMul(0x0e, r3);
    }
    return result;
}

/**
 * AES AddRoundKey: XOR state với round key
 */
function aesAddRoundKey(state, roundKey) {
    return state.map((b, i) => b ^ roundKey[i]);
}

/**
 * Mã hóa 1 block 16 bytes với AES-128
 */
function aesEncryptBlock(block16, roundKeys) {
    let state = aesAddRoundKey([...block16], roundKeys[0]);

    for (let round = 1; round <= 9; round++) {
        state = aesSubBytes(state);
        state = aesShiftRows(state);
        state = aesMixColumns(state);
        state = aesAddRoundKey(state, roundKeys[round]);
    }
    // Round cuối không có MixColumns
    state = aesSubBytes(state);
    state = aesShiftRows(state);
    state = aesAddRoundKey(state, roundKeys[10]);

    return state;
}

/**
 * Giải mã 1 block 16 bytes với AES-128
 */
function aesDecryptBlock(block16, roundKeys) {
    let state = aesAddRoundKey([...block16], roundKeys[10]);

    for (let round = 9; round >= 1; round--) {
        state = aesInvShiftRows(state);
        state = aesInvSubBytes(state);
        state = aesAddRoundKey(state, roundKeys[round]);
        state = aesInvMixColumns(state);
    }
    state = aesInvShiftRows(state);
    state = aesInvSubBytes(state);
    state = aesAddRoundKey(state, roundKeys[0]);

    return state;
}

/**
 * PKCS#7 Padding: thêm padding để độ dài chia hết cho 16
 */
function pkcs7Pad(bytes) {
    const padLen = 16 - (bytes.length % 16);
    const padded = [...bytes];
    for (let i = 0; i < padLen; i++) padded.push(padLen);
    return padded;
}

/**
 * PKCS#7 Unpadding: loại bỏ padding
 */
function pkcs7Unpad(bytes) {
    if (!bytes || bytes.length === 0) return bytes;
    const padLen = bytes[bytes.length - 1];
    if (padLen <= 0 || padLen > 16) throw new Error("Invalid padding");
    return bytes.slice(0, bytes.length - padLen);
}

/**
 * SHA-1 tự implement
 */
function leftRotate(n, b) { return ((n << b) | (n >>> (32 - b))) >>> 0; }
function concatBytes(a, b) {
    const r = new Array(a.length + b.length);
    for (let i = 0; i < a.length; i++) r[i] = a[i];
    for (let i = 0; i < b.length; i++) r[a.length + i] = b[i];
    return r;
}
function sha1(message) {
    let msg = [...message];
    let originalBitLen = msg.length * 8;
    msg.push(0x80);
    while (msg.length % 64 !== 56) msg.push(0x00);
    msg.push(0, 0, 0, 0); // Assuming length fits in bottom 32 bits
    msg.push((originalBitLen >>> 24) & 0xff);
    msg.push((originalBitLen >>> 16) & 0xff);
    msg.push((originalBitLen >>> 8) & 0xff);
    msg.push(originalBitLen & 0xff);

    let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;

    for (let i = 0; i < msg.length; i += 64) {
        let w = new Array(80);
        for (let j = 0; j < 16; j++) {
            w[j] = ((msg[i + j * 4] << 24) | (msg[i + j * 4 + 1] << 16) | (msg[i + j * 4 + 2] << 8) | msg[i + j * 4 + 3]) >>> 0;
        }
        for (let j = 16; j < 80; j++) {
            w[j] = leftRotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
        }

        let a = h0, b = h1, c = h2, d = h3, e = h4;

        for (let j = 0; j < 80; j++) {
            let f, k;
            if (j < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
            else if (j < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (j < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            let temp = (leftRotate(a, 5) + f + e + k + w[j]) >>> 0;
            e = d; d = c; c = leftRotate(b, 30); b = a; a = temp;
        }

        h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
    }

    return [(h0 >>> 24) & 0xff, (h0 >>> 16) & 0xff, (h0 >>> 8) & 0xff, h0 & 0xff,
    (h1 >>> 24) & 0xff, (h1 >>> 16) & 0xff, (h1 >>> 8) & 0xff, h1 & 0xff,
    (h2 >>> 24) & 0xff, (h2 >>> 16) & 0xff, (h2 >>> 8) & 0xff, h2 & 0xff,
    (h3 >>> 24) & 0xff, (h3 >>> 16) & 0xff, (h3 >>> 8) & 0xff, h3 & 0xff,
    (h4 >>> 24) & 0xff, (h4 >>> 16) & 0xff, (h4 >>> 8) & 0xff, h4 & 0xff];
}

/**
 * Tự implement custom HMAC
 * HMAC = SHA1(key + SHA1(key + data))
 */
function hmacSha1(keyStr, dataStr) {
    const k = stringToBytes(keyStr);
    const d = stringToBytes(dataStr);
    const inner = sha1(concatBytes(k, d));
    const outer = sha1(concatBytes(k, inner));
    return bytesToHex(outer); // Trả về 40 ký tự hex
}

/**
 * Chuẩn hóa key về đúng 16 bytes (AES-128)
 * Nếu key < 16 bytes: pad bằng 0
 * Nếu key > 16 bytes: lấy 16 bytes đầu
 */
function normalizeKey16(keyStr) {
    const keyBytes = stringToBytes(keyStr);
    const key16 = new Array(16).fill(0);
    for (let i = 0; i < 16 && i < keyBytes.length; i++) key16[i] = keyBytes[i];
    return key16;
}

/**
 * AES-128 CBC Encrypt (tự implement + random IV)
 * Trả về: HMAC(40 hex chars) + IV(32 hex chars) + Khối mã hóa(tùy ý)
 */
function aesEncrypt(plaintext, keyStr) {
    const key16 = normalizeKey16(keyStr);
    const roundKeys = aesKeyExpansion(key16);
    const ptBytes = pkcs7Pad(stringToBytes(plaintext));

    const cipherBytes = [];

    // Tạo 16 byte IV ngẫu nhiên
    let iv = [];
    for (let i = 0; i < 16; i++) iv.push(randInt(0, 256));
    let prevBlock = iv;

    // Ghi IV vào đầu
    for (let i = 0; i < 16; i++) cipherBytes.push(iv[i]);

    for (let i = 0; i < ptBytes.length; i += 16) {
        const block = ptBytes.slice(i, i + 16);
        for (let j = 0; j < 16; j++) block[j] ^= prevBlock[j]; // CBC mode
        const encBlock = aesEncryptBlock(block, roundKeys);
        for (const b of encBlock) cipherBytes.push(b);
        prevBlock = encBlock;
    }
    const cipherHex = bytesToHex(cipherBytes);
    // Sinh MAC bằng cách băm chuỗi hex đã chạy IV + CipherText
    const mac = hmacSha1(keyStr, cipherHex);
    return mac + cipherHex;
}

/**
 * AES-128 CBC Decrypt (tự implement hoàn toàn) + Check integrity
 */
function aesDecrypt(macAndCipherHex, keyStr) {
    if (!macAndCipherHex || macAndCipherHex.length < 72) return "(Lỗi d.l. hoặc rỗng)"; // MAC=40 + IV=32

    const mac = macAndCipherHex.substring(0, 40);
    const cipherHex = macAndCipherHex.substring(40);

    // Kiểm tra tính toàn vẹn (Integrity check)
    const expectedMac = hmacSha1(keyStr, cipherHex);
    if (mac !== expectedMac) {
        return "HMAC verification failed! Dữ liệu bị giả mạo.";
    }

    const key16 = normalizeKey16(keyStr);
    const roundKeys = aesKeyExpansion(key16);
    const fullBytes = hexToBytes(cipherHex);

    const iv = fullBytes.slice(0, 16);
    let prevBlock = iv;
    const ptBytes = [];

    for (let i = 16; i < fullBytes.length; i += 16) {
        const block = fullBytes.slice(i, i + 16);
        const decBlock = aesDecryptBlock(block, roundKeys);
        for (let j = 0; j < 16; j++) decBlock[j] ^= prevBlock[j]; // CBC un-chain
        for (const b of decBlock) ptBytes.push(b);
        prevBlock = block;
    }

    try {
        const unpadded = pkcs7Unpad(ptBytes);
        return bytesToString(unpadded);
    } catch (e) {
        return "(Lỗi Decrypt/Unpad)";
    }
}

// ============================================================
// PHẦN 5: TOKENIZATION (Thay thế bằng token ngẫu nhiên)
// ============================================================

// Token store lưu trong bộ nhớ (in-memory)
const _tokenStore = {};

/**
 * Sinh chuỗi token ngẫu nhiên độ dài 32 ký tự (tự viết, không dùng crypto)
 * Sử dụng LCG kết hợp timestamp để tạo entropy
 */
function generateToken(prefix) {
    const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let token = (prefix || 'TK') + '_';
    const tokenLen = 24;

    for (let i = 0; i < tokenLen; i++) {
        token += CHARS[randInt(0, CHARS.length)];
    }
    return token;
}

/**
 * Tokenize: thay thế giá trị gốc bằng token ngẫu nhiên
 * @param {string} original  - Giá trị gốc
 * @param {string} fieldType - Loại trường (cccd, salary, ...)
 * @returns {string}         - Token đại diện
 */
function tokenize(original, fieldType) {
    // Kiểm tra xem giá trị này đã có token chưa (deterministic)
    for (const tok in _tokenStore) {
        if (_tokenStore[tok].original === String(original) &&
            _tokenStore[tok].fieldType === fieldType) {
            return tok;
        }
    }
    const token = generateToken(fieldType.toUpperCase().substring(0, 3));
    _tokenStore[token] = { original: String(original), fieldType };
    return token;
}

/**
 * Detokenize: khôi phục giá trị gốc từ token
 * @param {string} token - Token cần giải
 * @returns {string}     - Giá trị gốc, hoặc null nếu không tìm thấy
 */
function detokenize(token) {
    return _tokenStore[token] ? _tokenStore[token].original : null;
}

/**
 * Lấy toàn bộ token map để lưu vào database
 */
function getTokenMap() {
    return _tokenStore;
}

// ============================================================
// PHẦN 6: FORMAT-PRESERVING MASKING (Giữ định dạng gốc)
// ============================================================

/**
 * FP Masking cho SỐ ĐIỆN THOẠI
 * Thay số thật bằng số ngẫu nhiên, giữ đúng định dạng
 * VD: "0912345678" → "0834719265" (vẫn là số ĐT hợp lệ)
 */
function fpMaskPhone(phone) {
    if (!phone) return '0900000000';
    const cleaned = phone.trim();

    let result = cleaned[0]; // '0'
    result += cleaned[1];     // mã mạng

    const DIGITS = '0123456789';
    for (let i = 2; i < cleaned.length; i++) {
        result += DIGITS[randInt(0, 10)];
    }
    return result;
}

/**
 * FP Masking cho SỐ TIỀN LƯƠNG
 * Giữ nguyên số chữ số, thay bằng giá trị ngẫu nhiên cùng bậc
 * VD: 15000000.00 → 23847291.00 (vẫn là số 8 chữ số)
 */
function fpMaskSalary(salary) {
    const salaryStr = String(Math.floor(parseFloat(salary)));
    const numDigits = salaryStr.length;

    const DIGITS = '0123456789';
    let result = '';
    result += DIGITS[randInt(1, 10)];
    for (let i = 1; i < numDigits; i++) {
        result += DIGITS[randInt(0, 10)];
    }
    return result + '.00';
}

/**
 * FP Masking cho CCCD
 * Giữ 3 số đầu (mã tỉnh), sinh 9 số còn lại
 * VD: "012345678901" → "012839471023"
 */
function fpMaskCCCD(cccd) {
    if (!cccd) return '000000000000';
    const cleaned = cccd.trim();
    const DIGITS = '0123456789';

    let result = cleaned.substring(0, 3);
    for (let i = 3; i < cleaned.length; i++) {
        result += DIGITS[randInt(0, 10)];
    }
    return result;
}

// ============================================================
// EXPORTS
// ============================================================

module.exports = {
    // Static Masking
    maskPhone,
    maskEmail,
    maskName,
    maskAddress,
    maskBirthDate,

    // XOR Cipher
    xorEncrypt,
    xorDecrypt,

    // AES-128 (tự implement)
    aesEncrypt,
    aesDecrypt,

    // Tokenization
    tokenize,
    detokenize,
    getTokenMap,

    // Format-Preserving Masking
    fpMaskPhone,
    fpMaskSalary,
    fpMaskCCCD,

    // Utilities (export để test)
    stringToBytes,
    bytesToString,
    bytesToHex,
    hexToBytes,
};
