// ============================================================
// src/masking.js
// CÃ¡c thuáº­t toÃ¡n Data Masking Tá»° VIáº¾T - KHÃ”NG dÃ¹ng thÆ° viá»‡n
// ============================================================

// ============================================================
// PHáº¦N 1: TIá»†N ÃCH CÆ  Báº¢N (tá»± implement)
// ============================================================

/**
 * Chuyá»ƒn chuá»—i sang máº£ng byte UTF-8 (tá»± viáº¿t, khÃ´ng dÃ¹ng Buffer lib)
 * Má»—i kÃ½ tá»± ASCII = 1 byte, kÃ½ tá»± Unicode dÃ¹ng encoding thá»§ cÃ´ng
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
 * Chuyá»ƒn máº£ng byte UTF-8 vá» chuá»—i (tá»± viáº¿t)
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
 * Chuyá»ƒn sá»‘ thÃ nh chuá»—i HEX 2 kÃ½ tá»± (tá»± viáº¿t, khÃ´ng dÃ¹ng toString(16))
 */
function byteToHex(byte) {
    const HEX_CHARS = '0123456789ABCDEF';
    return HEX_CHARS[(byte >> 4) & 0x0F] + HEX_CHARS[byte & 0x0F];
}

/**
 * Chuyá»ƒn chuá»—i HEX vá» sá»‘ (tá»± viáº¿t)
 */
function hexToByte(hex) {
    const h = hex.toUpperCase();
    const high = h.charCodeAt(0) <= 57 ? h.charCodeAt(0) - 48 : h.charCodeAt(0) - 55;
    const low = h.charCodeAt(1) <= 57 ? h.charCodeAt(1) - 48 : h.charCodeAt(1) - 55;
    return (high << 4) | low;
}

/**
 * Chuyá»ƒn máº£ng byte thÃ nh chuá»—i HEX (tá»± viáº¿t)
 */
function bytesToHex(bytes) {
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += byteToHex(bytes[i]);
    }
    return hex;
}

/**
 * Chuyá»ƒn chuá»—i HEX vá» máº£ng byte (tá»± viáº¿t)
 */
function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(hexToByte(hex.substring(i, i + 2)));
    }
    return bytes;
}

/**
 * Sinh sá»‘ ngáº«u nhiÃªn trong khoáº£ng [min, max) (tá»± viáº¿t LCG - Linear Congruential Generator)
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
// PHáº¦N 2: STATIC MASKING (Che giáº¥u tÄ©nh)
// ============================================================

/**
 * Static Masking cho Sá» ÄIá»†N THOáº I
 * Giá»¯ 3 sá»‘ Ä‘áº§u vÃ  2 sá»‘ cuá»‘i, che pháº§n giá»¯a báº±ng ***
 * VD: "0912345678" â†’ "091*****78"
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
 * Che pháº§n local, giá»¯ kÃ½ tá»± Ä‘áº§u vÃ  domain
 * VD: "nguyenvanan@gmail.com" â†’ "ng*******@gmail.com"
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
 * Static Masking cho Há»Œ TÃŠN
 * Giá»¯ kÃ½ tá»± Ä‘áº§u má»—i tá»«, che pháº§n cÃ²n láº¡i
 * VD: "Nguyá»…n VÄƒn An" â†’ "N****** V** A*"
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
 * Static Masking cho Äá»ŠA CHá»ˆ
 * Che toÃ n bá»™ sá»‘ nhÃ  vÃ  tÃªn Ä‘Æ°á»ng, giá»¯ quáº­n/tá»‰nh
 * VD: "123 Nguyá»…n Huá»‡, Q1, TP.HCM" â†’ "***, ***, TP.HCM"
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
        // Giá»¯ pháº§n tá»‰nh/thÃ nh phá»‘ (pháº§n cuá»‘i)
        if (i === parts.length - 1) {
            maskedParts.push(parts[i]);
        } else {
            maskedParts.push('***');
        }
    }
    return maskedParts.join(', ');
}

/**
 * Static Masking cho NGÃ€Y SINH
 * Giá»¯ nÄƒm, che thÃ¡ng vÃ  ngÃ y
 * VD: "1990-05-15" â†’ "1990-**-**"
 */
function maskBirthDate(dateStr) {
    if (!dateStr) return '****-**-**';
    const str = typeof dateStr === 'object' ? dateStr.toISOString().substring(0, 10) : dateStr.toString().substring(0, 10);
    // Giá»¯ nÄƒm, áº©n thÃ¡ng vÃ  ngÃ y
    const year = str.substring(0, 4);
    return year + '-**-**';
}

// ============================================================
// PHáº¦N 3: XOR CIPHER (MÃ£ hÃ³a XOR tá»± viáº¿t)
// ============================================================

/**
 * Má»Ÿ rá»™ng key Ä‘á»ƒ khá»›p Ä‘á»™ dÃ i plaintext (Key Stretching Ä‘Æ¡n giáº£n)
 * Láº·p láº¡i key vÃ  trá»™n vá»›i vá»‹ trÃ­ Ä‘á»ƒ tÄƒng Ä‘á»™ phá»©c táº¡p
 */
function stretchKey(keyBytes, targetLen) {
    const stretched = [];
    for (let i = 0; i < targetLen; i++) {
        // Káº¿t há»£p key byte + vá»‹ trÃ­ + byte káº¿ tiáº¿p Ä‘á»ƒ trÃ¡nh pattern láº·p
        const k1 = keyBytes[i % keyBytes.length];
        const k2 = keyBytes[(i + 1) % keyBytes.length];
        stretched.push((k1 ^ (i & 0xFF) ^ (k2 >> 1)) & 0xFF);
    }
    return stretched;
}

/**
 * XOR Encrypt: text XOR key â†’ chuá»—i HEX
 * @param {string} plaintext  - VÄƒn báº£n gá»‘c
 * @param {string} key        - KhÃ³a bÃ­ máº­t
 * @returns {string}          - Ciphertext dáº¡ng HEX
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
 * XOR Decrypt: chuá»—i HEX â†’ text gá»‘c
 * @param {string} cipherHex  - Ciphertext dáº¡ng HEX
 * @param {string} key        - KhÃ³a bÃ­ máº­t (pháº£i trÃ¹ng vá»›i lÃºc mÃ£ hÃ³a)
 * @returns {string}          - Plaintext gá»‘c
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
// PHáº¦N 4: AES-128 Tá»° VIáº¾T (ECB mode)
// ============================================================

// S-Box chuáº©n AES (256 giÃ¡ trá»‹ cá»‘ Ä‘á»‹nh theo Ä‘áº·c táº£ AES/FIPS-197)
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

// Inverse S-Box (dÃ¹ng cho giáº£i mÃ£)
const AES_INV_SBOX = (function () {
    const inv = new Array(256);
    for (let i = 0; i < 256; i++) inv[AES_SBOX[i]] = i;
    return inv;
})();

// Round constants cho Key Expansion
const AES_RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d, 0x9a
];

/**
 * GF(2^8) multiplication - nhÃ¢n trong trÆ°á»ng Galois (phÃ©p XOR + shift)
 * ÄÃ¢y lÃ  phÃ©p nhÃ¢n modulo Ä‘a thá»©c báº¥t kháº£ quy x^8 + x^4 + x^3 + x + 1
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
 * AES Key Expansion: tá»« 16-byte key â†’ 11 round keys (176 bytes)
 */
function getAesConfig(keySizeBits) {
    if (keySizeBits === 192) return { keySizeBits: 192, nk: 6, nr: 12 };
    if (keySizeBits === 256) return { keySizeBits: 256, nk: 8, nr: 14 };
    return { keySizeBits: 128, nk: 4, nr: 10 };
}

function rotateWord(word) {
    return [word[1], word[2], word[3], word[0]];
}

function subWord(word) {
    return word.map(b => AES_SBOX[b]);
}

function xorWords(a, b) {
    return a.map((value, index) => value ^ b[index]);
}

function aesKeyExpansion(keyBytes, keySizeBits) {
    const { nk, nr } = getAesConfig(keySizeBits);
    const totalWords = 4 * (nr + 1);
    const words = [];

    for (let i = 0; i < nk; i++) {
        words.push([
            keyBytes[4 * i],
            keyBytes[4 * i + 1],
            keyBytes[4 * i + 2],
            keyBytes[4 * i + 3]
        ]);
    }

    for (let i = nk; i < totalWords; i++) {
        let temp = [...words[i - 1]];
        if (i % nk === 0) {
            temp = subWord(rotateWord(temp));
            temp[0] ^= AES_RCON[(i / nk) - 1];
        } else if (nk > 6 && i % nk === 4) {
            temp = subWord(temp);
        }
        words.push(xorWords(words[i - nk], temp));
    }

    const roundKeys = [];
    for (let round = 0; round <= nr; round++) {
        const roundKey = [];
        for (let column = 0; column < 4; column++) {
            for (let byteIndex = 0; byteIndex < 4; byteIndex++) {
                roundKey.push(words[round * 4 + column][byteIndex]);
            }
        }
        roundKeys.push(roundKey);
    }
    return roundKeys;
}

function aesSubBytes(state) {
    return state.map(b => AES_SBOX[b]);
}

/**
 * AES InvSubBytes: thay tháº¿ ngÆ°á»£c
 */
function aesInvSubBytes(state) {
    return state.map(b => AES_INV_SBOX[b]);
}

/**
 * AES ShiftRows: dá»‹ch vÃ²ng cÃ¡c hÃ ng trong state 4x4
 * HÃ ng 0: khÃ´ng dá»‹ch, HÃ ng 1: dá»‹ch 1, HÃ ng 2: dá»‹ch 2, HÃ ng 3: dá»‹ch 3
 */
function aesShiftRows(state) {
    const s = [...state];
    // HÃ ng 1: dá»‹ch trÃ¡i 1
    let tmp = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = tmp;
    // HÃ ng 2: dá»‹ch trÃ¡i 2
    tmp = s[2]; s[2] = s[10]; s[10] = tmp;
    tmp = s[6]; s[6] = s[14]; s[14] = tmp;
    // HÃ ng 3: dá»‹ch trÃ¡i 3 (= pháº£i 1)
    tmp = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = tmp;
    return s;
}

/**
 * AES InvShiftRows: dá»‹ch ngÆ°á»£c
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
 * AES MixColumns: trá»™n tá»«ng cá»™t sá»­ dá»¥ng phÃ©p nhÃ¢n GF(2^8)
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
 * AES AddRoundKey: XOR state vá»›i round key
 */
function aesAddRoundKey(state, roundKey) {
    return state.map((b, i) => b ^ roundKey[i]);
}

/**
 * MÃ£ hÃ³a 1 block 16 bytes vá»›i AES-128
 */
function aesEncryptBlock(block16, roundKeys, nr) {
    let state = aesAddRoundKey([...block16], roundKeys[0]);

    for (let round = 1; round < nr; round++) {
        state = aesSubBytes(state);
        state = aesShiftRows(state);
        state = aesMixColumns(state);
        state = aesAddRoundKey(state, roundKeys[round]);
    }
    state = aesSubBytes(state);
    state = aesShiftRows(state);
    state = aesAddRoundKey(state, roundKeys[nr]);

    return state;
}

function aesDecryptBlock(block16, roundKeys, nr) {
    let state = aesAddRoundKey([...block16], roundKeys[nr]);

    for (let round = nr - 1; round >= 1; round--) {
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

function pkcs7Pad(bytes) {
    const padLen = 16 - (bytes.length % 16);
    const padded = [...bytes];
    for (let i = 0; i < padLen; i++) padded.push(padLen);
    return padded;
}

/**
 * PKCS#7 Unpadding: loáº¡i bá» padding
 */
function pkcs7Unpad(bytes) {
    if (!bytes || bytes.length === 0) return bytes;
    const padLen = bytes[bytes.length - 1];
    if (padLen <= 0 || padLen > 16) throw new Error("Invalid padding");
    return bytes.slice(0, bytes.length - padLen);
}

/**
 * SHA-1 tá»± implement
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
 * Tá»± implement custom HMAC
 * HMAC = SHA1(key + SHA1(key + data))
 */
function hmacSha1(keyStr, dataStr) {
    const k = stringToBytes(keyStr);
    const d = stringToBytes(dataStr);
    const inner = sha1(concatBytes(k, d));
    const outer = sha1(concatBytes(k, inner));
    return bytesToHex(outer); // Tráº£ vá» 40 kÃ½ tá»± hex
}

/**
 * Chuáº©n hÃ³a key vá» Ä‘Ãºng 16 bytes (AES-128)
 * Náº¿u key < 16 bytes: pad báº±ng 0
 * Náº¿u key > 16 bytes: láº¥y 16 bytes Ä‘áº§u
 */
function normalizeKey(keyStr, keySizeBits) {
    const { keySizeBits: normalizedBits } = getAesConfig(keySizeBits);
    const keyBytes = stringToBytes(keyStr);
    const keyLen = normalizedBits / 8;
    const normalizedKey = new Array(keyLen).fill(0);
    for (let i = 0; i < keyLen && i < keyBytes.length; i++) normalizedKey[i] = keyBytes[i];
    return normalizedKey;
}

function aesEncryptAdvanced(plaintext, keyStr, keySizeBits) {
    const { nr, keySizeBits: normalizedBits } = getAesConfig(keySizeBits);
    const normalizedKey = normalizeKey(keyStr, normalizedBits);
    const roundKeys = aesKeyExpansion(normalizedKey, normalizedBits);
    const ptBytes = pkcs7Pad(stringToBytes(plaintext));

    const cipherBytes = [];
    let iv = [];
    for (let i = 0; i < 16; i++) iv.push(randInt(0, 256));
    let prevBlock = iv;

    for (let i = 0; i < 16; i++) cipherBytes.push(iv[i]);

    for (let i = 0; i < ptBytes.length; i += 16) {
        const block = ptBytes.slice(i, i + 16);
        for (let j = 0; j < 16; j++) block[j] ^= prevBlock[j];
        const encBlock = aesEncryptBlock(block, roundKeys, nr);
        for (const b of encBlock) cipherBytes.push(b);
        prevBlock = encBlock;
    }
    const cipherHex = bytesToHex(cipherBytes);
    const mac = hmacSha1(keyStr, cipherHex);
    return mac + cipherHex;
}

function aesDecryptAdvanced(macAndCipherHex, keyStr, keySizeBits) {
    if (!macAndCipherHex || macAndCipherHex.length < 72) return "(L?i d.l. ho?c r?ng)";

    const mac = macAndCipherHex.substring(0, 40);
    const cipherHex = macAndCipherHex.substring(40);
    const expectedMac = hmacSha1(keyStr, cipherHex);
    if (mac !== expectedMac) {
        return "HMAC verification failed! D? li?u b? gi? m?o.";
    }

    const { nr, keySizeBits: normalizedBits } = getAesConfig(keySizeBits);
    const normalizedKey = normalizeKey(keyStr, normalizedBits);
    const roundKeys = aesKeyExpansion(normalizedKey, normalizedBits);
    const fullBytes = hexToBytes(cipherHex);

    const iv = fullBytes.slice(0, 16);
    let prevBlock = iv;
    const ptBytes = [];

    for (let i = 16; i < fullBytes.length; i += 16) {
        const block = fullBytes.slice(i, i + 16);
        const decBlock = aesDecryptBlock(block, roundKeys, nr);
        for (let j = 0; j < 16; j++) decBlock[j] ^= prevBlock[j];
        for (const b of decBlock) ptBytes.push(b);
        prevBlock = block;
    }

    try {
        const unpadded = pkcs7Unpad(ptBytes);
        return bytesToString(unpadded);
    } catch (e) {
        return "(L?i Decrypt/Unpad)";
    }
}

function aesEncrypt(plaintext, keyStr) {
    return aesEncryptAdvanced(plaintext, keyStr, 128);
}

function aesDecrypt(macAndCipherHex, keyStr) {
    return aesDecryptAdvanced(macAndCipherHex, keyStr, 128);
}

const _tokenStore = {};

/**
 * Sinh chuá»—i token ngáº«u nhiÃªn Ä‘á»™ dÃ i 32 kÃ½ tá»± (tá»± viáº¿t, khÃ´ng dÃ¹ng crypto)
 * Sá»­ dá»¥ng LCG káº¿t há»£p timestamp Ä‘á»ƒ táº¡o entropy
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
 * Tokenize: thay tháº¿ giÃ¡ trá»‹ gá»‘c báº±ng token ngáº«u nhiÃªn
 * @param {string} original  - GiÃ¡ trá»‹ gá»‘c
 * @param {string} fieldType - Loáº¡i trÆ°á»ng (cccd, salary, ...)
 * @returns {string}         - Token Ä‘áº¡i diá»‡n
 */
function tokenize(original, fieldType) {
    // Kiá»ƒm tra xem giÃ¡ trá»‹ nÃ y Ä‘Ã£ cÃ³ token chÆ°a (deterministic)
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
 * Detokenize: khÃ´i phá»¥c giÃ¡ trá»‹ gá»‘c tá»« token
 * @param {string} token - Token cáº§n giáº£i
 * @returns {string}     - GiÃ¡ trá»‹ gá»‘c, hoáº·c null náº¿u khÃ´ng tÃ¬m tháº¥y
 */
function detokenize(token) {
    return _tokenStore[token] ? _tokenStore[token].original : null;
}

/**
 * Láº¥y toÃ n bá»™ token map Ä‘á»ƒ lÆ°u vÃ o database
 */
function getTokenMap() {
    return _tokenStore;
}

// ============================================================
// PHáº¦N 6: FORMAT-PRESERVING MASKING (Giá»¯ Ä‘á»‹nh dáº¡ng gá»‘c)
// ============================================================

/**
 * FP Masking cho Sá» ÄIá»†N THOáº I
 * Thay sá»‘ tháº­t báº±ng sá»‘ ngáº«u nhiÃªn, giá»¯ Ä‘Ãºng Ä‘á»‹nh dáº¡ng
 * VD: "0912345678" â†’ "0834719265" (váº«n lÃ  sá»‘ ÄT há»£p lá»‡)
 */
function fpMaskPhone(phone) {
    if (!phone) return '0900000000';
    const cleaned = phone.trim();

    let result = cleaned[0]; // '0'
    result += cleaned[1];     // mÃ£ máº¡ng

    const DIGITS = '0123456789';
    for (let i = 2; i < cleaned.length; i++) {
        result += DIGITS[randInt(0, 10)];
    }
    return result;
}

/**
 * FP Masking cho Sá» TIá»€N LÆ¯Æ NG
 * Giá»¯ nguyÃªn sá»‘ chá»¯ sá»‘, thay báº±ng giÃ¡ trá»‹ ngáº«u nhiÃªn cÃ¹ng báº­c
 * VD: 15000000.00 â†’ 23847291.00 (váº«n lÃ  sá»‘ 8 chá»¯ sá»‘)
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
 * Giá»¯ 3 sá»‘ Ä‘áº§u (mÃ£ tá»‰nh), sinh 9 sá»‘ cÃ²n láº¡i
 * VD: "012345678901" â†’ "012839471023"
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

    // AES (tá»± implement)
    aesEncrypt,
    aesDecrypt,
    aesEncryptAdvanced,
    aesDecryptAdvanced,

    // Tokenization
    tokenize,
    detokenize,
    getTokenMap,

    // Format-Preserving Masking
    fpMaskPhone,
    fpMaskSalary,
    fpMaskCCCD,

    // Utilities (export Ä‘á»ƒ test)
    stringToBytes,
    bytesToString,
    bytesToHex,
    hexToBytes,
};



