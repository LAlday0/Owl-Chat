/*
 * Owl Chat - AES-128 (FIPS 197) with CBC mode (NIST SP 800-38A) and PKCS#7 padding.
 *
 * This is a from-scratch implementation written for learning purposes:
 * key expansion, SubBytes, ShiftRows, MixColumns, AddRoundKey and their
 * inverses are all implemented here. It is NOT hardened against side-channel
 * attacks and CBC alone does not detect tampering.
 *
 * The state is kept as a flat 16-byte array in column-major order, exactly as
 * the bytes arrive from the input block: index = row + 4 * column.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.OwlAES = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const BLOCK_SIZE = 16;
  const KEY_SIZE = 16;
  const ROUNDS = 10;

  // ---------------------------------------------------------------- GF(2^8)

  // Multiply two bytes in the Rijndael finite field GF(2^8), modulo x^8+x^4+x^3+x+1.
  function gmul(a, b) {
    let product = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 1) {
        product ^= a;
      }
      const highBit = a & 0x80;
      a = (a << 1) & 0xff;
      if (highBit) {
        a ^= 0x1b;
      }
      b >>= 1;
    }
    return product & 0xff;
  }

  // ------------------------------------------------------------ lookup tables

  // The substitution table from FIPS 197 figure 7. Each entry is the
  // multiplicative inverse of its index in GF(2^8) run through the AES affine
  // transform (0x00 has no inverse and maps to 0x63 by definition).
  const SBOX = new Uint8Array([
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
  ]);

  // FIPS 197 figure 14: INV_SBOX[SBOX[b]] === b for every byte.
  const INV_SBOX = new Uint8Array([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
  ]);

  // Round constants for the key schedule: RCON[i] = x^(i-1) in GF(2^8).
  // Index 0 is unused; the key schedule only ever reads RCON[1..10].
  const RCON = new Uint8Array([
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
  ]);

  // ----------------------------------------------------------- key expansion

  // Expands a 16-byte key into 11 round keys of 16 bytes (176 bytes total).
  function expandKey(key) {
    const keyBytes = toBytes(key);
    if (keyBytes.length !== KEY_SIZE) {
      throw new Error('AES-128 requires a 16-byte key, got ' + keyBytes.length);
    }

    const expanded = new Uint8Array(BLOCK_SIZE * (ROUNDS + 1));
    expanded.set(keyBytes, 0);

    const temp = new Uint8Array(4);
    for (let word = 4; word < 4 * (ROUNDS + 1); word++) {
      for (let i = 0; i < 4; i++) {
        temp[i] = expanded[(word - 1) * 4 + i];
      }
      if (word % 4 === 0) {
        // RotWord
        const first = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = first;
        // SubWord
        for (let i = 0; i < 4; i++) {
          temp[i] = SBOX[temp[i]];
        }
        // Rcon
        temp[0] ^= RCON[word / 4];
      }
      for (let i = 0; i < 4; i++) {
        expanded[word * 4 + i] = expanded[(word - 4) * 4 + i] ^ temp[i];
      }
    }
    return expanded;
  }

  // --------------------------------------------------------- round functions

  function addRoundKey(state, roundKeys, round) {
    const offset = round * BLOCK_SIZE;
    for (let i = 0; i < BLOCK_SIZE; i++) {
      state[i] ^= roundKeys[offset + i];
    }
  }

  function subBytes(state) {
    for (let i = 0; i < BLOCK_SIZE; i++) {
      state[i] = SBOX[state[i]];
    }
  }

  function invSubBytes(state) {
    for (let i = 0; i < BLOCK_SIZE; i++) {
      state[i] = INV_SBOX[state[i]];
    }
  }

  // Row r is rotated left by r positions. State index = row + 4 * column.
  function shiftRows(state) {
    const source = state.slice();
    for (let row = 1; row < 4; row++) {
      for (let col = 0; col < 4; col++) {
        state[row + 4 * col] = source[row + 4 * ((col + row) % 4)];
      }
    }
  }

  function invShiftRows(state) {
    const source = state.slice();
    for (let row = 1; row < 4; row++) {
      for (let col = 0; col < 4; col++) {
        state[row + 4 * ((col + row) % 4)] = source[row + 4 * col];
      }
    }
  }

  // Each column is treated as a polynomial and multiplied by 3x^3+x^2+x+2.
  function mixColumns(state) {
    for (let col = 0; col < 4; col++) {
      const i = 4 * col;
      const a0 = state[i];
      const a1 = state[i + 1];
      const a2 = state[i + 2];
      const a3 = state[i + 3];
      state[i] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
      state[i + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
      state[i + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
      state[i + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
    }
  }

  // Inverse multiplication by 11x^3+13x^2+9x+14.
  function invMixColumns(state) {
    for (let col = 0; col < 4; col++) {
      const i = 4 * col;
      const a0 = state[i];
      const a1 = state[i + 1];
      const a2 = state[i + 2];
      const a3 = state[i + 3];
      state[i] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
      state[i + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
      state[i + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
      state[i + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
    }
  }

  // ------------------------------------------------------- single block cipher

  function encryptBlock(block, roundKeys) {
    const state = new Uint8Array(toBytes(block).subarray(0, BLOCK_SIZE));
    addRoundKey(state, roundKeys, 0);
    for (let round = 1; round < ROUNDS; round++) {
      subBytes(state);
      shiftRows(state);
      mixColumns(state);
      addRoundKey(state, roundKeys, round);
    }
    // The final round omits MixColumns.
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys, ROUNDS);
    return state;
  }

  function decryptBlock(block, roundKeys) {
    const state = new Uint8Array(toBytes(block).subarray(0, BLOCK_SIZE));
    addRoundKey(state, roundKeys, ROUNDS);
    for (let round = ROUNDS - 1; round >= 1; round--) {
      invShiftRows(state);
      invSubBytes(state);
      addRoundKey(state, roundKeys, round);
      invMixColumns(state);
    }
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, roundKeys, 0);
    return state;
  }

  // ------------------------------------------------------------- PKCS#7

  function padPkcs7(bytes) {
    const padLength = BLOCK_SIZE - (bytes.length % BLOCK_SIZE);
    const padded = new Uint8Array(bytes.length + padLength);
    padded.set(bytes, 0);
    padded.fill(padLength, bytes.length);
    return padded;
  }

  function unpadPkcs7(bytes) {
    if (bytes.length === 0 || bytes.length % BLOCK_SIZE !== 0) {
      throw new Error('Invalid padded length');
    }
    const padLength = bytes[bytes.length - 1];
    if (padLength < 1 || padLength > BLOCK_SIZE || padLength > bytes.length) {
      throw new Error('Invalid PKCS#7 padding');
    }
    for (let i = bytes.length - padLength; i < bytes.length; i++) {
      if (bytes[i] !== padLength) {
        throw new Error('Invalid PKCS#7 padding');
      }
    }
    return bytes.slice(0, bytes.length - padLength);
  }

  // ---------------------------------------------------------------- CBC mode

  function encryptCbc(plaintextBytes, key, iv) {
    const roundKeys = expandKey(key);
    const ivBytes = toBytes(iv);
    if (ivBytes.length !== BLOCK_SIZE) {
      throw new Error('The IV must be 16 bytes long');
    }

    const padded = padPkcs7(toBytes(plaintextBytes));
    const ciphertext = new Uint8Array(padded.length);
    let previous = ivBytes;

    for (let offset = 0; offset < padded.length; offset += BLOCK_SIZE) {
      const block = padded.slice(offset, offset + BLOCK_SIZE);
      for (let i = 0; i < BLOCK_SIZE; i++) {
        block[i] ^= previous[i];
      }
      const encrypted = encryptBlock(block, roundKeys);
      ciphertext.set(encrypted, offset);
      previous = encrypted;
    }
    return ciphertext;
  }

  function decryptCbc(ciphertextBytes, key, iv) {
    const roundKeys = expandKey(key);
    const ivBytes = toBytes(iv);
    if (ivBytes.length !== BLOCK_SIZE) {
      throw new Error('The IV must be 16 bytes long');
    }

    const ciphertext = toBytes(ciphertextBytes);
    if (ciphertext.length === 0 || ciphertext.length % BLOCK_SIZE !== 0) {
      throw new Error('The ciphertext length must be a non-zero multiple of 16');
    }

    const plaintext = new Uint8Array(ciphertext.length);
    let previous = ivBytes;

    for (let offset = 0; offset < ciphertext.length; offset += BLOCK_SIZE) {
      const block = ciphertext.slice(offset, offset + BLOCK_SIZE);
      const decrypted = decryptBlock(block, roundKeys);
      for (let i = 0; i < BLOCK_SIZE; i++) {
        decrypted[i] ^= previous[i];
      }
      plaintext.set(decrypted, offset);
      previous = block;
    }
    return unpadPkcs7(plaintext);
  }

  // Encrypts a string and returns { iv, ciphertext } as base64 strings.
  function encryptMessage(text, key, iv) {
    const ivBytes = iv ? toBytes(iv) : randomBytes(BLOCK_SIZE);
    const ciphertext = encryptCbc(utf8ToBytes(text), key, ivBytes);
    return {
      iv: bytesToBase64(ivBytes),
      ciphertext: bytesToBase64(ciphertext)
    };
  }

  // Reverses encryptMessage.
  function decryptMessage(payload, key) {
    const plaintext = decryptCbc(base64ToBytes(payload.ciphertext), key, base64ToBytes(payload.iv));
    return bytesToUtf8(plaintext);
  }

  // ------------------------------------------------------------- conversions

  function toBytes(value) {
    if (value instanceof Uint8Array) {
      return value;
    }
    if (Array.isArray(value)) {
      return Uint8Array.from(value);
    }
    if (typeof value === 'string') {
      return hexToBytes(value);
    }
    if (value && typeof value.byteLength === 'number') {
      return new Uint8Array(value);
    }
    throw new Error('Unsupported byte source');
  }

  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  function utf8ToBytes(text) {
    return textEncoder.encode(text);
  }

  function bytesToUtf8(bytes) {
    return textDecoder.decode(toBytes(bytes));
  }

  // Hex is the one conversion without a portable built-in, so it stays here.
  function hexToBytes(hex) {
    const clean = String(hex).replace(/\s+/g, '');
    if (clean.length % 2 !== 0) {
      throw new Error('A hex string must have an even number of characters');
    }
    if (!/^[0-9a-fA-F]*$/.test(clean)) {
      throw new Error('A hex string may only contain the digits 0-9 and a-f');
    }
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(toBytes(bytes), (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  // btoa/atob work on latin1 strings, so the bytes are mapped one to one onto
  // char codes first. They reject malformed base64 rather than ignoring it.
  function bytesToBase64(bytes) {
    const source = toBytes(bytes);
    let binary = '';
    for (let i = 0; i < source.length; i++) {
      binary += String.fromCharCode(source[i]);
    }
    return btoa(binary);
  }

  function base64ToBytes(text) {
    const binary = atob(String(text));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function randomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
  }

  return {
    BLOCK_SIZE: BLOCK_SIZE,
    SBOX: SBOX,
    INV_SBOX: INV_SBOX,
    gmul: gmul,
    expandKey: expandKey,
    encryptBlock: encryptBlock,
    decryptBlock: decryptBlock,
    padPkcs7: padPkcs7,
    unpadPkcs7: unpadPkcs7,
    encryptCbc: encryptCbc,
    decryptCbc: decryptCbc,
    encryptMessage: encryptMessage,
    decryptMessage: decryptMessage,
    utf8ToBytes: utf8ToBytes,
    bytesToUtf8: bytesToUtf8,
    hexToBytes: hexToBytes,
    bytesToHex: bytesToHex,
    bytesToBase64: bytesToBase64,
    base64ToBytes: base64ToBytes,
    randomBytes: randomBytes
  };
});
