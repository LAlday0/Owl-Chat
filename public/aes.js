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

  function rotl8(x, shift) {
    return ((x << shift) | (x >> (8 - shift))) & 0xff;
  }

  // The S-box is generated rather than hardcoded: for every non-zero byte we
  // take its multiplicative inverse in GF(2^8) and apply the AES affine transform.
  const SBOX = new Uint8Array(256);
  const INV_SBOX = new Uint8Array(256);

  (function buildSBoxes() {
    let p = 1;
    let q = 1;
    do {
      // p *= 3 (generator of the multiplicative group)
      p = (p ^ ((p << 1) & 0xff) ^ ((p & 0x80) ? 0x1b : 0)) & 0xff;
      // q /= 3 (multiplication by the inverse of 3)
      q ^= (q << 1) & 0xff;
      q ^= (q << 2) & 0xff;
      q ^= (q << 4) & 0xff;
      q &= 0xff;
      if (q & 0x80) {
        q ^= 0x09;
      }
      const value = (q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4) ^ 0x63) & 0xff;
      SBOX[p] = value;
      INV_SBOX[value] = p;
    } while (p !== 1);
    // 0 has no multiplicative inverse, the affine transform of 0 is 0x63.
    SBOX[0] = 0x63;
    INV_SBOX[0x63] = 0x00;
  })();

  // Round constants for the key schedule: rcon[i] = x^(i-1) in GF(2^8).
  const RCON = new Uint8Array(11);
  (function buildRcon() {
    let value = 1;
    for (let i = 1; i <= 10; i++) {
      RCON[i] = value;
      value = gmul(value, 2);
    }
  })();

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

  function utf8ToBytes(text) {
    if (typeof TextEncoder !== 'undefined') {
      return new TextEncoder().encode(text);
    }
    const encoded = unescape(encodeURIComponent(text));
    const bytes = new Uint8Array(encoded.length);
    for (let i = 0; i < encoded.length; i++) {
      bytes[i] = encoded.charCodeAt(i);
    }
    return bytes;
  }

  function bytesToUtf8(bytes) {
    if (typeof TextDecoder !== 'undefined') {
      return new TextDecoder().decode(toBytes(bytes));
    }
    let binary = '';
    const source = toBytes(bytes);
    for (let i = 0; i < source.length; i++) {
      binary += String.fromCharCode(source[i]);
    }
    return decodeURIComponent(escape(binary));
  }

  function hexToBytes(hex) {
    const clean = hex.replace(/\s+/g, '');
    if (clean.length % 2 !== 0) {
      throw new Error('A hex string must have an even number of characters');
    }
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  function bytesToHex(bytes) {
    const source = toBytes(bytes);
    let hex = '';
    for (let i = 0; i < source.length; i++) {
      hex += source[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  function bytesToBase64(bytes) {
    const source = toBytes(bytes);
    let output = '';
    for (let i = 0; i < source.length; i += 3) {
      const b0 = source[i];
      const b1 = source[i + 1];
      const b2 = source[i + 2];
      output += BASE64_ALPHABET[b0 >> 2];
      output += BASE64_ALPHABET[((b0 & 0x03) << 4) | ((b1 === undefined ? 0 : b1) >> 4)];
      output += b1 === undefined ? '=' : BASE64_ALPHABET[((b1 & 0x0f) << 2) | ((b2 === undefined ? 0 : b2) >> 6)];
      output += b2 === undefined ? '=' : BASE64_ALPHABET[b2 & 0x3f];
    }
    return output;
  }

  function base64ToBytes(text) {
    const clean = String(text).replace(/[^A-Za-z0-9+/]/g, '');
    const bytes = new Uint8Array(Math.floor((clean.length * 3) / 4));
    let index = 0;
    for (let i = 0; i < clean.length; i += 4) {
      const c0 = BASE64_ALPHABET.indexOf(clean[i]);
      const c1 = BASE64_ALPHABET.indexOf(clean[i + 1]);
      const c2 = BASE64_ALPHABET.indexOf(clean[i + 2]);
      const c3 = BASE64_ALPHABET.indexOf(clean[i + 3]);
      bytes[index++] = (c0 << 2) | (c1 >> 4);
      if (c2 >= 0) {
        bytes[index++] = ((c1 & 0x0f) << 4) | (c2 >> 2);
      }
      if (c3 >= 0) {
        bytes[index++] = ((c2 & 0x03) << 6) | c3;
      }
    }
    return bytes.slice(0, index);
  }

  function randomBytes(length) {
    const bytes = new Uint8Array(length);
    const webcrypto = typeof globalThis !== 'undefined' ? globalThis.crypto : undefined;
    if (webcrypto && typeof webcrypto.getRandomValues === 'function') {
      webcrypto.getRandomValues(bytes);
      return bytes;
    }
    for (let i = 0; i < length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
    return bytes;
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
