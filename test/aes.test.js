/*
 * Known-answer tests for the Owl Chat AES-128 implementation.
 *
 * Vectors come from FIPS 197 (appendix B and C.1) and NIST SP 800-38A
 * (section F.2, CBC-AES128). The implementation is also cross-checked against
 * Node's built-in OpenSSL AES.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

const aes = require('../public/aes.js');

const hex = aes.bytesToHex;

// The same derivation the client performs with crypto.subtle:
// key = SHA-256(shared secret) truncated to 128 bits.
function deriveAesKey(passphrase) {
  return new Uint8Array(crypto.createHash('sha256').update(passphrase, 'utf8').digest()).slice(0, 16);
}

test('the S-box matches FIPS 197', () => {
  assert.strictEqual(aes.SBOX[0x00], 0x63);
  assert.strictEqual(aes.SBOX[0x01], 0x7c);
  assert.strictEqual(aes.SBOX[0x53], 0xed);
  assert.strictEqual(aes.SBOX[0xff], 0x16);
  for (let i = 0; i < 256; i++) {
    assert.strictEqual(aes.INV_SBOX[aes.SBOX[i]], i, 'S-box must be a bijection, failed at ' + i);
  }
});

test('key expansion matches FIPS 197 appendix A.1', () => {
  const roundKeys = aes.expandKey('2b7e151628aed2a6abf7158809cf4f3c');
  // w[4..7] and the last round key w[40..43]
  assert.strictEqual(hex(roundKeys.slice(16, 32)), 'a0fafe1788542cb123a339392a6c7605');
  assert.strictEqual(hex(roundKeys.slice(160, 176)), 'd014f9a8c9ee2589e13f0cc8b6630ca6');
});

test('single block encryption matches FIPS 197 C.1', () => {
  const roundKeys = aes.expandKey('000102030405060708090a0b0c0d0e0f');
  const ciphertext = aes.encryptBlock(aes.hexToBytes('00112233445566778899aabbccddeeff'), roundKeys);
  assert.strictEqual(hex(ciphertext), '69c4e0d86a7b0430d8cdb78070b4c55a');
  assert.strictEqual(hex(aes.decryptBlock(ciphertext, roundKeys)), '00112233445566778899aabbccddeeff');
});

test('single block encryption matches FIPS 197 appendix B', () => {
  const roundKeys = aes.expandKey('2b7e151628aed2a6abf7158809cf4f3c');
  const ciphertext = aes.encryptBlock(aes.hexToBytes('3243f6a8885a308d313198a2e0370734'), roundKeys);
  assert.strictEqual(hex(ciphertext), '3925841d02dc09fbdc118597196a0b32');
});

test('CBC mode matches NIST SP 800-38A F.2.1', () => {
  const key = '2b7e151628aed2a6abf7158809cf4f3c';
  const iv = '000102030405060708090a0b0c0d0e0f';
  const plaintext =
    '6bc1bee22e409f96e93d7e117393172a' +
    'ae2d8a571e03ac9c9eb76fac45af8e51' +
    '30c81c46a35ce411e5fbc1191a0a52ef' +
    'f69f2445df4f9b17ad2b417be66c3710';
  const expected =
    '7649abac8119b246cee98e9b12e9197d' +
    '5086cb9b507219ee95db113a917678b2' +
    '73bed6b8e3c1743b7116e69e22229516' +
    '3ff1caa1681fac09120eca307586e1a7';

  const ciphertext = aes.encryptCbc(aes.hexToBytes(plaintext), key, iv);
  // the plaintext is a whole number of blocks, so PKCS#7 appends one extra block
  assert.strictEqual(hex(ciphertext.slice(0, 64)), expected);
  assert.strictEqual(ciphertext.length, 80);
  assert.strictEqual(hex(aes.decryptCbc(ciphertext, key, iv)), plaintext);
});

test('PKCS#7 padding is applied and removed correctly', () => {
  const padded = aes.padPkcs7(aes.utf8ToBytes('owl'));
  assert.strictEqual(padded.length, 16);
  assert.strictEqual(hex(padded.slice(3)), '0d'.repeat(13));

  const full = aes.padPkcs7(new Uint8Array(16));
  assert.strictEqual(full.length, 32, 'a full block gets a whole block of padding');
  assert.strictEqual(aes.unpadPkcs7(full).length, 16);

  assert.throws(() => aes.unpadPkcs7(aes.hexToBytes('00'.repeat(16))), /padding/);
});

test('messages of any length survive a round trip', () => {
  const key = deriveAesKey('a secret shared by two owls');
  const samples = ['', 'hi', 'exactly 16 bytes', 'a'.repeat(1000), 'unicode: 🦉 héllo'];
  for (const text of samples) {
    const payload = aes.encryptMessage(text, key);
    assert.strictEqual(aes.decryptMessage(payload, key), text);
  }
});

test('every message uses a fresh IV, so identical texts differ', () => {
  const key = deriveAesKey('secret');
  const first = aes.encryptMessage('same message', key);
  const second = aes.encryptMessage('same message', key);
  assert.notStrictEqual(first.iv, second.iv);
  assert.notStrictEqual(first.ciphertext, second.ciphertext);
});

test('a wrong key does not reveal the message', () => {
  const payload = aes.encryptMessage('top secret', deriveAesKey('right'));
  let recovered = null;
  try {
    recovered = aes.decryptMessage(payload, deriveAesKey('wrong'));
  } catch (e) {
    recovered = null; // padding check rejected it
  }
  assert.notStrictEqual(recovered, 'top secret');
});

test('ciphertext matches OpenSSL aes-128-cbc', () => {
  for (let i = 0; i < 20; i++) {
    const key = crypto.randomBytes(16);
    const iv = crypto.randomBytes(16);
    const message = crypto.randomBytes(1 + Math.floor(Math.random() * 200));

    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    const reference = Buffer.concat([cipher.update(message), cipher.final()]);

    const ours = aes.encryptCbc(new Uint8Array(message), new Uint8Array(key), new Uint8Array(iv));
    assert.strictEqual(hex(ours), reference.toString('hex'));
    assert.strictEqual(hex(aes.decryptCbc(ours, new Uint8Array(key), new Uint8Array(iv))), message.toString('hex'));
  }
});

test('base64 helpers round trip', () => {
  for (let length = 0; length < 40; length++) {
    const bytes = new Uint8Array(crypto.randomBytes(length));
    assert.strictEqual(hex(aes.base64ToBytes(aes.bytesToBase64(bytes))), hex(bytes));
    assert.strictEqual(aes.bytesToBase64(bytes), Buffer.from(bytes).toString('base64'));
  }
});

test('the key derivation yields a 128-bit key', async () => {
  const passphrase = 'a secret shared by two owls';
  const key = deriveAesKey(passphrase);
  assert.strictEqual(key.length, 16, 'the AES key is 128 bits');

  // the browser derives the very same key through the Web Crypto API
  const digest = await crypto.webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(passphrase));
  assert.strictEqual(hex(new Uint8Array(digest).slice(0, 16)), hex(key));
});
