/*
 * Compares our AES-128-CBC implementation with the platform's built-in
 * Web Crypto implementation (crypto.subtle), as described in the proposal.
 *
 *   node bench/aes-benchmark.js
 */
const { webcrypto } = require('node:crypto');
const aes = require('../public/aes.js');

const MESSAGE_SIZES = [64, 1024, 16384];
const ITERATIONS = 200;

function millis(start) {
  return Number(process.hrtime.bigint() - start) / 1e6;
}

async function main() {
  const keyBytes = aes.randomBytes(16);
  const webKey = await webcrypto.subtle.importKey('raw', keyBytes, 'AES-CBC', false, ['encrypt', 'decrypt']);

  console.log('AES-128-CBC, ' + ITERATIONS + ' iterations per size\n');
  console.log('size (B)   ours enc   ours dec   webcrypto enc   webcrypto dec');

  for (const size of MESSAGE_SIZES) {
    const message = aes.randomBytes(size);
    const iv = aes.randomBytes(16);

    let start = process.hrtime.bigint();
    let ciphertext;
    for (let i = 0; i < ITERATIONS; i++) {
      ciphertext = aes.encryptCbc(message, keyBytes, iv);
    }
    const oursEncrypt = millis(start);

    start = process.hrtime.bigint();
    for (let i = 0; i < ITERATIONS; i++) {
      aes.decryptCbc(ciphertext, keyBytes, iv);
    }
    const oursDecrypt = millis(start);

    start = process.hrtime.bigint();
    let webCiphertext;
    for (let i = 0; i < ITERATIONS; i++) {
      webCiphertext = await webcrypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, webKey, message);
    }
    const webEncrypt = millis(start);

    start = process.hrtime.bigint();
    for (let i = 0; i < ITERATIONS; i++) {
      await webcrypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, webKey, webCiphertext);
    }
    const webDecrypt = millis(start);

    // sanity check: both implementations must agree
    if (aes.bytesToHex(ciphertext) !== aes.bytesToHex(new Uint8Array(webCiphertext))) {
      throw new Error('the two implementations disagree on the ciphertext');
    }

    console.log(
      String(size).padEnd(10) +
      (oursEncrypt.toFixed(1) + ' ms').padEnd(11) +
      (oursDecrypt.toFixed(1) + ' ms').padEnd(11) +
      (webEncrypt.toFixed(1) + ' ms').padEnd(16) +
      (webDecrypt.toFixed(1) + ' ms')
    );
  }
}

main();
