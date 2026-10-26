/*
 * End-to-end test for the Socket.IO part of Owl Chat.
 *
 * A real server is started on a temporary port with a temporary database, two
 * clients connect, and an AES-128-CBC encrypted message travels from one to the
 * other. The test also checks that neither the relayed payload nor the stored
 * row contains the plaintext.
 */
const test = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { io } = require('socket.io-client');
const crypto = require('node:crypto');
const aes = require('../public/aes.js');

// The same derivation the client performs with crypto.subtle:
// key = SHA-256(shared secret) truncated to 128 bits.
function deriveAesKey(passphrase) {
  return new Uint8Array(crypto.createHash('sha256').update(passphrase, 'utf8').digest()).slice(0, 16);
}

const PORT = 3100 + Math.floor(Math.random() * 500);
const DB_FILE = path.join(os.tmpdir(), `owlchat-test-${process.pid}.db`);
const URL = `http://localhost:${PORT}`;

function startServer() {
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'index.js')], {
    env: { ...process.env, PORT: String(PORT), OWLCHAT_DB: DB_FILE },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('the server did not start in time')), 15000);
    child.stdout.on('data', (chunk) => {
      if (chunk.toString().includes('server running')) {
        clearTimeout(timer);
        resolve(child);
      }
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function connect(username) {
  return io(URL, {
    auth: { serverOffset: 0, username },
    transports: ['websocket'],
    forceNew: true
  });
}

test('two clients exchange an end-to-end encrypted message', async (t) => {
  const server = await startServer();
  const key = deriveAesKey('owls fly silently');
  const clients = [];

  t.after(async () => {
    clients.forEach((client) => client.disconnect());
    server.kill();
    await once(server, 'exit');
    fs.rmSync(DB_FILE, { force: true });
  });

  const alice = connect('alice');
  const bob = connect('bob');
  clients.push(alice, bob);
  await Promise.all([once(alice, 'connect'), once(bob, 'connect')]);

  // bob must be told that somebody joined, with the username
  const connectedPromise = once(bob, 'user connected');

  const plaintext = 'meet me at the old oak 🦉';
  const payload = aes.encryptMessage(plaintext, key);
  payload.username = 'alice';

  const receivedPromise = once(bob, 'chat message');
  alice.emit('chat message', payload, 'alice-0');

  const [relayed, serverOffset] = await receivedPromise;
  assert.strictEqual(relayed.username, 'alice');
  assert.strictEqual(typeof serverOffset, 'number');
  assert.ok(!JSON.stringify(relayed).includes('old oak'), 'the relayed payload must not contain plaintext');
  assert.strictEqual(aes.decryptMessage(relayed, key), plaintext);

  // the database must hold ciphertext only
  const stored = fs.readFileSync(DB_FILE);
  assert.ok(!stored.includes('old oak'), 'the database must not contain plaintext');
  assert.ok(stored.includes(relayed.ciphertext), 'the ciphertext must be stored');

  // a client joining later receives the stored history and can decrypt it
  const carol = connect('carol');
  clients.push(carol);
  const [replayed] = await once(carol, 'chat message');
  assert.strictEqual(aes.decryptMessage(replayed, key), plaintext);

  const [connectedName] = await connectedPromise;
  assert.ok(['alice', 'bob', 'carol'].includes(connectedName));
});
