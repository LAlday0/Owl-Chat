const express = require('express');
const { createServer } = require('node:http');
const { join } = require('node:path');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');

const DB_FILE = process.env.OWLCHAT_DB || 'owlchat.db';
const PORT = Number(process.env.PORT) || 3000;

async function main() {
  // open the database file
  const db = await open({
    filename: DB_FILE,
    driver: sqlite3.Database
  });

  // create 'messages' table
  // only ciphertext is stored: the server never sees the plaintext or the key
  await db.exec(`
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_offset TEXT UNIQUE,
        username TEXT,
        iv TEXT,
        ciphertext TEXT
    );
  `);

  const app = express();
  const server = createServer(app);
  const io = new Server(server, {
    connectionStateRecovery: {}
  });

  app.use(express.static(join(__dirname, 'public')));

  app.get('/', (req, res) => {
    res.sendFile(join(__dirname, 'index.html'));
  });

  io.on('connection', async (socket) => {
    const username = (socket.handshake.auth.username || 'anonymous owl').toString().slice(0, 32);
    socket.data.username = username;
    socket.broadcast.emit('user connected', username);

    socket.on('chat message', async (payload, clientOffset, callback) => {
      // the acknowledgement is optional, so keep a no-op around
      const acknowledge = typeof callback === 'function' ? callback : () => {};

      // the payload only carries ciphertext: { iv, ciphertext } both base64 encoded
      if (!payload || typeof payload.iv !== 'string' || typeof payload.ciphertext !== 'string') {
        // malformed message, nothing to relay
        acknowledge();
        return;
      }

      const message = {
        username: (payload.username || username).toString().slice(0, 32),
        iv: payload.iv,
        ciphertext: payload.ciphertext
      };

      let result;
      try {
        result = await db.run(
          'INSERT INTO messages (client_offset, username, iv, ciphertext) VALUES (?, ?, ?, ?)',
          clientOffset,
          message.username,
          message.iv,
          message.ciphertext
        );
      } catch (e) {
        if (e.errno === 19) {
          //message already inserted, so notify client
          acknowledge();
        } else {
          //nothing to do. Just let the client retry
        }
        return;
      }

      io.emit('chat message', message, result.lastID);
      //acknowledge the event
      acknowledge();
    });

    socket.on('disconnect', () => {
      socket.broadcast.emit('user disconnected', socket.data.username);
    });

    if (!socket.recovered) {
      // if the connection state recovery was not successful
      try {
        await db.each('SELECT id, username, iv, ciphertext FROM messages WHERE id > ?',
          [socket.handshake.auth.serverOffset || 0],
          (_err, row) => {
            if (!row) {
              return;
            }
            socket.emit('chat message', {
              username: row.username,
              iv: row.iv,
              ciphertext: row.ciphertext
            }, row.id);
          }
        )
      } catch (e) {
        // something went wrong
      }
    }
  });

  server.listen(PORT, () => {
    console.log(`server running at http://localhost:${PORT}`);
  });
}

main();
