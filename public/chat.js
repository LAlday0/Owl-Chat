/*
 * Owl Chat client: all cryptography happens here, in the browser.
 *
 * A message is encrypted with AES-128-CBC before it is emitted over the socket
 * and decrypted only after it arrives on the other side. The server only ever
 * sees { username, iv, ciphertext }.
 *
 * For now the AES key is derived from a secret the two peers already share:
 * key = SHA-256(secret) truncated to 128 bits. The hash comes from the browser's
 * Web Crypto API - only AES itself is implemented from scratch in this project.
 * The Diffie-Hellman exchange that replaces this step is the next piece of the
 * project.
 */
(function () {
  'use strict';

  let counter = 0;
  let aesKey = null;
  const history = [];

  const setup = document.getElementById('setup');
  const usernameInput = document.getElementById('username');
  const passphraseInput = document.getElementById('passphrase');
  const joinButton = document.getElementById('join');
  const statusLabel = document.getElementById('status');
  const showCipher = document.getElementById('show-cipher');
  const form = document.getElementById('form');
  const input = document.getElementById('input');
  const messages = document.getElementById('messages');

  const socket = io({
    auth: {
      serverOffset: 0,
      username: ''
    },
    //enable retries
    ackTimeout: 10000,
    retries: 3,
    autoConnect: false
  });

  function setStatus(text) {
    statusLabel.textContent = text;
  }

  // key = SHA-256(shared secret), truncated to 128 bits.
  // crypto.subtle is only available in a secure context (https:// or localhost).
  async function deriveAesKey(passphrase) {
    const subtle = window.crypto && window.crypto.subtle;
    if (!subtle) {
      throw new Error('Web Crypto is unavailable: open the page over https:// or on localhost.');
    }
    const digest = await subtle.digest('SHA-256', new TextEncoder().encode(passphrase));
    return new Uint8Array(digest).slice(0, OwlAES.BLOCK_SIZE);
  }

  function scrollToBottom() {
    window.scrollTo(0, document.body.scrollHeight);
  }

  function appendSystem(text) {
    const item = document.createElement('li');
    item.className = 'system';
    item.textContent = text;
    messages.appendChild(item);
    scrollToBottom();
  }

  function renderMessage(entry) {
    const item = document.createElement('li');

    const author = document.createElement('span');
    author.className = 'author';
    author.textContent = (entry.username || 'anonymous owl') + ':';
    item.appendChild(author);

    const body = document.createElement('span');
    if (aesKey) {
      try {
        body.textContent = OwlAES.decryptMessage(entry, aesKey);
      } catch (e) {
        item.classList.add('locked');
        body.textContent = '[cannot be decrypted with this secret]';
      }
    } else {
      item.classList.add('locked');
      body.textContent = '[encrypted - join with the shared secret to read]';
    }
    item.appendChild(body);

    if (showCipher.checked) {
      const cipher = document.createElement('span');
      cipher.className = 'cipher';
      cipher.textContent = 'iv=' + entry.iv + ' ct=' + entry.ciphertext;
      item.appendChild(cipher);
    }

    item.dataset.index = String(entry.index);
    messages.appendChild(item);
    scrollToBottom();
  }

  function renderAll() {
    messages.innerHTML = '';
    history.forEach(renderMessage);
  }

  joinButton.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    const passphrase = passphraseInput.value;
    if (!username || !passphrase) {
      setStatus('A username and a shared secret are both required.');
      return;
    }

    joinButton.disabled = true;
    try {
      aesKey = await deriveAesKey(passphrase);
    } catch (e) {
      setStatus(e.message);
      return;
    } finally {
      joinButton.disabled = false;
    }
    socket.auth.username = username;

    if (socket.connected) {
      renderAll();
    } else {
      socket.connect();
    }
    setStatus('Joined as ' + username + '. Messages are encrypted with AES-128-CBC.');
    input.focus();
  });

  showCipher.addEventListener('change', renderAll);

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!aesKey) {
      setStatus('Join with a username and a shared secret before sending messages.');
      return;
    }
    if (!input.value) {
      return;
    }

    // encrypt before the message leaves the browser, with a fresh random IV
    const payload = OwlAES.encryptMessage(input.value, aesKey);
    payload.username = socket.auth.username;

    //compute unique offset
    const clientOffset = `${socket.id}-${counter++}`;
    socket.emit('chat message', payload, clientOffset);
    input.value = '';
  });

  socket.on('chat message', (payload, serverOffset) => {
    const entry = {
      index: history.length,
      username: payload.username,
      iv: payload.iv,
      ciphertext: payload.ciphertext
    };
    history.push(entry);
    renderMessage(entry);
    socket.auth.serverOffset = serverOffset;
  });

  socket.on('user connected', (username) => {
    appendSystem((username || 'A user') + ' connected');
  });

  socket.on('user disconnected', (username) => {
    appendSystem((username || 'A user') + ' disconnected');
  });

  socket.on('connect', () => {
    setup.classList.add('connected');
  });
})();
