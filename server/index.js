const express = require('express');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'home.html'));
});

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

let activeCode = null;
let activeSenderId = null;
let senderSocket = null;

function generateCode() {
  return crypto.randomInt(100000, 999999).toString();
}

function generateSenderId() {
  return crypto.randomBytes(3).toString('hex').toUpperCase();
}

wss.on('connection', (ws) => {
  console.log('A client connected');
  ws.isVerified = false;

  ws.on('message', (raw) => {
    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch {
      return;
    }

    if (data.type === 'start-pairing') {
      activeCode = generateCode();
      activeSenderId = generateSenderId();
      senderSocket = ws;
      ws.isVerified = true;
      ws.send(JSON.stringify({ type: 'pairing-code', code: activeCode, senderId: activeSenderId }));
      console.log('New pairing code generated:', activeCode, '| Sender ID:', activeSenderId);
      return;
    }

    if (data.type === 'verify-code') {
      if (data.code === activeCode) {
        ws.isVerified = true;
        ws.deviceName = data.deviceName || 'Unnamed device';
        ws.send(JSON.stringify({ type: 'verified', success: true, senderId: activeSenderId }));
        console.log('A receiver verified successfully:', ws.deviceName);

        if (senderSocket && senderSocket.readyState === WebSocket.OPEN) {
          senderSocket.send(JSON.stringify({ type: 'peer-connected', deviceName: ws.deviceName }));
        }
      } else {
        ws.send(JSON.stringify({ type: 'verified', success: false }));
        console.log('A receiver entered the wrong code');
      }
      return;
    }

    if (data.type === 'file') {
      if (!ws.isVerified) {
        console.log('Blocked file from unverified client');
        return;
      }
      console.log(`Relaying encrypted file: ${data.filename} (${data.data.length} bytes, base64)`);
      wss.clients.forEach((client) => {
        if (client !== ws && client.readyState === WebSocket.OPEN && client.isVerified) {
          client.send(JSON.stringify({
            type: 'file',
            filename: data.filename,
            data: data.data,
            iv: data.iv,
            hash: data.hash
          }));
        }
      });
    }
  });

  ws.on('close', () => {
    console.log('A client disconnected');
    if (ws === senderSocket) senderSocket = null;
  });
});

server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});