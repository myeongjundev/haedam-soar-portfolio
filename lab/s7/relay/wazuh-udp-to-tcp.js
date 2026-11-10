// Wazuh syslog_output(UDP) -> D Graylog Raw/Plaintext TCP relay.
// Wazuh csyslogd only sends UDP; datagrams over ~1,400 bytes (FIM 550 with
// hashes and diff) are lost between C and D (VPN fragments, Docker Desktop UDP
// port forwarding). This relay receives on the C Docker network and forwards
// each datagram as one newline-terminated line over TCP.
"use strict";
const dgram = require("node:dgram");
const net = require("node:net");

const LISTEN_PORT = Number(process.env.LISTEN_PORT || 5514);
const TARGET_HOST = process.env.TARGET_HOST || "192.0.2.100";
const TARGET_PORT = Number(process.env.TARGET_PORT || 5514);
const MAX_QUEUE = Number(process.env.MAX_QUEUE || 10000);
const STATS_SEC = Number(process.env.STATS_SEC || 60);

const stats = { received: 0, sent: 0, dropped: 0, reconnects: 0 };
const queue = [];
let sock = null;
let connected = false;
let retryMs = 1000;

function log(msg) {
  console.log(`${new Date().toISOString()} ${msg}`);
}

function toLine(buf) {
  // Graylog Raw/Plaintext TCP splits messages on newline. Wazuh JSON escapes
  // newlines inside strings, so only stray CR/LF at the edges are removed.
  return buf.toString("utf8").replace(/[\r\n]+/g, " ").trim() + "\n";
}

function flush() {
  while (connected && queue.length > 0) {
    const line = queue.shift();
    if (!sock.write(line)) {
      stats.sent++;
      sock.once("drain", flush);
      return;
    }
    stats.sent++;
  }
}

function connect() {
  sock = net.createConnection({ host: TARGET_HOST, port: TARGET_PORT });
  sock.setKeepAlive(true, 30000);
  sock.on("connect", () => {
    connected = true;
    retryMs = 1000;
    log(`connected to ${TARGET_HOST}:${TARGET_PORT}, queued=${queue.length}`);
    flush();
  });
  sock.on("error", (err) => log(`tcp error: ${err.code || err.message}`));
  sock.on("close", () => {
    if (connected) log("tcp closed");
    connected = false;
    stats.reconnects++;
    setTimeout(connect, retryMs);
    retryMs = Math.min(retryMs * 2, 30000);
  });
}

const udp = dgram.createSocket("udp4");
udp.on("message", (msg) => {
  stats.received++;
  if (queue.length >= MAX_QUEUE) {
    queue.shift();
    stats.dropped++;
  }
  queue.push(toLine(msg));
  flush();
});
udp.on("listening", () => log(`udp listening on 0.0.0.0:${LISTEN_PORT} -> tcp ${TARGET_HOST}:${TARGET_PORT}`));
udp.bind(LISTEN_PORT, "0.0.0.0");

setInterval(() => {
  log(`stats received=${stats.received} sent=${stats.sent} dropped=${stats.dropped} queued=${queue.length} connected=${connected} reconnects=${stats.reconnects}`);
}, STATS_SEC * 1000);

connect();
