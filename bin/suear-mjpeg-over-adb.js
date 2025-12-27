#!/usr/bin/env node
'use strict';

const http = require('http');
const { spawn, spawnSync } = require('child_process');
const net = require('net');

const DEVICE_IP = process.env.SUEAR_DEVICE_IP || '192.168.1.1';
const DEVICE_SRC_PORT = Number(process.env.SUEAR_DEVICE_SRC_PORT || '10006');
const IFACE = process.env.SUEAR_IFACE || 'wlan0';
const HTTP_PORT = Number(process.env.SUEAR_HTTP_PORT || '8081');
const DEBUG = process.env.SUEAR_DEBUG === '1';
const FORWARD_PORT = Number(process.env.SUEAR_FORWARD_PORT || '27183');

function indexOfMarker(buf, a, b, start = 0) {
  for (let i = start; i + 1 < buf.length; i++) {
    if (buf[i] === a && buf[i + 1] === b) return i;
  }
  return -1;
}

class JpegAssembler {
  constructor() {
    this.collecting = false;
    this.buf = Buffer.alloc(0);
    this.maxFrameBytes = 5 * 1024 * 1024;
  }

  feed(chunk) {
    const frames = [];
    let data = chunk;

    while (data.length > 0) {
      if (!this.collecting) {
        const soi = indexOfMarker(data, 0xff, 0xd8);
        if (soi === -1) break;
        this.collecting = true;
        this.buf = data.subarray(soi);
        data = Buffer.alloc(0);
      } else {
        this.buf = Buffer.concat([this.buf, data]);
        data = Buffer.alloc(0);
      }

      if (this.buf.length > this.maxFrameBytes) {
        this.collecting = false;
        this.buf = Buffer.alloc(0);
        break;
      }

      // There may be multiple frames buffered; emit all complete ones.
      while (this.collecting) {
        const eoi = indexOfMarker(this.buf, 0xff, 0xd9);
        if (eoi === -1) break;
        const frame = this.buf.subarray(0, eoi + 2);
        frames.push(frame);
        const rest = this.buf.subarray(eoi + 2);
        this.collecting = false;
        this.buf = Buffer.alloc(0);
        if (rest.length > 0) {
          data = rest;
          break;
        }
      }
    }

    return frames;
  }
}

function parsePcapStream(onPacket) {
  let buf = Buffer.alloc(0);
  let pcap = null;

  const DEBUG_PCAP = process.env.SUEAR_DEBUG === '1';

  function stripTcpdumpBanner() {
    // Android tcpdump sometimes writes its "listening on ..." banner to stdout,
    // which corrupts the binary pcap stream. Strip any leading ASCII line(s)
    // starting with "tcpdump:".
    while (buf.length >= 8 && buf.subarray(0, 8).toString('ascii') === 'tcpdump:') {
      const nl = buf.indexOf(0x0a);
      if (nl === -1) return false; // need more bytes
      buf = buf.subarray(nl + 1);
    }
    return true;
  }

  function tryResync(le) {
    // Scan forward a bit for a plausible per-packet header.
    // header: ts_sec(u32), ts_usec(u32), incl_len(u32), orig_len(u32)
    const maxScan = Math.min(buf.length - 16, 4096);
    for (let i = 0; i <= maxScan; i++) {
      const tsUsec = le ? buf.readUInt32LE(i + 4) : buf.readUInt32BE(i + 4);
      const inclLen = le ? buf.readUInt32LE(i + 8) : buf.readUInt32BE(i + 8);
      const origLen = le ? buf.readUInt32LE(i + 12) : buf.readUInt32BE(i + 12);
      if (tsUsec > 1_000_000) continue;
      if (inclLen !== origLen) continue;
      if (inclLen < 14 || inclLen > 262_144) continue;
      if (i !== 0 && DEBUG_PCAP) console.log(`[pcap] resync +${i} (inclLen=${inclLen})`);
      buf = buf.subarray(i);
      return true;
    }
    return false;
  }

  function need(n) {
    return buf.length >= n;
  }

  function readU32(off, le) {
    return le ? buf.readUInt32LE(off) : buf.readUInt32BE(off);
  }

  function drain(n) {
    buf = buf.subarray(n);
  }

  return {
    push(data) {
      buf = Buffer.concat([buf, data]);

      if (!pcap) {
      if (!need(24)) return;
      const magicBE = buf.readUInt32BE(0);
      const magicLE = buf.readUInt32LE(0);
      let le = null;
        // microsecond-resolution PCAP (common)
        if (magicBE === 0xa1b2c3d4) le = false;
        else if (magicLE === 0xa1b2c3d4) le = true;
        // nanosecond-resolution PCAP (less common)
        else if (magicBE === 0xa1b23c4d) le = false;
        else if (magicLE === 0xa1b23c4d) le = true;
        else throw new Error(`Unknown pcap magic: be=0x${magicBE.toString(16)} le=0x${magicLE.toString(16)}`);

        const network = le ? buf.readUInt32LE(20) : buf.readUInt32BE(20);
        pcap = { le, network };
        if (pcap.network !== 1) {
          throw new Error(`Unsupported pcap linktype=${pcap.network} (expected 1/EN10MB).`);
        }
        if (DEBUG_PCAP) console.log(`[pcap] header ok le=${pcap.le} linktype=${pcap.network}`);
        drain(24);
      }

      if (pcap && !stripTcpdumpBanner()) return;

      while (need(16)) {
        if (!stripTcpdumpBanner()) return;
        const le = pcap.le;
        const inclLen = readU32(8, le);
        const origLen = readU32(12, le);
        const tsUsec = readU32(4, le);
        if (tsUsec > 1_000_000 || inclLen !== origLen || inclLen < 14 || inclLen > 262_144) {
          if (!tryResync(le)) {
            if (DEBUG_PCAP) {
              const preview = buf.subarray(0, Math.min(buf.length, 64));
              console.log(`[pcap] desync (tsUsec=${tsUsec} incl=${inclLen} orig=${origLen}) next=${preview.toString('hex')}`);
            }
            return;
          }
          continue;
        }
        if (!need(16 + inclLen)) return;
        const pkt = buf.subarray(16, 16 + inclLen);
        drain(16 + inclLen);
        onPacket(pkt);
      }
    },
  };
}

function decodeUdpPayloadFromEthernetFrame(frame) {
  // Ethernet II
  if (frame.length < 14) return null;
  let ethType = frame.readUInt16BE(12);
  let off = 14;
  if (ethType === 0x8100 && frame.length >= 18) {
    ethType = frame.readUInt16BE(16);
    off = 18;
  }
  if (ethType !== 0x0800) return null; // IPv4

  if (frame.length < off + 20) return null;
  const verIhl = frame[off];
  const version = verIhl >> 4;
  const ihl = (verIhl & 0x0f) * 4;
  if (version !== 4 || ihl < 20) return null;
  if (frame.length < off + ihl) return null;

  const proto = frame[off + 9];
  if (proto !== 17) return null; // UDP

  const srcIp = `${frame[off + 12]}.${frame[off + 13]}.${frame[off + 14]}.${frame[off + 15]}`;
  const dstIp = `${frame[off + 16]}.${frame[off + 17]}.${frame[off + 18]}.${frame[off + 19]}`;

  const udpOff = off + ihl;
  if (frame.length < udpOff + 8) return null;
  const srcPort = frame.readUInt16BE(udpOff);
  const dstPort = frame.readUInt16BE(udpOff + 2);
  const udpLen = frame.readUInt16BE(udpOff + 4);
  const payloadOff = udpOff + 8;
  const payloadLen = Math.max(0, Math.min(frame.length - payloadOff, udpLen - 8));
  const payload = frame.subarray(payloadOff, payloadOff + payloadLen);

  return { srcIp, dstIp, srcPort, dstPort, payload };
}

function start() {
  console.log(`tcpdump: iface=${IFACE} device=${DEVICE_IP}:${DEVICE_SRC_PORT}`);

  const bpf = `udp and src host ${DEVICE_IP} and src port ${DEVICE_SRC_PORT}`;
  function escDq(s) {
    return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  }

  // IMPORTANT:
  // Streaming binary pcap over `adb exec-out` can be corrupted on some devices/adb versions
  // due to stdout/stderr multiplexing. Use `adb forward` + device-local TCP server instead.
  // We write a clean pcap to a file, then stream it with `tail -c +1 -f ... | nc -l`.
  const capFile = `/data/local/tmp/suear-stream-${FORWARD_PORT}.pcap`;
  const srvPidFile = `/data/local/tmp/suear-stream-${FORWARD_PORT}.pid`;
  console.log(`adb forward: localhost:${FORWARD_PORT} -> device tcp:${FORWARD_PORT}`);
  // Best-effort cleanup of any prior runs.
  spawnSync('adb', ['forward', '--remove', `tcp:${FORWARD_PORT}`], { stdio: 'ignore' });
  const cleanupDeviceCmd =
    `kill $(cat ${srvPidFile}) 2>/dev/null || true; ` +
    `rm -f ${srvPidFile} ${capFile} 2>/dev/null || true; ` +
    // Kill anything currently listening on the port.
    `ss -ltnp 2>/dev/null | grep ':${FORWARD_PORT} ' | ` +
    `sed -n 's/.*pid=\\([0-9]*\\).*/\\1/p' | ` +
    `while read -r p; do [ -n \"$p\" ] && kill -9 \"$p\" 2>/dev/null || true; done; ` +
    // Kill any tcpdump writing to our cap file.
    `ps -A -o PID,ARGS | grep '${capFile}' | grep tcpdump | awk '{print $1}' | ` +
    `while read -r p; do [ -n \"$p\" ] && kill -9 \"$p\" 2>/dev/null || true; done`;
  spawnSync('adb', ['shell', 'su', '-c', cleanupDeviceCmd], { stdio: 'ignore' });

  spawnSync('adb', ['forward', `tcp:${FORWARD_PORT}`, `tcp:${FORWARD_PORT}`], { stdio: 'ignore' });

  const serverPipeline =
    `rm -f ${capFile}; :> ${capFile}; ` +
    `/system/bin/tcpdump -i ${IFACE} -s 0 -U -w ${capFile} ${bpf} >/dev/null 2>&1 & ` +
    `tail -c +1 -f ${capFile} | nc -s 127.0.0.1 -p ${FORWARD_PORT} -l >/dev/null 2>&1`;
  const startServerCmd = `nohup sh -c "${escDq(serverPipeline)}" >/dev/null 2>&1 & echo $! > ${srvPidFile}`;
  spawnSync('adb', ['shell', 'su', '-c', startServerCmd], { stdio: 'ignore' });

  let pcapBytes = 0;
  let pcapPackets = 0;
  let matchedUdp = 0;
  let assembledFrames = 0;

  const assembler = new JpegAssembler();
  let frameCount = 0;
  let lastFpsT = Date.now();
  let lastFrame = null;

  const clients = new Set();
  const server = http.createServer((req, res) => {
    if (req.url === '/frame.jpg') {
      if (!lastFrame) {
        res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('no frame yet (start live preview in the Suear app)\n');
        return;
      }
      res.writeHead(200, {
        'cache-control': 'no-cache',
        'pragma': 'no-cache',
        'content-type': 'image/jpeg',
        'content-length': String(lastFrame.length),
      });
      res.end(lastFrame);
      return;
    }
    if (req.url !== '/mjpeg') {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('OK. Use /mjpeg or /frame.jpg\n');
      return;
    }
    res.writeHead(200, {
      'cache-control': 'no-cache',
      'pragma': 'no-cache',
      'connection': 'close',
      'content-type': 'multipart/x-mixed-replace; boundary=frame',
    });
    clients.add(res);
    req.on('close', () => clients.delete(res));
    if (lastFrame) {
      res.write(`--frame\r\nContent-Type: image/jpeg\r\nContent-Length: ${lastFrame.length}\r\n\r\n`);
      res.write(lastFrame);
      res.write('\r\n');
    }
  });
  server.listen(HTTP_PORT, '127.0.0.1', () => {
    console.log(`MJPEG server: http://127.0.0.1:${HTTP_PORT}/mjpeg`);
  });

  const pcap = parsePcapStream((pkt) => {
    pcapPackets++;
    const udp = decodeUdpPayloadFromEthernetFrame(pkt);
    if (!udp) return;
    if (udp.srcIp !== DEVICE_IP) return;
    if (udp.srcPort !== DEVICE_SRC_PORT) return;
    matchedUdp++;

    // Heuristic: Suear packets often have a small per-datagram header before JPEG bytes.
    // If we see SOI inside the first 64 bytes, strip everything before it.
    // Otherwise strip a default 16-byte header when present.
    let payload = udp.payload;
    const soi = indexOfMarker(payload, 0xff, 0xd8);
    if (soi >= 0 && soi <= 64) payload = payload.subarray(soi);
    else if (payload.length > 16) payload = payload.subarray(16);

    const frames = assembler.feed(payload);
    for (const f of frames) {
      frameCount++;
      assembledFrames++;
      lastFrame = f;
      const header = `--frame\r\nContent-Type: image/jpeg\r\nContent-Length: ${f.length}\r\n\r\n`;
      const footer = '\r\n';
      for (const res of clients) {
        try {
          res.write(header);
          res.write(f);
          res.write(footer);
        } catch (_) {
          clients.delete(res);
        }
      }
    }

    const now = Date.now();
    if (now - lastFpsT >= 1000) {
      const fps = frameCount / ((now - lastFpsT) / 1000);
      if (frameCount > 0) console.log(`frames: ${frameCount} (${fps.toFixed(1)} fps), last=${lastFrame ? lastFrame.length : 0} bytes`);
      frameCount = 0;
      lastFpsT = now;
    }
  });

  let sock = null;
  let connectAttempts = 0;
  const maxAttempts = 200;
  let shuttingDown = false;
  let receivedAnyData = false;

  function attachSocket(s) {
    s.on('connect', () => {
      if (DEBUG) console.log('[debug] connected to forwarded pcap stream');
    });
    s.on('error', (e) => {
      if (!shuttingDown && connectAttempts < maxAttempts) {
        setTimeout(connectLoop, 150);
        return;
      }
      console.error(`pcap stream socket error: ${e && e.message ? e.message : e}`);
      process.exitCode = 1;
    });
    s.on('close', () => {
      if (DEBUG) console.log('[debug] pcap stream socket closed');
      if (!shuttingDown && !receivedAnyData && connectAttempts < maxAttempts) {
        setTimeout(connectLoop, 150);
      }
    });
    s.on('data', (d) => {
      receivedAnyData = true;
      pcapBytes += d.length;
      try {
        pcap.push(d);
      } catch (e) {
        console.error(`pcap parse error: ${e && e.message ? e.message : e}`);
        try {
          s.destroy();
        } catch (_) {}
      }
    });
  }

  function connectLoop() {
    if (shuttingDown) return;
    connectAttempts++;
    try {
      if (sock) sock.destroy();
    } catch (_) {}
    sock = new net.Socket();
    receivedAnyData = false;
    attachSocket(sock);
    sock.connect({ host: '127.0.0.1', port: FORWARD_PORT });
  }

  connectLoop();

  if (DEBUG) {
    setInterval(() => {
      console.log(`[debug] pcapBytes=${pcapBytes} pcapPackets=${pcapPackets} matchedUdp=${matchedUdp} frames=${assembledFrames}`);
    }, 1000).unref();
  }

  function cleanup() {
    shuttingDown = true;
    try {
      if (sock) sock.destroy();
    } catch (_) {}
    spawn('adb', ['forward', '--remove', `tcp:${FORWARD_PORT}`], { stdio: 'ignore' });
    const stopDeviceCmd =
      `kill $(cat ${srvPidFile}) 2>/dev/null || true; ` +
      `rm -f ${srvPidFile} 2>/dev/null || true; ` +
      // Kill anything listening on the port.
      `ss -ltnp 2>/dev/null | grep ':${FORWARD_PORT} ' | sed -n 's/.*pid=\\([0-9]*\\).*/\\1/p' | ` +
      `while read -r p; do [ -n \"$p\" ] && kill -9 \"$p\" 2>/dev/null || true; done; ` +
      // Kill any tcpdump/tail tied to our capture file.
      `ps -A -o PID,ARGS | grep '${capFile}' | awk '{print $1}' | while read -r p; do [ -n \"$p\" ] && kill -9 \"$p\" 2>/dev/null || true; done; ` +
      `rm -f ${capFile} 2>/dev/null || true`;
    spawn('adb', ['shell', 'su', '-c', stopDeviceCmd], { stdio: 'ignore' });
  }
  process.on('SIGINT', () => {
    cleanup();
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    cleanup();
    process.exit(0);
  });
}

start();
