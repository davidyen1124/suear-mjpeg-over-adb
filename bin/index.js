#!/usr/bin/env node
'use strict';

const http = require('http');
const { spawn, spawnSync } = require('child_process');
const net = require('net');

const { PcapParserTransform } = require('../lib/pcap-parser');
const { UdpDecoderTransform } = require('../lib/udp-decoder');
const { SuearPayloadTransform } = require('../lib/suear-payload');
const { JpegAssemblerTransform } = require('../lib/jpeg-assembler');

const DEVICE_IP = process.env.SUEAR_DEVICE_IP || '192.168.1.1';
const DEVICE_SRC_PORT = Number(process.env.SUEAR_DEVICE_SRC_PORT || '10006');
const IFACE = process.env.SUEAR_IFACE || 'wlan0';
const HTTP_PORT = Number(process.env.SUEAR_HTTP_PORT || '8081');
const DEBUG = process.env.SUEAR_DEBUG === '1';
const FORWARD_PORT = Number(process.env.SUEAR_FORWARD_PORT || '27183');

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

  let frameCount = 0;
  let lastFpsT = Date.now();
  let lastFrame = null;

  const clients = new Set();
  const server = http.createServer((req, res) => {
    if (req.url !== '/mjpeg') {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('OK. Use /mjpeg\n');
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

  const pcap = new PcapParserTransform();
  const udpDecoder = new UdpDecoderTransform();
  const suearPayload = new SuearPayloadTransform({ deviceIp: DEVICE_IP, devicePort: DEVICE_SRC_PORT });
  const jpegAssembler = new JpegAssemblerTransform();

  pcap.on('packet', () => {
    pcapPackets++;
  });
  suearPayload.on('match', () => {
    matchedUdp++;
  });
  jpegAssembler.on('data', (f) => {
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

    const now = Date.now();
    if (now - lastFpsT >= 1000) {
      const fps = frameCount / ((now - lastFpsT) / 1000);
      if (frameCount > 0) console.log(`frames: ${frameCount} (${fps.toFixed(1)} fps), last=${lastFrame ? lastFrame.length : 0} bytes`);
      frameCount = 0;
      lastFpsT = now;
    }
  });

  function handleStreamError(e) {
    console.error(`pcap parse error: ${e && e.message ? e.message : e}`);
    try {
      if (sock) sock.destroy();
    } catch (_) {}
  }

  pcap.on('error', handleStreamError);
  udpDecoder.on('error', handleStreamError);
  suearPayload.on('error', handleStreamError);
  jpegAssembler.on('error', handleStreamError);

  pcap.pipe(udpDecoder).pipe(suearPayload).pipe(jpegAssembler);

  let sock = null;
  let connectAttempts = 0;
  const maxAttempts = 200;
  let shuttingDown = false;
  let receivedAnyData = false;

  function detachAndDestroySocket(s) {
    if (!s) return;
    try {
      s.unpipe(pcap);
    } catch (_) {}
    try {
      s.destroy();
    } catch (_) {}
  }

  function attachSocket(s) {
    s.on('connect', () => {
      if (DEBUG) console.log('[debug] connected to forwarded pcap stream');
    });
    s.on('error', (e) => {
      detachAndDestroySocket(s);
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
    });

    // Pipe the socket into the parser so backpressure is handled automatically.
    // Note: don't end the pipeline when the socket disconnects; reconnect logic replaces it.
    s.pipe(pcap, { end: false });
  }

  function connectLoop() {
    if (shuttingDown) return;
    connectAttempts++;
    detachAndDestroySocket(sock);
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
      detachAndDestroySocket(sock);
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
