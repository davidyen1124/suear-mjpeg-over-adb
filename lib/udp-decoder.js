'use strict';

const { Transform } = require('stream');

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

class UdpDecoderTransform extends Transform {
  constructor() {
    super({ writableObjectMode: true, readableObjectMode: true });
  }

  _transform(frame, _enc, cb) {
    try {
      const udp = decodeUdpPayloadFromEthernetFrame(frame);
      if (udp) {
        this.push(udp);
        this.emit('udp', udp);
      }
      cb();
    } catch (err) {
      cb(err);
    }
  }
}

module.exports = { decodeUdpPayloadFromEthernetFrame, UdpDecoderTransform };
