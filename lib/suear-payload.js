'use strict';

const { Transform } = require('stream');
const { indexOfMarker } = require('./buffer-utils');

class SuearPayloadTransform extends Transform {
  constructor({ deviceIp, devicePort } = {}) {
    super({ writableObjectMode: true, readableObjectMode: true });
    this.deviceIp = deviceIp;
    this.devicePort = devicePort;
  }

  _transform(udp, _enc, cb) {
    try {
      if (!udp) return cb();
      if (this.deviceIp && udp.srcIp !== this.deviceIp) return cb();
      if (this.devicePort && udp.srcPort !== this.devicePort) return cb();
      this.emit('match', udp);

      // Heuristic: Suear packets often have a small per-datagram header before JPEG bytes.
      // If we see SOI inside the first 64 bytes, strip everything before it.
      // Otherwise strip a default 16-byte header when present.
      let payload = udp.payload;
      const soi = indexOfMarker(payload, 0xff, 0xd8);
      if (soi >= 0 && soi <= 64) payload = payload.subarray(soi);
      else if (payload.length > 16) payload = payload.subarray(16);

      // `payload` is a slice into `pkt`, which may reference internal parser storage.
      // Copy to ensure stable bytes while the assembler buffers chunks and while writes are pending.
      const safePayload = Buffer.from(payload);
      this.push(safePayload);
      this.emit('payload', safePayload);
      cb();
    } catch (err) {
      cb(err);
    }
  }
}

module.exports = { SuearPayloadTransform };
