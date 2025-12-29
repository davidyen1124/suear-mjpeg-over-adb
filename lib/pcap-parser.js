'use strict';

const { Transform } = require('stream');
const ByteQueue = require('./byte-queue');

class PcapStreamParser {
  constructor(onPacket) {
    this.onPacket = onPacket;
    this.q = new ByteQueue();
    this.pcap = null;
    this.debug = process.env.SUEAR_DEBUG === '1';
  }

  need(n) {
    return this.q.length >= n;
  }

  drain(n) {
    this.q.drain(n);
  }

  readU32(off, le) {
    return le ? this.q.readUInt32LE(off) : this.q.readUInt32BE(off);
  }

  stripTcpdumpBanner() {
    // Android tcpdump sometimes writes its "listening on ..." banner to stdout,
    // which corrupts the binary pcap stream. Strip any leading ASCII line(s)
    // starting with "tcpdump:".
    while (this.q.length >= 8 && this.q.peek(8).toString('ascii') === 'tcpdump:') {
      const nl = this.q.indexOf(0x0a);
      if (nl === -1) return false; // need more bytes
      this.q.drain(nl + 1);
    }
    return true;
  }

  tryResync(le) {
    // Scan forward a bit for a plausible per-packet header.
    // header: ts_sec(u32), ts_usec(u32), incl_len(u32), orig_len(u32)
    const maxScan = Math.min(this.q.length - 16, 4096);
    for (let i = 0; i <= maxScan; i++) {
      const tsUsec = this.readU32(i + 4, le);
      const inclLen = this.readU32(i + 8, le);
      const origLen = this.readU32(i + 12, le);
      if (tsUsec > 1_000_000) continue;
      if (inclLen !== origLen) continue;
      if (inclLen < 14 || inclLen > 262_144) continue;
      if (i !== 0 && this.debug) console.log(`[pcap] resync +${i} (inclLen=${inclLen})`);
      this.drain(i);
      return true;
    }
    return false;
  }

  push(data) {
    this.q.push(data);

    if (!this.pcap) {
      if (!this.need(24)) return;
      const magicBE = this.q.readUInt32BE(0);
      const magicLE = this.q.readUInt32LE(0);
      let le = null;
      // microsecond-resolution PCAP (common)
      if (magicBE === 0xa1b2c3d4) le = false;
      else if (magicLE === 0xa1b2c3d4) le = true;
      // nanosecond-resolution PCAP (less common)
      else if (magicBE === 0xa1b23c4d) le = false;
      else if (magicLE === 0xa1b23c4d) le = true;
      else throw new Error(`Unknown pcap magic: be=0x${magicBE.toString(16)} le=0x${magicLE.toString(16)}`);

      const network = le ? this.q.readUInt32LE(20) : this.q.readUInt32BE(20);
      this.pcap = { le, network };
      if (this.pcap.network !== 1) {
        throw new Error(`Unsupported pcap linktype=${this.pcap.network} (expected 1/EN10MB).`);
      }
      if (this.debug) console.log(`[pcap] header ok le=${this.pcap.le} linktype=${this.pcap.network}`);
      this.drain(24);
    }

    if (this.pcap && !this.stripTcpdumpBanner()) return;

    while (this.need(16)) {
      if (!this.stripTcpdumpBanner()) return;
      const le = this.pcap.le;
      const inclLen = this.readU32(8, le);
      const origLen = this.readU32(12, le);
      const tsUsec = this.readU32(4, le);
      if (tsUsec > 1_000_000 || inclLen !== origLen || inclLen < 14 || inclLen > 262_144) {
        if (!this.tryResync(le)) {
          if (this.debug) {
            const preview = this.q.peek(Math.min(this.q.length, 64));
            console.log(`[pcap] desync (tsUsec=${tsUsec} incl=${inclLen} orig=${origLen}) next=${preview.toString('hex')}`);
          }
          return;
        }
        continue;
      }
      if (!this.need(16 + inclLen)) return;
      const pkt = this.q.subarray(16, 16 + inclLen);
      this.drain(16 + inclLen);
      this.onPacket(pkt);
    }
  }
}

class PcapParserTransform extends Transform {
  constructor() {
    super({ readableObjectMode: true });
    this.parser = new PcapStreamParser((pkt) => {
      this.push(pkt);
      this.emit('packet', pkt);
    });
  }

  _transform(chunk, _enc, cb) {
    try {
      this.parser.push(chunk);
      cb();
    } catch (err) {
      cb(err);
    }
  }
}

module.exports = { PcapStreamParser, PcapParserTransform };
