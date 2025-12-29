'use strict';

class ByteQueue {
  constructor(initialCapacity = 64 * 1024) {
    this.buf = Buffer.alloc(initialCapacity);
    this.start = 0;
    this.end = 0;
  }

  get length() {
    return this.end - this.start;
  }

  _ensureCapacity(extra) {
    const len = this.length;
    const needed = len + extra;

    if (needed <= this.buf.length) {
      if (this.end + extra <= this.buf.length) return;
      if (this.start > 0) {
        this.buf.copy(this.buf, 0, this.start, this.end);
        this.start = 0;
        this.end = len;
        return;
      }
    }

    let cap = Math.max(this.buf.length, 1024);
    while (cap < needed) cap *= 2;
    const next = Buffer.alloc(cap);
    if (len > 0) this.buf.copy(next, 0, this.start, this.end);
    this.buf = next;
    this.start = 0;
    this.end = len;
  }

  push(data) {
    if (!data || data.length === 0) return;
    this._ensureCapacity(data.length);
    data.copy(this.buf, this.end);
    this.end += data.length;
  }

  drain(n) {
    if (n > this.length) throw new RangeError(`drain(${n}) exceeds length=${this.length}`);
    this.start += n;
    if (this.start === this.end) {
      this.start = 0;
      this.end = 0;
    }
  }

  peek(n) {
    if (n > this.length) throw new RangeError(`peek(${n}) exceeds length=${this.length}`);
    return this.buf.subarray(this.start, this.start + n);
  }

  subarray(relStart, relEnd) {
    return this.buf.subarray(this.start + relStart, this.start + relEnd);
  }

  indexOf(byte, relFrom = 0) {
    const view = this.buf.subarray(this.start, this.end);
    return view.indexOf(byte, relFrom);
  }

  readUInt32LE(off) {
    return this.buf.readUInt32LE(this.start + off);
  }

  readUInt32BE(off) {
    return this.buf.readUInt32BE(this.start + off);
  }
}

module.exports = ByteQueue;
