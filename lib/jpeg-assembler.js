'use strict';

const { Transform } = require('stream');
const { indexOfMarker } = require('./buffer-utils');

const EMPTY = Buffer.alloc(0);

class JpegAssembler {
  constructor() {
    this.collecting = false;
    this.chunks = [];
    this.totalBytes = 0;
    this.prevByte = null;
    this.carryByte = null; // for split SOI across chunk boundaries when not collecting
    this.maxFrameBytes = 5 * 1024 * 1024;
  }

  _resetFrame() {
    this.collecting = false;
    this.chunks = [];
    this.totalBytes = 0;
    this.prevByte = null;
  }

  _pushFrameChunk(buf) {
    if (!buf || buf.length === 0) return;
    this.chunks.push(buf);
    this.totalBytes += buf.length;
    this.prevByte = buf[buf.length - 1];
  }

  _finishFrame() {
    const frame =
      this.chunks.length === 1 && this.chunks[0].length === this.totalBytes
        ? this.chunks[0]
        : Buffer.concat(this.chunks, this.totalBytes);
    this._resetFrame();
    return frame;
  }

  feed(chunk) {
    const frames = [];
    let data = chunk || EMPTY;

    while (data.length > 0) {
      if (!this.collecting) {
        if (this.carryByte === 0xff && data[0] === 0xd8) {
          // SOI split across chunk boundary: previous ended with 0xff, new begins with 0xd8.
          this.collecting = true;
          this.chunks = [Buffer.from([0xff])];
          this.totalBytes = 1;
          this.prevByte = 0xff;
          this.carryByte = null;
        } else {
          const soi = indexOfMarker(data, 0xff, 0xd8);
          if (soi === -1) {
            this.carryByte = data[data.length - 1] === 0xff ? 0xff : null;
            break;
          }
          this.collecting = true;
          this.chunks = [];
          this.totalBytes = 0;
          this.prevByte = null;
          this.carryByte = null;
          data = data.subarray(soi);
        }
      }

      // EOI split across chunk boundary: previous ended with 0xff, new begins with 0xd9.
      if (this.prevByte === 0xff && data[0] === 0xd9) {
        this._pushFrameChunk(data.subarray(0, 1));
        if (this.totalBytes > this.maxFrameBytes) {
          this._resetFrame();
          break;
        }
        frames.push(this._finishFrame());
        data = data.subarray(1);
        continue;
      }

      const eoi = indexOfMarker(data, 0xff, 0xd9);
      if (eoi === -1) {
        this._pushFrameChunk(data);
        if (this.totalBytes > this.maxFrameBytes) {
          this._resetFrame();
          break;
        }
        data = EMPTY;
      } else {
        const end = eoi + 2;
        this._pushFrameChunk(data.subarray(0, end));
        if (this.totalBytes > this.maxFrameBytes) {
          this._resetFrame();
          break;
        }
        frames.push(this._finishFrame());
        data = data.subarray(end);
      }
    }

    return frames;
  }
}

class JpegAssemblerTransform extends Transform {
  constructor() {
    super({ writableObjectMode: true, readableObjectMode: true });
    this.assembler = new JpegAssembler();
  }

  _transform(chunk, _enc, cb) {
    try {
      const frames = this.assembler.feed(chunk);
      for (const frame of frames) {
        this.push(frame);
        this.emit('frame', frame);
      }
      cb();
    } catch (err) {
      cb(err);
    }
  }
}

module.exports = { JpegAssembler, JpegAssemblerTransform };
