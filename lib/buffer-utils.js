'use strict';

function indexOfMarker(buf, a, b, start = 0) {
  for (let i = start; i + 1 < buf.length; i++) {
    if (buf[i] === a && buf[i + 1] === b) return i;
  }
  return -1;
}

module.exports = { indexOfMarker };
