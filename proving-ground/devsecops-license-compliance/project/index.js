// Tiny thumbnail service. It shells out to the ffmpeg binary shipped by
// ffmpeg-static to render poster frames for uploaded media.
const { spawn } = require('node:child_process');
const path = require('node:path');
const ffmpeg = require('ffmpeg-static');
const { chunk } = require('lodash');
const { from } = require('rxjs');

function thumbnail(input, outDir) {
  const out = path.join(outDir, 'poster.png');
  const args = ['-y', '-i', input, '-frames:v', '1', out];
  return new Promise((resolve, reject) => {
    const p = spawn(ffmpeg, args, { stdio: 'ignore' });
    p.on('exit', (code) => (code === 0 ? resolve(out) : reject(new Error(`ffmpeg exit ${code}`))));
  });
}

function queue(files) {
  return from(chunk(files, 4));
}

module.exports = { thumbnail, queue };
