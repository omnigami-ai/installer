import { gzipSync } from 'node:zlib';
export function tar(entries) {
  const chunks = [];
  for (const {
    name,
    type = '0',
    data = Buffer.from('skill'),
    mode = 0o644,
  } of entries) {
    const h = Buffer.alloc(512);
    h.write(name, 0, 100);
    h.write(mode.toString(8).padStart(7, '0') + '\0', 100, 8);
    h.write(data.length.toString(8).padStart(11, '0') + '\0', 124, 12);
    h.fill(32, 148, 156);
    h[156] = type.charCodeAt(0);
    h.write('ustar\0', 257);
    let sum = 0;
    for (const n of h) sum += n;
    h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8);
    chunks.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  return gzipSync(Buffer.concat([...chunks, Buffer.alloc(1024)]));
}
