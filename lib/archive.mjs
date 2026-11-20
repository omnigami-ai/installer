import { gunzipSync } from 'node:zlib';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { CliError } from './config.mjs';
const fail = (message) => {
  throw new CliError('unsafe_archive', message);
};
const string = (b) => {
  const zero = b.indexOf(0);
  const data = zero < 0 ? b : b.subarray(0, zero);
  if (zero >= 0 && b.subarray(zero).some((n) => n !== 0))
    fail('Invalid tar string');
  return new TextDecoder('utf-8', { fatal: true }).decode(data);
};
function number(b) {
  const text = b.toString('ascii').replace(/\0.*$/s, '').trim();
  if (!/^[0-7]*$/.test(text)) fail('Unsupported tar numeric field');
  const n = parseInt(text || '0', 8);
  if (!Number.isSafeInteger(n) || n < 0) fail('Invalid tar size');
  return n;
}
export function safePath(name) {
  if (
    !name ||
    name.length > 4096 ||
    name.startsWith('/') ||
    name.includes('\\') ||
    /[\x00-\x1f\x7f:]/.test(name)
  )
    fail('Unsafe archive path');
  // A leading ./ is conventional tar output; internal dot segments are refused.
  while (name.startsWith('./')) name = name.slice(2);
  const parts = name.replace(/\/$/, '').split('/');
  if (
    parts.some(
      (p) =>
        !p ||
        p === '.' ||
        p === '..' ||
        p.endsWith('.') ||
        p.endsWith(' ') ||
        /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(p),
    )
  )
    fail('Unsafe archive path');
  return parts.join('/');
}
function pax(data) {
  const attrs = {};
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(32, offset);
    if (space < 0) fail('Invalid PAX record');
    const lenText = data.subarray(offset, space).toString();
    if (!/^[1-9][0-9]*$/.test(lenText)) fail('Invalid PAX length');
    const n = Number(lenText);
    if (
      !Number.isSafeInteger(n) ||
      n <= space - offset + 2 ||
      offset + n > data.length ||
      data[offset + n - 1] !== 10
    )
      fail('Invalid PAX length');
    const text = data.subarray(space + 1, offset + n - 1).toString('utf8'),
      eq = text.indexOf('=');
    if (eq < 1) fail('Invalid PAX key');
    const key = text.slice(0, eq);
    if (Object.hasOwn(attrs, key)) fail('Duplicate PAX key');
    // Permit common metadata; reject sparse, size overrides and unknown extraction semantics.
    if (
      ![
        'path',
        'mtime',
        'atime',
        'ctime',
        'uid',
        'gid',
        'uname',
        'gname',
        'comment',
      ].includes(key)
    )
      fail('Unsupported PAX extension');
    attrs[key] = text.slice(eq + 1);
    offset += n;
  }
  return attrs;
}
export function archiveEntries(compressed) {
  let tar;
  try {
    tar = gunzipSync(compressed, { maxOutputLength: 512 * 1024 * 1024 });
  } catch {
    fail('Invalid or oversized gzip');
  }
  if (tar.length % 512 !== 0) fail('Truncated tar');
  const entries = [],
    seen = new Map();
  let offset = 0,
    attrs = null,
    ended = false,
    headers = 0;
  while (offset + 512 <= tar.length) {
    const h = tar.subarray(offset, offset + 512);
    offset += 512;
    if (h.every((n) => n === 0)) {
      if (
        offset + 512 > tar.length ||
        !tar.subarray(offset).every((n) => n === 0)
      )
        fail('Invalid tar trailer');
      ended = true;
      break;
    }
    if (++headers > 30000) fail('Too many archive entries');
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : h[i];
    if (sum !== number(h.subarray(148, 156))) fail('Invalid tar checksum');
    const size = number(h.subarray(124, 136)),
      type = String.fromCharCode(h[156] || 48);
    if (
      size > 512 * 1024 * 1024 ||
      offset + Math.ceil(size / 512) * 512 > tar.length
    )
      fail('Truncated tar entry');
    const data = tar.subarray(offset, offset + size);
    offset += Math.ceil(size / 512) * 512;
    if (type === 'x') {
      if (attrs || size > 65536) fail('Invalid PAX header');
      attrs = pax(data);
      continue;
    }
    if (!['0', '5'].includes(type))
      fail('Links and special archive entries are refused');
    const prefix = string(h.subarray(345, 500)),
      base = string(h.subarray(0, 100));
    let name = attrs?.path ?? (prefix ? prefix + '/' + base : base);
    attrs = null;
    if ((name === '.' || name === './') && type === '5') continue;
    name = safePath(name);
    const folded = name.normalize('NFC').toLowerCase();
    if (seen.has(folded)) fail('Duplicate or case-colliding archive path');
    const parts = folded.split('/');
    for (let i = 1; i < parts.length; i++)
      if (seen.get(parts.slice(0, i).join('/')) === '0')
        fail('File used as directory');
    if (
      type === '0' &&
      [...seen.keys()].some((p) => p.startsWith(folded + '/'))
    )
      fail('Directory used as file');
    if (type === '5' && size !== 0) fail('Directory has file content');
    seen.set(folded, type);
    const mode = number(h.subarray(100, 108));
    entries.push({
      name,
      directory: type === '5',
      executable: !!(mode & 0o111),
      data,
    });
  }
  if (
    !ended ||
    attrs ||
    !entries.some((e) => e.name === 'SKILL.md' && !e.directory)
  )
    fail('Archive must contain SKILL.md at root');
  return entries;
}
export async function extractEntries(entries, target) {
  // target is a newly created private staging directory; all paths were validated before any writes.
  for (const e of entries) {
    const dest = path.join(target, ...e.name.split('/'));
    if (e.directory) await mkdir(dest, { recursive: true, mode: 0o700 });
    else {
      await mkdir(path.dirname(dest), { recursive: true, mode: 0o700 });
      await writeFile(dest, e.data, {
        flag: 'wx',
        mode: e.executable ? 0o700 : 0o600,
      });
    }
  }
}
