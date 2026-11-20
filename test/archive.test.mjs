import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import {
  mkdtemp,
  realpath,
  writeFile,
  readFile,
  symlink,
  mkdir,
  rm,
  lstat,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { archiveEntries, safePath, extractEntries } from '../lib/archive.mjs';
import { verifiedEntries, agentTarget } from '../lib/client.mjs';
import { privateRead, privateWrite, noSymlinks } from '../lib/storage.mjs';
import { config } from '../lib/config.mjs';
import { tar } from './fixtures.mjs';

const valid = [
  { name: 'SKILL.md' },
  {
    name: 'scripts/run.sh',
    data: Buffer.from('#!/bin/sh\necho safe'),
    mode: 0o755,
  },
];
test('ordinary archive parses without executing bundled scripts', () => {
  const entries = archiveEntries(tar(valid));
  assert.equal(entries.length, 2);
  assert.equal(entries[1].executable, true);
});
for (const name of [
  '../outside',
  '/absolute',
  'C:/drive',
  'a/../b',
  'a\\b',
  'a//b',
  'a/./b',
  'NUL.txt',
  'dir/thing.',
  'space /x',
  'a\u0000b',
])
  test(`refuses unsafe path ${JSON.stringify(name)}`, () =>
    assert.throws(() => safePath(name), { code: 'unsafe_archive' }));
for (const type of ['1', '2', '3', '4', '6', 'S', 'L', 'g'])
  test(`refuses link or extension type ${type}`, () =>
    assert.throws(
      () => archiveEntries(tar([...valid, { name: 'bad', type }])),
      { code: 'unsafe_archive' },
    ));
test('refuses duplicate, case collisions, and file-directory aliases', () => {
  for (const entries of [
    [...valid, { name: 'SKILL.md' }],
    [...valid, { name: 'skill.md' }],
    [...valid, { name: 'scripts' }],
  ])
    assert.throws(() => archiveEntries(tar(entries)), {
      code: 'unsafe_archive',
    });
});
test('requires root SKILL.md and valid trailer', () =>
  assert.throws(() => archiveEntries(tar([{ name: 'nested/SKILL.md' }])), {
    code: 'unsafe_archive',
  }));
test('rejects invalid gzip, truncated tar and header checksum', () => {
  assert.throws(() => archiveEntries(Buffer.from('broken')), {
    code: 'unsafe_archive',
  });
  assert.throws(() => archiveEntries(gzipSync(Buffer.alloc(513))), {
    code: 'unsafe_archive',
  });
  const bad = Buffer.alloc(1536);
  bad.write('SKILL.md');
  assert.throws(() => archiveEntries(gzipSync(bad)), {
    code: 'unsafe_archive',
  });
});
test('pinned signature and digest both required before extraction', async () => {
  const root = await realpath(
    await mkdtemp(path.join(os.tmpdir(), 'installer-unit-')),
  );
  try {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519'),
      pub = publicKey.export({ type: 'spki', format: 'pem' }),
      keyFile = path.join(root, 'pub.pem');
    await writeFile(keyFile, pub);
    const c = config({
      OMNIGAMI_DEV_SERVER: 'http://localhost:4337',
      OMNIGAMI_DEV_PUBLIC_KEY_FILE: keyFile,
    });
    const bytes = tar(valid),
      sha = createHash('sha256').update(bytes).digest('hex');
    const r = {
      slug: 'sample',
      version: '1.0.0',
      filename: `sample-1.0.0-${sha}.tar.gz`,
      bytes: bytes.length,
      sha256: sha,
      keyId: createHash('sha256')
        .update(publicKey.export({ type: 'spki', format: 'der' }))
        .digest('hex'),
      issuedAt: new Date().toISOString(),
      channel: 'development',
    };
    r.signature = sign(
      null,
      Buffer.from(JSON.stringify(r)),
      privateKey,
    ).toString('base64');
    const entries = await verifiedEntries(c, r, bytes, 'sample');
    assert.equal(entries.length, 2);
    const changed = Buffer.from(bytes);
    changed[20] ^= 1;
    await assert.rejects(() => verifiedEntries(c, r, changed, 'sample'), {
      code: 'digest',
    });
    await assert.rejects(
      () => verifiedEntries(c, { ...r, version: '9.0.0' }, bytes, 'sample'),
      { code: 'signature' },
    );
    await assert.rejects(() => verifiedEntries(c, r, bytes, 'other'), {
      code: 'signature',
    });
    const out = path.join(root, 'stage');
    await mkdir(out, { mode: 0o700 });
    await extractEntries(entries, out);
    assert.equal(await readFile(path.join(out, 'SKILL.md'), 'utf8'), 'skill');
    const other = generateKeyPairSync('ed25519').publicKey.export({
      type: 'spki',
      format: 'pem',
    });
    await writeFile(keyFile, other);
    await assert.rejects(() => verifiedEntries(c, r, bytes, 'sample'), {
      code: 'signature',
    });
    // The production client pins the real publisher key (trusted-keys.json), so a release signed by any other key,
    // a development one included, is refused as a bad signature.
    await assert.rejects(
      () => verifiedEntries(config({}), r, bytes, 'sample'),
      { code: 'signature' },
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test('private storage refuses symlinks and unsafe permissions', async () => {
  const root = await realpath(
    await mkdtemp(path.join(os.tmpdir(), 'installer-perm-')),
  );
  try {
    const file = path.join(root, 'credential.json');
    await privateWrite(file, { sample: true });
    assert.deepEqual(await privateRead(file), { sample: true });
    assert.equal((await lstat(file)).mode & 0o777, 0o600);
    const link = path.join(root, 'link');
    await symlink(root, link);
    await assert.rejects(() => noSymlinks(path.join(link, 'target')), {
      code: 'unsafe_path',
    });
    await writeFile(path.join(root, 'unsafe.json'), '{}', { mode: 0o644 });
    await assert.rejects(() => privateRead(path.join(root, 'unsafe.json')), {
      code: 'permissions',
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test('agent directories and explicit target semantics', () => {
  assert.equal(agentTarget('codex'), path.join(os.homedir(), '.agents/skills'));
  assert.equal(agentTarget('claude-code', '/skills'), '/skills');
  assert.throws(() => agentTarget('unknown'), { code: 'agent' });
  assert.throws(() =>
    config({ OMNIGAMI_DEV_SERVER: 'https://untrusted.example' }),
  );
});

test('bounded PAX long paths are supported, dangerous overrides are refused', () => {
  const name = 'assets/' + 'long-name-'.repeat(20) + 'file.txt';
  function record(key, value) {
    let n = key.length + value.length + 4;
    while (true) {
      const text = `${n} ${key}=${value}\n`;
      if (Buffer.byteLength(text) === n) return Buffer.from(text);
      n = Buffer.byteLength(text);
    }
  }
  const entries = archiveEntries(
    tar([
      { name: 'SKILL.md' },
      { name: 'PaxHeader', type: 'x', data: record('path', name) },
      { name: 'placeholder', data: Buffer.from('asset') },
    ]),
  );
  assert.equal(entries[1].name, name);
  assert.throws(
    () =>
      archiveEntries(
        tar([
          { name: 'SKILL.md' },
          { name: 'PaxHeader', type: 'x', data: record('path', '../escape') },
          { name: 'placeholder' },
        ]),
      ),
    { code: 'unsafe_archive' },
  );
  assert.throws(
    () =>
      archiveEntries(
        tar([
          { name: 'PaxHeader', type: 'x', data: record('size', '123') },
          { name: 'SKILL.md' },
        ]),
      ),
    { code: 'unsafe_archive' },
  );
});
