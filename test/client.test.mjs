import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtemp,
  mkdir,
  writeFile,
  readFile,
  rm,
  realpath,
} from 'node:fs/promises';
import { existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import {
  api,
  update,
  fingerprint,
  retryDelay,
  serverMessages,
} from '../lib/client.mjs';
import { saveCredentials, privateWrite, ledgerFile } from '../lib/storage.mjs';
import { config } from '../lib/config.mjs';
import { tar } from './fixtures.mjs';
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

test('update 30 skills in one run, separate list/download limits and Retry-After', async (t) => {
  const temp = await realpath(
    await mkdtemp(path.join(os.tmpdir(), 'installer-update-')),
  );
  t.after(() => rm(temp, { recursive: true, force: true }));
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const key = path.join(temp, 'public.pem');
  await writeFile(key, publicKey.export({ type: 'spki', format: 'pem' }));
  const c = config({
    OMNIGAMI_DEV_SERVER: 'http://localhost:4337',
    OMNIGAMI_CONFIG_DIR: path.join(temp, 'config'),
    OMNIGAMI_DEV_PUBLIC_KEY_FILE: key,
    OMNIGAMI_DEV_FILE_STORE: '1',
  });
  await saveCredentials(c, {
    origin: c.origin,
    token: 'a'.repeat(43),
    expiresAt: new Date(Date.now() + 2592000000).toISOString(),
  });
  const target = path.join(temp, 'skills'),
    ledger = { installs: [] },
    releases = new Map(),
    archives = new Map();
  for (let i = 0; i < 30; i++) {
    const slug = `sample-${i}`,
      dir = path.join(target, slug);
    await mkdir(dir, { recursive: true });
    await writeFile(path.join(dir, 'SKILL.md'), 'old instructions');
    ledger.installs.push({
      slug,
      version: '1.0.0',
      origin: c.origin,
      agent: 'codex',
      target,
      files: await fingerprint(dir),
    });
    const bytes = tar([
      { name: 'SKILL.md', data: Buffer.from('updated instructions') },
    ]);
    const r = {
      slug,
      version: '1.0.1',
      filename: `${slug}-1.0.1-${hash(bytes)}.tar.gz`,
      bytes: bytes.length,
      sha256: hash(bytes),
      keyId: hash(publicKey.export({ type: 'spki', format: 'der' })),
      issuedAt: new Date().toISOString(),
      channel: 'development',
    };
    r.signature = sign(
      null,
      Buffer.from(JSON.stringify(r)),
      privateKey,
    ).toString('base64');
    releases.set(slug, { ...r, url: `/api/download-file?ticket=${slug}` });
    archives.set(slug, bytes);
  }
  await privateWrite(ledgerFile(c), ledger);
  let listings = 0,
    downloads = 0,
    retried = false;
  const waits = [];
  c.onWait = (message) => waits.push(message);
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    const route = new URL(url),
      body = options.body && JSON.parse(options.body);
    if (route.pathname === '/api/devices') {
      listings++;
      return Response.json({
        skills: [...releases.values()].map((r) => ({ ...r, available: true })),
      });
    }
    if (route.pathname === '/api/downloads') {
      downloads++;
      if (!retried && downloads === 15) {
        retried = true;
        return Response.json(
          { error: 'rate' },
          { status: 429, headers: { 'retry-after': '1' } },
        );
      }
      return Response.json(releases.get(body.slug));
    }
    return new Response(archives.get(route.searchParams.get('ticket')));
  });
  const result = await update(c);
  assert.equal(result.updates.length, 30);
  assert.equal(listings, 1);
  assert.equal(downloads, 31);
  assert.equal(waits.length, 1);
  for (const item of result.updates) {
    assert.ok(item.updated && item.backup);
    assert.equal(
      await readFile(path.join(item.path, 'SKILL.md'), 'utf8'),
      'updated instructions',
    );
    assert.equal(
      await readFile(path.join(item.backup, 'SKILL.md'), 'utf8'),
      'old instructions',
    );
  }
});

test('Retry-After seconds/date validation, bounded retry exhaustion, long/daily waits fail clearly', async (t) => {
  assert.equal(retryDelay('1'), 1000);
  const now = Date.parse('2026-11-20T12:00:00Z');
  assert.equal(retryDelay('Fri, 20 Nov 2026 12:00:03 GMT', now), 3000);
  for (const value of [null, 'bad', '-1', '61', 'Infinity'])
    assert.equal(retryDelay(value), null);
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async () => {
    calls++;
    return Response.json(
      { error: 'rate' },
      { status: 429, headers: { 'retry-after': '0' } },
    );
  });
  await assert.rejects(
    api({ origin: 'http://localhost:4337' }, '/api/downloads', {}),
    { code: 'rate', message: serverMessages.rate },
  );
  assert.equal(calls, 4);
  globalThis.fetch = async () =>
    Response.json(
      { error: 'rate' },
      { status: 429, headers: { 'retry-after': '600' } },
    );
  await assert.rejects(
    api({ origin: 'http://localhost:4337' }, '/api/downloads', {}),
    { code: 'rate' },
  );
  globalThis.fetch = async () =>
    Response.json(
      { error: 'daily_limit' },
      { status: 429, headers: { 'retry-after': '86400' } },
    );
  await assert.rejects(
    api({ origin: 'http://localhost:4337' }, '/api/downloads', {}),
    { code: 'daily_limit', message: serverMessages.daily_limit },
  );
});

// Reads the site's handlers, which sit beside the installer only in omnigami's own repository; skipped elsewhere.
const siteApi = new URL('../../../site/api/', import.meta.url);
test('every delivery handler error has a clear English client message', { skip: !existsSync(siteApi) }, async () => {
  for (const name of [
    'downloads',
    'download-file',
    'preferences',
    'device-code',
    'device-token',
    'devices',
  ]) {
    const source = await readFile(
      new URL(`../../../site/api/${name}.js`, import.meta.url),
      'utf8',
    );
    for (const match of source.matchAll(/error:\s*'([^']+)'/g))
      assert.ok(serverMessages[match[1]], `${name}: ${match[1]}`);
  }
  assert.match(serverMessages.signin, /30 days/);
  assert.match(serverMessages.daily_limit, /6 free skills/);
});
