import { installerPackage } from './package-name.mjs';
import { spawn } from 'node:child_process';
import { createHash, createPublicKey, verify, randomUUID } from 'node:crypto';
import {
  readFile,
  mkdir,
  lstat,
  rename,
  rm,
  readdir,
  mkdtemp,
} from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { CliError, trustedKeys } from './config.mjs';
import {
  credentials,
  saveCredentials,
  clearCredentials,
  privateDir,
  privateWrite,
  ledgerFile,
  readLedger,
  noSymlinks,
  withLock,
} from './storage.mjs';
import { archiveEntries, extractEntries } from './archive.mjs';
const hash = (b) => createHash('sha256').update(b).digest('hex');
const slugOK = (s) =>
  typeof s === 'string' &&
  /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(s) &&
  s.length <= 100;
export async function responseBytes(response, max) {
  if (Number(response.headers.get('content-length')) > max)
    throw new CliError('size', 'Response exceeds size limit');
  const reader = response.body.getReader(),
    chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > max)
        throw new CliError('size', 'Response exceeds size limit');
      chunks.push(Buffer.from(value));
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return Buffer.concat(chunks);
}
export const serverMessages = Object.freeze({
  signin: `Installer approval expired or was revoked. Run ${installerPackage} login again. Approval lasts 30 days.`,
  license:
    'Accept the current license on your account page before downloading.',
  'license-version':
    'The license changed. Review and accept the current license on your account page.',
  skill: 'Skill unavailable or this account does not have access.',
  entitlement: 'This account no longer has access to this skill.',
  rate: 'Account request limit reached. Try again later.',
  daily_limit: "You've reached today's limit of 6 free skills; more tomorrow",
  disabled: 'Installer access is not enabled on this server.',
  unavailable: 'Release or service unavailable. Try again later.',
  authorization_pending: 'Waiting for you to approve the code in your browser.',
  slow_down:
    'The server needs slower authorization polling. Waiting before trying again.',
  access_denied:
    'Device approval was denied. Run login again if you meant to approve it.',
  expired_token: 'The authorization code expired. Run login again.',
  invalid_request:
    'Invalid authorization request. Check for an installer update.',
  method: 'Unsupported request method. Check for an installer update.',
  origin:
    'Request origin was refused. Use the official site or an explicit localhost development server.',
  size: 'The request exceeds the server size limit.',
  body: 'The server could not read the request. Check for an installer update.',
  scope: 'This approval only allows listing and downloading skills.',
  action: 'Unsupported device action. Check for an installer update.',
  code: 'The code is invalid, expired or already used. Run login again.',
  device:
    'This device was not found or was already revoked. Refresh your account page.',
  ticket: 'The download link expired or is invalid. Request a fresh download.',
  release: 'The release changed. Request a fresh download.',
});
export function retryDelay(header, now = Date.now()) {
  if (!header) return null;
  const seconds = /^\d+$/.test(header)
    ? Number(header)
    : (Date.parse(header) - now) / 1000;
  // Do not shorten the server's requested delay. Long/day limits return immediately.
  return Number.isFinite(seconds) && seconds >= 0 && seconds <= 60
    ? Math.max(1000, Math.ceil(seconds * 1000))
    : null;
}
export async function api(c, route, body, credential = null, form = false) {
  let waited = 0;
  for (let attempt = 0; ; attempt++) {
    let response;
    try {
      response = await fetch(c.origin + route, {
        method: 'POST',
        redirect: 'error',
        signal: AbortSignal.timeout(30000),
        headers: {
          'content-type': form
            ? 'application/x-www-form-urlencoded'
            : 'application/json',
          ...(credential
            ? { authorization: `Bearer ${credential.token}` }
            : {}),
        },
        body: form
          ? new URLSearchParams(body).toString()
          : JSON.stringify(body),
      });
    } catch {
      throw new CliError(
        'network',
        'Cannot reach omnigami. Check the connection and try again.',
      );
    }
    let data;
    try {
      data = JSON.parse(
        (await responseBytes(response, 1024 * 1024)).toString(),
      );
    } catch {
      throw new CliError('response', 'Unexpected server response');
    }
    if (response.ok) return data;
    const code = Object.hasOwn(serverMessages, data.error)
      ? data.error
      : 'request';
    if (response.status === 429 && code === 'rate') {
      const delay = retryDelay(response.headers.get('retry-after'));
      if (delay !== null && attempt < 3 && waited + delay <= 120000) {
        c.onWait?.(
          `Request limit reached. Retrying in ${Math.ceil(delay / 1000)} seconds…`,
        );
        await new Promise((resolve) => setTimeout(resolve, delay));
        waited += delay;
        continue;
      }
    }
    throw new CliError(
      code,
      serverMessages[code] ||
        'The server refused this request. Check for an installer update and try again.',
    );
  }
}
async function requireCredential(c) {
  const value = await credentials(c);
  if (!value)
    throw new CliError('signin', `Run ${installerPackage} login first.`);
  return value;
}
function openBrowser(url) {
  const command =
    process.platform === 'darwin'
      ? ['open', [url]]
      : process.platform === 'win32'
        ? ['rundll32', ['url.dll,FileProtocolHandler', url]]
        : ['xdg-open', [url]];
  const p = spawn(command[0], command[1], { stdio: 'ignore', detached: true });
  p.on('error', () => {});
  p.unref();
}
export async function login(c, emit) {
  const existing = await credentials(c);
  if (existing) {
    try {
      await api(c, '/api/devices', { action: 'status' }, existing);
      throw new CliError(
        'already_signed_in',
        'A credential is already stored. Run status to check it, or logout before approving another device.',
      );
    } catch (e) {
      if (e.code === 'signin') await clearCredentials(c);
      else throw e;
    }
  }
  const grant = await api(
    c,
    '/api/device-code',
    { client_id: 'omnigami-cli', scope: 'downloads' },
    null,
    true,
  );
  if (
    !/^[A-Za-z0-9_-]{43}$/.test(grant.device_code) ||
    !/^\w{4}-\w{4}$/.test(grant.user_code) ||
    !Number.isInteger(grant.interval) ||
    grant.interval < 5 ||
    grant.interval > 60 ||
    grant.expires_in !== 600 ||
    grant.verification_uri !== c.origin + '/device'
  )
    throw new CliError('response', 'Invalid device authorization response');
  const verification = new URL(grant.verification_uri_complete);
  if (
    verification.origin !== c.origin ||
    verification.pathname !== '/device' ||
    verification.searchParams.get('user_code') !== grant.user_code
  )
    throw new CliError('response', 'Invalid verification URL');
  emit({
    event: 'authorization',
    verificationUri: grant.verification_uri,
    verificationUriComplete: verification.href,
    userCode: grant.user_code,
    expiresIn: grant.expires_in,
  });
  if (c.env.OMNIGAMI_NO_BROWSER !== '1') openBrowser(verification.href);
  let interval = grant.interval;
  const deadline = Date.now() + grant.expires_in * 1000;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, interval * 1000));
    try {
      const r = await api(
        c,
        '/api/device-token',
        {
          client_id: 'omnigami-cli',
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: grant.device_code,
        },
        null,
        true,
      );
      if (
        !/^[A-Za-z0-9_-]{43}$/.test(r.access_token) ||
        r.scope !== 'downloads' ||
        r.token_type !== 'Bearer' ||
        r.expires_in !== 2592000
      )
        throw new CliError('response', 'Invalid token response');
      const storage = await saveCredentials(c, {
        origin: c.origin,
        token: r.access_token,
        expiresAt: new Date(Date.now() + r.expires_in * 1000).toISOString(),
      });
      return {
        event: 'authenticated',
        scope: r.scope,
        storage,
        expiresIn: r.expires_in,
      };
    } catch (e) {
      if (e.code === 'slow_down') interval += 5;
      else if (e.code !== 'authorization_pending') throw e;
    }
  }
  throw new CliError(
    'expired_token',
    'Authorization expired. Run login again.',
  );
}
export async function status(c) {
  const credential = await credentials(c);
  if (!credential) return { authenticated: false };
  return api(c, '/api/devices', { action: 'status' }, credential);
}
export async function logout(c) {
  const credential = await credentials(c);
  if (!credential) return { signedOut: true };
  try {
    await api(c, '/api/devices', { action: 'logout' }, credential);
  } catch (e) {
    if (e.code !== 'signin') throw e;
  }
  await clearCredentials(c);
  return { signedOut: true };
}
export const list = async (c) =>
  api(c, '/api/devices', { action: 'list' }, await requireCredential(c));
export async function verifiedEntries(c, r, bytes, slug) {
  const fields = {
    slug: r.slug,
    version: r.version,
    filename: r.filename,
    bytes: r.bytes,
    sha256: r.sha256,
    keyId: r.keyId,
    issuedAt: r.issuedAt,
    channel: r.channel,
  };
  const keys = await trustedKeys(c);
  if (!keys.length)
    throw new CliError(
      'trust',
      'No production verification key is provisioned in this development client.',
    );
  const valid =
    slugOK(slug) &&
    r.slug === slug &&
    /^\d+\.\d+\.\d+$/.test(r.version) &&
    r.filename === `${slug}-${r.version}-${r.sha256}.tar.gz` &&
    /^[a-f0-9]{64}$/.test(r.sha256) &&
    Number.isInteger(r.bytes) &&
    r.bytes > 0 &&
    r.bytes <= 256 * 1024 * 1024 &&
    Number.isFinite(Date.parse(r.issuedAt)) &&
    (r.channel === 'release' || (c.dev && r.channel === 'development'));
  let signed = false;
  if (valid)
    for (const key of keys)
      try {
        const pub = createPublicKey(key);
        if (
          pub.asymmetricKeyType === 'ed25519' &&
          hash(pub.export({ type: 'spki', format: 'der' })) === r.keyId &&
          verify(
            null,
            Buffer.from(JSON.stringify(fields)),
            pub,
            Buffer.from(r.signature, 'base64'),
          )
        )
          signed = true;
      } catch {
        /* invalid key or signature */
      }
  if (!signed)
    throw new CliError(
      'signature',
      'Release signature does not match the pinned publisher key. Nothing installed.',
    );
  if (bytes.length !== r.bytes || hash(bytes) !== r.sha256)
    throw new CliError('digest', 'Archive digest mismatch. Nothing installed.');
  return archiveEntries(bytes);
}
export async function download(c, slug) {
  const credential = await requireCredential(c),
    r = await api(c, '/api/downloads', { slug }, credential);
  if (!Number.isInteger(r.bytes) || r.bytes <= 0 || r.bytes > 256 * 1024 * 1024)
    throw new CliError('size', 'Invalid archive size');
  const url = new URL(r.url, c.origin);
  if (
    !(
      (url.origin === c.origin && url.pathname === '/api/download-file') ||
      /^https:\/\/[a-f0-9]{32}\.r2\.cloudflarestorage\.com\//.test(url.href)
    )
  )
    throw new CliError('download_host', 'Unexpected download host');
  let response;
  try {
    response = await fetch(url, {
      redirect: 'error',
      signal: AbortSignal.timeout(120000),
      headers:
        url.origin === c.origin
          ? { authorization: `Bearer ${credential.token}` }
          : {},
    });
  } catch {
    throw new CliError('network', 'Archive download failed');
  }
  if (!response.ok)
    throw new CliError(
      'download',
      'Archive download failed. Run status to check device access.',
    );
  const bytes = await responseBytes(
    response,
    Math.min(r.bytes, 256 * 1024 * 1024),
  );
  return { release: r, entries: await verifiedEntries(c, r, bytes, slug) };
}
export function agentTarget(agent = 'shared', target) {
  const dirs = {
    'claude-code': '.claude/skills',
    codex: '.agents/skills',
    cursor: '.cursor/skills',
    'gemini-cli': '.gemini/skills',
    shared: '.agents/skills',
  };
  if (!Object.hasOwn(dirs, agent))
    throw new CliError(
      'agent',
      'Supported agents: claude-code, codex, cursor, gemini-cli, shared',
    );
  return path.resolve(target || path.join(os.homedir(), dirs[agent]));
}
export async function fingerprint(root) {
  const files = Object.create(null);
  async function walk(dir, prefix = '') {
    for (const d of await readdir(dir, { withFileTypes: true })) {
      const rel = prefix + d.name,
        file = path.join(dir, d.name);
      if (d.isSymbolicLink() || (!d.isDirectory() && !d.isFile()))
        throw new CliError(
          'modified',
          'Installed copy contains links or special files; use install --force to back it up.',
        );
      if (d.isDirectory()) await walk(file, rel + '/');
      else files[rel] = hash(await readFile(file));
    }
  }
  await noSymlinks(root);
  await walk(root);
  return files;
}
const sameFiles = (a, b) =>
  Object.keys(a).length === Object.keys(b).length &&
  Object.keys(a).every((k) => a[k] === b[k]);
async function applyInstall(
  c,
  slug,
  { agent = 'shared', target, force = false, previous } = {},
  ledger,
) {
  if (!slugOK(slug))
    throw new CliError('skill', 'Use a skill slug such as end-card.');
  const parent = agentTarget(agent, target),
    dest = path.join(parent, slug);
  await noSymlinks(dest);
  let existing;
  try {
    existing = await lstat(dest);
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
  if (existing && !force)
    throw new CliError(
      'exists',
      'Skill already exists. Use --force to keep a backup and replace it.',
    );
  if (previous) {
    if (!existing || !sameFiles(await fingerprint(dest), previous.files))
      throw new CliError(
        'modified',
        'Installed skill has local changes. Use install --force to back it up and replace it.',
      );
  }
  const { release: r, entries } = await download(c, slug); // verification and parsing precede target writes
  await noSymlinks(parent);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  return withLock(path.join(parent, `.omnigami-${slug}.lock`), async () => {
    await noSymlinks(dest);
    // Detect a destination created during the download before replacing it.
    let now;
    try {
      now = await lstat(dest);
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
    if (
      !!now !== !!existing ||
      (now &&
        existing &&
        (now.ino !== existing.ino || now.dev !== existing.dev))
    )
      throw new CliError(
        'changed',
        'Install destination changed; retry the command.',
      );
    if (previous && !sameFiles(await fingerprint(dest), previous.files))
      throw new CliError(
        'modified',
        'Installed files changed during download; retry after reviewing edits.',
      );
    const stage = await mkdtemp(path.join(parent, `.omnigami-${slug}-`)),
      backup = existing
        ? path.join(
            parent,
            `${slug}.backup-${Date.now()}-${randomUUID().slice(0, 8)}`,
          )
        : null;
    let moved = false,
      placed = false;
    try {
      await extractEntries(entries, stage);
      const files = await fingerprint(stage);
      if (backup) {
        await rename(dest, backup);
        moved = true;
      }
      await rename(stage, dest);
      placed = true;
      const record = {
        slug,
        version: r.version,
        sha256: r.sha256,
        origin: c.origin,
        agent,
        target: parent,
        files,
      };
      const next = {
        installs: [
          ...ledger.installs.filter(
            (i) => !(i.target === parent && i.slug === slug),
          ),
          record,
        ],
      };
      await privateWrite(ledgerFile(c), next);
      ledger.installs = next.installs;
      return { slug, version: r.version, agent, path: dest, backup };
    } catch (e) {
      if (placed) await rm(dest, { recursive: true, force: true });
      if (moved) await rename(backup, dest);
      throw e;
    } finally {
      await rm(stage, { recursive: true, force: true });
    }
  });
}
export async function install(c, slug, options) {
  await privateDir(c.dir);
  return withLock(path.join(c.dir, 'install.lock'), async () =>
    applyInstall(c, slug, options, await readLedger(c)),
  );
}
export async function update(c, slug) {
  if (slug && !slugOK(slug)) throw new CliError('skill', 'Invalid skill slug');
  await privateDir(c.dir);
  return withLock(path.join(c.dir, 'install.lock'), async () => {
    const ledger = await readLedger(c),
      installed = ledger.installs.filter(
        (i) => i.origin === c.origin && (!slug || i.slug === slug),
      );
    if (slug && !installed.length)
      throw new CliError(
        'not_installed',
        'Skill is not managed by this installer. Run install first.',
      );
    const catalog = await list(c),
      results = [];
    for (const item of installed) {
      const current = catalog.skills.find((s) => s.slug === item.slug);
      if (!current)
        throw new CliError(
          'entitlement',
          `Account no longer has access to ${item.slug}.`,
        );
      if (current.version === item.version) {
        results.push({
          slug: item.slug,
          version: item.version,
          updated: false,
        });
        continue;
      }
      if (!current.available)
        throw new CliError(
          'release',
          `Release for ${item.slug} is not prepared yet.`,
        );
      const parts = (v) => v.split('.').map(Number);
      if (
        !/^\d+\.\d+\.\d+$/.test(current.version) ||
        parts(current.version).reduce(
          (cmp, n, i) => cmp || Math.sign(n - parts(item.version)[i]),
          0,
        ) <= 0
      )
        throw new CliError(
          'version',
          'Update would downgrade the installed skill.',
        );
      results.push({
        ...(await applyInstall(
          c,
          item.slug,
          {
            agent: item.agent,
            target: item.target,
            force: true,
            previous: item,
          },
          ledger,
        )),
        updated: true,
      });
    }
    return { updates: results };
  });
}
