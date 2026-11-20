import {
  mkdir,
  lstat,
  readFile,
  writeFile,
  rename,
  unlink,
} from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { CliError } from './config.mjs';
export async function noSymlinks(target) {
  const absolute = path.resolve(target),
    root = path.parse(absolute).root;
  let current = root;
  for (const part of absolute
    .slice(root.length)
    .split(path.sep)
    .filter(Boolean)) {
    current = path.join(current, part);
    try {
      const s = await lstat(current);
      if (s.isSymbolicLink())
        throw new CliError('unsafe_path', `Refusing symlink: ${current}`);
    } catch (e) {
      if (e.code === 'ENOENT') return;
      throw e;
    }
  }
}
export async function privateDir(dir) {
  await noSymlinks(dir);
  let created = false;
  try {
    await mkdir(dir, { mode: 0o700 });
    created = true;
  } catch (e) {
    if (e.code === 'ENOENT') {
      await mkdir(path.dirname(dir), { recursive: true });
      await mkdir(dir, { mode: 0o700 });
      created = true;
    } else if (e.code !== 'EEXIST') throw e;
  }
  if (process.platform === 'win32') await windowsPrivacy(dir, created);
  const s = await lstat(dir);
  if (
    !s.isDirectory() ||
    (process.platform !== 'win32' &&
      ((s.mode & 0o077) !== 0 || s.uid !== process.getuid()))
  )
    throw new CliError(
      'permissions',
      `Config directory must be owned by you and private (0700): ${dir}`,
    );
}
export async function privateRead(file) {
  await noSymlinks(file);
  try {
    const s = await lstat(file);
    if (process.platform === 'win32') await windowsPrivacy(file, false);
    if (
      !s.isFile() ||
      (process.platform !== 'win32' &&
        ((s.mode & 0o077) !== 0 || s.uid !== process.getuid()))
    )
      throw new CliError(
        'permissions',
        `Private file must be owned by you (0600): ${file}`,
      );
    return JSON.parse(await readFile(file, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
}
export async function privateWrite(file, value) {
  await privateDir(path.dirname(file));
  await noSymlinks(file);
  const tmp = file + '.' + randomUUID() + '.tmp';
  try {
    await writeFile(tmp, JSON.stringify(value) + '\n', {
      mode: 0o600,
      flag: 'wx',
    });
    if (process.platform === 'win32') await windowsPrivacy(tmp, false);
    await rename(tmp, file);
  } finally {
    await unlink(tmp).catch(() => {});
  }
}
function run(exe, args, input = '') {
  return new Promise((resolve, reject) => {
    const p = spawn(exe, args, {
      stdio: ['pipe', 'pipe', 'ignore'],
      windowsHide: true,
    });
    let out = '';
    const timer = setTimeout(() => {
      p.kill();
      reject(new Error('Keychain timeout'));
    }, 8000);
    p.stdout.setEncoding('utf8');
    p.stdout.on('data', (s) => {
      out += s;
      if (out.length > 20000) p.kill();
    });
    p.on('error', () => {
      clearTimeout(timer);
      reject(new Error('Keychain unavailable'));
    });
    p.on('close', (code) => {
      clearTimeout(timer);
      code === 0
        ? resolve(out.trim())
        : reject(new Error('Keychain unavailable'));
    });
    p.stdin.on('error', () => {});
    p.stdin.end(input);
  });
}
const quote = (s) =>
  '"' + s.replaceAll('\\', '\\\\').replaceAll('"', '\\"') + '"';
async function keychain(c, action, value) {
  if (c.dev && c.env.OMNIGAMI_DEV_FILE_STORE === '1')
    throw new Error('Test file store');
  const service = 'omnigami-cli',
    account = c.origin;
  if (process.platform === 'darwin') {
    if (action === 'get')
      return JSON.parse(
        await run('security', [
          'find-generic-password',
          '-s',
          service,
          '-a',
          account,
          '-w',
        ]),
      );
    if (action === 'delete')
      return run('security', [
        'delete-generic-password',
        '-s',
        service,
        '-a',
        account,
      ]);
    // security -i reads its command from stdin: credential never appears in argv or shell history.
    return run(
      'security',
      ['-i'],
      `add-generic-password -U -s ${quote(service)} -a ${quote(account)} -w ${quote(JSON.stringify(value))}\n`,
    );
  }
  if (process.platform === 'linux') {
    const args = ['service', service, 'account', account];
    if (action === 'get')
      return JSON.parse(await run('secret-tool', ['lookup', ...args]));
    if (action === 'delete') return run('secret-tool', ['clear', ...args]);
    return run(
      'secret-tool',
      ['store', '--label=omnigami CLI', ...args],
      JSON.stringify(value),
    );
  }
  if (process.platform === 'win32') {
    const script = `$ErrorActionPreference='Stop';[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];[void][Windows.Security.Credentials.PasswordCredential,Windows.Security.Credentials,ContentType=WindowsRuntime];$v=New-Object Windows.Security.Credentials.PasswordVault;$i=ConvertFrom-Json ([Console]::In.ReadLine()); if($i.action -eq 'get'){$c=$v.Retrieve($i.service,$i.account);$c.RetrievePassword();[Console]::Write($c.Password)} elseif($i.action -eq 'delete'){$v.Remove($v.Retrieve($i.service,$i.account))} else {try{$v.Remove($v.Retrieve($i.service,$i.account))}catch{};$v.Add((New-Object Windows.Security.Credentials.PasswordCredential($i.service,$i.account,$i.value)))}`;
    const out = await run(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      JSON.stringify({
        action,
        service,
        account,
        value: JSON.stringify(value),
      }) + '\n',
    );
    return action === 'get' ? JSON.parse(out) : undefined;
  }
  throw new Error('No keychain adapter');
}
const credentialFile = (c) => path.join(c.dir, 'credential.json');
export async function credentials(c) {
  await privateDir(c.dir);
  let value = await privateRead(credentialFile(c));
  if (!value)
    try {
      value = await keychain(c, 'get');
    } catch {
      return null;
    }
  if (
    value?.origin !== c.origin ||
    !/^[A-Za-z0-9_-]{43}$/.test(value?.token || '')
  )
    return null;
  return value;
}
export async function saveCredentials(c, value) {
  await privateDir(c.dir);
  try {
    await keychain(c, 'set', value);
    const saved = await keychain(c, 'get');
    if (saved?.token !== value.token || saved?.origin !== value.origin)
      throw new Error('Credential was not saved');
    await unlink(credentialFile(c)).catch((e) => {
      if (e.code !== 'ENOENT') throw e;
    });
    return 'system-keychain';
  } catch {
    await privateWrite(credentialFile(c), value);
    return 'private-file';
  }
}
export async function clearCredentials(c) {
  await keychain(c, 'delete').catch(() => {});
  await noSymlinks(credentialFile(c));
  await unlink(credentialFile(c)).catch((e) => {
    if (e.code !== 'ENOENT') throw e;
  });
}
export const ledgerFile = (c) => path.join(c.dir, 'installed.json');
export const readLedger = async (c) =>
  (await privateRead(ledgerFile(c))) || { installs: [] };
export async function withLock(file, fn) {
  await noSymlinks(file);
  try {
    await mkdir(file, { mode: 0o700 });
  } catch (e) {
    if (e.code === 'EEXIST')
      throw new CliError(
        'locked',
        `Installer lock exists: ${file}. If no installer is running, inspect and remove this directory before retrying.`,
      );
    throw e;
  }
  try {
    return await fn();
  } finally {
    const { rmdir } = await import('node:fs/promises');
    await rmdir(file);
  }
}

async function windowsPrivacy(file, create) {
  // On Windows chmod does not restrict access: require an explicit per-user ACL.
  const script = `$ErrorActionPreference='Stop';$i=ConvertFrom-Json ([Console]::In.ReadLine());$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User;$acl=Get-Acl -LiteralPath $i.path;if($i.create){$acl.SetAccessRuleProtection($true,$false);$rule=New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.SetAccessRule($rule);Set-Acl -LiteralPath $i.path -AclObject $acl;$acl=Get-Acl -LiteralPath $i.path};if($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value){throw 'Owner'};foreach($r in $acl.Access){if($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value){throw 'Permissions'}}`;
  try {
    await run(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      JSON.stringify({ path: file, create }) + '\n',
    );
  } catch {
    throw new CliError(
      'permissions',
      'Private storage requires an ACL granting access only to the current Windows user.',
    );
  }
}
