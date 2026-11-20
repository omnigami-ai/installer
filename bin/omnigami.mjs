#!/usr/bin/env node
import { installerPackage } from '../lib/package-name.mjs';
import { parseArgs } from 'node:util';
import { config, CliError } from '../lib/config.mjs';
import {
  login,
  status,
  logout,
  list,
  install,
  update,
} from '../lib/client.mjs';
const json = process.argv.includes('--json');
function emit(value) {
  if (json) {
    process.stdout.write(JSON.stringify(value) + '\n');
    return;
  }
  if (value.event === 'authorization')
    process.stdout.write(
      `Open ${value.verificationUriComplete}\nCode: ${value.userCode}\nSign in, compare the code, and approve the device. Waiting for approval…\n`,
    );
  else process.stdout.write(JSON.stringify(value, null, 2) + '\n');
}
try {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: 'boolean' },
      agent: { type: 'string' },
      target: { type: 'string' },
      force: { type: 'boolean' },
      help: { type: 'boolean' },
    },
  });
  const [command, slug, ...extra] = positionals;
  if (values.help || !command) {
    process.stdout.write(
      `${installerPackage} login|status|logout|list|install <skill> [--agent <name>] [--target <dir>] [--force]|update [<skill>] [--json]\n`,
    );
  } else {
    if (
      !['login', 'status', 'logout', 'list', 'install', 'update'].includes(
        command,
      ) ||
      extra.length ||
      (['login', 'status', 'logout', 'list'].includes(command) && slug) ||
      (command === 'install' && !slug)
    )
      throw new CliError('usage', 'Invalid command or arguments. Use --help.');
    if (
      command !== 'install' &&
      (values.agent || values.target || values.force)
    )
      throw new CliError(
        'usage',
        '--agent, --target and --force apply only to install.',
      );
    const c = config();
    c.onWait = (message) => {
      if (!json) process.stderr.write(message + '\n');
    };
    const result = await {
      login: () => login(c, emit),
      status: () => status(c),
      logout: () => logout(c),
      list: () => list(c),
      install: () => install(c, slug, values),
      update: () => update(c, slug),
    }[command]();
    emit(result);
  }
} catch (e) {
  const known = e instanceof CliError;
  const code = known
    ? e.code
    : e.code === 'ERR_PARSE_ARGS_UNKNOWN_OPTION'
      ? 'usage'
      : 'failed';
  const message = known
    ? e.message
    : code === 'usage'
      ? 'Unknown option. Use --help.'
      : 'Command failed. Check file permissions and server availability, then try again.';
  const out = json
    ? JSON.stringify({ error: code, message })
    : `${code}: ${message}`;
  process.stderr.write(out + '\n');
  process.exitCode = 1;
}
