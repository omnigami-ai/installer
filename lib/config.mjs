import os from 'node:os';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
export function config(env = process.env) {
  const origin = env.OMNIGAMI_DEV_SERVER || 'https://omnigami.ai';
  const url = new URL(origin);
  const dev = /^http:\/\/localhost:[0-9]{4,5}$/.test(origin);
  if (origin !== 'https://omnigami.ai' && !dev)
    throw new Error(
      'Only https://omnigami.ai or an explicit localhost development server is allowed',
    );
  if (url.origin !== origin) throw new Error('Invalid server origin');
  return {
    origin,
    dev,
    dir: path.resolve(
      env.OMNIGAMI_CONFIG_DIR ||
        path.join(
          os.homedir(),
          '.config',
          // its own folder: on the maker's machines ~/.config/omnigami already holds other things
          dev ? `omnigami-dev-${url.port}` : 'omnigami-installer',
        ),
    ),
    env,
  };
}
export async function trustedKeys(c) {
  if (c.dev && c.env.OMNIGAMI_DEV_PUBLIC_KEY_FILE)
    return [await readFile(c.env.OMNIGAMI_DEV_PUBLIC_KEY_FILE, 'utf8')];
  return Object.values(
    JSON.parse(
      await readFile(new URL('../trusted-keys.json', import.meta.url), 'utf8'),
    ),
  );
}
export class CliError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}
