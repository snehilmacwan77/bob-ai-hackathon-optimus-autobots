import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const frontend = join(root, 'src', 'frontend');
const isWindows = process.platform === 'win32';
const command = isWindows ? (process.env.ComSpec || 'cmd.exe') : 'npm';
const args = isWindows
  ? ['/d', '/s', '/c', 'npm install --no-audit --no-fund']
  : ['install', '--no-audit', '--no-fund'];
const env = { ...process.env };
delete env.npm_config_allow_scripts;
delete env.NPM_CONFIG_ALLOW_SCRIPTS;
const result = spawnSync(command, args, {
  cwd: frontend,
  stdio: 'inherit',
  shell: false,
  env,
});

if (result.error) throw result.error;
process.exit(result.status ?? 1);
