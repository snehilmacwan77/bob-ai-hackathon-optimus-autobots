import { existsSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const backend = join(root, 'src', 'backend');
const venv = join(backend, '.venv');
const requirements = join(backend, 'requirements.txt');
const python = process.platform === 'win32' ? join(venv, 'Scripts', 'python.exe') : join(venv, 'bin', 'python');

function run(command, args) {
  const result = spawnSync(command, args, { cwd: backend, stdio: 'inherit', shell: false });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

if (!existsSync(python)) {
  const systemPython = process.platform === 'win32' ? 'py' : 'python3';
  mkdirSync(venv, { recursive: true });
  run(systemPython, process.platform === 'win32' ? ['-3', '-m', 'venv', venv] : ['-m', 'venv', venv]);
}

run(python, ['-m', 'pip', 'install', '--disable-pip-version-check', '-r', requirements]);
