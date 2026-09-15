import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const backend = join(root, 'src', 'backend');
const python = process.platform === 'win32'
  ? join(backend, '.venv', 'Scripts', 'python.exe')
  : join(backend, '.venv', 'bin', 'python');

const result = spawnSync(python, ['-m', 'pytest'], { cwd: backend, stdio: 'inherit' });
if (result.error) throw result.error;
process.exit(result.status ?? 1);
