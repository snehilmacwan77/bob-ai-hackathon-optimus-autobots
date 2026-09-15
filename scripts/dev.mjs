import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const frontend = join(root, 'src', 'frontend');
const backend = join(root, 'src', 'backend');
const python = process.platform === 'win32'
  ? join(backend, '.venv', 'Scripts', 'python.exe')
  : join(backend, '.venv', 'bin', 'python');
const isWindows = process.platform === 'win32';
const frontendCommand = isWindows ? (process.env.ComSpec || 'cmd.exe') : 'npm';
const frontendArgs = isWindows
  ? ['/d', '/s', '/c', 'npm run dev -- --host 127.0.0.1']
  : ['run', 'dev', '--', '--host', '127.0.0.1'];

if (!existsSync(python)) {
  const setup = spawnSync(process.execPath, [join(root, 'scripts', 'setup-backend.mjs')], { stdio: 'inherit' });
  if (setup.status !== 0) process.exit(setup.status ?? 1);
}

const children = [
  spawn(python, ['-m', 'uvicorn', 'app.main:app', '--reload', '--host', '127.0.0.1', '--port', '9000'], {
    cwd: backend,
    stdio: 'inherit',
    env: { ...process.env, PYTHONUNBUFFERED: '1' },
    windowsHide: false,
  }),
  spawn(frontendCommand, frontendArgs, {
    cwd: frontend,
    stdio: 'inherit',
    shell: false,
    windowsHide: false,
  }),
];

let stopping = false;
function stop() {
  if (stopping) return;
  stopping = true;
  for (const child of children) {
    if (!child.killed && child.pid) {
      if (process.platform === 'win32') {
        spawnSync('taskkill', ['/pid', String(child.pid), '/t', '/f'], { stdio: 'ignore' });
      } else {
        child.kill('SIGTERM');
      }
    }
  }
}

for (const child of children) {
  child.once('exit', (code) => {
    if (!stopping && code !== 0) {
      console.error(`A development process stopped with exit code ${code ?? 'unknown'}.`);
      stop();
      process.exitCode = code ?? 1;
    }
  });
}

process.on('SIGINT', () => { stop(); process.exit(0); });
process.on('SIGTERM', () => { stop(); process.exit(0); });

console.log('\nThreatFusion is running:');
console.log('  Frontend: http://localhost:5174');
console.log('  Backend:  http://localhost:9000/docs');
