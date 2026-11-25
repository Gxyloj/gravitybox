import assert from 'node:assert/strict';
import test from 'node:test';
import { win32 } from 'node:path';
import { verifyWslPageService } from '../dist/platform/wsl.js';

const endpoint = { pid: 1234, profile: 'profile-fixture', appVersion: '2.35.1' };
const wsl = win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'wsl.exe');
const distribution = 'Ubuntu Fixture';
const launchLog = `${wsl} -d ${distribution} --exec sh -c ANTIGRAVITY_VSCODE_HOST=1 exec "$HOME/.antigravity-server/bin/2.35.1/language_server" "$@"`;
const child = {
  pid: 1235,
  ppid: endpoint.pid,
  exeName: 'wsl.exe',
  exePath: wsl,
  cmdLine: `"${wsl}" -d "${distribution}" --exec sh -c "ANTIGRAVITY_VSCODE_HOST=1 exec \\"$HOME/.antigravity-server/bin/2.35.1/language_server\\" \\"$@\\""`,
};
const info = text => `[2026-01-01 00:00:00.000] [info]  ${text}`;
const log = [
  info('Starting app (v2.35.1) with dynamic port…'),
  info(`Spawning: ${launchLog}`),
  info('Local: https://127.0.0.1:44001/'),
].join('\r\n');

test('WSL 窗口的发行版、当前端口和桌面子进程一致时，查询 Linux 监听', async () => {
  const calls = [];
  const deps = {
    readMainLogTail: async profile => { assert.equal(profile, endpoint.profile); return log; },
    processTree: async () => [child, { ...child, pid: 1236, ppid: child.pid }],
    inspectListener: async (...args) => { calls.push(args); return '1000'; },
  };
  assert.deepEqual(await verifyWslPageService(44001, endpoint, deps), { kind: 'wsl', distribution, uid: '1000' });
  assert.deepEqual(calls, [[wsl, distribution, 44001, endpoint.appVersion]]);
  assert.equal(await verifyWslPageService(44001, endpoint, { ...deps, inspectListener: async () => 'invalid' }), undefined);
});

test('WSL 更换端口后拒绝旧端口，缺失或冲突的桌面归属也不查询 Linux', async () => {
  let listenerCalls = 0;
  const deps = {
    readMainLogTail: async () => `${log}\n${info('[Auto-Restart] Port changed! Reloading all windows with URL: https://127.0.0.1:44002/')}`,
    processTree: async () => [child],
    inspectListener: async () => { listenerCalls++; return '1000'; },
  };
  assert.equal(await verifyWslPageService(44001, endpoint, deps), undefined);
  assert.deepEqual(await verifyWslPageService(44002, endpoint, deps), { kind: 'wsl', distribution, uid: '1000' });
  assert.equal(await verifyWslPageService(44002, { ...endpoint, appVersion: '2.34.0' }, deps), undefined);
  for (const children of [
    [{ ...child, ppid: 1 }],
    [{ ...child, exePath: 'C:\\Other\\wsl.exe' }],
    [{ ...child, cmdLine: child.cmdLine.replace(distribution, 'Debian') }],
    [child, { ...child, pid: 1237 }],
  ]) {
    assert.equal(await verifyWslPageService(44002, endpoint, { ...deps, processTree: async () => children }), undefined);
  }
  assert.equal(await verifyWslPageService(44001, endpoint, {
    ...deps,
    readMainLogTail: async () => `${log}\n${info('Starting app (v2.35.1) with dynamic port…')}\n${info('Local: https://127.0.0.1:44001/')}`,
  }), undefined);
  assert.equal(listenerCalls, 1);
  assert.equal(await verifyWslPageService(44002, endpoint, {
    ...deps, inspectListener: async () => { throw new Error('listener verification failed'); },
  }), undefined);
});
