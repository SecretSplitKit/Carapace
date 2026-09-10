import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

test('stopped feeds cannot overwrite a new session or schedule stale reconnects', async () => {
  const sockets = [], requests = [], probes = [], timers = new Map();
  const context = vm.createContext({
    writable: value => ({ value, set(next) { this.value = next; } }),
    apiToken: () => 'session', window: {}, location: { protocol: 'http:', host: 'localhost' },
    api: { status: () => new Promise(resolve => requests.push(resolve)) },
    fetch: () => new Promise(resolve => probes.push(resolve)),
    WebSocket: class { constructor() { sockets.push(this); } close() { this.onclose?.(); } },
    setTimeout: callback => { const id = timers.size + 1; timers.set(id, callback); return id; },
    clearTimeout: id => timers.delete(id),
  });
  const source = readFileSync(new URL('../src/lib/statusStore.ts', import.meta.url), 'utf8')
    .replace(/^import .*;\n/gm, '').replace(/export /g, '');
  vm.runInContext(ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText +
    '\nglobalThis.feed = { startStatusFeed, stopStatusFeed, status, live, sessionExpired };', context);
  const feed = context.feed;
  feed.startStatusFeed();
  const closing = sockets[0].onclose();
  feed.stopStatusFeed();
  feed.startStatusFeed();
  requests[1]({ marker: 'current' });
  await Promise.resolve();
  requests[0]({ marker: 'stale' });
  probes[0]({ status: 401 });
  await closing;
  assert.equal(feed.status.value.marker, 'current');
  assert.equal(feed.sessionExpired.value, false);
  assert.equal(timers.size, 0);
  sockets[0].onmessage({ data: '{"marker":"stale socket"}' });
  assert.equal(feed.status.value.marker, 'current');
  const expired = sockets[1].onclose();
  probes[1]({ status: 401 });
  await expired;
  assert.equal(feed.sessionExpired.value, true);
  assert.equal(timers.size, 0);
  feed.stopStatusFeed();
});
