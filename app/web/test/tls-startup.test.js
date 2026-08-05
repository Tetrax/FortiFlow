'use strict';

const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const WEB_ROOT = path.resolve(__dirname, '..');
const SERVER = path.join(WEB_ROOT, 'server.js');
const HEALTHCHECK = path.join(WEB_ROOT, 'scripts', 'container-healthcheck.js');
const HOSTNAME = 'fortiflow.test.lan';

function freePort() {
  return new Promise((resolve, reject) => {
    const server = require('node:net').createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

function request(scheme, port) {
  const client = scheme === 'https' ? https : http;
  return new Promise((resolve, reject) => {
    client.get({
      hostname: '127.0.0.1', port, path: '/', rejectUnauthorized: false, timeout: 3000,
    }, response => {
      response.resume();
      response.on('end', () => resolve(response.statusCode));
    }).on('error', reject);
  });
}

function startServer(env) {
  const child = spawn(process.execPath, [SERVER], {
    cwd: WEB_ROOT,
    env: { ...process.env, FORTIFLOW_BIND_ADDRESS: '127.0.0.1', ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });
  return { child, output: () => output };
}

async function waitFor(childState, needle) {
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) {
    if (childState.output().includes(needle)) return;
    if (childState.child.exitCode !== null) {
      throw new Error(`server exited ${childState.child.exitCode}: ${childState.output()}`);
    }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`timeout waiting for ${needle}: ${childState.output()}`);
}

async function stop(child) {
  if (child.exitCode !== null) return;
  child.kill('SIGTERM');
  await new Promise(resolve => child.once('exit', resolve));
}

function createCertificate(directory, hostname = HOSTNAME) {
  const cert = path.join(directory, 'fullchain.pem');
  const key = path.join(directory, 'privkey.pem');
  const result = spawnSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
    '-keyout', key, '-out', cert, '-subj', `/CN=${hostname}`,
    '-addext', `subjectAltName=DNS:${hostname}`,
  ], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return { cert, key };
}

test('starts in HTTP when all TLS variables are empty', async () => {
  const port = await freePort();
  const running = startServer({
    PORT: String(port), FORTIFLOW_TLS_CERT: '', FORTIFLOW_TLS_KEY: '', FORTIFLOW_TLS_HOSTNAME: '',
  });
  try {
    await waitFor(running, `http://127.0.0.1:${port}`);
    assert.equal(await request('http', port), 200);
  } finally {
    await stop(running.child);
  }
});

test('starts direct HTTPS with a configured certificate pair and hostname', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fortiflow-tls-'));
  const { cert, key } = createCertificate(directory);
  const port = await freePort();
  const running = startServer({
    PORT: String(port), FORTIFLOW_TLS_CERT: cert, FORTIFLOW_TLS_KEY: key,
    FORTIFLOW_TLS_HOSTNAME: HOSTNAME,
  });
  try {
    await waitFor(running, `https://${HOSTNAME}:${port}`);
    assert.equal(await request('https', port), 200);
    await assert.rejects(request('http', port));

    const healthEnv = {
      ...process.env,
      PORT: String(port),
      FORTIFLOW_TLS_CERT: cert,
      FORTIFLOW_TLS_KEY: key,
      FORTIFLOW_TLS_HOSTNAME: HOSTNAME,
    };
    const healthy = spawnSync(process.execPath, [HEALTHCHECK], {
      cwd: WEB_ROOT, env: healthEnv, encoding: 'utf8',
    });
    assert.equal(healthy.status, 0, healthy.stderr);

    const wrongHostname = spawnSync(process.execPath, [HEALTHCHECK], {
      cwd: WEB_ROOT,
      env: { ...healthEnv, FORTIFLOW_TLS_HOSTNAME: 'wrong.test.lan' },
      encoding: 'utf8',
    });
    assert.notEqual(wrongHostname.status, 0);
    assert.match(wrongHostname.stderr, /Hostname\/IP does not match certificate/);
  } finally {
    await stop(running.child);
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('fails closed on partial TLS configuration', async () => {
  const port = await freePort();
  const running = startServer({
    PORT: String(port), FORTIFLOW_TLS_CERT: '/certs/active/fullchain.pem',
    FORTIFLOW_TLS_KEY: '', FORTIFLOW_TLS_HOSTNAME: HOSTNAME,
  });
  const exitCode = await new Promise(resolve => running.child.once('exit', resolve));
  assert.notEqual(exitCode, 0);
  assert.match(running.output(), /FORTIFLOW_TLS_CERT.*FORTIFLOW_TLS_KEY.*FORTIFLOW_TLS_HOSTNAME/s);
});
