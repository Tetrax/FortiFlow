'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const test = require('node:test');

const WEB_ROOT = path.resolve(__dirname, '..');
const SERVER = path.join(WEB_ROOT, 'server.js');

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const port = probe.address().port;
      probe.close(() => resolve(port));
    });
  });
}

function request(port, options = {}) {
  return new Promise((resolve, reject) => {
    const body = options.body;
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method: options.method || 'GET',
      path: options.path || '/',
      headers: options.headers,
      timeout: 3000,
    }, response => {
      response.resume();
      response.once('end', () => resolve(response.statusCode));
    });
    req.once('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function startServer(extraEnv = {}) {
  return freePort().then(port => {
    const child = spawn(process.execPath, [SERVER], {
      cwd: WEB_ROOT,
      env: {
        ...process.env,
        FORTIFLOW_BIND_ADDRESS: '127.0.0.1',
        FORTIFLOW_TLS_CERT: '',
        FORTIFLOW_TLS_KEY: '',
        FORTIFLOW_TLS_HOSTNAME: '',
        FORTIFLOW_TRUST_PROXY: '',
        PORT: String(port),
        ...extraEnv,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', chunk => { output += chunk; });
    child.stderr.on('data', chunk => { output += chunk; });
    return { child, port, output: () => output };
  });
}

async function waitForReady(state) {
  const needle = `http://127.0.0.1:${state.port}`;
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) {
    if (state.output().includes(needle)) return;
    if (state.child.exitCode !== null) {
      throw new Error(`server exited ${state.child.exitCode}: ${state.output()}`);
    }
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error(`timeout waiting for ${needle}: ${state.output()}`);
}

async function stop(state) {
  if (state.child.exitCode !== null) return;
  state.child.kill('SIGTERM');
  await new Promise(resolve => state.child.once('exit', resolve));
}

async function requestMany(port, count, options) {
  const statuses = [];
  for (let i = 0; i < count; i++) statuses.push(await request(port, options));
  return statuses;
}

test('limite /api/admin avant l’exécution du handler', async () => {
  const state = await startServer();
  try {
    await waitForReady(state);
    const statuses = await requestMany(state.port, 21, { path: '/api/admin/sessions' });
    assert.deepEqual(statuses.slice(0, 20), Array(20).fill(200));
    assert.equal(statuses[20], 429);
  } finally {
    await stop(state);
  }
});

test('limite /api/upload avant le parsing multipart de multer', async () => {
  const state = await startServer();
  try {
    await waitForReady(state);
    const options = { method: 'POST', path: '/api/upload', headers: { 'content-length': '0' } };
    const statuses = await requestMany(state.port, 21, options);
    assert.deepEqual(statuses.slice(0, 20), Array(20).fill(400));
    assert.equal(statuses[20], 429);
  } finally {
    await stop(state);
  }
});

test('utilise l’adresse client X-Forwarded-For seulement via un proxy explicitement approuvé', async () => {
  const state = await startServer({ FORTIFLOW_TRUST_PROXY: '127.0.0.1' });
  try {
    await waitForReady(state);
    const clientA = { path: '/api/admin/sessions', headers: { 'x-forwarded-for': '198.51.100.10' } };
    const clientB = { path: '/api/admin/sessions', headers: { 'x-forwarded-for': '198.51.100.11' } };
    assert.deepEqual(await requestMany(state.port, 20, clientA), Array(20).fill(200));
    assert.equal(await request(state.port, clientA), 429);
    assert.equal(await request(state.port, clientB), 200);
  } finally {
    await stop(state);
  }
});

test('n’accorde pas de confiance implicite à X-Forwarded-For', async () => {
  const state = await startServer();
  try {
    await waitForReady(state);
    const clientA = { path: '/api/admin/sessions', headers: { 'x-forwarded-for': '198.51.100.20' } };
    const clientB = { path: '/api/admin/sessions', headers: { 'x-forwarded-for': '198.51.100.21' } };
    assert.deepEqual(await requestMany(state.port, 20, clientA), Array(20).fill(200));
    assert.equal(await request(state.port, clientB), 429);
  } finally {
    await stop(state);
  }
});

function uploadRequest(port, fileSize) {
  const boundary = '----FortiFlowBoundary';
  const prefix = Buffer.from(
    `--${boundary}\r\n`
    + 'Content-Disposition: form-data; name="logfile"; filename="capture.log"\r\n'
    + 'Content-Type: text/plain\r\n\r\n',
  );
  const suffix = Buffer.from(`\r\n--${boundary}--\r\n`);
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method: 'POST',
      path: '/api/upload',
      headers: {
        'content-type': `multipart/form-data; boundary=${boundary}`,
        'content-length': prefix.length + fileSize + suffix.length,
      },
      timeout: 5000,
    }, response => {
      response.resume();
      response.once('end', () => resolve(response.statusCode));
    });
    req.once('error', reject);
    req.write(prefix);
    req.write(Buffer.alloc(fileSize, 'x'));
    req.end(suffix);
  });
}

test('respecte la limite upload configurée sans créer de fichier géant', async () => {
  const state = await startServer({ MAX_UPLOAD_SIZE_MB: '1' });
  try {
    await waitForReady(state);
    assert.equal(await uploadRequest(state.port, 1024 * 1024 - 1), 200);
    assert.equal(await uploadRequest(state.port, 1024 * 1024 + 1), 413);
  } finally {
    await stop(state);
  }
});

function multipartWithoutFile(pathname) {
  const boundary = '----FortiFlowNoFileBoundary';
  const body = Buffer.from(`--${boundary}--\r\n`);
  return {
    method: 'POST',
    path: pathname,
    headers: {
      'content-type': `multipart/form-data; boundary=${boundary}`,
      'content-length': body.length,
    },
    body,
  };
}

const costlyRouteCases = [
  {
    name: 'policy-engine V2 avant le calcul synchrone',
    request: port => request(port, { path: '/api/policy-engine/v2?session=missing' }),
    downstreamStatus: 404,
  },
  {
    name: 'import workspace avant le parsing raw',
    request: port => request(port, {
      method: 'POST',
      path: '/api/import/workspace',
      headers: { 'content-type': 'application/octet-stream', 'content-length': '1' },
      body: Buffer.from('{'),
    }),
    downstreamStatus: 400,
  },
  {
    name: 'import policies-xlsx avant Multer',
    request: port => request(port, multipartWithoutFile('/api/import/policies-xlsx')),
    downstreamStatus: 400,
  },
  {
    name: 'deploy config-upload avant Multer',
    request: port => request(port, multipartWithoutFile('/api/deploy/config-upload')),
    downstreamStatus: 400,
  },
  {
    name: 'deploy dynamic-routes avant express.json',
    request: port => request(port, {
      method: 'POST',
      path: '/api/deploy/dynamic-routes',
      headers: { 'content-type': 'application/json', 'content-length': '1' },
      body: Buffer.from('{'),
    }),
    downstreamStatus: 400,
  },
];

for (const routeCase of costlyRouteCases) {
  test(`limite ${routeCase.name}`, async () => {
    const state = await startServer();
    try {
      await waitForReady(state);
      const statuses = [];
      for (let i = 0; i < 21; i++) statuses.push(await routeCase.request(state.port));
      assert.deepEqual(statuses.slice(0, 20), Array(20).fill(routeCase.downstreamStatus));
      assert.equal(statuses[20], 429);
    } finally {
      await stop(state);
    }
  });
}
