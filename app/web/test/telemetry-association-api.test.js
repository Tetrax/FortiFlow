'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const { spawn } = require('node:child_process');
const path = require('node:path');

let child;
let uploadDir;
let baseUrl;

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

function request(pathname, { method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(pathname, baseUrl);
    const req = http.request(url, { method, headers }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = text ? JSON.parse(text) : null; } catch {}
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.once('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function multipart(field, filename, content) {
  const boundary = `----FortiFlowTest${Date.now()}${Math.random().toString(16).slice(2)}`;
  const body = Buffer.from([
    `--${boundary}\r\n`,
    `Content-Disposition: form-data; name="${field}"; filename="${filename}"\r\n`,
    'Content-Type: text/plain\r\n\r\n',
    content,
    `\r\n--${boundary}--\r\n`,
  ].join(''), 'utf8');
  return {
    body,
    headers: {
      'Content-Type': `multipart/form-data; boundary=${boundary}`,
      'Content-Length': body.length,
    },
  };
}

async function uploadLog(devnames = ['FW-COM']) {
  const lines = devnames.map((devname, index) => [
    'date=2026-08-23 time=12:00:0' + index,
    'type=traffic subtype=forward',
    `devname=${devname} devid=FGT-AVR-01 vd=root`,
    `srcip=10.250.16.${10 + index} dstip=10.251.16.20`,
    'proto=6 dstport=443 action=accept service=HTTPS',
    'srcintf=lan dstintf=servers policyid=1 sentbyte=10 rcvdbyte=10',
  ].join(' ')).join('\n');
  const part = multipart('logfile', `telemetry-${Date.now()}-${Math.random().toString(16).slice(2)}.log`, lines);
  const uploaded = await request('/api/upload', { method: 'POST', headers: part.headers, body: part.body });
  assert.equal(uploaded.status, 200, uploaded.text);
  const sessionId = uploaded.json.sessionId;
  for (let i = 0; i < 100; i++) {
    const stats = await request(`/api/stats?session=${sessionId}`);
    if (stats.status === 200) return sessionId;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error('analyse télémétrie non terminée');
}

const configText = hostname => `
config system global
    set hostname "${hostname}"
end
config system interface
    edit "lan"
        set ip 10.250.16.1 255.255.254.0
        set role lan
    next
    edit "servers"
        set ip 10.251.16.1 255.255.255.0
        set role lan
    next
end
`;

async function uploadConfig(sessionId, hostname, text = configText(hostname)) {
  const part = multipart('conffile', `${hostname}-${Date.now()}-${Math.random().toString(16).slice(2)}.conf`, text);
  return request(`/api/deploy/config-upload?session=${sessionId}`, {
    method: 'POST', headers: part.headers, body: part.body,
  });
}

test.beforeEach(async () => {
  const port = await freePort();
  uploadDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fortiflow-association-'));
  baseUrl = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(port),
      FORTIFLOW_BIND_ADDRESS: '127.0.0.1',
      FORTIFLOW_UPLOAD_DIR: uploadDir,
    },
    stdio: 'ignore',
  });
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error(`serveur FortiFlow arrêté (${child.exitCode})`);
    try {
      const health = await request('/api/health');
      if (health.status === 200) return;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error('serveur FortiFlow non démarré');
});

test.afterEach(async () => {
  if (child && child.exitCode === null) {
    child.kill('SIGTERM');
    await new Promise(resolve => child.once('exit', resolve));
  }
  if (uploadDir) fs.rmSync(uploadDir, { recursive: true, force: true });
});

test('l’API demande puis enregistre une confirmation de nom sans perdre les garde-fous', async () => {
  const sessionId = await uploadLog(['FW-COM']);
  const mismatch = await uploadConfig(sessionId, 'FW-AVR-01');
  assert.equal(mismatch.status, 409, mismatch.text);
  assert.equal(mismatch.json.code, 'CONFIG_TELEMETRY_ASSOCIATION_REQUIRED');
  assert.equal(mismatch.json.association.telemetryDeviceName, 'FW-COM');
  assert.equal(mismatch.json.association.configHostname, 'FW-AVR-01');

  const staleWithoutContext = await request(`/api/deploy/config-association?session=${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'confirm', telemetryDeviceName: 'FW-COM' }),
  });
  assert.equal(staleWithoutContext.status, 409, staleWithoutContext.text);
  assert.equal(staleWithoutContext.json.code, 'CONFIG_TELEMETRY_ASSOCIATION_STALE');

  const confirmed = await request(`/api/deploy/config-association?session=${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      action: 'confirm',
      telemetryDeviceName: 'FW-COM',
      pendingConfigId: mismatch.json.pendingConfigId,
    }),
  });
  assert.equal(confirmed.status, 200, confirmed.text);
  assert.equal(confirmed.json.code, 'CONFIG_TELEMETRY_ASSOCIATED');
  assert.equal(confirmed.json.telemetryAssociation.confirmedByUser, true);
  assert.equal(confirmed.json.telemetryAssociation.telemetryDeviceName, 'FW-COM');
  assert.equal(confirmed.json.telemetryAssociation.configHostname, 'FW-AVR-01');
  assert.equal(confirmed.json.associationStatus, 'associated');

  const usable = await request(`/api/deploy/interfaces?session=${sessionId}`);
  assert.equal(usable.status, 200, usable.text);
});

test('une confirmation survit à l’export/import et à la recharge d’un workspace', async () => {
  const sessionId = await uploadLog(['FW-COM']);
  const mismatch = await uploadConfig(sessionId, 'FW-AVR-01');
  const confirmed = await request(`/api/deploy/config-association?session=${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      action: 'confirm', telemetryDeviceName: 'FW-COM', pendingConfigId: mismatch.json.pendingConfigId,
    }),
  });
  assert.equal(confirmed.status, 200, confirmed.text);

  const exported = await request(`/api/export/workspace?session=${sessionId}`);
  assert.equal(exported.status, 200, exported.text);
  assert.equal(exported.json.telemetryAssociation.confirmedByUser, true);
  assert.equal(exported.json.telemetryAssociation.telemetryDeviceName, 'FW-COM');
  assert.equal(exported.json.telemetryAssociation.configHostname, 'FW-AVR-01');
  assert.equal(typeof exported.json.telemetryContextId, 'string');
  assert.equal(
    Object.hasOwn(exported.json, 'fortiConfigRawText'),
    false,
    'le workspace ne doit pas embarquer le texte brut potentiellement sensible de la configuration',
  );

  const imported = await request('/api/import/workspace', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(exported.text) },
    body: exported.text,
  });
  assert.equal(imported.status, 200, imported.text);
  const restoredId = imported.json.sessionId;
  const restored = await request(`/api/deploy/interfaces?session=${restoredId}`);
  assert.equal(restored.status, 200, restored.text);
  const restoredExport = await request(`/api/export/workspace?session=${restoredId}`);
  assert.equal(restoredExport.status, 200, restoredExport.text);
  assert.deepEqual(restoredExport.json.telemetryAssociation, exported.json.telemetryAssociation);
  assert.equal(restoredExport.json.telemetryContextId, exported.json.telemetryContextId);
});

test('la télémétrie multi-équipement impose une sélection puis une confirmation si le nom diffère', async () => {
  const sessionId = await uploadLog(['FW-A', 'FW-B']);
  const selection = await uploadConfig(sessionId, 'FW-B-01');
  assert.equal(selection.status, 409, selection.text);
  assert.equal(selection.json.code, 'CONFIG_TELEMETRY_DEVICE_SELECTION_REQUIRED');
  assert.deepEqual(selection.json.association.telemetryDeviceNames, ['FW-A', 'FW-B']);
  assert.equal(selection.json.association.telemetryDeviceName, null);

  const selected = await request(`/api/deploy/config-association?session=${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      action: 'select',
      telemetryDeviceName: 'FW-B',
      pendingConfigId: selection.json.pendingConfigId,
    }),
  });
  assert.equal(selected.status, 409, selected.text);
  assert.equal(selected.json.code, 'CONFIG_TELEMETRY_ASSOCIATION_REQUIRED');
  assert.equal(selected.json.association.telemetryDeviceName, 'FW-B');
  assert.equal(selected.json.association.configHostname, 'FW-B-01');

  const confirmed = await request(`/api/deploy/config-association?session=${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      action: 'confirm',
      telemetryDeviceName: 'FW-B',
      pendingConfigId: selection.json.pendingConfigId,
    }),
  });
  assert.equal(confirmed.status, 200, confirmed.text);
  assert.equal(confirmed.json.telemetryAssociation.confirmedByUser, true);
  assert.equal(confirmed.json.telemetryAssociation.telemetryDeviceName, 'FW-B');
  const scopedStats = await request(`/api/stats?session=${sessionId}`);
  assert.equal(scopedStats.status, 200, scopedStats.text);
  assert.equal(scopedStats.json.stats.uniqueFlows, 1);
});

test('une confirmation survit aussi au workspace nommé de l’historique', async () => {
  const sessionId = await uploadLog(['FW-COM']);
  const mismatch = await uploadConfig(sessionId, 'FW-AVR-01');
  const confirmed = await request(`/api/deploy/config-association?session=${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'confirm', telemetryDeviceName: 'FW-COM', pendingConfigId: mismatch.json.pendingConfigId }),
  });
  assert.equal(confirmed.status, 200, confirmed.text);
  const saved = await request(`/api/workspaces?session=${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: `association-${Date.now()}-${Math.random().toString(16).slice(2)}` }),
  });
  assert.equal(saved.status, 200, saved.text);
  const loaded = await request(`/api/workspaces/${saved.json.id}`);
  assert.equal(loaded.status, 200, loaded.text);
  assert.equal(loaded.json.telemetryAssociation.confirmedByUser, true);
  assert.equal(loaded.json.fortiConfig.telemetryAssociation.confirmedByUser, true);
  assert.equal((await request(`/api/deploy/interfaces?session=${loaded.json.sessionId}`)).status, 200);
  const removed = await request(`/api/workspaces/${saved.json.id}`, { method: 'DELETE' });
  assert.equal(removed.status, 200, removed.text);
});

test('le changement de configuration et une nouvelle session ne réutilisent jamais une association', async () => {
  const sessionId = await uploadLog(['FW-COM']);
  const mismatch = await uploadConfig(sessionId, 'FW-AVR-01');
  const confirmed = await request(`/api/deploy/config-association?session=${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'confirm', telemetryDeviceName: 'FW-COM', pendingConfigId: mismatch.json.pendingConfigId }),
  });
  assert.equal(confirmed.status, 200, confirmed.text);

  const changedConfig = await uploadConfig(sessionId, 'FW-OTHER');
  assert.equal(changedConfig.status, 409, changedConfig.text);
  assert.equal(changedConfig.json.code, 'CONFIG_TELEMETRY_ASSOCIATION_REQUIRED');
  assert.notEqual(changedConfig.json.pendingConfigId, mismatch.json.pendingConfigId);
  assert.equal((await request(`/api/deploy/interfaces?session=${sessionId}`)).status, 404);

  const refused = await request(`/api/deploy/config-association?session=${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'refuse', pendingConfigId: changedConfig.json.pendingConfigId }),
  });
  assert.equal(refused.status, 200, refused.text);
  assert.equal(refused.json.code, 'CONFIG_TELEMETRY_ASSOCIATION_REFUSED');
  assert.equal(refused.json.status, 'unassociated');

  const newSessionId = await uploadLog(['FW-COM']);
  const newSessionConfig = await uploadConfig(newSessionId, 'FW-AVR-01');
  assert.equal(newSessionConfig.status, 409, newSessionConfig.text);
  assert.equal(newSessionConfig.json.code, 'CONFIG_TELEMETRY_ASSOCIATION_REQUIRED');
});
