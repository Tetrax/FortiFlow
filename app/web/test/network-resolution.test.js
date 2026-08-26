'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { buildAnalysis } = require('../lib/analyzer');
const { parseFortiConfig, extractKnownSubnets } = require('../lib/forticonfig');

function acceptedFlow(srcip, dstip, srcintf = 'Stations', dstintf = 'Admin') {
  return {
    srcip,
    dstip,
    srcport: '55000',
    dstport: '443',
    proto: '6',
    action: 'accept',
    service: 'HTTPS',
    srcintf,
    dstintf,
    policyid: '1',
    count: 1,
    sentBytes: 100,
    rcvdBytes: 200,
  };
}

async function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(error => error ? reject(error) : resolve(port));
    });
  });
}

async function waitForReady(baseUrl) {
  for (let attempt = 0; attempt < 50; attempt++) {
    try {
      const response = await fetch(`${baseUrl}/api/health`);
      if (response.ok) return;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error('FortiFlow test server did not start');
}

test('uses the most specific FortiGate interface networks instead of a broad address object', () => {
  const fortiConfig = parseFortiConfig(`
config firewall address
    edit "RFC1918-10.0.0.0/8"
        set subnet 10.0.0.0 255.0.0.0
    next
end
config system interface
    edit "Stations"
        set ip 10.250.17.254 255.255.254.0
    next
    edit "Admin"
        set ip 10.250.7.254 255.255.255.0
    next
end
`);

  const analysis = buildAnalysis(
    [acceptedFlow('10.250.16.49', '10.250.7.106')],
    extractKnownSubnets(fortiConfig),
  );

  assert.equal(analysis.flows[0].srcSubnet, '10.250.16.0/23');
  assert.equal(analysis.flows[0].dstSubnet, '10.250.7.0/24');
  assert.deepEqual(analysis.policies.map(policy => [policy.srcSubnet, policy.dstTarget]), [
    ['10.250.16.0/23', '10.250.7.0/24'],
  ]);
});

test('prefers a more specific firewall address object over an interface network', () => {
  const fortiConfig = parseFortiConfig(`
config firewall address
    edit "Stations-Printers"
        set subnet 10.250.16.0 255.255.255.128
    next
end
config system interface
    edit "Stations"
        set ip 10.250.17.254 255.255.254.0
    next
end
`);

  const analysis = buildAnalysis(
    [acceptedFlow('10.250.16.49', '8.8.8.8')],
    extractKnownSubnets(fortiConfig),
  );

  assert.equal(analysis.flows[0].srcSubnet, '10.250.16.0/25');
});

test('keeps an unmatched private IP as a host instead of inventing a subnet', () => {
  const fortiConfig = parseFortiConfig(`
config system interface
    edit "Stations"
        set ip 10.250.17.254 255.255.254.0
    next
end
`);

  const analysis = buildAnalysis(
    [acceptedFlow('10.99.1.12', '10.99.2.34', 'unknown-src', 'unknown-dst')],
    extractKnownSubnets(fortiConfig),
  );

  assert.equal(analysis.flows[0].srcSubnet, '10.99.1.12/32');
  assert.equal(analysis.flows[0].dstSubnet, '10.99.2.34/32');
});

test('reanalyzes imported logs with the networks from the selected VDOM', async t => {
  const port = await getFreePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const appDir = path.resolve(__dirname, '..');
  const child = spawn(process.execPath, ['server.js'], {
    cwd: appDir,
    env: {
      ...process.env,
      PORT: String(port),
      SSL_KEY: '/nonexistent/fortiflow-test.key',
      SSL_CERT: '/nonexistent/fortiflow-test.crt',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverOutput = '';
  let sessionId = null;
  child.stdout.on('data', chunk => { serverOutput += chunk; });
  child.stderr.on('data', chunk => { serverOutput += chunk; });
  t.after(async () => {
    if (sessionId) {
      await fetch(`${baseUrl}/api/admin/sessions/${sessionId}`, { method: 'DELETE' }).catch(() => {});
    }
    child.kill('SIGTERM');
  });

  await waitForReady(baseUrl);

  const logForm = new FormData();
  logForm.append('logfile', new Blob([
    'type=traffic srcip=10.250.16.49 dstip=10.250.7.106 srcport=55000 dstport=22 proto=6 action=accept service=SSH srcintf="Stations" dstintf="Admin" policyid=1 sentbyte=100 rcvdbyte=200\n',
  ]), 'traffic.log');
  const uploadResponse = await fetch(`${baseUrl}/api/upload`, { method: 'POST', body: logForm });
  assert.equal(uploadResponse.status, 200, serverOutput);
  ({ sessionId } = await uploadResponse.json());

  for (let attempt = 0; attempt < 50; attempt++) {
    const progressResponse = await fetch(`${baseUrl}/api/progress/${sessionId}`);
    const progress = await progressResponse.json();
    if (progress.done) break;
    await new Promise(resolve => setTimeout(resolve, 50));
  }

  const configForm = new FormData();
  configForm.append('conffile', new Blob([`
config vdom
    edit "root"
        config system interface
            edit "root-lan"
                set ip 192.168.1.254 255.255.255.0
            next
        end
    next
    edit "tenant"
        config system interface
            edit "Stations"
                set ip 10.250.17.254 255.255.254.0
            next
            edit "Admin"
                set ip 10.250.7.254 255.255.255.0
            next
        end
    next
end
`]), 'fortigate.conf');
  const configResponse = await fetch(`${baseUrl}/api/deploy/config-upload?session=${sessionId}`, {
    method: 'POST',
    body: configForm,
  });
  assert.equal(configResponse.status, 200, serverOutput);
  const configResult = await configResponse.json();
  assert.equal(configResult.selectedVdom, 'root');
  assert.deepEqual(configResult.vdomList, ['root', 'tenant']);

  const switchResponse = await fetch(`${baseUrl}/api/deploy/config-vdom?session=${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vdom: 'tenant' }),
  });
  assert.equal(switchResponse.status, 200, serverOutput);

  const flowsResponse = await fetch(`${baseUrl}/api/flows?session=${sessionId}`);
  assert.equal(flowsResponse.status, 200, serverOutput);
  const flows = await flowsResponse.json();
  assert.equal(flows.data[0].srcSubnet, '10.250.16.0/23');
  assert.equal(flows.data[0].dstSubnet, '10.250.7.0/24');

  const policiesResponse = await fetch(`${baseUrl}/api/policies?session=${sessionId}`);
  assert.equal(policiesResponse.status, 200, serverOutput);
  const { policies } = await policiesResponse.json();
  assert.deepEqual(policies.map(policy => [policy.srcSubnet, policy.dstTarget]), [
    ['10.250.16.0/23', '10.250.7.0/24'],
  ]);

  const legacyAnalysisResponse = await fetch(`${baseUrl}/api/deploy/generate?session=${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ selectedPolicies: policies, opts: {} }),
  });
  assert.equal(legacyAnalysisResponse.status, 200, serverOutput);
  const legacyAnalysisResult = await legacyAnalysisResponse.json();
  assert.equal(legacyAnalysisResult.cli, undefined);
  assert.ok(legacyAnalysisResult.analyzed[0].analysis);

  const analysisResponse = await fetch(`${baseUrl}/api/deploy/analyze?session=${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ selectedPolicies: policies, opts: {} }),
  });
  assert.equal(analysisResponse.status, 200, serverOutput);
  const analysisResult = await analysisResponse.json();
  assert.equal(analysisResult.analyzed.length, 1);
  assert.ok(analysisResult.analyzed[0].analysis);

  const generateResponse = await fetch(`${baseUrl}/api/deploy/generate?session=${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ selectedPolicies: analysisResult.analyzed, opts: {} }),
  });
  assert.equal(generateResponse.status, 200, serverOutput);
  const generated = await generateResponse.json();
  assert.match(generated.cli, /set subnet 10\.250\.16\.0 255\.255\.254\.0/);
  assert.match(generated.cli, /set subnet 10\.250\.7\.0 255\.255\.255\.0/);
});

test('re-resolves a persisted policy before it is sent to the drawer', async t => {
  const fortiConfig = parseFortiConfig(`
config firewall address
    edit "RFC1918-10.0.0.0/8"
        set subnet 10.0.0.0 255.0.0.0
    next
end
config system interface
    edit "Stations"
        set ip 10.250.17.254 255.255.254.0
    next
    edit "Admin"
        set ip 10.250.7.254 255.255.255.0
    next
end
`);
  const broadOnly = parseFortiConfig(`
config firewall address
    edit "RFC1918-10.0.0.0/8"
        set subnet 10.0.0.0 255.0.0.0
    next
end
`);
  const staleAnalysis = buildAnalysis(
    [acceptedFlow('10.250.16.49', '10.250.7.106')],
    extractKnownSubnets(broadOnly),
  );
  staleAnalysis.meta = { filename: 'persisted.log' };
  assert.equal(staleAnalysis.policies[0].srcSubnet, '10.0.0.0/8');

  const sessionId = `networkresolution${process.pid}${Date.now()}`;
  const cacheDir = path.resolve(__dirname, '../../sessions-cache');
  const cachePath = path.join(cacheDir, `${sessionId}.json`);
  fs.mkdirSync(cacheDir, { recursive: true });
  fs.writeFileSync(cachePath, JSON.stringify({
    id: sessionId,
    createdAt: Date.now(),
    lastAccess: Date.now(),
    status: 'ready',
    data: staleAnalysis,
    fortiConfig,
  }));

  const port = await getFreePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, ['server.js'], {
    cwd: path.resolve(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(port),
      SSL_KEY: '/nonexistent/fortiflow-test.key',
      SSL_CERT: '/nonexistent/fortiflow-test.crt',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverOutput = '';
  child.stdout.on('data', chunk => { serverOutput += chunk; });
  child.stderr.on('data', chunk => { serverOutput += chunk; });
  t.after(async () => {
    await fetch(`${baseUrl}/api/admin/sessions/${sessionId}`, { method: 'DELETE' }).catch(() => {});
    child.kill('SIGTERM');
    fs.rmSync(cachePath, { force: true });
  });

  await waitForReady(baseUrl);
  const policiesResponse = await fetch(`${baseUrl}/api/policies?session=${sessionId}&include_no_rcvd=1`);
  assert.equal(policiesResponse.status, 200, serverOutput);
  const { policies } = await policiesResponse.json();

  assert.equal(policies[0].srcSubnet, '10.250.16.0/23');
  assert.equal(policies[0].dstTarget, '10.250.7.0/24');
  assert.notEqual(policies[0].srcSubnet, '10.0.0.0/8');
});
