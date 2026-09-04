'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { Readable } = require('node:stream');

const { parseStream } = require('../lib/parser');
const { buildAnalysis } = require('../lib/analyzer');
const {
  buildPolicyStrategyPreviews,
  generateConfig,
} = require('../lib/forticonfig');

function trafficLine(overrides = {}) {
  const fields = {
    type: 'traffic',
    srcip: '10.0.0.10',
    dstip: '10.0.1.20',
    srcport: '55000',
    dstport: '443',
    action: 'accept',
    service: 'HTTPS',
    srcintf: 'LAN',
    dstintf: 'DMZ',
    policyid: '1',
    ...overrides,
  };
  return Object.entries(fields)
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => `${key}=${value}`)
    .join(' ');
}

async function parseLines(lines) {
  return parseStream(Readable.from(lines.map(line => `${line}\n`)));
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
  throw new Error('Le serveur de test ne répond pas');
}

test('rejette explicitement les services sans protocole au lieu de l’inférer du nom', async () => {
  const result = await parseLines([
    trafficLine({ service: 'DNS', dstport: '53', proto: undefined }),
    trafficLine({ service: 'HTTPS', dstport: '443', proto: undefined, dstip: '10.0.1.21' }),
    trafficLine({ service: 'PING', dstport: '', proto: undefined, dstip: '10.0.1.22' }),
  ]);

  assert.equal(result.flowMap.size, 0);
  assert.equal(result.skipped, 3);
  assert.equal(result.skipReasons.missingProtocol, 3);
  assert.equal(result.skipReasons.invalidProtocol, 0);
});

test('rejette explicitement les protocoles malformés ou non pris en charge', async () => {
  const result = await parseLines([
    trafficLine({ proto: 'garbage' }),
    trafficLine({ proto: '6foo', dstip: '10.0.1.21' }),
    trafficLine({ proto: '132', dstip: '10.0.1.22' }),
    trafficLine({ proto: '0', dstip: '10.0.1.23' }),
    trafficLine({ proto: '256', dstip: '10.0.1.24' }),
  ]);

  assert.equal(result.flowMap.size, 0);
  assert.equal(result.skipped, 5);
  assert.equal(result.skipReasons.missingProtocol, 0);
  assert.equal(result.skipReasons.invalidProtocol, 5);
});

test('conserve les protocoles numériques pris en charge et les alias historiques', async () => {
  const inputs = [
    ['1', '1'], ['6', '6'], ['17', '17'], ['47', '47'], ['50', '50'], ['58', '58'], ['89', '89'],
    ['TCP', '6'], ['udp', '17'], ['ICMP', '1'],
  ];
  const result = await parseLines(inputs.map(([proto], index) =>
    trafficLine({ proto, dstip: `10.0.1.${20 + index}` })));

  assert.equal(result.skipped, 0);
  assert.deepEqual([...result.flowMap.values()].map(flow => flow.proto), inputs.map(([, expected]) => expected));
});

test('agrège les ports source comme un ensemble sans conserver arbitrairement le premier', async () => {
  const result = await parseLines([
    trafficLine({ proto: '6', srcport: '55000' }),
    trafficLine({ proto: '6', srcport: '55001' }),
  ]);

  assert.equal(result.flowMap.size, 1);
  const [flow] = result.flowMap.values();
  assert.equal(flow.count, 2);
  assert.equal(flow.srcport, '');
  assert.deepEqual(flow.srcports, ['55000', '55001']);
  assert.equal(flow.srcportMissing, false);
});

test('ordonne les preuves de ports source indépendamment de l’ordre des logs', async () => {
  const buildLines = (ports) => ports.map((srcport) => trafficLine({
    srcport,
    proto: '6',
    service: 'HTTPS',
    dstport: '443',
  }));

  const forward = await parseLines(buildLines(['2', '10', '1x']));
  const reverse = await parseLines(buildLines(['1x', '2', '10']));

  const forwardFlow = Array.from(forward.flowMap.values())[0];
  const reverseFlow = Array.from(reverse.flowMap.values())[0];
  assert.deepEqual(forwardFlow.srcports, ['2', '10', '1x']);
  assert.deepEqual(reverseFlow.srcports, forwardFlow.srcports);
});

test('une preuve protocolaire absente ne fournit aucune policy ni service générable', async () => {
  const parsed = await parseLines([
    trafficLine({ service: 'DNS', dstport: '53', proto: undefined }),
  ]);
  const analysis = buildAnalysis(parsed.flowMap);
  const previews = buildPolicyStrategyPreviews(analysis.policies, { scope: 'all' });
  const cli = generateConfig([], {});

  assert.equal(parsed.flowMap.size, 0);
  assert.equal(analysis.policies.length, 0);
  assert.deepEqual(
    Object.values(previews.strategies).map(strategy => strategy.policyCount),
    [0, 0, 0],
  );
  assert.doesNotMatch(cli, /FF_SVC_53_UDP|udp-portrange 53|set service/);
});

test('la chaîne HTTP refuse le log DNS sans protocole jusqu’à la génération', async t => {
  const port = await getFreePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const appDir = path.resolve(__dirname, '..');
  const child = spawn(process.execPath, ['server.js'], {
    cwd: appDir,
    env: { ...process.env, PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverOutput = '';
  let sessionId;
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
    `${trafficLine({ service: 'DNS', dstport: '53', proto: undefined })}\n`,
  ]), 'missing-proto.log');
  const uploadResponse = await fetch(`${baseUrl}/api/upload`, { method: 'POST', body: logForm });
  assert.equal(uploadResponse.status, 200, serverOutput);
  ({ sessionId } = await uploadResponse.json());

  let progress;
  for (let attempt = 0; attempt < 50; attempt++) {
    const progressResponse = await fetch(`${baseUrl}/api/progress/${sessionId}`);
    progress = await progressResponse.json();
    if (progress.done) break;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.equal(progress?.done, true, serverOutput);
  assert.equal(progress.meta.uniqueFlows, 0);
  assert.equal(progress.meta.skipped, 1);
  assert.equal(progress.meta.skipReasons.missingProtocol, 1);

  const policiesResponse = await fetch(`${baseUrl}/api/policies?session=${sessionId}`);
  assert.equal(policiesResponse.status, 200, serverOutput);
  const policies = await policiesResponse.json();
  assert.deepEqual(policies.policies, []);

  const configForm = new FormData();
  configForm.append('conffile', new Blob([`
config system interface
    edit "LAN"
        set ip 10.0.0.1 255.255.255.0
    next
    edit "DMZ"
        set ip 10.0.1.1 255.255.255.0
    next
end
`]), 'fortigate.conf');
  const configResponse = await fetch(`${baseUrl}/api/deploy/config-upload?session=${sessionId}`, {
    method: 'POST',
    body: configForm,
  });
  assert.equal(configResponse.status, 200, serverOutput);

  const requests = [
    ['/api/deploy/analyze', { selectedPolicies: [], opts: {} }],
    ['/api/deploy/preview', { analyzed: [], scope: 'all' }],
    ['/api/deploy/preflight', { selectedPolicies: [], opts: {} }],
    ['/api/deploy/generate', { selectedPolicies: [], opts: {} }],
  ];
  for (const [endpoint, body] of requests) {
    const response = await fetch(`${baseUrl}${endpoint}?session=${sessionId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const result = await response.json();
    assert.equal(response.status, 400, `${endpoint}: ${JSON.stringify(result)}\n${serverOutput}`);
    assert.doesNotMatch(JSON.stringify(result), /FF_SVC_53_UDP|udp-portrange 53|"cli"/);
  }
});
