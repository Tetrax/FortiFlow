'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('node:stream');

const { parseStream, normalizeDecision } = require('../lib/parser');
const { buildAnalysis, flowDecision } = require('../lib/analyzer');
const { parseFortiConfig, generateConfig } = require('../lib/forticonfig');

function aggregate(overrides = {}) {
  return {
    srcip: '10.0.0.10',
    dstip: '10.0.1.20',
    dstport: '443',
    proto: '6',
    action: 'accept',
    decision: 'allow',
    service: 'HTTPS',
    srcintf: 'lan',
    dstintf: 'servers',
    policyid: '10',
    devname: 'FGT-A',
    devid: 'FGT123',
    vdom: 'root',
    count: 1,
    sentBytes: 100,
    rcvdBytes: 200,
    firstTs: null,
    lastTs: null,
    days: [],
    ...overrides,
  };
}

function wanPolicy(overrides = {}) {
  return {
    id: 1,
    policyName: 'FF-WAN-DNS',
    srcSubnet: '10.0.0.0/24',
    dstTarget: '8.8.8.8',
    dstType: 'public',
    _isWan: true,
    srcintf: 'lan',
    dstintf: 'wan1',
    analysis: {
      srcAddr: { found: false, cidr: '10.0.0.0/24' },
      dstAddr: { found: false, cidr: '8.8.8.8/32' },
      services: [],
    },
    ...overrides,
  };
}

test('normalise les actions FortiOS et refuse les actions inconnues', () => {
  assert.equal(normalizeDecision('accept'), 'allow');
  assert.equal(normalizeDecision('close'), 'allow');
  assert.equal(normalizeDecision('client-rst'), 'allow');
  assert.equal(normalizeDecision('deny'), 'deny');
  assert.equal(normalizeDecision('blocked'), 'deny');
  assert.equal(normalizeDecision('unseen-action'), 'unknown');
  assert.equal(flowDecision({ action: 'unseen-action' }), 'unknown');
});

test('le parser ne fusionne pas deux VDOM utilisant les mêmes adresses', async () => {
  const logs = [
    'date=2026-07-01 time=10:00:00 type=traffic devname="FGT-A" devid="FGT123" vd="root" srcip=10.0.0.10 dstip=10.0.1.20 srcport=50000 dstport=443 proto=6 action=accept service=HTTPS srcintf="lan" dstintf="servers"',
    'date=2026-07-01 time=10:00:01 type=traffic devname="FGT-A" devid="FGT123" vd="tenant-b" srcip=10.0.0.10 dstip=10.0.1.20 srcport=50001 dstport=443 proto=6 action=accept service=HTTPS srcintf="lan" dstintf="servers"',
  ].join('\n');
  const result = await parseStream(Readable.from([logs]));
  assert.equal(result.flowMap.size, 2);
  assert.deepEqual([...result.flowMap.values()].map(f => f.vdom).sort(), ['root', 'tenant-b']);
});

test('seuls les flux explicitement autorisés produisent des suggestions', () => {
  const unknown = buildAnalysis([aggregate({ action: 'mystery', decision: 'unknown', count: 4 })]);
  assert.equal(unknown.stats.unknownSessions, 4);
  assert.equal(unknown.stats.acceptSessions, 0);
  assert.equal(unknown.policies.length, 0);

  const allowed = buildAnalysis([aggregate({ action: 'close', decision: 'allow', count: 3 })]);
  assert.equal(allowed.stats.acceptSessions, 3);
  assert.equal(allowed.policies.length, 1);
  assert.equal(allowed.policies[0].scope.vdom, 'root');
});

test('la relation protocole-port-service est conservée sans troncature', () => {
  const flows = Array.from({ length: 25 }, (_, i) => aggregate({
    dstport: String(10000 + i),
    service: '',
  }));
  const analysis = buildAnalysis(flows);
  assert.equal(analysis.policies.length, 1);
  assert.equal(analysis.policies[0].ports.length, 25);
  assert.equal(analysis.policies[0].serviceTuples.length, 25);
  assert.deepEqual(analysis.policies[0].serviceTuples[0], {
    proto: '6', port: '10000', service: '', sessions: 1,
  });
});

test('l’ordre first-match FortiGate est conservé même avec des IDs numériques', () => {
  const config = parseFortiConfig(`
config firewall policy
    edit 100
        set name "FIRST"
        set srcintf "lan"
        set dstintf "servers"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
    edit 2
        set name "SECOND"
        set srcintf "lan"
        set dstintf "servers"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action deny
    next
end
`);
  assert.deepEqual(config.existingPolicies.map(p => p.policyid), [100, 2]);
});

test('une policy WAN reste spécifique sauf choix explicite de all', () => {
  const safeCli = generateConfig([wanPolicy()], { defaultSrcIntf: 'lan', defaultDstIntf: 'wan1' });
  assert.doesNotMatch(safeCli, /set dstaddr "all"/);
  assert.match(safeCli, /8_8_8_8/);

  const broadCli = generateConfig([wanPolicy({ _dstUseAll: true })], { defaultSrcIntf: 'lan', defaultDstIntf: 'wan1' });
  assert.match(broadCli, /set dstaddr "all"/);

  assert.throws(
    () => generateConfig([wanPolicy({ dstTarget: '', analysis: { srcAddr: { found: false, cidr: '10.0.0.0/24' }, dstAddr: { found: false, cidr: null }, services: [] } })]),
    /sans destination spécifique/,
  );
});

test('un groupe de profils utilise la syntaxe FortiOS correcte', () => {
  const cli = generateConfig([
    wanPolicy({ _dstUseAll: true, securityProfiles: { profileGroup: 'EDGE-PROFILES' } }),
  ], { defaultSrcIntf: 'lan', defaultDstIntf: 'wan1' });
  assert.match(cli, /set profile-type group/);
  assert.match(cli, /set profile-group "EDGE-PROFILES"/);
  assert.doesNotMatch(cli, /set profile-protocol-options "EDGE-PROFILES"/);
});
