'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('node:stream');

const { parseStream, normalizeDecision } = require('../lib/parser');
const { buildAnalysis, flowDecision, consolidatePolicies } = require('../lib/analyzer');
const { parseFortiConfig, analyzePolicies, generateConfig, preflightValidation } = require('../lib/forticonfig');
const { buildPoliciesByPlan } = require('../public/segmentation-plan.js');
const { getCaptureDeploymentBlockers } = require('../lib/deploy-safety');

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
  assert.equal(normalizeDecision('dns'), 'unknown');
  assert.equal(normalizeDecision('dns', {
    msg: 'Connection Failed',
    dstport: '53',
    proto: '17',
    service: 'DNS',
  }), 'failed');
  assert.equal(normalizeDecision('unseen-action'), 'unknown');
  assert.equal(flowDecision({ action: 'unseen-action' }), 'unknown');
  assert.equal(flowDecision({
    action: 'dns',
    decision: 'unknown',
    service: 'DNS',
    dstport: '53',
    proto: '17',
    sentBytes: 0,
    rcvdBytes: 0,
  }), 'failed');
});

test('les échecs DNS FortiOS restent distincts des flux acceptés et des actions inconnues', async () => {
  const log = 'date=2026-07-23 time=12:00:00 type=traffic logid="0000000011" srcip=10.0.0.10 dstip=10.0.1.53 srcport=53000 dstport=53 proto=17 action=dns service=DNS srcintf="lan" dstintf="servers" policyid=1194 sentbyte=0 rcvdbyte=0 duration=0 msg="Connection Failed"';
  const parsed = await parseStream(Readable.from([log]));
  const flows = [...parsed.flowMap.values()];
  assert.equal(flows.length, 1);
  assert.equal(flows[0].decision, 'failed');

  const analysis = buildAnalysis(flows);
  assert.equal(analysis.stats.failedSessions, 1);
  assert.equal(analysis.stats.unknownSessions, 0);
  assert.equal(analysis.stats.acceptSessions, 0);
  assert.equal(analysis.policies.length, 0);
});

test('le parser accepte les CSV FAZ au point-virgule avec directive Excel', async () => {
  const csv = [
    '\uFEFFsep=;',
    'Date;Time;IP source;IP destination;Port destination;Protocole;Action;Service;Interface source;Interface destination',
    '2026-07-23;12:00:00;10.0.0.10;10.0.1.53;53;17;accept;DNS;lan;servers',
  ].join('\n');
  const result = await parseStream(Readable.from([csv]));
  const flows = [...result.flowMap.values()];
  assert.equal(flows.length, 1);
  assert.equal(flows[0].srcip, '10.0.0.10');
  assert.equal(flows[0].dstip, '10.0.1.53');
  assert.equal(flows[0].decision, 'allow');
});

test('un CSV aux colonnes incompatibles est refusé avec un diagnostic lisible', async () => {
  const csv = 'foo;bar;baz\n1;2;3';
  await assert.rejects(
    parseStream(Readable.from([csv])),
    /colonnes obligatoires introuvables.*srcip.*dstip.*action/i
  );
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


test('un préfixe public porté par une interface LAN reste interne', () => {
  const netA = (203 * 0x1000000 + 0 * 0x10000 + 113 * 0x100) >>> 0;
  const netB = (203 * 0x1000000 + 0 * 0x10000 + 114 * 0x100) >>> 0;
  const known = [
    { prefix: 24, networkInt: netA, cidr: '203.0.113.0/24', internal: true },
    { prefix: 24, networkInt: netB, cidr: '203.0.114.0/24', internal: true },
  ];
  const result = buildAnalysis([
    aggregate({ srcip: '203.0.113.10', dstip: '203.0.114.20' }),
  ], known);
  assert.equal(result.policies.length, 1);
  assert.equal(result.policies[0].srcSubnet, '203.0.113.0/24');
  assert.equal(result.policies[0].dstType, 'private');
  assert.equal(result.policies[0].dstTarget, '203.0.114.0/24');
});

test('les routes statiques désactivées sont ignorées et la priorité est respectée', () => {
  const config = parseFortiConfig(`
config system interface
    edit "lan"
        set ip 10.0.0.1 255.255.255.0
        set role lan
    next
    edit "wan1"
        set ip 192.0.2.2 255.255.255.252
        set role wan
    next
    edit "wan2"
        set ip 198.51.100.2 255.255.255.252
        set role wan
    next
end
config router static
    edit 1
        set status disable
        set dst 0.0.0.0 0.0.0.0
        set device "bad-wan"
    next
    edit 2
        set dst 0.0.0.0 0.0.0.0
        set device "wan2"
        set distance 10
        set priority 20
    next
    edit 3
        set dst 0.0.0.0 0.0.0.0
        set device "wan1"
        set distance 10
        set priority 5
    next
end
`);
  assert.equal(config.staticRoutes.some(r => r.device === 'bad-wan'), false);
  assert.deepEqual(config.staticRoutes.map(r => r.device), ['wan1', 'wan2']);
});

test('le preflight refuse une action invalide et les scopes VDOM mélangés', () => {
  const config = {
    addresses: {},
    addressGroups: {},
    interfaces: { lan: {}, wan1: {} },
    zones: {},
    selectedVdom: 'root',
  };
  const base = {
    srcintf: 'lan',
    dstintf: 'wan1',
    dstType: 'public',
    dstTarget: '8.8.8.8',
    _dstUseAll: false,
    dstHosts: ['8.8.8.8'],
    action: 'accept',
    log: 'all',
    scope: { devid: 'FGT123', vdom: 'root' },
    analysis: {
      srcAddr: { found: false, name: 'SRC' },
      dstAddr: { found: false, name: 'DST' },
      services: [{ label: 'HTTPS', name: 'HTTPS', found: true }],
      srcIface: 'lan',
      dstIface: 'wan1',
    },
  };

  assert.equal(preflightValidation([base], config).ok, true);
  const badAction = preflightValidation([{ ...base, action: 'permit' }], config);
  assert.equal(badAction.ok, false);
  assert.match(badAction.issues.find(i => i.level === 'error').msg, /action FortiGate invalide/);

  const mixed = preflightValidation([
    base,
    { ...base, scope: { devid: 'FGT123', vdom: 'tenant-b' } },
  ], config);
  assert.equal(mixed.ok, false);
  assert.ok(mixed.issues.some(i => /Plusieurs équipements\/VDOM/.test(i.msg)));
  assert.ok(mixed.issues.some(i => /incompatible/.test(i.msg)));
});


test('la consolidation ne fusionne jamais deux scopes FortiGate/VDOM', () => {
  const base = {
    srcSubnet: '10.0.0.0/24',
    dstTarget: '10.0.1.0/24',
    dstType: 'private',
    services: ['HTTPS'],
    ports: [443],
    protos: ['TCP'],
    serviceTuples: [{ proto: '6', port: '443', service: 'HTTPS', sessions: 1 }],
    sessions: 1,
    sentBytes: 10,
    rcvdBytes: 20,
    noRcvdFlows: 0,
    noRcvdSrcHosts: [],
  };
  const result = consolidatePolicies([
    { ...base, scope: { devid: 'FGT-A', vdom: 'root' } },
    { ...base, scope: { devid: 'FGT-A', vdom: 'tenant-b' } },
  ]);
  assert.equal(result.length, 2);
  assert.deepEqual(result.map(p => p.scope.vdom).sort(), ['root', 'tenant-b']);
});


test('les flux IPv6 non pris en charge sont comptés explicitement', async () => {
  const log = 'date=2026-07-01 time=10:00:00 type=traffic devname="FGT-A" vd="root" srcip=2001:db8::10 dstip=2001:db8::20 dstport=443 proto=6 action=accept service=HTTPS';
  const result = await parseStream(Readable.from([log]));
  assert.equal(result.flowMap.size, 0);
  assert.equal(result.skipped, 1);
  assert.equal(result.skipReasons.ipv6, 1);
  assert.equal(result.skipReasons.invalidFlow, 0);
});


test('un service TCP+UDP doit couvrir chaque tuple observé', () => {
  const policy = {
    srcSubnet: '10.0.0.0/24',
    flowSrcintf: 'lan',
    dstTarget: '10.0.1.0/24',
    dstType: 'private',
    services: ['APPDNS'],
    ports: [1053],
    protos: ['TCP', 'UDP'],
    serviceTuples: [
      { proto: '6', port: '1053', service: 'APPDNS', sessions: 1 },
      { proto: '17', port: '1053', service: 'APPDNS', sessions: 1 },
    ],
  };
  const config = (customServices) => ({
    addresses: {},
    customServices,
    interfaces: {
      lan: { name: 'lan', cidr: '10.0.0.1/24' },
      servers: { name: 'servers', cidr: '10.0.1.1/24' },
    },
    zones: {},
    fullRoutes: [],
    staticRoutes: [],
    sdwanEnabled: false,
    sdwanMembers: [],
  });
  const both = {
    APPDNS: {
      proto: 'TCP/UDP/SCTP',
      tcpPorts: [1053], udpPorts: [1053],
      _tcpSet: new Set([1053]), _udpSet: new Set([1053]),
    },
  };
  const tcpOnly = {
    APPDNS: {
      proto: 'TCP/UDP/SCTP',
      tcpPorts: [1053], udpPorts: [],
      _tcpSet: new Set([1053]), _udpSet: new Set(),
    },
  };

  assert.equal(analyzePolicies([policy], config(both))[0].analysis.services[0].found, true);
  assert.equal(analyzePolicies([policy], config(tcpOnly))[0].analysis.services[0].found, false);
});


test('le preflight ignore la présence de PBR mais bloque une VRF non sélectionnée', () => {
  const policy = {
    srcintf: 'lan', dstintf: 'wan1',
    dstType: 'public', dstTarget: '8.8.8.8', dstHosts: ['8.8.8.8'], _dstUseAll: false,
    action: 'accept', log: 'all',
    analysis: {
      srcAddr: { found: false, name: 'SRC' },
      dstAddr: { found: false, name: 'DST' },
      services: [{ label: 'DNS', name: 'DNS', found: true }],
      srcIface: 'lan', dstIface: 'wan1',
    },
  };
  const baseConfig = { addresses: {}, addressGroups: {}, interfaces: { lan: {}, wan1: {} }, zones: {} };
  const pbr = preflightValidation([policy], { ...baseConfig, hasPolicyRoutes: true });
  const vrf = preflightValidation([policy], { ...baseConfig, hasNonDefaultVrf: true });

  assert.equal(pbr.ok, true);
  assert.equal(pbr.issues.some(i => /Policy-Based Routing|PBR/.test(i.msg)), false);

  assert.equal(vrf.ok, false);
  assert.ok(vrf.issues.some(i => i.code === 'VRF_CONTEXT'));
});


test('le preflight prouve une règle stricte avec les flux acceptés exacts', () => {
  const config = {
    addresses: {}, addressGroups: {}, zones: {},
    interfaces: { lan: {}, servers: {} },
  };
  const policy = {
    srcintf: 'lan',
    dstintf: 'servers',
    srcSubnet: '10.0.0.10/32',
    dstTarget: '10.0.1.20/32',
    srcHosts: ['10.0.0.10'],
    dstHosts: ['10.0.1.20'],
    services: ['HTTPS'],
    serviceTuples: [{ proto: '6', port: '443', service: 'HTTPS' }],
    _use32Src: true,
    _use32Dst: true,
    _segmentationPlan: { source: 'host', destination: 'host', services: 'separate' },
    action: 'accept',
    log: 'all',
    scope: { devid: 'FGT123', vdom: 'root' },
    analysis: {
      srcAddr: { found: false, name: 'SRC' },
      dstAddr: { found: false, name: 'DST' },
      srcIface: 'lan',
      dstIface: 'servers',
      services: [{ label: 'HTTPS', name: 'HTTPS', found: true }],
    },
  };
  const flows = [aggregate()];

  assert.equal(preflightValidation([policy], config, flows).ok, true);

  const phantom = {
    ...policy,
    dstTarget: '10.0.1.21/32',
    dstHosts: ['10.0.1.21'],
  };
  const rejected = preflightValidation([phantom], config, flows);
  assert.equal(rejected.ok, false);
  assert.ok(rejected.issues.some(issue => /aucun flux accepté|non observé/.test(issue.msg)));
});

test('le preflight bloque les services techniques plus larges que le plan', () => {
  const config = {
    addresses: {}, addressGroups: {}, zones: {},
    interfaces: { lan: {}, servers: {} },
  };
  const policy = {
    srcintf: 'lan',
    dstintf: 'servers',
    srcSubnet: '10.0.0.10/32',
    dstTarget: '10.0.1.20/32',
    srcHosts: ['10.0.0.10'],
    dstHosts: ['10.0.1.20'],
    services: ['HTTPS', 'DNS'],
    serviceTuples: [
      { proto: '6', port: '443', service: 'HTTPS' },
      { proto: '17', port: '53', service: 'DNS' },
    ],
    _use32Src: true,
    _use32Dst: true,
    _segmentationPlan: { source: 'host', destination: 'host', services: 'separate' },
    analysis: {
      srcAddr: { found: false, name: 'SRC' },
      dstAddr: { found: false, name: 'DST' },
      srcIface: 'lan',
      dstIface: 'servers',
      services: [{ label: 'HTTPS', name: 'HTTPS', found: true }],
    },
  };
  const rejected = preflightValidation([policy], config, [aggregate()]);
  assert.equal(rejected.ok, false);
  assert.ok(rejected.issues.some(issue => /services techniques hors périmètre/.test(issue.msg)));
  assert.ok(rejected.issues.some(issue => /tuples protocole\/port hors/.test(issue.msg)));
});

test('la chaîne plan → ré-analyse → CLI conserve une règle par service', () => {
  const serviceObjects = [
    { label: 'HTTPS', name: 'HTTPS', found: true },
    { label: 'DNS', name: 'DNS', found: true },
  ];
  const base = {
    srcSubnet: '10.0.0.0/24',
    dstTarget: '10.0.1.0/24',
    dstType: 'private',
    flowSrcintf: 'lan',
    services: ['HTTPS', 'DNS'],
    ports: [443, 53],
    protos: ['TCP', 'UDP'],
    serviceTuples: [
      { proto: '6', port: '443', service: 'HTTPS', sessions: 1 },
      { proto: '17', port: '53', service: 'DNS', sessions: 1 },
    ],
    srcHosts: ['10.0.0.10'],
    dstHosts: ['10.0.1.20'],
    analysis: { services: serviceObjects },
  };
  const hostPairServices = { '10.0.0.10|10.0.1.20': ['HTTPS', 'DNS'] };
  const planned = buildPoliciesByPlan([base], {
    source: 'host',
    destination: 'host',
    services: 'separate',
  }, {
    hostPairServices,
    getServicesForPair: () => serviceObjects,
  });
  const config = {
    addresses: {}, addressGroups: {}, customServices: {}, serviceGroups: {},
    interfaces: {
      lan: { name: 'lan', cidr: '10.0.0.1/24' },
      servers: { name: 'servers', cidr: '10.0.1.1/24' },
    },
    zones: {}, fullRoutes: [], staticRoutes: [],
    sdwanEnabled: false, sdwanMembers: [],
  };
  const analyzed = analyzePolicies(planned, config);
  assert.deepEqual(analyzed.map(policy => policy.analysis.services.map(service => service.label)), [['HTTPS'], ['DNS']]);

  const flows = [
    aggregate(),
    aggregate({ dstport: '53', proto: '17', service: 'DNS' }),
  ];
  assert.equal(preflightValidation(analyzed, config, flows).ok, true);

  const cli = generateConfig(analyzed, { addresses: {}, addressGroups: {}, zones: {} });
  const serviceLines = cli.split('\n').filter(line => line.trim().startsWith('set service '));
  assert.equal(serviceLines.length, 2);
  assert.ok(serviceLines.every(line => !line.includes('" "')));
  assert.ok(serviceLines.some(line => line.includes('"HTTPS"')));
  assert.ok(serviceLines.some(line => line.includes('"DNS"')));
});


test('les flux exclus restent signalés sans élargir ni bloquer une policy prouvée', () => {
  const sessionData = {
    meta: { skipReasons: { ipv6: 3 } },
    stats: { unknownSessions: 7, failedSessions: 11 },
  };
  assert.deepEqual(getCaptureDeploymentBlockers(sessionData), {
    unsupportedIpv6: 3,
    unknownActionSessions: 7,
    failedConnectionSessions: 11,
    hasExcludedTraffic: true,
    blocked: false,
  });
  assert.deepEqual(getCaptureDeploymentBlockers({}), {
    unsupportedIpv6: 0,
    unknownActionSessions: 0,
    failedConnectionSessions: 0,
    hasExcludedTraffic: false,
    blocked: false,
  });
});
