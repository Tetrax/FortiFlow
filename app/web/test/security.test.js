'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('node:stream');

const { parseStream, normalizeDecision } = require('../lib/parser');
const { buildAnalysis, flowDecision, consolidatePolicies } = require('../lib/analyzer');
const {
  parseFortiConfig,
  analyzePolicies,
  applyPolicyAddressSelections,
  generateConfig,
  preflightValidation,
  findAddress,
  resolveInterfaceByRoute,
} = require('../lib/forticonfig');
const { buildPoliciesByPlan } = require('../public/segmentation-plan.js');
const { getCaptureDeploymentBlockers } = require('../lib/deploy-safety');
const { buildHostPairCoverage, buildPolicyOrderIssues, resolveServiceNames } = require('../lib/coverage');

function aggregate(overrides = {}) {
  return {
    srcip: '10.0.0.10',
    dstip: '10.0.1.20',
    dstport: '443',
    proto: '6',
    action: 'accept',
    decision: 'allow',
    deploymentEligible: true,
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
      services: [{ label: 'HTTPS', found: true, name: 'HTTPS' }],
    },
    ...overrides,
  };
}

test('normalise les actions FortiOS et refuse les actions inconnues', () => {
  assert.equal(normalizeDecision('accept'), 'allow');
  assert.equal(normalizeDecision('start'), 'allow');
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

test('déduplique les logs start/close d’une même session sans perdre les compteurs terminaux', async () => {
  const common = 'type=traffic subtype=forward devname="FGT-A" devid="FGT123" vd="root" sessionid=9001 srcip=10.0.0.10 srcport=51000 dstip=10.0.1.20 dstport=443 proto=6 srcintf="lan" dstintf="servers" policyid=10';
  const logs = [
    `date=2026-07-23 time=10:00:00 action=start service="" sentbyte=200 rcvdbyte=300 ${common}`,
    `date=2026-07-23 time=10:05:00 action=close service=HTTPS sentbyte=1200 rcvdbyte=3400 ${common}`,
  ].join('\n');
  const result = await parseStream(Readable.from([logs]));
  const flows = [...result.flowMap.values()];

  assert.equal(flows.length, 1);
  assert.equal(flows[0].count, 1);
  assert.equal(flows[0].sentBytes, 1200);
  assert.equal(flows[0].rcvdBytes, 3400);
  assert.equal(flows[0].service, 'HTTPS');
  assert.equal(result.dedupe.duplicateRecords, 1);
});

test('compte une nouvelle session quand FortiOS réutilise un sessionid terminé', async () => {
  const common = 'type=traffic subtype=forward devname="FGT-A" devid="FGT123" vd="root" sessionid=42 srcip=10.0.0.10 srcport=51000 dstip=10.0.1.20 dstport=443 proto=6 service=HTTPS srcintf="lan" dstintf="servers" policyid=10';
  const logs = [
    `date=2026-07-23 time=10:00:00 action=start sentbyte=0 rcvdbyte=0 ${common}`,
    `date=2026-07-23 time=10:01:00 action=close sentbyte=100 rcvdbyte=200 ${common}`,
    `date=2026-07-24 time=10:00:00 action=start sentbyte=10 rcvdbyte=20 ${common}`,
  ].join('\n');
  const result = await parseStream(Readable.from([logs]));
  const flow = [...result.flowMap.values()][0];

  assert.equal(flow.count, 2);
  assert.equal(flow.sentBytes, 110);
  assert.equal(flow.rcvdBytes, 220);
  assert.equal(result.dedupe.duplicateRecords, 1);
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

test('le parser accepte les exports FAZ CSV sans en-tête composés de cellules key=value', async () => {
  const csv = [
    '"itime=1784816350","date=""2026-07-23""","time=""16:19:10""","type=""traffic""","action=""close""","dstintf=""AGGREGAT""","dstip=""10.1.6.103""","dstport=8531","policyid=1194","proto=6","rcvdbyte=6531","sentbyte=1750","service=""WSUS""","srcintf=""vlan-850""","srcip=""10.61.2.112""","srcport=62885"',
    '"itime=1784816351","date=""2026-07-23""","time=""16:19:11""","type=""traffic""","action=""accept""","dstintf=""AGGREGAT""","dstip=""10.1.6.10""","dstport=53","policyid=1194","proto=17","rcvdbyte=179","sentbyte=69","service=""DNS""","srcintf=""vlan-850""","srcip=""10.50.2.249""","srcport=53883"',
  ].join('\n');
  const result = await parseStream(Readable.from([csv]));
  const flows = [...result.flowMap.values()].sort((a, b) => a.dstport.localeCompare(b.dstport));
  assert.equal(result.lineCount, 2);
  assert.equal(result.skipped, 0);
  assert.equal(flows.length, 2);
  assert.equal(flows[0].srcip, '10.50.2.249');
  assert.equal(flows[0].dstip, '10.1.6.10');
  assert.equal(flows[0].service, 'DNS');
  assert.equal(flows[0].decision, 'allow');
  assert.equal(flows[1].srcip, '10.61.2.112');
  assert.equal(flows[1].dstport, '8531');
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

test('une policy existante avec horaire ou négation reste incertaine dans la couverture', () => {
  const config = parseFortiConfig(`
config firewall policy
    edit 10
        set name "LIMITED"
        set srcintf "lan"
        set dstintf "servers"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set schedule "workhours"
    next
end
`);
  const { hostPairCoverage } = buildHostPairCoverage([aggregate()], config);
  assert.equal(hostPairCoverage['10.0.0.10|10.0.1.20'].verdict, 'uncertain');
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

test('la confiance distingue les jours réellement observés de la plage calendaire', () => {
  const dayOne = Date.parse('2026-07-01T10:00:00Z');
  const dayThirty = Date.parse('2026-07-30T10:00:00Z');
  const analysis = buildAnalysis([
    aggregate({ firstTs: dayOne, lastTs: dayOne, days: ['2026-07-01'] }),
    aggregate({ firstTs: dayThirty, lastTs: dayThirty, days: ['2026-07-30'] }),
  ]);

  assert.equal(analysis.stats.captureActiveDays, 2);
  assert.equal(analysis.stats.captureSpanDays, 30);
  assert.ok(analysis.stats.captureCoverageRatio < 0.07);
  assert.equal(analysis.policies[0].daysObserved, 2);
  assert.equal(analysis.policies[0].confidence, 'medium');
});

test('un flux UDP explicitement unidirectionnel n’est pas classé comme destination silencieuse', () => {
  const analysis = buildAnalysis([
    aggregate({
      proto: '17',
      dstport: '514',
      service: 'SYSLOG',
      sentBytes: 500,
      rcvdBytes: 0,
      rcvdPackets: 0,
    }),
  ]);

  assert.equal(analysis.policies[0].noRcvdFlows, 0);
  assert.equal(analysis.policies[0].expectedOneWayFlows, 1);
});


test('les flux IPv6 non pris en charge sont comptés explicitement', async () => {
  const log = 'date=2026-07-01 time=10:00:00 type=traffic devname="FGT-A" vd="root" srcip=2001:db8::10 dstip=2001:db8::20 dstport=443 proto=6 action=accept service=HTTPS';
  const result = await parseStream(Readable.from([log]));
  assert.equal(result.flowMap.size, 0);
  assert.equal(result.skipped, 1);
  assert.equal(result.skipReasons.ipv6, 1);
  assert.equal(result.skipReasons.invalidFlow, 0);
});

test('les flux locaux, NATés ou à protocole déduit restent visibles mais ne produisent aucune règle', async () => {
  const logs = [
    'date=2026-07-01 time=10:00:00 type=traffic subtype=local devname="FGT-A" vd="root" srcip=10.0.0.10 dstip=10.0.0.1 dstport=443 proto=6 action=accept service=HTTPS srcintf="lan" dstintf="root" policyid=1',
    'date=2026-07-01 time=10:00:01 type=traffic subtype=forward devname="FGT-A" vd="root" srcip=10.0.0.10 dstip=8.8.8.8 dstport=53 proto=17 action=accept service=DNS srcintf="lan" dstintf="wan1" policyid=2 trandisp=snat transip=192.0.2.10',
    'date=2026-07-01 time=10:00:02 type=traffic subtype=forward devname="FGT-A" vd="root" srcip=10.0.0.10 dstip=10.0.1.20 dstport=443 action=accept service=HTTPS srcintf="lan" dstintf="servers" policyid=3',
  ].join('\n');
  const parsed = await parseStream(Readable.from([logs]));
  const analysis = buildAnalysis(parsed.flowMap);

  assert.equal(analysis.stats.acceptSessions, 3);
  assert.equal(analysis.stats.nonDeployableSessions, 3);
  assert.equal(analysis.stats.evidenceIssueSessions.non_forward_traffic, 1);
  assert.equal(analysis.stats.evidenceIssueSessions.nat_translation, 1);
  assert.equal(analysis.stats.evidenceIssueSessions.protocol_inferred, 1);
  assert.equal(analysis.policies.length, 0);
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

test('un objet service plus large que les tuples observés est remplacé par un objet exact', () => {
  const policy = {
    srcSubnet: '10.0.0.0/24',
    flowSrcintf: 'lan',
    dstTarget: '10.0.1.0/24',
    dstType: 'private',
    services: ['APP-WEB'],
    ports: [443],
    protos: ['TCP'],
    serviceTuples: [{ proto: '6', port: '443', service: 'APP-WEB', sessions: 1 }],
  };
  const config = {
    addresses: {},
    customServices: {
      'APP-WEB': {
        proto: 'TCP/UDP/SCTP',
        tcpPorts: [443, 8443],
        udpPorts: [],
        _tcpSet: new Set([443, 8443]),
        _udpSet: new Set(),
      },
    },
    interfaces: {
      lan: { name: 'lan', cidr: '10.0.0.1/24' },
      servers: { name: 'servers', cidr: '10.0.1.1/24' },
    },
    zones: {},
    fullRoutes: [],
    staticRoutes: [],
    sdwanEnabled: false,
    sdwanMembers: [],
  };

  const analyzed = analyzePolicies([policy], config)[0];
  const service = analyzed.analysis.services[0];
  assert.equal(service.found, false);
  assert.equal(service.source, 'generated-exact');
  assert.deepEqual(service.tcpPorts, [443]);
  assert.deepEqual(service.udpPorts, []);

  const cli = generateConfig([{
    ...analyzed,
    srcintf: 'lan',
    dstintf: 'servers',
  }], {
    addresses: {},
    addressGroups: {},
    zones: {},
  });
  assert.match(cli, /set tcp-portrange 443/);
  assert.doesNotMatch(cli, /8443/);
});

test('DNS UDP seul ne réutilise pas le service prédéfini TCP+UDP', () => {
  const policy = {
    srcSubnet: '10.0.0.0/24',
    flowSrcintf: 'lan',
    dstTarget: '10.0.1.0/24',
    dstType: 'private',
    services: ['DNS'],
    ports: [53],
    protos: ['UDP'],
    serviceTuples: [{ proto: '17', port: '53', service: 'DNS', sessions: 1 }],
  };
  const config = {
    addresses: {}, customServices: {},
    interfaces: {
      lan: { name: 'lan', cidr: '10.0.0.1/24' },
      servers: { name: 'servers', cidr: '10.0.1.1/24' },
    },
    zones: {}, fullRoutes: [], staticRoutes: [],
    sdwanEnabled: false, sdwanMembers: [],
  };

  const analyzed = analyzePolicies([policy], config)[0];
  assert.equal(analyzed.analysis.services[0].found, false);
  assert.deepEqual(analyzed.analysis.services[0].udpPorts, [53]);
  const cli = generateConfig([{ ...analyzed, srcintf: 'lan', dstintf: 'servers' }], {
    addresses: {}, addressGroups: {}, zones: {},
  });
  assert.match(cli, /set udp-portrange 53/);
  assert.doesNotMatch(cli, /set tcp-portrange 53/);
  assert.doesNotMatch(cli, /set service "DNS"/);
});

test('le générateur refuse tout service non résolu sans tuple exact et ne retombe jamais sur ALL', () => {
  const invalid = {
    ...wanPolicy(),
    analysis: {
      srcAddr: { found: false, cidr: '10.0.0.0/24' },
      dstAddr: { found: false, cidr: '8.8.8.8/32' },
      services: [{ label: 'SERVICE-INCONNU', found: false, suggestedName: 'SERVICE-INCONNU' }],
    },
  };
  assert.throws(() => generateConfig([invalid]), /sans protocole\/port exact/);
});


test('le preflight classe PBR en conditionnel et bloque une VRF non sélectionnée', () => {
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
  assert.ok(pbr.issues.some(i => i.code === 'ROUTING_CONTEXT_UNPROVEN'));
  assert.equal(pbr.certification.level, 'conditional');

  assert.equal(vrf.ok, false);
  assert.ok(vrf.issues.some(i => i.code === 'VRF_CONTEXT'));
});

test('détecte uniquement les vraies règles PBR et SD-WAN dans leur section', () => {
  const withoutRules = parseFortiConfig(`
config system sdwan
    config members
        edit 1
            set interface "wan1"
        next
    end
end
config firewall service custom
    edit "HTTPS-CUSTOM"
        set tcp-portrange 443
    next
end
`);
  assert.equal(withoutRules.hasPolicyRoutes, false);
  assert.equal(withoutRules.hasSdwanRules, false);

  const withRules = parseFortiConfig(`
config router policy
    edit 1
        set input-device "lan"
        set output-device "wan1"
    next
end
config system sdwan
    config service
        edit 1
            set dst "all"
        next
    end
end
`);
  assert.equal(withRules.hasPolicyRoutes, true);
  assert.equal(withRules.hasSdwanRules, true);
});

test('un ECMP vers plusieurs interfaces reste indéterminé au lieu de choisir un chemin arbitraire', () => {
  const resolution = resolveInterfaceByRoute('8.8.8.8', [
    { dst: '0.0.0.0/0', device: 'wan1', distance: 10, priority: 0 },
    { dst: '0.0.0.0/0', device: 'wan2', distance: 10, priority: 0 },
  ]);
  assert.equal(resolution.device, null);
  assert.equal(resolution.ambiguous, true);
  assert.deepEqual(resolution.candidates.sort(), ['wan1', 'wan2']);

  const analyzed = analyzePolicies([{
    srcSubnet: '10.0.0.0/24',
    flowSrcintf: 'lan',
    dstTarget: '8.8.8.8',
    dstType: 'public',
    services: ['HTTPS'],
    ports: [443],
    protos: ['TCP'],
    serviceTuples: [{ proto: '6', port: '443', service: 'HTTPS', sessions: 1 }],
  }], {
    addresses: {},
    customServices: {},
    interfaces: {
      lan: { name: 'lan', cidr: '10.0.0.1/24' },
      wan1: { name: 'wan1', isWan: true },
      wan2: { name: 'wan2', isWan: true },
    },
    zones: {},
    fullRoutes: [
      { dst: '0.0.0.0/0', device: 'wan1', distance: 10, priority: 0 },
      { dst: '0.0.0.0/0', device: 'wan2', distance: 10, priority: 0 },
    ],
    sdwanEnabled: false,
    sdwanMembers: [],
  })[0];

  assert.equal(analyzed.analysis.dstIface, null);
  assert.equal(analyzed.analysis.dstIfaceSource, 'ecmp-ambiguous');
  assert.equal(analyzed.analysis.status, 'error');
});

test('les groupes de services imbriqués sont résolus sans élargir la couverture', () => {
  const resolved = resolveServiceNames(
    ['APPLICATIONS'],
    { 'HTTPS-EXACT': { tcpPorts: [443], udpPorts: [] } },
    {
      WEB: { members: ['HTTPS-EXACT'] },
      APPLICATIONS: { members: ['WEB'] },
    },
  );
  assert.deepEqual([...resolved.tcp], [443]);
  assert.equal(resolved.udp.size, 0);
  assert.equal(resolved.unresolvable, false);
});

test('une deny précédente bloque la génération et une accept large la rend conditionnelle', () => {
  const policy = {
    srcHosts: ['10.0.0.10'],
    dstHosts: ['10.0.1.20'],
  };
  const denied = buildPolicyOrderIssues([policy], {
    '10.0.0.10|10.0.1.20': { verdict: 'blocked', broad: false },
  });
  assert.equal(denied[0].level, 'error');
  assert.equal(denied[0].code, 'ORDER_BLOCKED_BY_EXISTING_DENY');

  const broad = buildPolicyOrderIssues([policy], {
    '10.0.0.10|10.0.1.20': { verdict: 'allowed', broad: true },
  });
  assert.equal(broad[0].level, 'warn');
  assert.equal(broad[0].code, 'ORDER_SHADOWED_BY_BROAD_ACCEPT');
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
  assert.equal(preflightValidation([policy], config, flows).certification.level, 'exact');

  const phantom = {
    ...policy,
    dstTarget: '10.0.1.21/32',
    dstHosts: ['10.0.1.21'],
  };
  const rejected = preflightValidation([phantom], config, flows);
  assert.equal(rejected.ok, false);
  assert.ok(rejected.issues.some(issue => /aucun flux accepté|non observé/.test(issue.msg)));
});

test('les profils réseau sont explicitement classés comme généralisation', () => {
  const config = {
    addresses: {}, addressGroups: {}, zones: {},
    interfaces: { lan: {}, servers: {} },
  };
  const policy = {
    srcintf: 'lan',
    dstintf: 'servers',
    srcSubnet: '10.0.0.0/24',
    dstTarget: '10.0.1.0/24',
    srcHosts: ['10.0.0.10'],
    dstHosts: ['10.0.1.20'],
    services: ['HTTPS'],
    serviceTuples: [{ proto: '6', port: '443', service: 'HTTPS' }],
    _segmentationPlan: { source: 'network', destination: 'network', services: 'grouped' },
    action: 'accept',
    log: 'all',
    analysis: {
      srcAddr: { found: false, name: 'SRC' },
      dstAddr: { found: false, name: 'DST' },
      srcIface: 'lan',
      dstIface: 'servers',
      services: [{ label: 'HTTPS', name: 'HTTPS', found: true }],
    },
  };
  const result = preflightValidation([policy], config, [aggregate()]);
  assert.equal(result.ok, true);
  assert.equal(result.certification.level, 'generalized');
  assert.ok(result.issues.some(issue => issue.code === 'GENERALIZED_SCOPE'));
});

test('les collisions d’objets générés sont refusées au lieu de produire une CLI incohérente', () => {
  const first = wanPolicy({
    srcAddrName: 'SRC-A',
    dstTarget: '8.8.8.8',
  });
  const second = wanPolicy({
    srcAddrName: 'SRC-B',
    dstTarget: '1.1.1.1',
  });
  assert.throws(
    () => generateConfig([first, second]),
    /Collision d'adresses/,
  );

  const badCidr = wanPolicy({
    srcSubnet: '999.0.0.0/24',
    analysis: {
      srcAddr: { found: false, cidr: '999.0.0.0/24' },
      dstAddr: { found: false, cidr: '8.8.8.8/32' },
      services: [{ label: 'HTTPS', found: true, name: 'HTTPS' }],
    },
  });
  assert.throws(() => generateConfig([badCidr]), /IPv4 invalide/);
});

test('un objet plage plus large ne remplace jamais un hôte /32 exact', () => {
  const config = parseFortiConfig(`
config firewall address
    edit "SERVER-RANGE"
        set type iprange
        set start-ip 10.0.1.10
        set end-ip 10.0.1.99
    next
    edit "ONE-HOST-RANGE"
        set type iprange
        set start-ip 10.0.2.10
        set end-ip 10.0.2.10
    next
end
`);
  const broad = findAddress('10.0.1.20/32', config.addresses);
  assert.equal(broad.found, false);
  assert.deepEqual(broad.broaderMatches.map(match => match.name), ['SERVER-RANGE']);
  assert.equal(findAddress('10.0.2.10/32', config.addresses).found, true);
});

test('le preflight interdit srcaddr all et les services globaux sur une règle accept', () => {
  const config = {
    addresses: {}, addressGroups: {},
    interfaces: { lan: {}, servers: {} },
    zones: {},
  };
  const policy = {
    srcintf: 'lan',
    dstintf: 'servers',
    action: 'accept',
    analysis: {
      srcAddr: { found: true, name: 'all' },
      dstAddr: { found: true, name: 'DST' },
      services: [{ found: true, name: 'ALL', label: 'ALL' }],
    },
  };
  const result = preflightValidation([policy], config);
  assert.equal(result.ok, false);
  assert.ok(result.issues.some(issue => /srcaddr=all/.test(issue.msg)));
  assert.ok(result.issues.some(issue => /service global interdit/.test(issue.msg)));
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
  assert.ok(serviceLines.every(line => /"FF_SVC_/.test(line)));
  assert.match(cli, /set tcp-portrange 443/);
  assert.match(cli, /set udp-portrange 53/);
});


test('l’analyse expose les choix d’adresse simples sans choisir implicitement un subnet calculé', () => {
  const policy = {
    srcSubnet: '10.0.0.0/24',
    srcHosts: ['10.0.0.10', '10.0.0.20'],
    flowSrcintf: 'lan',
    dstTarget: '10.1.1.0/24',
    dstHosts: ['10.1.1.10', '10.1.1.20'],
    dstType: 'private',
    services: ['HTTPS'],
    ports: [443],
    protos: ['TCP'],
    serviceTuples: [{ proto: '6', port: '443', service: 'HTTPS', sessions: 1 }],
  };
  const fortiConfig = {
    addresses: {
      USERS_WIDE: { name: 'USERS_WIDE', cidr: '10.0.0.0/16' },
    },
    customServices: {},
    interfaces: {
      lan: { name: 'lan', cidr: '10.0.0.1/24' },
      servers: { name: 'servers', cidr: '10.1.1.1/24' },
    },
    zones: {},
    fullRoutes: [],
    staticRoutes: [],
    sdwanEnabled: false,
    sdwanMembers: [],
  };

  const analyzed = analyzePolicies([policy], fortiConfig)[0];
  assert.equal(analyzed.analysis.srcAddr.found, true);
  assert.equal(analyzed.analysis.srcAddr.name, 'USERS_WIDE');
  assert.equal(analyzed.analysis.srcAddr.cidr, '10.0.0.0/16');
  assert.deepEqual(analyzed.analysis.addressChoices.source.existingObjects, [{
    name: 'USERS_WIDE', cidr: '10.0.0.0/16', unobservedIpCount: 65534,
  }]);
  assert.equal(analyzed.analysis.addressChoices.destination.existingObjects.length, 0);
  assert.equal(analyzed.analysis.addressChoices.destination.calculatedSubnet.cidr, '10.1.1.0/27');
  assert.equal(analyzed.analysis.addressChoices.destination.calculatedSubnet.unobservedIpCount, 30);
});

test('le preflight revalide les choix d’adresse stateless et refuse toute dérive', () => {
  const config = {
    addresses: { USERS: { name: 'USERS', cidr: '10.0.0.0/24' } },
    addressGroups: {},
    interfaces: { lan: {}, servers: {} },
    zones: {},
  };
  const base = {
    srcintf: 'lan',
    dstintf: 'servers',
    srcSubnet: '10.0.0.0/24',
    srcHosts: ['10.0.0.10'],
    dstTarget: '10.0.1.0/24',
    dstHosts: ['10.0.1.20'],
    dstType: 'private',
    addressSelections: {
      source: { mode: 'existing-object', objectName: 'USERS', confirmed: true },
      destination: { mode: 'hosts', ips: ['10.0.1.20'], confirmed: true },
    },
    action: 'accept',
    analysis: {
      srcAddr: { found: false, cidr: '10.0.0.0/24' },
      dstAddr: { found: false, cidr: '10.0.1.0/24' },
      srcIface: 'lan',
      dstIface: 'servers',
      services: [{ label: 'HTTPS', name: 'HTTPS', found: true }],
    },
  };

  assert.equal(preflightValidation([base], config).ok, true);

  const stale = preflightValidation([{
    ...base,
    addressSelections: {
      ...base.addressSelections,
      source: { mode: 'existing-object', objectName: 'REMOVED', confirmed: true },
    },
  }], config);
  assert.equal(stale.ok, false);
  assert.ok(stale.issues.some(issue => issue.code === 'ADDRESS_SELECTION_INVALID'));

  const excluded = preflightValidation([{
    ...base,
    addressSelections: {
      ...base.addressSelections,
      destination: { mode: 'subnet', cidr: '10.0.1.0/28', confirmed: true },
    },
  }], config);
  assert.equal(excluded.ok, false);
  assert.ok(excluded.issues.some(issue => /ne contient pas/i.test(issue.msg)));

  const unconfirmed = preflightValidation([{
    ...base,
    addressSelections: {
      ...base.addressSelections,
      source: { mode: 'existing-object', objectName: 'USERS', confirmed: false },
    },
  }], config);
  assert.equal(unconfirmed.ok, false);
  assert.ok(unconfirmed.issues.some(issue => /confirmation/i.test(issue.msg)));
});


test('applique les sélections d’adresse locales sans modifier la configuration de session', () => {
  const policy = {
    srcSubnet: '10.0.0.0/24',
    srcHosts: ['10.0.0.10'],
    dstTarget: '10.0.1.0/24',
    dstHosts: ['10.0.1.20'],
    dstType: 'private',
    flowSrcintf: 'lan',
    services: ['HTTPS'],
    ports: [443],
    protos: ['TCP'],
    serviceTuples: [{ proto: '6', port: '443', service: 'HTTPS', sessions: 1 }],
  };
  const config = {
    addresses: { USERS: { name: 'USERS', cidr: '10.0.0.0/24' } },
    customServices: {},
    interfaces: { lan: { cidr: '10.0.0.1/24' }, servers: { cidr: '10.0.1.1/24' } },
    zones: {}, fullRoutes: [], staticRoutes: [], sdwanEnabled: false, sdwanMembers: [],
  };
  const analyzed = analyzePolicies([policy], config);
  const selected = [{
    ...analyzed[0],
    addressSelections: {
      source: { mode: 'existing-object', objectName: 'USERS', confirmed: true },
      destination: { mode: 'subnet', cidr: '10.0.1.0/27', confirmed: true },
    },
  }];
  const applied = applyPolicyAddressSelections(analyzed, selected)[0];
  assert.equal(applied.analysis.srcAddr.name, 'USERS');
  assert.equal(applied.analysis.srcAddr.found, true);
  assert.equal(applied._dstCidrOverride, '10.0.1.0/27');
  assert.equal(applied._use32Dst, false);
});

test('applique aussi les sélections d’adresse aux policies Policy Engine V2', () => {
  const policy = {
    id: 'P-V2',
    _policyEngineV2: { profile: 'recommended', safeExact: true },
    srcSubnet: '10.0.0.10/32',
    srcHosts: ['10.0.0.10'],
    dstTarget: '10.0.1.20/32',
    dstHosts: ['10.0.1.20'],
    analysis: {
      addressChoices: {
        source: {
          existingObjects: [{ name: 'USERS', cidr: '10.0.0.0/24', unobservedIpCount: 255 }],
        },
      },
      srcAddr: { found: false, cidr: '10.0.0.10/32' },
      dstAddr: { found: false, cidr: '10.0.1.20/32' },
      services: [],
    },
  };
  const selected = [{
    ...policy,
    addressSelections: {
      source: { mode: 'existing-object', objectName: 'USERS', confirmed: true },
    },
  }];
  const applied = applyPolicyAddressSelections([policy], selected)[0];
  assert.equal(applied.analysis.srcAddr.name, 'USERS');
  assert.equal(applied.analysis.srcAddr.cidr, '10.0.0.0/24');
  assert.equal(applied._srcMode, 'subnet');
  assert.equal(applied._segmentationPlan.source, 'network');
  assert.equal(applied._policyEngineV2.safeExact, false);
});


test('les données non interprétables bloquent le CLI tandis que les échecs connus restent informatifs', () => {
  const sessionData = {
    meta: { skipReasons: { ipv6: 3 } },
    stats: { unknownSessions: 7, failedSessions: 11 },
  };
  const unsafe = getCaptureDeploymentBlockers(sessionData);
  assert.equal(unsafe.blocked, true);
  assert.deepEqual(unsafe.blockedReasons, ['ipv6_unsupported', 'unknown_actions']);
  assert.equal(unsafe.failedConnectionSessions, 11);

  const failedOnly = getCaptureDeploymentBlockers({
    stats: { failedSessions: 11 },
  });
  assert.equal(failedOnly.hasExcludedTraffic, true);
  assert.equal(failedOnly.blocked, false);

  const clean = getCaptureDeploymentBlockers({});
  assert.equal(clean.hasExcludedTraffic, false);
  assert.equal(clean.blocked, false);

  const incomplete = getCaptureDeploymentBlockers({
    meta: {
      possibleFazDownloadLimit: 1000000,
      dedupe: { duplicateRecords: 12, saturated: false },
    },
    stats: {
      captureSpanDays: 30,
      captureActiveDays: 5,
      captureCoverageRatio: 5 / 30,
    },
  });
  assert.equal(incomplete.blocked, false);
  assert.equal(incomplete.evidenceLimited, true);
  assert.deepEqual(
    incomplete.certificationWarnings.sort(),
    ['capture_calendar_gaps', 'possible_faz_download_limit'],
  );
  assert.equal(incomplete.duplicateSessionRecords, 12);

  const legacy = getCaptureDeploymentBlockers({
    flows: [{ ...aggregate(), deploymentEligible: undefined, count: 4 }],
    stats: {},
  });
  assert.equal(legacy.nonDeployableSessions, 4);
  assert.equal(legacy.blocked, true);
  assert.ok(legacy.blockedReasons.includes('unproven_forward_flows'));
});
