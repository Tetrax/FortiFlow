'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  parseFortiConfig,
  preserveDestinationServiceAffinity,
  analyzePolicies,
  applyPolicyUserDecisions,
  validatePolicyDecisionShapes,
  generateConfig,
} = require('../lib/forticonfig');

function service(label, key) {
  const [proto, port] = key.split('/');
  return {
    label,
    name: label,
    found: true,
    source: 'custom',
    isNamed: true,
    proto,
    port: Number(port),
    reuseKeys: [key],
  };
}

function origin(srcSubnet, dstTarget, services) {
  return { srcSubnet, dstTarget, analysis: { services } };
}

function mergedPolicy(origins) {
  const srcSubnets = [...new Set(origins.map(item => item.srcSubnet))].sort();
  const dstTargets = [...new Set(origins.map(item => item.dstTarget))].sort();
  const byKey = new Map();
  for (const item of origins) {
    for (const svc of item.analysis.services) byKey.set(svc.reuseKeys[0], svc);
  }
  const services = [...byKey.values()].sort((a, b) => a.reuseKeys[0].localeCompare(b.reuseKeys[0]));
  return {
    srcSubnet: srcSubnets[0],
    srcSubnets,
    dstTarget: dstTargets[0],
    dstTargets,
    dstType: 'private',
    _multiSrcSubnets: srcSubnets.map(subnet => ({ subnet, hosts: [], useSubnet: true, addrName: subnet, addrFound: true })),
    _multiDstSubnets: dstTargets.map(subnet => ({ subnet, hosts: [], useSubnet: true, addrName: subnet, addrFound: true })),
    analysis: { services },
    services: services.map(svc => svc.label),
    ports: services.map(svc => svc.port),
    protos: [...new Set(services.map(svc => svc.proto))],
    _mergedFrom: origins,
  };
}

function expandedTuples(policies) {
  const tuples = new Set();
  for (const policy of policies) {
    const sources = policy._multiSrcSubnets?.map(item => item.subnet)
      || policy.srcSubnets || [policy.srcSubnet];
    const destinations = policy._multiDstSubnets?.map(item => item.subnet)
      || policy.dstTargets || [policy.dstTarget];
    for (const source of sources) {
      for (const destination of destinations) {
        for (const svc of (policy.analysis?.services || [])) {
          for (const key of (svc.reuseKeys || [])) tuples.add(`${source}|${destination}|${key}`);
        }
      }
    }
  }
  return [...tuples].sort();
}

function observedTuples(origins) {
  return origins.flatMap(item => item.analysis.services.flatMap(svc =>
    svc.reuseKeys.map(key => `${item.srcSubnet}|${item.dstTarget}|${key}`))).sort();
}

function normalizedPolicies(policies) {
  return policies.map(policy => ({
    sources: [...(policy.srcSubnets || [policy.srcSubnet])],
    destinations: [...(policy.dstTargets || [policy.dstTarget])],
    services: (policy.analysis?.services || []).flatMap(svc => svc.reuseKeys || []).sort(),
  }));
}

test('FF2-02 ne crée aucun tuple cartésien entre sources destinations et services', () => {
  const origins = [
    origin('A', 'X', [service('HTTPS', 'TCP/443')]),
    origin('B', 'Y', [service('SSH', 'TCP/22')]),
  ];

  const result = preserveDestinationServiceAffinity([mergedPolicy(origins)]);

  assert.deepEqual(expandedTuples(result), observedTuples(origins));
  assert.equal(result.length, 2);
});

test('FF2-02 factorise un service commun et conserve le service résiduel', () => {
  const dns = service('DNS', 'UDP/53');
  const https = service('HTTPS', 'TCP/443');
  const origins = [
    origin('A', 'X', [dns, https]),
    origin('B', 'X', [dns]),
  ];

  const result = preserveDestinationServiceAffinity([mergedPolicy(origins)]);

  assert.deepEqual(expandedTuples(result), observedTuples(origins));
  assert.deepEqual(result.map(policy => ({
    sources: policy.srcSubnets,
    destinations: policy.dstTargets,
    services: policy.analysis.services.map(svc => svc.label),
  })), [
    { sources: ['A', 'B'], destinations: ['X'], services: ['DNS'] },
    { sources: ['A'], destinations: ['X'], services: ['HTTPS'] },
  ]);
});

test('FF2-02 sépare les services différents vers une destination commune', () => {
  const origins = [
    origin('A', 'X', [service('HTTPS', 'TCP/443')]),
    origin('B', 'X', [service('SSH', 'TCP/22')]),
  ];
  const result = preserveDestinationServiceAffinity([mergedPolicy(origins)]);
  assert.deepEqual(expandedTuples(result), observedTuples(origins));
  assert.equal(result.length, 2);
});

test('FF2-02 sépare les destinations et services différents d’une source commune', () => {
  const origins = [
    origin('A', 'X', [service('HTTPS', 'TCP/443')]),
    origin('A', 'Y', [service('SSH', 'TCP/22')]),
  ];
  const result = preserveDestinationServiceAffinity([mergedPolicy(origins)]);
  assert.deepEqual(expandedTuples(result), observedTuples(origins));
  assert.equal(result.length, 2);
});

test('FF2-02 conserve exactement les chevauchements partiels', () => {
  const dns = service('DNS', 'UDP/53');
  const origins = [
    origin('A', 'X', [dns, service('HTTPS', 'TCP/443')]),
    origin('A', 'Y', [dns]),
    origin('B', 'X', [dns]),
    origin('B', 'Y', [service('SSH', 'TCP/22')]),
  ];
  const result = preserveDestinationServiceAffinity([mergedPolicy(origins)]);
  assert.deepEqual(expandedTuples(result), observedTuples(origins));
  assert.deepEqual(normalizedPolicies(result), [
    { sources: ['A', 'B'], destinations: ['X'], services: ['UDP/53'] },
    { sources: ['A'], destinations: ['Y'], services: ['UDP/53'] },
    { sources: ['A'], destinations: ['X'], services: ['TCP/443'] },
    { sources: ['B'], destinations: ['Y'], services: ['TCP/22'] },
  ]);
});

test('FF2-02 produit le même résultat quel que soit l’ordre des logs', () => {
  const dns = service('DNS', 'UDP/53');
  const origins = [
    origin('A', 'X', [dns, service('HTTPS', 'TCP/443')]),
    origin('A', 'Y', [dns]),
    origin('B', 'X', [dns]),
    origin('B', 'Y', [service('SSH', 'TCP/22')]),
  ];
  const direct = preserveDestinationServiceAffinity([mergedPolicy(origins)]);
  const shuffled = preserveDestinationServiceAffinity([mergedPolicy([origins[3], origins[1], origins[0], origins[2]])]);
  assert.deepEqual(normalizedPolicies(shuffled), normalizedPolicies(direct));
  assert.deepEqual(
    shuffled.map(policy => policy._mergedFrom.map(item => [item.srcSubnet, item.dstTarget])),
    direct.map(policy => policy._mergedFrom.map(item => [item.srcSubnet, item.dstTarget])),
  );
});

test('FF2-02 préserve une destination Internet all explicitement retenue', () => {
  const origins = [
    origin('A', '203.0.113.10', [service('HTTPS', 'TCP/443')]),
    origin('A', '198.51.100.20', [service('HTTPS', 'TCP/443')]),
  ];
  const policy = { ...mergedPolicy(origins), dstTarget: 'all', dstType: 'public', _dstUseAll: true };
  const result = preserveDestinationServiceAffinity([policy]);
  assert.equal(result.length, 1);
  assert.equal(result[0], policy);
});

test('FF2-02 génère une CLI sans permissions croisées', () => {
  const origins = [
    origin('10.0.0.0/24', '10.0.10.0/24', [service('SVC-HTTPS', 'TCP/443')]),
    origin('10.0.1.0/24', '10.0.20.0/24', [service('SVC-SSH', 'TCP/22')]),
  ];
  const policies = preserveDestinationServiceAffinity([mergedPolicy(origins)]);
  const cli = generateConfig(policies, { addresses: {}, addressGroups: {}, zones: {} });
  const blocks = [...cli.matchAll(/\n    edit 0([\s\S]*?)\n    next/g)].map(match => match[1]);

  assert.equal(blocks.length, 2);
  assert.ok(blocks.some(block => block.includes('set srcaddr "10.0.0.0/24"')
    && block.includes('set dstaddr "10.0.10.0/24"') && block.includes('set service "SVC-HTTPS"')));
  assert.ok(blocks.some(block => block.includes('set srcaddr "10.0.1.0/24"')
    && block.includes('set dstaddr "10.0.20.0/24"') && block.includes('set service "SVC-SSH"')));
  assert.ok(blocks.every(block => !(block.includes('"10.0.0.0/24"') && block.includes('"10.0.20.0/24"'))));
  assert.ok(blocks.every(block => !(block.includes('"10.0.1.0/24"') && block.includes('"10.0.10.0/24"'))));
});

test('FF2-02 le backend refuse un rectangle forgé non couvert par les flux', () => {
  const dns = service('SVC-DNS', 'UDP/53');
  const forgedOrigins = [
    origin('10.0.0.0/24', '10.0.10.0/24', [dns]),
    origin('10.0.0.0/24', '10.0.20.0/24', [dns]),
    origin('10.0.1.0/24', '10.0.10.0/24', [dns]),
    origin('10.0.1.0/24', '10.0.20.0/24', [dns]),
  ];
  const submitted = preserveDestinationServiceAffinity([mergedPolicy(forgedOrigins)]);
  submitted[0].srcintf = 'LAN';
  submitted[0].dstintf = 'DMZ';
  const config = parseFortiConfig(`
config firewall address
    edit "10.0.0.0/24"
        set subnet 10.0.0.0 255.255.255.0
    next
    edit "10.0.1.0/24"
        set subnet 10.0.1.0 255.255.255.0
    next
    edit "10.0.10.0/24"
        set subnet 10.0.10.0 255.255.255.0
    next
    edit "10.0.20.0/24"
        set subnet 10.0.20.0 255.255.255.0
    next
end
config system interface
    edit "LAN"
        set ip 10.0.0.1 255.255.0.0
    next
    edit "DMZ"
        set ip 10.0.10.1 255.255.0.0
    next
end
config firewall service custom
    edit "SVC-DNS"
        set protocol UDP
        set udp-portrange 53
    next
end
`);
  const authoritative = analyzePolicies(structuredClone(submitted), config);
  const flows = [
    { srcip: '10.0.0.10', dstip: '10.0.10.10', srcSubnet: '10.0.0.0/24', dstSubnet: '10.0.10.0/24', dstType: 'private', srcintf: 'LAN', dstintf: 'DMZ', service: 'SVC-DNS', dstport: '53', proto: '17', protoName: 'UDP', action: 'accept' },
    { srcip: '10.0.1.10', dstip: '10.0.20.10', srcSubnet: '10.0.1.0/24', dstSubnet: '10.0.20.0/24', dstType: 'private', srcintf: 'LAN', dstintf: 'DMZ', service: 'SVC-DNS', dstport: '53', proto: '17', protoName: 'UDP', action: 'accept' },
  ];

  const honestSubmitted = preserveDestinationServiceAffinity([mergedPolicy([
    forgedOrigins[0], forgedOrigins[3],
  ])]);
  for (const policy of honestSubmitted) { policy.srcintf = 'LAN'; policy.dstintf = 'DMZ'; }
  const honestAuthoritative = analyzePolicies(structuredClone(honestSubmitted), config);
  const honestDecision = applyPolicyUserDecisions(honestAuthoritative, honestSubmitted, config, flows);
  assert.equal(honestDecision.ok, true, JSON.stringify(honestDecision.issues));

  const decision = applyPolicyUserDecisions(authoritative, submitted, config, flows);
  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'POLICY_AFFINITY_UNPROVEN'), JSON.stringify(decision.issues));
});

test('FF2-02 conserve les hôtes lors d’une partition singleton', () => {
  const origins = [
    origin('10.0.0.0/24', '10.0.10.0/24', [service('SVC-HTTPS', 'TCP/443')]),
    origin('10.0.1.0/24', '10.0.11.0/24', [service('SVC-SSH', 'TCP/22')]),
  ];
  const merged = mergedPolicy(origins);
  merged._multiSrcSubnets = [
    { subnet: '10.0.0.0/24', hosts: ['10.0.0.10'], useSubnet: false, addrName: '', addrFound: false },
    { subnet: '10.0.1.0/24', hosts: ['10.0.1.10'], useSubnet: false, addrName: '', addrFound: false },
  ];
  merged._multiDstSubnets = [
    { subnet: '10.0.10.0/24', hosts: ['10.0.10.10'], useSubnet: false, addrName: '', addrFound: false },
    { subnet: '10.0.11.0/24', hosts: ['10.0.11.10'], useSubnet: false, addrName: '', addrFound: false },
  ];

  const result = preserveDestinationServiceAffinity([merged]);

  assert.deepEqual(result.map(policy => ({
    srcHosts: policy.srcHosts,
    dstHosts: policy.dstHosts,
    use32Src: policy._use32Src,
    use32Dst: policy._use32Dst,
    multiSrc: policy._multiSrcSubnets,
    multiDst: policy._multiDstSubnets,
  })), [
    { srcHosts: ['10.0.0.10'], dstHosts: ['10.0.10.10'], use32Src: true, use32Dst: true, multiSrc: undefined, multiDst: undefined },
    { srcHosts: ['10.0.1.10'], dstHosts: ['10.0.11.10'], use32Src: true, use32Dst: true, multiSrc: undefined, multiDst: undefined },
  ]);

  const cli = generateConfig(result, { addresses: {}, addressGroups: {}, zones: {} });
  const blocks = [...cli.split('config firewall policy')[1].matchAll(/\n    edit 0([\s\S]*?)\n    next/g)].map(match => match[1]);
  assert.ok(blocks.some(block => block.includes('set srcaddr "FF_HOST_10_0_0_10"')
    && block.includes('set dstaddr "FF_HOST_10_0_10_10"')));
  assert.ok(blocks.some(block => block.includes('set srcaddr "FF_HOST_10_0_1_10"')
    && block.includes('set dstaddr "FF_HOST_10_0_11_10"')));
  assert.ok(blocks.every(block => !/set (?:src|dst)addr "10\.0\./.test(block)));
});

test('FF2-02 refuse un scope host vide', () => {
  const malformed = mergedPolicy([
    origin('A', 'X', [service('DNS', 'UDP/53')]),
    origin('B', 'X', [service('DNS', 'UDP/53')]),
  ]);
  malformed._multiSrcSubnets = [
    { subnet: 'A', hosts: [], useSubnet: false, addrName: '', addrFound: false },
  ];
  const shape = validatePolicyDecisionShapes([malformed]);
  assert.equal(shape.ok, false);
  assert.ok(shape.issues.some(issue => issue.code === 'SCOPE_DECISION_INVALID'));
});

test('FF2-02 refuse les scopes dupliqués qui mélangent subnet et hôtes', () => {
  for (const side of ['src', 'dst']) {
    const malformed = mergedPolicy([
      origin('10.0.0.0/24', '10.0.10.0/24', [service('DNS', 'UDP/53')]),
      origin('10.0.1.0/24', '10.0.11.0/24', [service('DNS', 'UDP/53')]),
    ]);
    const field = side === 'src' ? '_multiSrcSubnets' : '_multiDstSubnets';
    const flag = side === 'src' ? '_use32Src' : '_use32Dst';
    const mode = side === 'src' ? '_srcMode' : '_dstMode';
    const subnet = side === 'src' ? '10.0.0.0/24' : '10.0.10.0/24';
    const host = side === 'src' ? '10.0.0.10' : '10.0.10.10';
    malformed[field] = [
      { subnet, hosts: [], useSubnet: true, addrName: 'NET', addrFound: true },
      { subnet, hosts: [host], useSubnet: false, addrName: '', addrFound: false },
    ];
    malformed[flag] = true;
    malformed[mode] = 'hosts';
    const shape = validatePolicyDecisionShapes([malformed]);
    assert.equal(shape.ok, false, side);
    assert.ok(shape.issues.some(issue => issue.code === 'SCOPE_DECISION_INVALID'), side);
  }
});

test('FF2-02 refuse les conteneurs de scope explicites vides ou nuls', () => {
  const base = mergedPolicy([
    origin('A', 'X', [service('DNS', 'UDP/53')]),
    origin('B', 'Y', [service('DNS', 'UDP/53')]),
  ]);
  const forged = [
    { _multiSrcSubnets: [] },
    { _multiDstSubnets: [] },
    { srcSubnets: [] },
    { dstTargets: [] },
    { srcSubnets: null },
    { dstTargets: null },
    { _use32Src: true, _srcMode: 'hosts', srcHosts: [] },
    { _use32Dst: true, _dstMode: 'hosts', dstHosts: [] },
  ];
  for (const override of forged) {
    const candidate = { ...structuredClone(base), ...override };
    const shape = validatePolicyDecisionShapes(preserveDestinationServiceAffinity([candidate]));
    assert.equal(shape.ok, false, JSON.stringify(override));
    assert.ok(shape.issues.some(issue => issue.code === 'SCOPE_DECISION_INVALID'));
  }
});

test('FF2-02 refuse toute provenance _mergedFrom malformée', () => {
  const base = mergedPolicy([
    origin('A', 'X', [service('DNS', 'UDP/53')]),
    origin('B', 'Y', [service('DNS', 'UDP/53')]),
  ]);
  for (const value of [{ forged: true }, [], [
    { srcSubnet: 'A', dstTarget: 'X', analysis: null },
  ], [
    { srcSubnet: 42, dstTarget: 'X', analysis: { services: [service('DNS', 'UDP/53')] } },
  ], [
    { srcSubnet: 'A', dstTarget: ['X'], analysis: { services: [service('DNS', 'UDP/53')] } },
  ], [
    { srcSubnet: 'A', dstTarget: 'X', analysis: { services: [{ label: {}, reuseKeys: ['UDP/53'] }] } },
  ], [
    { srcSubnet: 'A', dstTarget: 'X', action: 'accept', analysis: { services: [service('DNS', 'UDP/53')] } },
    { srcSubnet: 'B', dstTarget: 'Y', action: 'deny', analysis: { services: [service('DNS', 'UDP/53')] } },
  ]]) {
    const candidate = { ...structuredClone(base), _mergedFrom: value };
    const preserved = preserveDestinationServiceAffinity([candidate]);
    const shape = validatePolicyDecisionShapes(preserved);
    assert.equal(shape.ok, false, JSON.stringify(value));
  }
});

test('FF2-02 une policy Internet all conserve l’affinité source-service', () => {
  const https = service('SVC-HTTPS', 'TCP/443');
  const ssh = service('SVC-SSH', 'TCP/22');
  const policy = {
    srcSubnet: '10.0.0.0/24',
    srcSubnets: ['10.0.0.0/24', '10.0.1.0/24'],
    _multiSrcSubnets: [
      { subnet: '10.0.0.0/24', hosts: [], useSubnet: true, addrName: 'SRC-A', addrFound: true },
      { subnet: '10.0.1.0/24', hosts: [], useSubnet: true, addrName: 'SRC-B', addrFound: true },
    ],
    dstTarget: 'all', dstTargets: ['all'], dstType: 'public', _dstUseAll: true, _isWan: true,
    srcintf: 'LAN', dstintf: 'WAN', services: ['SVC-HTTPS', 'SVC-SSH'], ports: [22, 443], protos: ['TCP'],
    analysis: {
      srcAddr: { found: true, name: 'SRC-A', cidr: '10.0.0.0/24' },
      dstAddr: { found: true, name: 'all', cidr: 'all' },
      srcIface: 'LAN', dstIface: 'WAN', services: [https, ssh],
    },
  };
  const config = parseFortiConfig(`
config firewall address
    edit "SRC-A"
        set subnet 10.0.0.0 255.255.255.0
    next
    edit "SRC-B"
        set subnet 10.0.1.0 255.255.255.0
    next
end
config system interface
    edit "LAN"
        set ip 10.0.0.1 255.255.254.0
    next
    edit "WAN"
        set ip 192.0.2.1 255.255.255.0
        set role wan
    next
end
config firewall service custom
    edit "SVC-HTTPS"
        set protocol TCP
        set tcp-portrange 443
    next
    edit "SVC-SSH"
        set protocol TCP
        set tcp-portrange 22
    next
end
`);
  const flows = [
    { srcip: '10.0.0.10', dstip: '203.0.113.10', srcSubnet: '10.0.0.0/24', dstSubnet: null, dstType: 'public', srcintf: 'LAN', dstintf: 'WAN', service: 'SVC-HTTPS', dstport: '443', proto: '6', protoName: 'TCP', action: 'accept' },
    { srcip: '10.0.1.10', dstip: '198.51.100.20', srcSubnet: '10.0.1.0/24', dstSubnet: null, dstType: 'public', srcintf: 'LAN', dstintf: 'WAN', service: 'SVC-SSH', dstport: '22', proto: '6', protoName: 'TCP', action: 'accept' },
  ];
  const decision = applyPolicyUserDecisions([policy], [structuredClone(policy)], config, flows);
  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'POLICY_AFFINITY_UNPROVEN'), JSON.stringify(decision.issues));
});

test('FF2-02 refuse les scopes scalaires et hôtes mal typés', () => {
  const base = mergedPolicy([
    origin('A', 'X', [service('DNS', 'UDP/53')]),
    origin('B', 'Y', [service('DNS', 'UDP/53')]),
  ]);
  for (const override of [
    { srcSubnet: 42 }, { dstTarget: 42 }, { srcHosts: [42] }, { dstHosts: [42] },
    { _multiSrcSubnets: 'bad' }, { _multiDstSubnets: {} },
    { _multiSrcSubnets: [null] }, { _multiDstSubnets: [null] },
  ]) {
    const candidate = { ...structuredClone(base), ...override };
    assert.doesNotThrow(() => preserveDestinationServiceAffinity([candidate]));
    const shape = validatePolicyDecisionShapes(preserveDestinationServiceAffinity([candidate]));
    assert.equal(shape.ok, false, JSON.stringify(override));
  }
});

test('FF2-02 la CLI WAN singleton reste limitée à sa destination explicite', () => {
  const https = service('SVC-HTTPS', 'TCP/443');
  const policy = {
    srcSubnet: '10.0.0.0/24', dstTarget: '203.0.113.10', dstType: 'public', _isWan: true,
    srcintf: 'LAN', dstintf: 'WAN', services: ['SVC-HTTPS'], ports: [443], protos: ['TCP'],
    analysis: {
      srcAddr: { found: true, name: 'SRC-A', cidr: '10.0.0.0/24' },
      dstAddr: { found: false, suggestedName: 'DST-203-0-113-10', cidr: '203.0.113.10/32' },
      srcIface: 'LAN', dstIface: 'WAN', services: [https],
    },
  };
  const cli = generateConfig([policy], { addresses: {}, addressGroups: {}, zones: {} });
  const block = cli.split('config firewall policy')[1];
  assert.ok(!block.includes('set dstaddr "all"'));
  assert.ok(cli.includes('203.0.113.10'));
});

test('FF2-02 refuse all pour une destination privée', () => {
  const candidate = {
    ...mergedPolicy([origin('A', 'X', [service('DNS', 'UDP/53')])]),
    dstType: 'private', dstTarget: 'all', dstTargets: ['all'],
    _dstUseAll: true, _isMultiDst: true, _isWan: false,
  };
  const shape = validatePolicyDecisionShapes([candidate]);
  assert.equal(shape.ok, false);
});

test('FF2-02 borne la cardinalité du produit d’affinité', () => {
  const candidate = mergedPolicy([origin('A', 'X', [service('DNS', 'UDP/53')])]);
  candidate._multiSrcSubnets = Array.from({ length: 400 }, (_, index) => ({
    subnet: `10.${Math.floor(index / 256)}.${index % 256}.0/24`, hosts: [], useSubnet: true,
  }));
  candidate._multiDstSubnets = Array.from({ length: 400 }, (_, index) => ({
    subnet: `172.${Math.floor(index / 256)}.${index % 256}.0/24`, hosts: [], useSubnet: true,
  }));
  const shape = validatePolicyDecisionShapes([candidate]);
  assert.equal(shape.ok, false);
});

test('FF2-02 autorise un override deny sur des origines accept homogènes', () => {
  const candidate = mergedPolicy([
    { ...origin('A', 'X', [service('DNS', 'UDP/53')]), action: 'accept' },
    { ...origin('B', 'Y', [service('DNS', 'UDP/53')]), action: 'accept' },
  ]);
  candidate.action = 'deny';
  candidate._action = 'deny';
  assert.equal(validatePolicyDecisionShapes([candidate]).ok, true);
});

test('FF2-02 refuse null comme policy sans exception', () => {
  assert.doesNotThrow(() => preserveDestinationServiceAffinity([null]));
  assert.equal(validatePolicyDecisionShapes([null]).ok, false);
});

test('FF2-02 borne aussi les tableaux d’hôtes top-level', () => {
  const candidate = mergedPolicy([origin('A', 'X', [service('DNS', 'UDP/53')])]);
  candidate._multiSrcSubnets = undefined;
  candidate._multiDstSubnets = undefined;
  candidate._use32Src = true;
  candidate._use32Dst = true;
  candidate.srcHosts = Array(1001).fill('10.0.0.10');
  candidate.dstHosts = Array(1001).fill('10.0.1.10');
  assert.equal(validatePolicyDecisionShapes([candidate]).ok, false);
});

test('FF2-02 refuse analysis.services malformé sans exception', () => {
  for (const services of ['not-an-array', [null], [false], [{}], ['bad'],
    [{ label: '' }], [{ name: '' }], [{ label: ' ', name: ' ' }], Array(1001).fill({})]) {
    const candidate = mergedPolicy([origin('A', 'X', [service('DNS', 'UDP/53')])]);
    candidate.analysis.services = services;
    assert.doesNotThrow(() => preserveDestinationServiceAffinity([candidate]));
    assert.equal(validatePolicyDecisionShapes(preserveDestinationServiceAffinity([candidate])).ok, false);
  }
});

test('FF2-02 refuse les métadonnées CLI mal typées ou désalignées', () => {
  const base = mergedPolicy([origin('A', 'X', [service('DNS', 'UDP/53')])]);
  for (const override of [
    { policyName: {} },
    { _policyName: [] },
    { tags: 'x' },
    { tags: [null] },
    { srcAddrNames: ['EVIL-A', 'EVIL-B'] },
    { srcAddrNames: ['x'], _multiSrcSubnets: 'bad' },
    { srcAddrNames: ['x'], srcSubnets: 'bad' },
  ]) {
    let shape;
    assert.doesNotThrow(() => { shape = validatePolicyDecisionShapes([{ ...structuredClone(base), ...override }]); });
    assert.equal(shape.ok, false, JSON.stringify(override));
  }
});

test('FF2-02 borne la provenance avant recomposition', () => {
  const candidate = mergedPolicy([origin('A', 'X', [service('DNS', 'UDP/53')])]);
  candidate._mergedFrom = Array.from({ length: 1001 }, (_, index) => ({
    srcSubnet: `10.${Math.floor(index / 256)}.${index % 256}.0/24`,
    dstTarget: `172.${Math.floor(index / 256)}.${index % 256}.0/24`,
    analysis: { services: [service('DNS', 'UDP/53')] },
  }));
  assert.equal(validatePolicyDecisionShapes([candidate]).ok, false);
});

test('FF2-02 borne les cardinalités imbriquées avant expansion', () => {
  const candidate = mergedPolicy([origin('A', 'X', [service('DNS', 'UDP/53')])]);
  candidate._multiSrcSubnets = Array.from({ length: 101 }, (_, index) => ({
    subnet: `10.0.${index}.0/24`,
    hosts: Array.from({ length: 100 }, (__, host) => `10.0.${index}.${host + 1}`),
    useSubnet: false,
  }));
  assert.equal(validatePolicyDecisionShapes([candidate]).ok, false);
  assert.equal(validatePolicyDecisionShapes(preserveDestinationServiceAffinity([candidate])).ok, false);
});

test('FF2-02 borne les listes techniques top-level', () => {
  const candidate = mergedPolicy([origin('A', 'X', [service('DNS', 'UDP/53')])]);
  candidate.services = Array(1001).fill('DNS');
  assert.equal(validatePolicyDecisionShapes([candidate]).ok, false);
});

test('FF2-02 borne les tableaux techniques imbriqués des services', () => {
  const candidate = mergedPolicy([origin('A', 'X', [service('DNS', 'UDP/53')])]);
  candidate.analysis.services[0].reuseKeys = Array(1001).fill('UDP/53');
  assert.equal(validatePolicyDecisionShapes([candidate]).ok, false);

  const provenance = mergedPolicy([origin('A', 'X', [service('DNS', 'UDP/53')])]);
  provenance._mergedFrom[0].analysis.services = Array(1001).fill(service('DNS', 'UDP/53'));
  assert.equal(validatePolicyDecisionShapes([provenance]).ok, false);

  for (const override of [
    { reuseKeys: [42] },
    { ports: ['42'] },
    { tcpRanges: [{ bad: true }] },
    { compatibleMatches: [{ bad: true }] },
    { sourcePorts: Array(1001).fill(443) },
  ]) {
    const malformed = mergedPolicy([origin('A', 'X', [service('DNS', 'UDP/53')])]);
    Object.assign(malformed.analysis.services[0], override);
    assert.equal(validatePolicyDecisionShapes([malformed]).ok, false, JSON.stringify(override));
  }

  const validPort = mergedPolicy([origin('A', 'X', [service('DNS', 'UDP/53')])]);
  validPort.analysis.services[0].ports = [42];
  assert.equal(validatePolicyDecisionShapes([validPort]).ok, true);
});

test('FF2-02 refuse les alias de scopes dupliqués même avec des scopes multi', () => {
  const candidate = mergedPolicy([
    origin('A', 'X', [service('DNS', 'UDP/53')]),
    origin('B', 'Y', [service('DNS', 'UDP/53')]),
  ]);
  candidate.srcSubnets = ['A', 'A'];
  candidate.dstTargets = ['X', 'X'];
  assert.equal(validatePolicyDecisionShapes([candidate]).ok, false);
  assert.equal(validatePolicyDecisionShapes(preserveDestinationServiceAffinity([candidate])).ok, false);
});

test('FF2-02 refuse un all Internet dont les services varient par destination', () => {
  const candidate = mergedPolicy([
    origin('A', '203.0.113.10', [service('HTTPS', 'TCP/443')]),
    origin('A', '198.51.100.20', [service('SSH', 'TCP/22')]),
  ]);
  candidate.dstType = 'public';
  candidate.dstTarget = 'all';
  candidate.dstTargets = ['all'];
  candidate._multiDstSubnets = undefined;
  candidate._dstUseAll = true;
  candidate._isWan = true;
  assert.equal(validatePolicyDecisionShapes([candidate]).ok, false);
});
