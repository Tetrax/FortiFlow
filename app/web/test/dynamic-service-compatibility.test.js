'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  parseFortiConfig,
  findService,
  analyzePolicies,
  applyPolicyUserDecisions,
  generateConfig,
} = require('../lib/forticonfig');

function configWithServices(body) {
  return parseFortiConfig(`
config firewall service custom
${body}
end
`);
}

test('conserve les ranges FortiGate structurellement sans les développer', () => {
  const config = configWithServices(`
    edit "MS-RPC-DYNAMIC"
        set tcp-portrange 49152-65535
    next
  `);

  const service = config.customServices['MS-RPC-DYNAMIC'];
  assert.deepEqual(service.tcpRanges, [{ start: 49152, end: 65535 }]);
  assert.deepEqual(service.udpRanges, []);
  assert.deepEqual(service.tcpPorts, []);
  assert.equal(service._tcpSet.size, 0);
});

test('normalise les ranges inversés, multiples et suffixés par une plage source', () => {
  const config = configWithServices(`
    edit "MIXED-PORT-SPEC"
        set tcp-portrange 443 8000-8002 9000-8999 10000:20000-30000
        set udp-portrange 53 60000-65535
    next
  `);

  const service = config.customServices['MIXED-PORT-SPEC'];
  assert.deepEqual(service.tcpRanges, [
    { start: 443, end: 443 },
    { start: 8000, end: 8002 },
    { start: 8999, end: 9000 },
    { start: 10000, end: 10000 },
  ]);
  assert.deepEqual(service.udpRanges, [
    { start: 53, end: 53 },
    { start: 60000, end: 65535 },
  ]);
  assert.deepEqual(service.tcpPorts, [443, 10000]);
  assert.deepEqual(service.udpPorts, [53]);
});

test('distingue un service exact d’un service compatible plus large', () => {
  const config = configWithServices(`
    edit "MS-RPC-DYNAMIC"
        set tcp-portrange 49152-65535
    next
    edit "TCP-52980-EXACT"
        set tcp-portrange 52980
    next
  `);

  const result = findService(52980, 'TCP', config.customServices);
  assert.equal(result.found, true);
  assert.deepEqual(result.exactMatch, {
    name: 'TCP-52980-EXACT', source: 'custom', proto: 'TCP',
    portSpec: 'TCP/52980', coverageCount: 1, extraPortCount: 0,
  });
  assert.equal(result.compatibleMatch, undefined);
});

test('retourne un range couvrant le port comme suggestion compatible, jamais comme found', () => {
  const config = configWithServices(`
    edit "MS-RPC-DYNAMIC"
        set tcp-portrange 49152-65535
    next
  `);

  for (const port of [52980, 65000]) {
    const result = findService(port, 'TCP', config.customServices);
    assert.equal(result.found, false);
    assert.deepEqual(result.compatibleMatch, {
      name: 'MS-RPC-DYNAMIC', source: 'custom', proto: 'TCP',
      portSpec: 'TCP/49152-65535', coverageCount: 16384, extraPortCount: 16383,
    });
  }
});

test('ne propose jamais un range TCP pour un port UDP et classe l’absence comme missing', () => {
  const config = configWithServices(`
    edit "MS-RPC-DYNAMIC"
        set tcp-portrange 49152-65535
    next
  `);

  assert.deepEqual(findService(52980, 'UDP', config.customServices), { found: false });
  assert.deepEqual(findService(12345, 'TCP', config.customServices), { found: false });
});

test('analyse de façon identique un label TCP/port et un port brut', () => {
  const config = configWithServices(`
    edit "MS-RPC-DYNAMIC"
        set tcp-portrange 49152-65535
    next
  `);
  const base = {
    srcSubnet: '10.0.0.0/24', dstTarget: '10.0.1.0/24', dstType: 'private',
    ports: [52980], protos: ['TCP'], srcHosts: [], dstHosts: [],
  };

  const labeled = analyzePolicies([{ ...base, services: ['TCP/52980'] }], config)[0].analysis.services[0];
  const raw = analyzePolicies([{ ...base, services: [] }], config)[0].analysis.services[0];

  for (const item of [labeled, raw]) {
    assert.equal(item.found, false);
    assert.equal(item.compatibleMatch.name, 'MS-RPC-DYNAMIC');
    assert.equal(item.compatibleMatch.portSpec, 'TCP/49152-65535');
    assert.equal(item.compatibleMatch.extraPortCount, 16383);
  }
});

test('réutilise un service compatible uniquement après un choix explicite revalidé', () => {
  const config = configWithServices(`
    edit "MS-RPC-DYNAMIC"
        set tcp-portrange 49152-65535
    next
  `);
  const policy = {
    srcSubnet: '10.0.0.0/24', dstTarget: '10.0.1.0/24', dstType: 'private',
    services: ['TCP/52980'], ports: [52980], protos: ['TCP'], srcHosts: [], dstHosts: [],
    _serviceReuse: { 'TCP/52980': 'MS-RPC-DYNAMIC' },
  };

  const analyzed = analyzePolicies([policy], config)[0];
  const item = analyzed.analysis.services[0];
  assert.equal(item.found, true);
  assert.equal(item.name, 'MS-RPC-DYNAMIC');
  assert.equal(item.compatibilityAccepted, true);

  const cli = generateConfig([analyzed], {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.doesNotMatch(cli, /config firewall service custom/);
  assert.match(cli, /set service "MS-RPC-DYNAMIC"/);
});

test('ignore un choix compatible forgé ou devenu obsolète', () => {
  const config = configWithServices(`
    edit "MS-RPC-DYNAMIC"
        set tcp-portrange 49152-65535
    next
  `);
  const policy = {
    srcSubnet: '10.0.0.0/24', dstTarget: '10.0.1.0/24', dstType: 'private',
    services: ['TCP/52980'], ports: [52980], protos: ['TCP'], srcHosts: [], dstHosts: [],
    _serviceReuse: { 'TCP/52980': 'FORGED-SERVICE' },
  };

  const item = analyzePolicies([policy], config)[0].analysis.services[0];
  assert.equal(item.found, false);
  assert.equal(item.name, null);
  assert.equal(item.compatibilityAccepted, undefined);
});

test('la création spécifique conserve la génération CLI exacte existante', () => {
  const config = configWithServices(`
    edit "MS-RPC-DYNAMIC"
        set tcp-portrange 49152-65535
    next
  `);
  const policy = {
    srcSubnet: '10.0.0.0/24', dstTarget: '10.0.1.0/24', dstType: 'private',
    services: ['TCP/52980'], ports: [52980], protos: ['TCP'], srcHosts: [], dstHosts: [],
  };

  const analyzed = analyzePolicies([policy], config)[0];
  const cli = generateConfig([analyzed], {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.match(cli, /edit "FF_SVC_52980_TCP"/);
  assert.match(cli, /set tcp-portrange 52980/);
  assert.match(cli, /set service "FF_SVC_52980_TCP"/);
});

test('ne produit plus aucune suggestion dynamique automatique', () => {
  const config = configWithServices(`
    edit "MS-RPC-DYNAMIC"
        set tcp-portrange 49152-65535
    next
  `);
  const ports = [52121, 52134, 62966];
  const policy = {
    srcSubnet: '10.0.0.0/24', dstTarget: '10.0.1.0/24', dstType: 'private',
    services: ports.map(port => `TCP/${port}`), ports, protos: ['TCP'], srcHosts: [], dstHosts: [],
  };

  const analysis = analyzePolicies([policy], config)[0].analysis;
  assert.equal('dynamicServiceSuggestions' in analysis, false);
  assert.equal(analysis.services.length, 3);
  assert.ok(analysis.services.every(service => service.found === false));
  assert.ok(analysis.services.every(service =>
    service.compatibleMatches.some(match => match.name === 'MS-RPC-DYNAMIC')
  ));
});

test('réutilise un service compatible couvrant tous les ports sélectionnés sans créer de service', () => {
  const config = configWithServices(`
    edit "MS-RPC-DYNAMIC"
        set tcp-portrange 49152-65535
    next
  `);
  const ports = [52121, 52134, 62966];
  const policy = {
    srcSubnet: '10.0.0.0/24', dstTarget: '10.0.1.0/24', dstType: 'private',
    services: ports.map(port => `TCP/${port}`), ports, protos: ['TCP'], srcHosts: [], dstHosts: [],
    _serviceReuse: Object.fromEntries(ports.map(port => [`TCP/${port}`, 'MS-RPC-DYNAMIC'])),
  };

  const analyzed = analyzePolicies([policy], config)[0];
  assert.equal(analyzed.analysis.services.length, 1);
  assert.equal(analyzed.analysis.services[0].name, 'MS-RPC-DYNAMIC');
  assert.equal(analyzed.analysis.services[0].compatibilityAccepted, true);

  const cli = generateConfig([analyzed], {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.doesNotMatch(cli, /config firewall service custom/);
  assert.match(cli, /set service "MS-RPC-DYNAMIC"/);
});

test('propose un range compatible commun aux ports sélectionnés dans une policy multi-protocoles', () => {
  const config = parseFortiConfig(`
config firewall address
    edit "SRC"
        set subnet 10.0.0.0 255.255.255.0
    next
    edit "DST"
        set subnet 10.0.1.0 255.255.255.0
    next
end
config system interface
    edit "LAN"
        set ip 10.0.0.1 255.255.255.0
    next
    edit "DMZ"
        set ip 10.0.1.1 255.255.255.0
    next
end
config firewall service custom
    edit "DNS"
        set tcp-portrange 53
        set udp-portrange 53
    next
    edit "DCE-RPC-RANGE"
        set tcp-portrange 10000-65535
    next
end
  `);
  const ports = [52121, 52134, 62966];
  const policy = {
    srcSubnet: '10.0.0.0/24', dstTarget: '10.0.1.0/24', dstType: 'private',
    services: ['DNS', ...ports.map(port => `TCP/${port}`)],
    ports: [53, ...ports], protos: ['UDP', 'TCP'],
    srcHosts: ['10.0.0.10'], dstHosts: ['10.0.1.20'],
  };
  const flows = [
    { srcip: '10.0.0.10', dstip: '10.0.1.20', srcSubnet: '10.0.0.0/24', dstSubnet: '10.0.1.0/24', dstType: 'private', srcintf: 'LAN', dstintf: 'DMZ', service: 'DNS', dstport: '53', proto: '17', protoName: 'UDP', action: 'accept' },
    ...ports.map(port => ({
      srcip: '10.0.0.10', dstip: '10.0.1.20', srcSubnet: '10.0.0.0/24', dstSubnet: '10.0.1.0/24', dstType: 'private',
      srcintf: 'LAN', dstintf: 'DMZ', service: `TCP/${port}`, dstport: String(port), proto: '6', protoName: 'TCP', action: 'accept',
    })),
  ];

  const analyzed = analyzePolicies([policy], config, undefined, flows)[0];
  const selected = analyzed.analysis.services.filter(service => ports.includes(service.port));
  assert.equal(selected.length, 3);
  assert.ok(selected.every(service =>
    Array.isArray(service.compatibleMatches)
      && service.compatibleMatches.some(match => match.name === 'DCE-RPC-RANGE')
  ));
  const commonNames = selected[0].compatibleMatches.map(match => match.name)
    .filter(name => selected.slice(1).every(service =>
      service.compatibleMatches.some(match => match.name === name)));
  assert.deepEqual(commonNames, ['DCE-RPC-RANGE']);

  const mixedPort = 8530;
  const mixedPolicy = {
    ...policy,
    services: [...policy.services, `TCP/${mixedPort}`],
    ports: [...policy.ports, mixedPort],
  };
  const mixedFlows = [...flows, {
    srcip: '10.0.0.10', dstip: '10.0.1.20', srcSubnet: '10.0.0.0/24', dstSubnet: '10.0.1.0/24', dstType: 'private',
    srcintf: 'LAN', dstintf: 'DMZ', service: `TCP/${mixedPort}`, dstport: String(mixedPort), proto: '6', protoName: 'TCP', action: 'accept',
  }];
  const mixed = analyzePolicies([mixedPolicy], config, undefined, mixedFlows)[0];
  const mixedSelected = mixed.analysis.services.filter(service => [...ports, mixedPort].includes(service.port));
  assert.equal(mixedSelected.length, 4);
  assert.equal(mixedSelected.find(service => service.port === mixedPort).compatibleMatches, undefined);

  const contradictoryPolicy = {
    ...policy,
    services: ['TCP/52121'],
    ports: [52121],
    protos: ['UDP'],
  };
  const contradictory = analyzePolicies(
    [contradictoryPolicy],
    config,
    undefined,
    flows.filter(flow => Number(flow.dstport) === 52121),
  )[0].analysis.services[0];
  assert.equal(contradictory.found, false);
  assert.equal(contradictory.technicalConflict, true);
  assert.equal(contradictory.compatibleMatches, undefined);

  const submitted = structuredClone(policy);
  submitted._serviceReuse = Object.fromEntries(ports.map(port => [`TCP/${port}`, 'DCE-RPC-RANGE']));
  const authoritative = analyzePolicies([submitted], config, undefined, flows);
  assert.equal(authoritative[0].analysis.services.filter(service => service.name === 'DCE-RPC-RANGE').length, 1);
  assert.equal(authoritative[0].analysis.services.find(service => service.name === 'DCE-RPC-RANGE').compatibilityAccepted, true);
  const decision = applyPolicyUserDecisions(authoritative, [submitted], config, flows);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.match(cli, /set service "DNS" "DCE-RPC-RANGE"/);
  assert.doesNotMatch(cli, /FF_SVC_TCP_MULTI|FF_SVC_52121_TCP|FF_SVC_52134_TCP|FF_SVC_62966_TCP/);
});

test('ne propose pas un service prédéfini masqué par un objet FortiGate du même nom', () => {
  const config = parseFortiConfig(`
config firewall address
    edit "SRC"
        set subnet 10.0.0.0 255.255.255.0
    next
    edit "DST"
        set subnet 10.0.1.0 255.255.255.0
    next
end
config system interface
    edit "LAN"
        set ip 10.0.0.1 255.255.255.0
    next
    edit "DMZ"
        set ip 10.0.1.1 255.255.255.0
    next
end
config firewall service custom
    edit "LDAP"
        set tcp-portrange 389
    next
end
  `);
  const selected = {
    srcSubnet: '10.0.0.0/24', dstTarget: '10.0.1.0/24', dstType: 'private',
    services: ['LDAP', 'TCP/3268'], ports: [389, 3268], protos: ['TCP'],
    srcHosts: ['10.0.0.10'], dstHosts: ['10.0.1.20'],
    srcintf: 'LAN', dstintf: 'DMZ',
  };
  const flows = [389, 3268].map(port => ({
    srcip: '10.0.0.10', dstip: '10.0.1.20', srcSubnet: '10.0.0.0/24', dstSubnet: '10.0.1.0/24', dstType: 'private',
    srcintf: 'LAN', dstintf: 'DMZ', service: port === 389 ? 'LDAP' : 'TCP/3268',
    dstport: String(port), proto: '6', protoName: 'TCP', action: 'accept',
  }));

  const authoritative = analyzePolicies([selected], config, undefined, flows);
  const raw3268 = authoritative[0].analysis.services.find(service => service.port === 3268);
  assert.equal(raw3268.found, false);
  assert.equal(raw3268.compatibleMatch, undefined);
  assert.ok(!(raw3268.compatibleMatches || []).some(match => match.name === 'LDAP'));

  const forged = structuredClone(selected);
  forged._serviceReuse = { 'TCP/3268': 'LDAP' };
  const rejected = applyPolicyUserDecisions(
    analyzePolicies([forged], config, undefined, flows),
    [forged],
    config,
    flows,
  );
  assert.equal(rejected.ok, false);
  assert.ok(rejected.issues.some(issue => issue.code === 'SERVICE_REUSE_DECISION_INVALID'));
});

test('ne propose jamais ALL_TCP comme service compatible', () => {
  const config = configWithServices(`
    edit "ALL_TCP"
        set tcp-portrange 1-65535
    next
  `);

  assert.deepEqual(findService(52121, 'TCP', config.customServices), { found: false });
});

test('préserve le workflow historique des ranges fusionnés sans recréer les ports bruts', () => {
  const config = configWithServices('');
  const policy = {
    srcSubnet: '10.0.0.0/24', dstTarget: '10.0.1.0/24', dstType: 'private',
    services: [], ports: [12000, 13000], protos: ['TCP'], srcHosts: [], dstHosts: [],
    _mergedServices: [{ name: 'CUSTOM_RANGE', proto: 'TCP', portRange: '12000-13000' }],
  };

  const analyzed = analyzePolicies([policy], config)[0];
  assert.deepEqual(analyzed.analysis.services, []);
});
