'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  parseFortiConfig,
  findService,
  analyzePolicies,
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
