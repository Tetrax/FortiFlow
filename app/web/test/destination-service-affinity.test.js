'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  parseFortiConfig,
  preserveDestinationServiceAffinity,
  analyzePolicies,
  generateConfig,
} = require('../lib/forticonfig');

function service(label) {
  return { label, name: label, found: true, source: 'predefined', isNamed: true };
}

test('keeps common services grouped and splits destination-specific services', () => {
  const policy = {
    srcSubnet: '10.252.16.0/23',
    srcintf: 'Z-Stations',
    dstintf: 'Z-Serveurs',
    vdom: 'root',
    dstTarget: '10.40.1.10/32',
    dstTargets: ['10.40.1.10/32', '10.40.1.20/32'],
    dstType: 'private',
    _isMultiDst: true,
    _multiDstSubnets: [
      { subnet: '10.40.1.10/32', hosts: ['10.40.1.10'], useSubnet: true, addrName: 'Serveur-A', addrFound: true },
      { subnet: '10.40.1.20/32', hosts: ['10.40.1.20'], useSubnet: true, addrName: 'Serveur-B', addrFound: true },
    ],
    analysis: { services: ['DNS', 'HTTP', 'LDAP', 'SMB'].map(service) },
    services: ['DNS', 'HTTP', 'LDAP', 'SMB'],
    _mergedFrom: [
      { srcSubnet: '10.252.16.0/23', dstTarget: '10.40.1.10/32', analysis: { services: ['DNS', 'HTTP', 'LDAP'].map(service) } },
      { srcSubnet: '10.252.16.0/23', dstTarget: '10.40.1.20/32', analysis: { services: ['DNS', 'SMB'].map(service) } },
    ],
  };

  const result = preserveDestinationServiceAffinity([policy]);
  const normalized = result.map(item => ({
    destinations: item.dstTargets,
    services: item.analysis.services.map(svc => svc.label).sort(),
    srcintf: item.srcintf,
    dstintf: item.dstintf,
    vdom: item.vdom,
  })).sort((a, b) => a.destinations.join(',').localeCompare(b.destinations.join(',')) || a.services.join(',').localeCompare(b.services.join(',')));

  assert.deepEqual(normalized, [
    { destinations: ['10.40.1.10/32'], services: ['HTTP', 'LDAP'], srcintf: 'Z-Stations', dstintf: 'Z-Serveurs', vdom: 'root' },
    { destinations: ['10.40.1.10/32', '10.40.1.20/32'], services: ['DNS'], srcintf: 'Z-Stations', dstintf: 'Z-Serveurs', vdom: 'root' },
    { destinations: ['10.40.1.20/32'], services: ['SMB'], srcintf: 'Z-Stations', dstintf: 'Z-Serveurs', vdom: 'root' },
  ]);

  const fortiConfig = parseFortiConfig(`
config firewall address
    edit "Stations"
        set subnet 10.252.16.0 255.255.254.0
    next
    edit "Serveur-A"
        set subnet 10.40.1.10 255.255.255.255
    next
    edit "Serveur-B"
        set subnet 10.40.1.20 255.255.255.255
    next
end
config system interface
    edit "Z-Stations"
        set ip 10.252.17.254 255.255.254.0
    next
    edit "Z-Serveurs"
        set ip 10.40.1.254 255.255.255.0
    next
end
`);
  const analyzed = analyzePolicies(result, fortiConfig);
  const cli = generateConfig(analyzed, {
    addresses: fortiConfig.addresses,
    addressGroups: fortiConfig.addressGroups,
    zones: fortiConfig.zones,
  });
  const policySection = cli.split('config firewall policy')[1];
  const blocks = [...policySection.matchAll(/\n    edit 0([\s\S]*?)\n    next/g)].map(match => match[1]);

  assert.equal(blocks.length, 3);
  assert.ok(blocks.some(block => block.includes('set dstaddr "Serveur-A" "Serveur-B"') && block.includes('set service "DNS"')));
  assert.ok(blocks.some(block => block.includes('set dstaddr "Serveur-A"') && block.includes('set service "HTTP" "LDAP"')));
  assert.ok(blocks.some(block => block.includes('set dstaddr "Serveur-B"') && block.includes('set service "SMB"')));
  assert.ok(blocks.every(block => block.includes('set srcintf "Z-Stations"') && block.includes('set dstintf "Z-Serveurs"')));
});

test('keeps identical service labels separate when their technical tuples differ', () => {
  const tcp443 = { label: 'APP', name: null, found: false, isNamed: true, port: 443, proto: 'TCP', reuseKeys: ['TCP/443'] };
  const tcp8443 = { label: 'APP', name: null, found: false, isNamed: true, port: 8443, proto: 'TCP', reuseKeys: ['TCP/8443'] };
  const policy = {
    srcSubnet: '10.0.0.0/24',
    dstTarget: '10.0.1.0/24',
    dstTargets: ['10.0.1.0/24', '10.0.2.0/24'],
    dstType: 'private',
    analysis: { services: [tcp443, tcp8443] },
    services: ['APP'],
    _mergedFrom: [
      { srcSubnet: '10.0.0.0/24', dstTarget: '10.0.1.0/24', analysis: { services: [tcp443] } },
      { srcSubnet: '10.0.0.0/24', dstTarget: '10.0.2.0/24', analysis: { services: [tcp8443] } },
    ],
  };

  const result = preserveDestinationServiceAffinity([policy]);
  assert.equal(result.length, 2);
  assert.deepEqual(result.map(item => [item.dstTargets, item.analysis.services[0].reuseKeys]), [
    [['10.0.1.0/24'], ['TCP/443']],
    [['10.0.2.0/24'], ['TCP/8443']],
  ]);
});
