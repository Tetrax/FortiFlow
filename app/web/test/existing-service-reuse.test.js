'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  parseFortiConfig,
  analyzePolicies,
  generateConfig,
} = require('../lib/forticonfig');

function policy(overrides = {}) {
  return {
    srcSubnet: '10.0.0.0/24',
    dstTarget: '10.0.1.0/24',
    dstType: 'private',
    services: [],
    ports: [],
    protos: [],
    srcHosts: ['10.0.0.10'],
    dstHosts: ['10.0.1.20'],
    flowSrcintf: 'LAN',
    ...overrides,
  };
}

function flow(service, dstport, proto) {
  return {
    srcip: '10.0.0.10',
    dstip: '10.0.1.20',
    srcSubnet: '10.0.0.0/24',
    dstSubnet: '10.0.1.0/24',
    dstType: 'private',
    srcintf: 'LAN',
    dstintf: 'DMZ',
    service,
    dstport: String(dstport),
    proto: proto === 'TCP' ? '6' : '17',
    protoName: proto,
    action: 'accept',
  };
}

test('réutilise les services FortiGate exacts dans une policy multi-services et garde un port inconnu générable', () => {
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
    edit "HTTP"
        set tcp-portrange 80
    next
    edit "HTTPS"
        set tcp-portrange 443
    next
    edit "DHCP"
        set udp-portrange 67-68
    next
    edit "LDAP"
        set tcp-portrange 389
    next
    edit "NTP"
        set tcp-portrange 123
        set udp-portrange 123
    next
    edit "SMB"
        set tcp-portrange 445
    next
    edit "APP-CUSTOM"
        set tcp-portrange 9443
    next
end
`);

  const existingServices = ['DNS', 'HTTP', 'HTTPS', 'DHCP', 'LDAP', 'NTP', 'SMB', 'APP-CUSTOM'];
  const mixed = policy({
    services: existingServices,
    ports: [53, 67, 68, 80, 123, 389, 443, 445, 9443],
    protos: ['TCP', 'UDP'],
  });
  const missing = policy({
    dstTarget: '10.0.1.0/24',
    services: ['TCP/65000'],
    ports: [65000],
    protos: ['TCP'],
  });
  const observedFlows = [
    flow('DNS', 53, 'TCP'),
    flow('DNS', 53, 'UDP'),
    flow('HTTP', 80, 'TCP'),
    flow('HTTPS', 443, 'TCP'),
    flow('DHCP', 67, 'UDP'),
    flow('DHCP', 68, 'UDP'),
    flow('LDAP', 389, 'TCP'),
    flow('NTP', 123, 'TCP'),
    flow('NTP', 123, 'UDP'),
    flow('SMB', 445, 'TCP'),
    flow('APP-CUSTOM', 9443, 'TCP'),
    flow('TCP/65000', 65000, 'TCP'),
  ];

  const analyzed = analyzePolicies([mixed, missing], config, undefined, observedFlows);

  assert.equal(analyzed.length, 2);
  assert.equal(analyzed[0].srcSubnet, mixed.srcSubnet);
  assert.equal(analyzed[0].dstTarget, mixed.dstTarget);
  assert.deepEqual(
    analyzed[0].analysis.services.map(service => [service.label, service.found, service.name]),
    existingServices.map(name => [name, true, name]),
  );

  const missingService = analyzed[1].analysis.services[0];
  assert.equal(missingService.found, false);
  assert.equal(missingService.name, null);
  assert.equal(missingService.suggestedName, 'FF_SVC_65000_TCP');

  const cli = generateConfig(analyzed, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  for (const name of existingServices) {
    assert.doesNotMatch(cli, new RegExp(`edit "${name}"`));
  }
  assert.match(cli, /edit "FF_SVC_65000_TCP"/);
  assert.match(cli, /set tcp-portrange 65000/);
  assert.match(cli, /set service "DNS" "HTTP" "HTTPS" "DHCP" "LDAP" "NTP" "SMB" "APP-CUSTOM"/);
  assert.match(cli, /set service "FF_SVC_65000_TCP"/);
});
