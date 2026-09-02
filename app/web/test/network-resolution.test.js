'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { buildAnalysis } = require('../lib/analyzer');
const {
  parseFortiConfig,
  extractKnownSubnets,
  resolveDestinationSubnets,
  analyzePolicies,
  applyPolicyUserDecisions,
  generateConfig,
  validatePolicyDecisionShapes,
} = require('../lib/forticonfig');

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

test('ne regroupe pas plusieurs destinations sous la clé d’un objet RFC1918 /8', () => {
  const fortiConfig = parseFortiConfig(`
config firewall address
    edit "RFC1918-10.0.0.0/8"
        set subnet 10.0.0.0 255.0.0.0
    next
end
`);
  const analysis = buildAnalysis([
    acceptedFlow('10.250.16.49', '10.42.1.252', 'Stations', 'Interco_MPLS', 'SMB', '445'),
    acceptedFlow('10.250.16.49', '10.44.2.1', 'Stations', 'Interco_MPLS', 'SMB', '445'),
  ], extractKnownSubnets(fortiConfig));

  assert.deepEqual(analysis.policies.map(policy => policy.dstTarget).sort(), [
    '10.42.1.252/32', '10.44.2.1/32',
  ]);
  assert.ok(analysis.policies.every(policy => policy.dstTarget !== '10.0.0.0/8'));
});

test('conserve une interface /8 comme preuve réseau même si un objet /8 générique existe', () => {
  const fortiConfig = parseFortiConfig(`
config firewall address
    edit "RFC1918-10.0.0.0/8"
        set subnet 10.0.0.0 255.0.0.0
    next
end
config system interface
    edit "REMOTE"
        set ip 10.42.0.1 255.0.0.0
    next
end
`);
  const analysis = buildAnalysis([
    acceptedFlow('192.168.10.10', '10.42.1.252', 'LAN', 'REMOTE'),
  ], extractKnownSubnets(fortiConfig));

  assert.equal(analysis.policies[0].dstTarget, '10.0.0.0/8');
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

test('résout une destination privée depuis l’interface unique observée sans route', () => {
  const fortiConfig = parseFortiConfig(`
config system interface
    edit "LAN"
        set ip 192.168.10.1 255.255.255.0
    next
    edit "Interco_MPLS"
    next
end
config system zone
    edit "Z-INTERSITE"
        set interface "Interco_MPLS"
    next
end
`);
  const analysis = buildAnalysis([
    acceptedFlow('192.168.10.10', '10.40.0.10', 'LAN', 'Interco_MPLS'),
  ], extractKnownSubnets(fortiConfig));

  assert.equal(analysis.policies[0].flowDstintf, 'Interco_MPLS');
  assert.deepEqual(analysis.policies[0].flowDstintfs, ['Interco_MPLS']);

  const [analyzed] = analyzePolicies(
    analysis.policies,
    fortiConfig,
    undefined,
    analysis.flows,
  );
  assert.equal(analyzed.analysis.dstIface, 'Interco_MPLS');
  assert.equal(analyzed.analysis.dstZone, 'Z-INTERSITE');
  assert.equal(analyzed.analysis.dstIfaceSource, 'log');
  assert.ok(!analyzed.analysis.missingFields.includes('dstIface'));
});

test('ne choisit aucune interface quand plusieurs destinations sont observées', () => {
  const fortiConfig = parseFortiConfig(`
config system interface
    edit "LAN"
        set ip 192.168.10.1 255.255.255.0
    next
    edit "REMOTE-A"
    next
    edit "REMOTE-B"
    next
end
config router static
    edit 1
        set dst 10.40.0.0 255.255.255.0
        set device "REMOTE-A"
    next
end
`);
  const analysis = buildAnalysis([
    acceptedFlow('192.168.10.10', '10.40.0.10', 'LAN', 'REMOTE-A'),
    acceptedFlow('192.168.10.10', '10.40.0.10', 'LAN', 'REMOTE-B'),
  ], extractKnownSubnets(fortiConfig));

  assert.equal(analysis.policies.length, 1);
  assert.equal(analysis.policies[0].flowDstintf, null);
  assert.deepEqual(analysis.policies[0].flowDstintfs, ['REMOTE-A', 'REMOTE-B']);

  const [analyzed] = analyzePolicies(
    analysis.policies,
    fortiConfig,
    undefined,
    analysis.flows,
  );
  assert.equal(analyzed.analysis.dstIface, null);
  assert.equal(analyzed.analysis.dstZone, null);
  assert.equal(analyzed.analysis.dstIfaceSource, 'auto');
  assert.ok(analyzed.analysis.missingFields.includes('dstIface'));
});

test('exposes the most specific detected destination subnets without promoting a broad /8', () => {
  const fortiConfig = parseFortiConfig(`
config firewall address
    edit "RFC1918"
        set subnet 10.0.0.0 255.0.0.0
    next
end
config system interface
    edit "LAN"
        set ip 192.168.10.1 255.255.255.0
    next
    edit "Z-INTERSITE"
        set ip 172.20.0.1 255.255.255.0
    next
end
config router static
    edit 1
        set dst 10.42.0.0 255.255.254.0
        set gateway 172.20.0.2
        set device "Z-INTERSITE"
    next
    edit 2
        set dst 10.44.2.0 255.255.255.0
        set gateway 172.20.0.2
        set device "Z-INTERSITE"
    next
    edit 3
        set dst 10.45.0.0 255.255.252.0
        set gateway 172.20.0.2
        set device "Z-INTERSITE"
    next
    edit 4
        set dst 0.0.0.0 0.0.0.0
        set gateway 172.20.0.2
        set device "Z-INTERSITE"
    next
end
`);
  const destinations = ['10.42.1.252', '10.44.2.1', '10.45.2.1'];
  const observedFlows = destinations.map(dstip => ({
    srcip: '192.168.10.10', dstip, dstSubnet: '10.0.0.0/8', dstType: 'private',
    srcSubnet: '192.168.10.0/24', srcintf: 'LAN', dstintf: 'Z-INTERSITE',
    service: 'HTTPS', dstport: '443', proto: '6', protoName: 'TCP', action: 'accept',
  }));

  const [analyzed] = analyzePolicies([{
    srcSubnet: '192.168.10.0/24',
    dstTarget: '10.0.0.0/8',
    dstType: 'private',
    services: ['HTTPS'], ports: [443], protos: ['TCP'],
    srcHosts: ['192.168.10.10'], dstHosts: destinations,
    flowSrcintf: 'LAN',
  }], fortiConfig, undefined, observedFlows);

  assert.ok(Array.isArray(analyzed._dstDetectedSubnets), 'candidats de sous-réseaux destination absents');
  assert.deepEqual(analyzed._dstDetectedSubnets.map(item => [item.subnet, item.hosts]), [
    ['10.42.0.0/23', ['10.42.1.252']],
    ['10.44.2.0/24', ['10.44.2.1']],
    ['10.45.0.0/22', ['10.45.2.1']],
  ]);
  assert.deepEqual(analyzed._dstDetectedSubnets.map(item => [item.route.source, item.route.device]), [
    ['static', 'Z-INTERSITE'],
    ['static', 'Z-INTERSITE'],
    ['static', 'Z-INTERSITE'],
  ]);
  assert.ok(analyzed._dstDetectedSubnets.every(item => item.subnet !== '10.0.0.0/8'));
});

test('deduplicates detected destinations, preserves /27 and /28, and ignores the default route as a subnet', () => {
  const fortiConfig = parseFortiConfig(`
config firewall address
    edit "NET_27"
        set subnet 10.60.0.0 255.255.255.224
    next
end
config system interface
    edit "LAN"
        set ip 192.168.10.1 255.255.255.0
    next
    edit "Z-INTERSITE"
        set ip 172.20.0.1 255.255.255.0
    next
    edit "REMOTE-IF"
        set ip 10.62.5.1 255.255.255.224
    next
end
config router static
    edit 1
        set dst 10.61.1.0 255.255.255.240
        set gateway 172.20.0.2
        set device "Z-INTERSITE"
    next
    edit 2
        set dst 0.0.0.0 0.0.0.0
        set gateway 172.20.0.2
        set device "Z-INTERSITE"
    next
end
`);

  const detected = resolveDestinationSubnets([
    '10.60.0.1', '10.60.0.2', '10.61.1.14', '10.62.5.4', '10.99.1.7',
  ], fortiConfig);

  assert.deepEqual(detected.map(item => [item.subnet, item.hosts, item.useSubnet]), [
    ['10.60.0.0/27', ['10.60.0.1', '10.60.0.2'], true],
    ['10.61.1.0/28', ['10.61.1.14'], true],
    ['10.62.5.0/27', ['10.62.5.4'], true],
    ['10.99.1.7/32', ['10.99.1.7'], false],
  ]);
  assert.equal(detected[0].addrName, 'NET_27');
  assert.deepEqual(detected[2].sources, [
    { type: 'interface', name: 'REMOTE-IF', cidr: '10.62.5.0/27' },
    { type: 'route', dst: '10.62.5.0/27', device: 'REMOTE-IF', gateway: '', distance: 0, priority: 0, source: 'connected' },
  ]);
  assert.deepEqual(detected[2].route, {
    dst: '10.62.5.0/27', device: 'REMOTE-IF', gateway: '', distance: 0, priority: 0, source: 'connected',
  });
  assert.deepEqual(detected[3].route, {
    dst: '0.0.0.0/0', gateway: '172.20.0.2', device: 'Z-INTERSITE',
    distance: 10, priority: 0, source: 'static',
  });
  assert.notEqual(detected[3].subnet, '0.0.0.0/0');
});

test('valide la sélection de sous-réseaux détectés et génère CONFIG puis FF_NET_*', () => {
  const fortiConfig = parseFortiConfig(`
config firewall address
    edit "NET_42"
        set subnet 10.42.0.0 255.255.254.0
    next
end
config system interface
    edit "LAN"
        set ip 192.168.10.1 255.255.255.0
    next
    edit "Z-INTERSITE"
        set ip 172.20.0.1 255.255.255.0
    next
end
config router static
    edit 1
        set dst 10.42.0.0 255.255.254.0
        set gateway 172.20.0.2
        set device "Z-INTERSITE"
    next
    edit 2
        set dst 10.44.2.0 255.255.255.0
        set gateway 172.20.0.2
        set device "Z-INTERSITE"
    next
    edit 3
        set dst 10.45.0.0 255.255.252.0
        set gateway 172.20.0.2
        set device "Z-INTERSITE"
    next
end
`);
  const destinations = ['10.42.1.252', '10.44.2.1', '10.45.2.1'];
  const observedFlows = destinations.map(dstip => ({
    srcip: '192.168.10.10', dstip, dstSubnet: '10.0.0.0/8', dstType: 'private',
    srcSubnet: '192.168.10.0/24', srcintf: 'LAN', dstintf: 'Z-INTERSITE',
    service: 'SSH', dstport: '22', proto: '6', protoName: 'TCP', action: 'accept',
  }));
  const detected = resolveDestinationSubnets(destinations, fortiConfig);
  const selected = {
    srcSubnet: '192.168.10.0/24',
    dstTarget: detected[0].subnet,
    dstTargets: detected.map(item => item.subnet),
    dstType: 'private',
    _dstMode: 'detected-subnets',
    _isMultiDst: true,
    _use32Dst: false,
    _multiDstSubnets: detected,
    services: ['SSH'], ports: [22], protos: ['TCP'],
    srcHosts: ['192.168.10.10'], dstHosts: destinations, flowSrcintf: 'LAN',
  };
  const authoritative = analyzePolicies([selected], fortiConfig, undefined, observedFlows);
  const decision = applyPolicyUserDecisions(authoritative, [selected], fortiConfig, observedFlows);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));

  const cli = generateConfig(decision.policies, {
    addresses: fortiConfig.addresses,
    addressGroups: fortiConfig.addressGroups,
    zones: fortiConfig.zones,
  });
  assert.match(cli, /set dstaddr "NET_42" "FF_NET_10_44_2_0_24" "FF_NET_10_45_0_0_22"/);
  assert.doesNotMatch(cli, /set dstaddr "RFC1918"/);
});

test('refuse une représentation destination détectée forgée hors des candidats LPM', () => {
  const fortiConfig = parseFortiConfig(`
config firewall address
    edit "RFC1918"
        set subnet 10.0.0.0 255.0.0.0
    next
end
config system interface
    edit "LAN"
        set ip 192.168.10.1 255.255.255.0
    next
    edit "Z-INTERSITE"
        set ip 172.20.0.1 255.255.255.0
    next
end
config router static
    edit 1
        set dst 10.42.0.0 255.255.254.0
        set gateway 172.20.0.2
        set device "Z-INTERSITE"
    next
end
`);
  const destinations = ['10.42.1.252'];
  const observedFlows = [{
    srcip: '192.168.10.10', dstip: destinations[0], dstSubnet: '10.0.0.0/8', dstType: 'private',
    srcSubnet: '192.168.10.0/24', srcintf: 'LAN', dstintf: 'Z-INTERSITE',
    service: 'SSH', dstport: '22', proto: '6', protoName: 'TCP', action: 'accept',
  }];
  const forged = {
    srcSubnet: '192.168.10.0/24',
    dstTarget: '10.0.0.0/8', dstTargets: ['10.0.0.0/8'], dstType: 'private',
    _dstMode: 'detected-subnets', _isMultiDst: true, _use32Dst: false,
    _srcintf: 'LAN', _dstintf: 'Z-INTERSITE',
    srcintf: 'LAN', dstintf: 'Z-INTERSITE',
    _multiDstSubnets: [{ subnet: '10.0.0.0/8', hosts: destinations, useSubnet: true, addrName: 'RFC1918', addrFound: true }],
    services: ['SSH'], ports: [22], protos: ['TCP'],
    srcHosts: ['192.168.10.10'], dstHosts: destinations, flowSrcintf: 'LAN',
  };
  const authoritative = analyzePolicies([forged], fortiConfig, undefined, observedFlows);
  const decision = applyPolicyUserDecisions(authoritative, [forged], fortiConfig, observedFlows);
  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'DESTINATION_SUBNET_DECISION_INVALID'), JSON.stringify(decision.issues));
});

test('une seule destination détectée depuis un agrégat reste par défaut en /32', () => {
  const fortiConfig = parseFortiConfig(`
config firewall address
    edit "RFC1918"
        set subnet 10.0.0.0 255.0.0.0
    next
end
config system interface
    edit "LAN"
        set ip 192.168.10.1 255.255.255.0
    next
    edit "Z-INTERSITE"
        set ip 172.20.0.1 255.255.255.0
    next
end
config router static
    edit 1
        set dst 10.42.0.0 255.255.254.0
        set gateway 172.20.0.2
        set device "Z-INTERSITE"
    next
end
`);
  const flow = {
    srcip: '192.168.10.10', dstip: '10.42.1.252', dstSubnet: '10.0.0.0/8', dstType: 'private',
    srcSubnet: '192.168.10.0/24', srcintf: 'LAN', dstintf: 'Z-INTERSITE',
    service: 'SSH', dstport: '22', proto: '6', protoName: 'TCP', action: 'accept',
  };
  const [analyzed] = analyzePolicies([{
    srcSubnet: '192.168.10.0/24', dstTarget: '10.0.0.0/8', dstType: 'private',
    services: ['SSH'], ports: [22], protos: ['TCP'],
    srcHosts: ['192.168.10.10'], dstHosts: ['10.42.1.252'], flowSrcintf: 'LAN',
  }], fortiConfig, undefined, [flow]);

  assert.equal(analyzed._dstMode, 'hosts');
  assert.equal(analyzed._use32Dst, true);
  const cli = generateConfig([analyzed], {
    addresses: fortiConfig.addresses,
    addressGroups: fortiConfig.addressGroups,
    zones: fortiConfig.zones,
  });
  assert.match(cli, /set dstaddr "FF_HOST_10_42_1_252"/);
  assert.doesNotMatch(cli, /set dstaddr "RFC1918"/);
});

test('les invariants de mode destination empêchent une sélection détectée ignorée ou un /32 agrégé', () => {
  const base = {
    srcSubnet: '192.168.10.0/24', dstTarget: '10.42.0.0/23', dstType: 'private',
    services: ['SSH'], ports: [22], protos: ['TCP'],
    srcHosts: ['192.168.10.10'], dstHosts: ['10.42.1.252'],
  };
  const detected = validatePolicyDecisionShapes([{
    ...base,
    _dstMode: 'detected-subnets', _isMultiDst: false, _use32Dst: false,
    _multiDstSubnets: [{ subnet: '10.42.0.0/23', hosts: ['10.42.1.252'], useSubnet: true }],
  }]);
  const aggregate = validatePolicyDecisionShapes([{
    ...base,
    _dstMode: 'aggregate', _isMultiDst: false, _use32Dst: true,
  }]);
  assert.equal(detected.ok, false, JSON.stringify(detected.issues));
  assert.equal(aggregate.ok, false, JSON.stringify(aggregate.issues));
  assert.ok([...detected.issues, ...aggregate.issues]
    .some(issue => issue.code === 'SCOPE_DECISION_INVALID'));
});

test('conserve la provenance BGP des pseudo-routes utilisées pour une destination', () => {
  const fortiConfig = parseFortiConfig(`
config system interface
    edit "LAN"
        set ip 192.168.10.1 255.255.255.0
    next
    edit "Z-INTERSITE"
        set ip 172.20.0.1 255.255.255.0
    next
end
config router bgp
    set router-id 192.168.10.1
    config neighbor
        edit "10.99.1.1"
            set remote-as 65000
            set interface "Z-INTERSITE"
        next
    end
end
`);
  const [detected] = resolveDestinationSubnets(['10.99.1.1'], fortiConfig);
  assert.equal(detected.route.source, 'bgp');
  assert.equal(detected.route.dst, '10.99.1.1/32');
  assert.ok(detected.sources.some(source => source.type === 'route' && source.source === 'bgp'));
});

test('n’utilise ni un objet /32 ni le RFC1918 /8 pour inférer le subnet détecté', () => {
  const fortiConfig = parseFortiConfig(`
config firewall address
    edit "RFC1918"
        set subnet 10.0.0.0 255.0.0.0
    next
    edit "HOST-10.40.1.211"
        set subnet 10.40.1.211 255.255.255.255
    next
    edit "HOST-10.42.1.252"
        set subnet 10.42.1.252 255.255.255.255
    next
end
config system interface
    edit "LAN"
        set ip 192.168.10.1 255.255.255.0
    next
    edit "REMOTE"
        set ip 10.40.1.1 255.255.0.0
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 10.40.0.254
        set device "REMOTE"
    next
end
`);

  const withNetwork = resolveDestinationSubnets(['10.40.1.211'], fortiConfig)[0];
  assert.equal(withNetwork.subnet, '10.40.0.0/16');
  assert.equal(withNetwork.addrFound, false);
  assert.ok(withNetwork.sources.some(source => source.type === 'interface' && source.name === 'REMOTE'));

  const withoutNetwork = resolveDestinationSubnets(['10.42.1.252'], fortiConfig)[0];
  assert.equal(withoutNetwork.subnet, '10.42.1.252/32');
  assert.equal(withoutNetwork.useSubnet, false);
  assert.equal(withoutNetwork.addrFound, false);
  assert.equal(withoutNetwork.sources.some(source => source.type === 'object'), false);
  assert.equal(withoutNetwork.route.dst, '0.0.0.0/0');
  assert.equal(withoutNetwork.route.device, 'REMOTE');
});

test('accepte un CIDR destination saisi manuellement s’il contient les IP observées', () => {
  const fortiConfig = parseFortiConfig(`
config system interface
    edit "LAN"
        set ip 192.168.10.1 255.255.255.0
    next
    edit "REMOTE"
        set ip 172.20.0.1 255.255.255.0
    next
end
`);
  const observedFlows = [{
    srcip: '192.168.10.10', dstip: '10.42.1.252', dstSubnet: '10.0.0.0/8', dstType: 'private',
    srcSubnet: '192.168.10.0/24', srcintf: 'LAN', dstintf: 'REMOTE',
    service: 'SSH', dstport: '22', proto: '6', protoName: 'TCP', action: 'accept',
  }];
  const selected = {
    srcSubnet: '192.168.10.0/24', dstTarget: '10.42.1.224/27', dstTargets: ['10.42.1.224/27'],
    dstType: 'private', srcintf: 'LAN', dstintf: 'REMOTE', flowSrcintf: 'LAN',
    _dstMode: 'detected-subnets', _isMultiDst: true, _use32Dst: false,
    _multiDstSubnets: [{
      subnet: '10.42.1.224/27', hosts: ['10.42.1.252'], useSubnet: true,
      manual: true, addrName: 'FF_NET_10_42_1_224_27', addrFound: false,
    }],
    services: ['SSH'], ports: [22], protos: ['TCP'],
    srcHosts: ['192.168.10.10'], dstHosts: ['10.42.1.252'],
  };
  const authoritative = analyzePolicies([selected], fortiConfig, undefined, observedFlows);
  const decision = applyPolicyUserDecisions(authoritative, [selected], fortiConfig, observedFlows);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  const cli = generateConfig(decision.policies, {
    addresses: fortiConfig.addresses, addressGroups: fortiConfig.addressGroups, zones: fortiConfig.zones,
  });
  assert.match(cli, /edit "FF_NET_10_42_1_224_27"/);
  assert.match(cli, /set subnet 10\.42\.1\.224 255\.255\.255\.224/);
});

test('refuse un CIDR destination manuel qui ne contient pas l’IP observée sans crash', () => {
  const fortiConfig = parseFortiConfig(`
config system interface
    edit "LAN"
        set ip 192.168.10.1 255.255.255.0
    next
    edit "REMOTE"
        set ip 172.20.0.1 255.255.255.0
    next
end
`);
  const observedFlows = [{
    srcip: '192.168.10.10', dstip: '10.42.1.252', dstSubnet: '10.0.0.0/8', dstType: 'private',
    srcSubnet: '192.168.10.0/24', srcintf: 'LAN', dstintf: 'REMOTE',
    service: 'SSH', dstport: '22', proto: '6', protoName: 'TCP', action: 'accept',
  }];
  const selected = {
    srcSubnet: '192.168.10.0/24', dstTarget: '10.42.1.0/28', dstTargets: ['10.42.1.0/28'],
    dstType: 'private', srcintf: 'LAN', dstintf: 'REMOTE', flowSrcintf: 'LAN',
    _dstMode: 'detected-subnets', _isMultiDst: true, _use32Dst: false,
    _multiDstSubnets: [{ subnet: '10.42.1.0/28', hosts: ['10.42.1.252'], useSubnet: true, manual: true }],
    services: ['SSH'], ports: [22], protos: ['TCP'],
    srcHosts: ['192.168.10.10'], dstHosts: ['10.42.1.252'],
  };
  const authoritative = analyzePolicies([selected], fortiConfig, undefined, observedFlows);
  const decision = applyPolicyUserDecisions(authoritative, [selected], fortiConfig, observedFlows);
  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'DESTINATION_SUBNET_DECISION_INVALID'));
});

test('calcule un seul agrégat minimal depuis les seules IP observées et accepte son édition', () => {
  const fortiConfig = parseFortiConfig(`
config firewall address
    edit "RFC1918"
        set subnet 10.0.0.0 255.0.0.0
    next
end
config system interface
    edit "LAN"
        set ip 192.168.10.1 255.255.255.0
    next
    edit "REMOTE"
        set ip 172.20.0.1 255.255.255.0
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 172.20.0.2
        set device "REMOTE"
    next
end
`);
  const destinations = ['10.42.1.252', '10.44.2.1', '10.45.2.1'];
  const observedFlows = destinations.map(dstip => ({
    srcip: '192.168.10.10', dstip, dstSubnet: '10.0.0.0/8', dstType: 'private',
    srcSubnet: '192.168.10.0/24', srcintf: 'LAN', dstintf: 'REMOTE',
    service: 'SSH', dstport: '22', proto: '6', protoName: 'TCP', action: 'accept',
  }));
  const selected = {
    srcSubnet: '192.168.10.0/24', dstTarget: '10.40.0.0/13', dstTargets: ['10.40.0.0/13'],
    dstType: 'private', srcintf: 'LAN', dstintf: 'REMOTE', flowSrcintf: 'LAN',
    _dstMode: 'aggregate', _isMultiDst: false, _use32Dst: false,
    dstAddrName: 'FF_NET_10_40_0_0_13',
    services: ['SSH'], ports: [22], protos: ['TCP'],
    srcHosts: ['192.168.10.10'], dstHosts: destinations,
  };
  const authoritative = analyzePolicies([selected], fortiConfig, undefined, observedFlows);
  const decision = applyPolicyUserDecisions(authoritative, [selected], fortiConfig, observedFlows);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  const cli = generateConfig(decision.policies, {
    addresses: fortiConfig.addresses, addressGroups: fortiConfig.addressGroups, zones: fortiConfig.zones,
  });
  assert.match(cli, /set dstaddr "FF_NET_10_40_0_0_13"/);
  assert.match(cli, /set subnet 10\.40\.0\.0 255\.248\.0\.0/);
  assert.doesNotMatch(cli, /set dstaddr "RFC1918"/);

  const invalidSelected = {
    ...selected, dstTarget: '10.42.1.0/28', dstTargets: ['10.42.1.0/28'],
  };
  const invalidDecision = applyPolicyUserDecisions(authoritative, [invalidSelected], fortiConfig, observedFlows);
  assert.equal(invalidDecision.ok, false);
  assert.ok(invalidDecision.issues.some(issue => issue.code === 'DESTINATION_AGGREGATE_DECISION_INVALID'));
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
