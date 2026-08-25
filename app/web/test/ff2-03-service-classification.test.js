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
const { buildAnalysis, consolidatePolicies } = require('../lib/analyzer');

function fortiConfig(customServices = '') {
  return parseFortiConfig(`
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
${customServices}
end
`);
}

function policy({ services, ports = [], protos = ['TCP'] }) {
  return {
    srcSubnet: '10.0.0.0/24',
    dstTarget: '10.0.1.0/24',
    dstType: 'private',
    services,
    ports,
    protos,
    srcHosts: ['10.0.0.10'],
    dstHosts: ['10.0.1.20'],
    flowSrcintf: 'LAN',
  };
}

function observedFlow(overrides = {}) {
  return {
    srcip: '10.0.0.10',
    dstip: '10.0.1.20',
    srcSubnet: '10.0.0.0/24',
    dstSubnet: '10.0.1.0/24',
    dstType: 'private',
    srcintf: 'LAN',
    dstintf: 'DMZ',
    service: 'APP-WIDE',
    dstport: '443',
    proto: '6',
    protoName: 'TCP',
    action: 'accept',
    ...overrides,
  };
}

function serviceResult(input, config) {
  return analyzePolicies([policy(input)], config)[0].analysis.services[0];
}

test('FF2-03 un nom custom exact ne prouve pas un mauvais port', () => {
  const config = fortiConfig(`
    edit "APP-EXACT"
        set tcp-portrange 443
    next
  `);

  const result = serviceResult({ services: ['APP-EXACT'], ports: [9443] }, config);
  assert.equal(result.found, false);
  assert.equal(result.name, null);
  assert.equal(result.compatibleMatch, undefined);

  const nameOnly = serviceResult({ services: ['APP-EXACT'], ports: [] }, config);
  assert.equal(nameOnly.found, false);
  assert.equal(nameOnly.name, null);
});

test('FF2-03 un nom custom exact ne prouve pas un mauvais protocole', () => {
  const config = fortiConfig(`
    edit "APP-UDP"
        set udp-portrange 443
    next
  `);

  const result = serviceResult({ services: ['APP-UDP'], ports: [443], protos: ['TCP'] }, config);
  assert.equal(result.found, false);
  assert.equal(result.name, null);
  assert.equal(result.compatibleMatch.name, 'HTTPS');
  assert.notEqual(result.name, 'APP-UDP');
});

test('FF2-03 un service custom couvrant plus large est compatible et non exact', () => {
  const config = fortiConfig(`
    edit "APP-WIDE"
        set tcp-portrange 400-500
    next
  `);

  const result = serviceResult({ services: ['APP-WIDE'], ports: [443] }, config);
  assert.equal(result.found, false);
  assert.equal(result.name, null);
  assert.equal(result.compatibleMatch.name, 'APP-WIDE');
  assert.equal(result.compatibleMatch.extraPortCount, 100);
  assert.equal(result.compatibilityAccepted, undefined);
});

test('FF2-03 un service custom multiport est exact seulement pour le besoin complet', () => {
  const config = fortiConfig(`
    edit "APP-PAIR"
        set tcp-portrange 443 8443
    next
  `);

  const exact = serviceResult({ services: ['APP-PAIR'], ports: [443, 8443] }, config);
  assert.equal(exact.found, true);
  assert.equal(exact.name, 'APP-PAIR');
  assert.equal(exact.exactMatch.name, 'APP-PAIR');

  const subset = serviceResult({ services: ['APP-PAIR'], ports: [443] }, config);
  assert.equal(subset.found, false);
  assert.equal(subset.compatibleMatch.name, 'APP-PAIR');
});

test('FF2-03 le fuzzy custom reste soumis à la preuve technique', () => {
  const config = fortiConfig(`
    edit "WEBAPP-RANGE"
        set tcp-portrange 400-500
    next
  `);

  const compatible = serviceResult({ services: ['WEBAPP'], ports: [443] }, config);
  assert.equal(compatible.found, false);
  assert.equal(compatible.compatibleMatch.name, 'WEBAPP-RANGE');

  const unrelated = serviceResult({ services: ['WEBAPP'], ports: [9443] }, config);
  assert.equal(unrelated.found, false);
  assert.equal(unrelated.compatibleMatch, undefined);
});

test('FF2-03 un nom prédéfini exige le port et le protocole correspondants', () => {
  const config = fortiConfig('');

  const subset = serviceResult({ services: ['HTTPS'], ports: [443], protos: ['TCP'] }, config);
  assert.equal(subset.found, false);
  assert.equal(subset.name, null);
  assert.equal(subset.compatibleMatch.name, 'HTTPS');

  const selected = policy({ services: ['HTTPS'], ports: [443], protos: ['TCP'] });
  selected._serviceReuse = { 'TCP/443': 'HTTPS' };
  const accepted = analyzePolicies([selected], config)[0].analysis.services[0];
  assert.equal(accepted.found, true);
  assert.equal(accepted.name, 'HTTPS');
  assert.equal(accepted.compatibilityAccepted, true);

  const exact = serviceResult({ services: ['HTTPS'], ports: [443, 8443], protos: ['TCP'] }, config);
  assert.equal(exact.found, true);
  assert.equal(exact.name, 'HTTPS');

  const wrongPort = serviceResult({ services: ['HTTPS'], ports: [9443], protos: ['TCP'] }, config);
  assert.equal(wrongPort.found, false);
  assert.equal(wrongPort.name, null);

  const wrongProto = serviceResult({ services: ['HTTPS'], ports: [443], protos: ['UDP'] }, config);
  assert.equal(wrongProto.found, false);
  assert.equal(wrongProto.name, null);

  const nameOnly = serviceResult({ services: ['HTTPS'], ports: [], protos: ['TCP'] }, config);
  assert.equal(nameOnly.found, false);
  assert.equal(nameOnly.name, null);
});

test('FF2-03 le fuzzy prédéfini respecte aussi le protocole observé', () => {
  const config = fortiConfig('');

  const udp = serviceResult({ services: ['NETBIOS'], ports: [137], protos: ['UDP'] }, config);
  assert.equal(udp.found, true);
  assert.equal(udp.name, 'NetBIOS_NS');

  const tcp = serviceResult({ services: ['NETBIOS'], ports: [137], protos: ['TCP'] }, config);
  assert.equal(tcp.found, false);
  assert.equal(tcp.name, null);
});

test('FF2-03 ICMP est exact uniquement avec type et code exacts', () => {
  const config = fortiConfig(`
    edit "PING-EXACT"
        set protocol ICMP
        set icmptype 8
        set icmpcode 0
    next
  `);

  const exact = serviceResult({ services: ['ICMP/8/0'], protos: ['ICMP'] }, config);
  assert.equal(exact.found, true);
  assert.equal(exact.name, 'PING-EXACT');
  assert.equal(exact.exactMatch.name, 'PING-EXACT');

  const wrongCode = serviceResult({ services: ['ICMP/8/1'], protos: ['ICMP'] }, config);
  assert.equal(wrongCode.found, false);
  assert.equal(wrongCode.name, null);
});

test('FF2-03 un service ICMP sans code est compatible et non exact', () => {
  const config = fortiConfig(`
    edit "PING-TYPE"
        set protocol ICMP
        set icmptype 8
    next
  `);

  const result = serviceResult({ services: ['ICMP/8/0'], protos: ['ICMP'] }, config);
  assert.equal(result.found, false);
  assert.equal(result.name, null);
  assert.equal(result.compatibleMatch.name, 'PING-TYPE');
  assert.equal(result.compatibilityAccepted, undefined);
});

test('FF2-03 un service ICMP compatible exige un choix explicite revalidé', () => {
  const config = fortiConfig(`
    edit "PING-TYPE"
        set protocol ICMP
        set icmptype 8
    next
  `);
  const input = { services: ['ICMP/8/0'], protos: ['ICMP'] };
  const proposed = serviceResult(input, config);
  assert.equal(proposed.found, false);
  assert.equal(proposed.compatibleMatch.name, 'PING-TYPE');

  const selected = policy(input);
  selected._serviceReuse = { 'ICMP/8/0': 'PING-TYPE' };
  const authoritative = analyzePolicies([selected], config);
  assert.equal(authoritative[0].analysis.services[0].compatibilityAccepted, true);
  const flow = observedFlow({
    service: 'ICMP/8/0', dstport: '', proto: '1', protoName: 'ICMP',
  });
  const decision = applyPolicyUserDecisions(authoritative, [selected], config, [flow]);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));

  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.match(cli, /set service "PING-TYPE"/);
  assert.doesNotMatch(cli, /edit "PING-TYPE"/);
});

test('FF2-03 aucun fallback automatique vers ALL_ICMP', () => {
  const config = fortiConfig(`
    edit "ALL_ICMP_CUSTOM"
        set protocol ICMP
    next
  `);

  const result = serviceResult({ services: ['ICMP/8/0'], protos: ['ICMP'] }, config);
  assert.equal(result.found, false);
  assert.equal(result.name, null);
  assert.equal(result.compatibleMatch, undefined);
});

test('FF2-03 le nom ICMP seul ne prouve jamais le type observé', () => {
  const config = fortiConfig(`
    edit "PING-EXACT"
        set protocol ICMP
        set icmptype 8
        set icmpcode 0
    next
  `);

  const result = serviceResult({ services: ['PING-EXACT'], protos: ['ICMP'] }, config);
  assert.equal(result.found, false);
  assert.equal(result.name, null);
});

test('FF2-03 une réutilisation compatible nommée reste explicitement opt-in', () => {
  const config = fortiConfig(`
    edit "APP-WIDE"
        set tcp-portrange 400-500
    next
  `);
  const input = { services: ['APP-WIDE'], ports: [443], protos: ['TCP'] };

  const proposed = serviceResult(input, config);
  assert.equal(proposed.found, false);
  assert.equal(proposed.compatibleMatch.name, 'APP-WIDE');
  assert.equal(proposed.compatibilityAccepted, undefined);

  const acceptedPolicy = policy(input);
  acceptedPolicy._serviceReuse = { 'TCP/443': 'APP-WIDE' };
  const accepted = analyzePolicies([acceptedPolicy], config)[0].analysis.services[0];
  assert.equal(accepted.found, true);
  assert.equal(accepted.name, 'APP-WIDE');
  assert.equal(accepted.compatibilityAccepted, true);

  const forgedPolicy = policy(input);
  forgedPolicy._serviceReuse = { 'TCP/443': 'OTHER' };
  const forged = analyzePolicies([forgedPolicy], config)[0].analysis.services[0];
  assert.equal(forged.found, false);
  assert.equal(forged.compatibilityAccepted, undefined);
});

test('FF2-03 le backend revalide le choix compatible nommé avant la CLI', () => {
  const config = fortiConfig(`
    edit "APP-WIDE"
        set tcp-portrange 400-500
    next
  `);
  const selected = policy({ services: ['APP-WIDE'], ports: [443], protos: ['TCP'] });
  selected._serviceReuse = { 'TCP/443': 'APP-WIDE' };
  const authoritative = analyzePolicies([selected], config);
  const decision = applyPolicyUserDecisions(authoritative, [selected], config, [observedFlow()]);

  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  const service = decision.policies[0].analysis.services[0];
  assert.equal(service.found, true);
  assert.equal(service.compatibilityAccepted, true);
  assert.equal(service.name, 'APP-WIDE');

  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.match(cli, /set service "APP-WIDE"/);
  assert.doesNotMatch(cli, /edit "APP-WIDE"/);

  const forged = policy({ services: ['APP-WIDE'], ports: [443], protos: ['TCP'] });
  forged._serviceReuse = { 'TCP/443': 'OTHER' };
  const forgedAuthoritative = analyzePolicies([forged], config);
  const rejected = applyPolicyUserDecisions(forgedAuthoritative, [forged], config, [observedFlow()]);
  assert.equal(rejected.ok, false);
  assert.ok(rejected.issues.some(issue => issue.code === 'SERVICE_REUSE_DECISION_INVALID'));
});

test('FF2-03 le backend refuse un exact multiport absent des flux observés', () => {
  const customConfig = fortiConfig(`
    edit "APP-PAIR"
        set tcp-portrange 443 8443
    next
  `);
  const custom = policy({ services: ['APP-PAIR'], ports: [443, 8443], protos: ['TCP'] });
  const customAuthoritative = analyzePolicies([custom], customConfig);
  assert.equal(customAuthoritative[0].analysis.services[0].found, true);
  const customDecision = applyPolicyUserDecisions(customAuthoritative, [custom], customConfig, [
    observedFlow({ service: 'APP-PAIR', dstport: '443' }),
  ]);
  assert.equal(customDecision.ok, false);
  assert.ok(customDecision.issues.some(issue => issue.code === 'SERVICE_DECISION_UNPROVEN'));

  const predefinedConfig = fortiConfig('');
  const predefined = policy({ services: ['HTTP'], ports: [80, 8080], protos: ['TCP'] });
  const predefinedAuthoritative = analyzePolicies([predefined], predefinedConfig);
  assert.equal(predefinedAuthoritative[0].analysis.services[0].found, true);
  const predefinedDecision = applyPolicyUserDecisions(predefinedAuthoritative, [predefined], predefinedConfig, [
    observedFlow({ service: 'HTTP', dstport: '80' }),
  ]);
  assert.equal(predefinedDecision.ok, false);
  assert.ok(predefinedDecision.issues.some(issue => issue.code === 'SERVICE_DECISION_UNPROVEN'));
});

test('FF2-03 plusieurs protocoles observés ne sont jamais réduits au premier', () => {
  const config = fortiConfig(`
    edit "APP-TCP"
        set tcp-portrange 443
    next
  `);

  const result = serviceResult({ services: ['APP-TCP'], ports: [443], protos: ['TCP', 'UDP'] }, config);
  assert.equal(result.found, false);
  assert.equal(result.name, null);
});

test('FF2-03 ICMP4 ne correspond jamais à un objet ICMP6 de même type', () => {
  const config = fortiConfig(`
    edit "PING6"
        set protocol ICMP6
        set icmptype 8
        set icmpcode 0
    next
  `);

  const result = serviceResult({ services: ['ICMP/8/0'], protos: ['ICMP'] }, config);
  assert.equal(result.found, false);
  assert.equal(result.name, null);
});

test('FF2-03 ICMP exige une famille observée unique et cohérente', () => {
  const config = fortiConfig(`
    edit "PING4"
        set protocol ICMP
        set icmptype 8
        set icmpcode 0
    next
    edit "PING6"
        set protocol ICMP6
        set icmptype 128
        set icmpcode 0
    next
  `);

  for (const protos of [[], ['ICMP', 'ICMP6'], ['PROTO58']]) {
    const input = policy({ services: ['ICMP/8/0'], protos });
    const authoritative = analyzePolicies([input], config);
    assert.equal(authoritative[0].analysis.services[0].found, false);
    const decision = applyPolicyUserDecisions(authoritative, [input], config, [
      observedFlow({ service: 'ICMP/8/0', dstport: '', proto: '58', protoName: 'PROTO58' }),
    ]);
    assert.equal(decision.ok, false);
    assert.ok(decision.issues.some(issue => issue.code === 'SERVICE_DECISION_UNPROVEN'));
  }

  const icmp6 = serviceResult({ services: ['ICMP6/128/0'], protos: ['ICMP6'] }, config);
  assert.equal(icmp6.found, true);
  assert.equal(icmp6.name, 'PING6');
});

test('FF2-03 une notation de port contradictoire reste non résolue et refusée', () => {
  const config = fortiConfig('');
  for (const scenario of [
    { ports: [443], protos: ['UDP'] },
    { ports: [80], protos: ['TCP'] },
    { ports: [443, 8443], protos: ['TCP'] },
  ]) {
    const input = policy({ services: ['TCP/443'], ...scenario });
    const authoritative = analyzePolicies([input], config);
    const service = authoritative[0].analysis.services[0];
    assert.equal(service.found, false);
    assert.equal(service.technicalConflict, true);

    const decision = applyPolicyUserDecisions(authoritative, [input], config, [
      observedFlow({ service: 'TCP/443', dstport: '443', proto: '6', protoName: 'TCP' }),
    ]);
    assert.equal(decision.ok, false);
    assert.ok(decision.issues.some(issue => issue.code === 'SERVICE_DECISION_UNPROVEN'));
  }
});

test('FF2-03 une compatibilité nommée multiport est réutilisable explicitement', () => {
  const config = fortiConfig(`
    edit "APP-WIDE"
        set tcp-portrange 400-500 8443
    next
  `);
  const input = policy({ services: ['APP-WIDE'], ports: [443, 8443], protos: ['TCP'] });
  const proposed = analyzePolicies([input], config)[0].analysis.services[0];
  assert.equal(proposed.found, false);
  assert.equal(proposed.compatibleMatch.name, 'APP-WIDE');
  assert.deepEqual(proposed.reuseKeys, ['TCP/443', 'TCP/8443']);

  input._serviceReuse = { 'TCP/443': 'APP-WIDE', 'TCP/8443': 'APP-WIDE' };
  const authoritative = analyzePolicies([input], config);
  assert.equal(authoritative[0].analysis.services[0].compatibilityAccepted, true);
  const insufficient = applyPolicyUserDecisions(authoritative, [input], config, [
    observedFlow({ service: 'APP-WIDE', dstport: '443' }),
  ]);
  assert.equal(insufficient.ok, false);
  assert.ok(insufficient.issues.some(issue => issue.code === 'SERVICE_DECISION_UNPROVEN'));

  const decision = applyPolicyUserDecisions(authoritative, [input], config, [
    observedFlow({ service: 'APP-WIDE', dstport: '443' }),
    observedFlow({ service: 'APP-WIDE', dstport: '8443' }),
  ]);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.equal((cli.match(/"APP-WIDE"/g) || []).length, 1);
});

test('FF2-03 une création spécifique multiport est revalidée avant génération', () => {
  const config = fortiConfig(`
    edit "APP-WIDE"
        set tcp-portrange 400-500 8443
    next
  `);
  const selected = analyzePolicies([
    policy({ services: ['APP-WIDE'], ports: [443, 8443], protos: ['TCP'] }),
  ], config)[0];
  selected._resolvedServiceKeys = { 'TCP/443': 'specific', 'TCP/8443': 'specific' };
  selected.analysis.services[0].suggestedName = 'APP-SPECIFIC';
  selected.analysis.services[0].ports = [443, 8443];
  selected.analysis.services[0].sourcePorts = [443, 8443];
  selected.analysis.services[0].proto = 'TCP';

  const authoritative = analyzePolicies([selected], config);
  const decision = applyPolicyUserDecisions(authoritative, [selected], config, [
    observedFlow({ service: 'APP-WIDE', dstport: '443' }),
    observedFlow({ service: 'APP-WIDE', dstport: '8443' }),
  ]);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.match(cli, /edit "APP-SPECIFIC"/);
  assert.match(cli, /set tcp-portrange 443 8443/);
  assert.match(cli, /set service "APP-SPECIFIC"/);
  assert.doesNotMatch(cli, /set service "APP-WIDE"/);
});

test('FF2-03 plusieurs codes ICMP compatibles conservent toutes les clés explicites', () => {
  const config = fortiConfig(`
    edit "PING-TYPE"
        set protocol ICMP
        set icmptype 8
    next
  `);
  const input = policy({ services: ['ICMP/8/0', 'ICMP/8/1'], protos: ['ICMP'] });
  input._serviceReuse = { 'ICMP/8/0': 'PING-TYPE', 'ICMP/8/1': 'PING-TYPE' };
  const authoritative = analyzePolicies([input], config);
  assert.equal(authoritative[0].analysis.services.length, 1);
  assert.deepEqual(authoritative[0].analysis.services[0].reuseKeys, ['ICMP/8/0', 'ICMP/8/1']);
  assert.ok(authoritative[0].analysis.services.every(service => service.compatibilityAccepted));
  const decision = applyPolicyUserDecisions(authoritative, [input], config, [
    observedFlow({ service: 'ICMP/8/0', dstport: '', proto: '1', protoName: 'ICMP' }),
    observedFlow({ service: 'ICMP/8/1', dstport: '', proto: '1', protoName: 'ICMP' }),
  ]);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.equal((cli.match(/"PING-TYPE"/g) || []).length, 1);
});

test('FF2-03 les types et codes ICMP malformés ne sont jamais tronqués', () => {
  for (const [type, code] of [['8foo', '0foo'], ['8.5', '0.5'], ['256', '0'], ['8', '256']]) {
    const config = fortiConfig(`
      edit "BAD"
          set protocol ICMP
          set icmptype ${type}
          set icmpcode ${code}
      next
    `);
    const result = serviceResult({ services: ['ICMP/8/0'], protos: ['ICMP'] }, config);
    assert.equal(result.found, false, `${type}/${code}`);
    assert.equal(result.name, null, `${type}/${code}`);
  }
});

test('FF2-03 le chemin buildAnalysis conserve ICMP6 de bout en bout', () => {
  const analysis = buildAnalysis([{
    srcip: '10.0.0.10', dstip: '10.0.1.20', srcport: '', dstport: '',
    proto: '58', action: 'accept', service: 'ICMP6/128/0',
    srcintf: 'LAN', dstintf: 'DMZ', policyid: '1', count: 1,
    sentBytes: 64, rcvdBytes: 64,
  }]);
  assert.equal(analysis.flows[0].protoName, 'ICMP6');
  assert.deepEqual(analysis.policies[0].protos, ['ICMP6']);

  const config = fortiConfig(`
    edit "PING6"
        set protocol ICMP6
        set icmptype 128
        set icmpcode 0
    next
  `);
  const resolved = analyzePolicies(analysis.policies, config)[0].analysis.services[0];
  assert.equal(resolved.found, true);
  assert.equal(resolved.name, 'PING6');
});

test('FF2-03 un token de port malformé reste inconnu', () => {
  const config = fortiConfig('');
  const input = policy({ services: ['UNKNOWN'], ports: ['443foo'], protos: ['TCP'] });
  const authoritative = analyzePolicies([input], config);
  const service = authoritative[0].analysis.services[0];
  assert.equal(service.found, false);
  assert.equal(service.technicalConflict, true);
  assert.notEqual(service.name, 'HTTPS');

  const decision = applyPolicyUserDecisions(authoritative, [input], config, [
    observedFlow({ service: 'UNKNOWN', dstport: '443' }),
  ]);
  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'SERVICE_DECISION_UNPROVEN'));
});

test('FF2-03 le protocole déclaré interdit les ranges techniques contradictoires', () => {
  const config = fortiConfig(`
    edit "BAD-PROTO"
        set protocol UDP
        set tcp-portrange 443
    next
  `);
  const result = serviceResult({ services: ['BAD-PROTO'], ports: [443], protos: ['TCP'] }, config);
  assert.equal(result.found, false);
  assert.equal(result.name, null);
  assert.notEqual(result.compatibleMatch?.name, 'BAD-PROTO');
});

test('FF2-03 un range custom malformé n’est jamais réduit à un port valide', () => {
  for (const token of ['443-foo', '443-444foo', '443foo']) {
    const config = fortiConfig(`
      edit "BAD-RANGE"
          set protocol TCP
          set tcp-portrange ${token}
      next
    `);
    const result = serviceResult({ services: ['BAD-RANGE'], ports: [443], protos: ['TCP'] }, config);
    assert.equal(result.found, false, token);
    assert.notEqual(result.name, 'BAD-RANGE', token);
    assert.notEqual(result.compatibleMatch?.name, 'BAD-RANGE', token);
  }
});

test('FF2-03 les tokens de port malformés restent absents du resolver et des statistiques', () => {
  const resolution = findService('22foo', 'TCP', {});
  assert.equal(resolution.found, false);
  assert.equal(resolution.compatibleMatch, undefined);

  const analysis = buildAnalysis([{
    srcip: '10.0.0.10', dstip: '10.0.1.20', srcport: '55000', dstport: '22foo',
    proto: '6', action: 'accept', service: 'UNKNOWN',
    srcintf: 'LAN', dstintf: 'DMZ', policyid: '1', count: 1,
    sentBytes: 64, rcvdBytes: 64,
  }]);
  assert.deepEqual(analysis.portStats.tcp, []);
  assert.deepEqual(analysis.policies[0].ports, []);
});

test('FF2-03 aucun port observé n’est tronqué avant la génération', () => {
  const ports = Array.from({ length: 25 }, (_, index) => 10000 + index);
  const config = fortiConfig('');
  const analyzed = analyzePolicies([policy({ services: [], ports, protos: ['TCP'] })], config);
  assert.equal(analyzed[0].analysis.services.length, ports.length);
  assert.deepEqual(analyzed[0].analysis.services.map(service => service.port), ports);

  const flows = ports.map((port, index) => ({
    srcip: '10.0.0.10', dstip: '10.0.1.20', srcport: String(55000 + index), dstport: String(port),
    proto: '6', action: 'accept', service: '',
    srcintf: 'LAN', dstintf: 'DMZ', policyid: '1', count: 1,
    sentBytes: 64, rcvdBytes: 64,
  }));
  const analysis = buildAnalysis(flows);
  assert.deepEqual(analysis.policies[0].ports, ports);
});

test('FF2-03 la consolidation conserve l’empreinte protocole et ports des services nommés', () => {
  const base = {
    dstTarget: '10.0.1.0/24', dstType: 'private', services: ['APP'], serviceDesc: 'APP',
    sessions: 1, sentBytes: 64, rcvdBytes: 64, noRcvdFlows: 0, noRcvdSrcHosts: [],
  };
  const consolidated = consolidatePolicies([
    { ...base, srcSubnet: '10.0.0.0/24', ports: [443], protos: ['TCP'] },
    { ...base, srcSubnet: '10.0.2.0/24', ports: [8443], protos: ['TCP'] },
    { ...base, srcSubnet: '10.0.3.0/24', ports: [443], protos: ['UDP'] },
  ]);
  assert.equal(consolidated.length, 3);
  assert.deepEqual(consolidated.map(item => [item.ports, item.protos]), [
    [[443], ['TCP']],
    [[8443], ['TCP']],
    [[443], ['UDP']],
  ]);
});
