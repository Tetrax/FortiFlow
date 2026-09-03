'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const {
  parseFortiConfig,
  analyzePolicies,
  buildPolicyStrategyPreviews,
  autoFinalizeExactObjectDecisions,
  applyPolicyUserDecisions,
  generateConfig,
} = require('../lib/forticonfig');

function fortiConfig(extra = '') {
  return parseFortiConfig(`
config system interface
    edit "LAN"
        set ip 10.0.0.1 255.255.255.0
    next
    edit "DMZ"
        set ip 10.0.1.1 255.255.255.0
    next
    edit "WAN"
        set ip 192.0.2.1 255.255.255.0
        set role wan
    next
end
${extra}
`);
}

function policy(overrides = {}) {
  return {
    srcSubnet: '10.0.0.0/24',
    dstTarget: '10.0.1.0/24',
    dstType: 'private',
    services: ['HTTPS'],
    ports: [443],
    protos: ['TCP'],
    srcHosts: ['10.0.0.10'],
    dstHosts: ['10.0.1.20'],
    flowSrcintf: 'LAN',
    srcintf: 'LAN',
    dstintf: 'DMZ',
    action: 'accept',
    ...overrides,
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
    service: 'HTTPS',
    dstport: '443',
    proto: '6',
    protoName: 'TCP',
    action: 'accept',
    ...overrides,
  };
}

function analyzedAndFinalized(inputPolicies, config, flows) {
  const analyzed = analyzePolicies(inputPolicies, config, undefined, flows);
  const before = structuredClone(analyzed);
  const finalized = autoFinalizeExactObjectDecisions(analyzed, config, flows);
  assert.deepEqual(analyzed, before, 'l’auto-finalisation ne doit pas muter le résultat autoritatif');
  return { analyzed, finalized };
}

function validateAndGenerate(analyzed, finalized, config, flows) {
  const decision = applyPolicyUserDecisions(analyzed, finalized, config, flows);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  return generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    serviceGroups: config.serviceGroups,
    zones: config.zones,
  });
}

test('auto-finalise la création d’un subnet exact avec un nom déterministe', () => {
  const config = fortiConfig();
  const input = policy();
  const flows = [observedFlow()];
  const { analyzed, finalized } = analyzedAndFinalized([input], config, flows);

  assert.equal(finalized[0]._srcAddrName, 'FF_10_0_0_0_24');
  assert.equal(finalized[0]._dstAddrName, 'FF_10_0_1_0_24');
  assert.equal(finalized[0]._resolvedObjectKeys['addr:src'], 'FF_10_0_0_0_24');
  assert.equal(finalized[0]._resolvedObjectKeys['addr:dst'], 'FF_10_0_1_0_24');

  const cli = validateAndGenerate(analyzed, finalized, config, flows);
  assert.match(cli, /edit "FF_10_0_0_0_24"[\s\S]*set subnet 10\.0\.0\.0 255\.255\.255\.0/);
  assert.match(cli, /edit "FF_10_0_1_0_24"[\s\S]*set subnet 10\.0\.1\.0 255\.255\.255\.0/);
});

test('auto-finalise une destination Internet /32 sans élargissement', () => {
  const config = fortiConfig();
  const input = policy({
    dstTarget: '8.8.8.8',
    dstType: 'public',
    dstHosts: ['8.8.8.8'],
    _dstUseAll: false,
    _use32Dst: true,
    dstintf: 'WAN',
  });
  const flows = [observedFlow({
    dstip: '8.8.8.8',
    dstSubnet: undefined,
    dstType: 'public',
    dstintf: 'WAN',
  })];
  const { analyzed, finalized } = analyzedAndFinalized([input], config, flows);

  assert.equal(finalized[0]._dstHostNames['8.8.8.8'], 'FF_HOST_8_8_8_8');
  assert.equal(finalized[0]._resolvedObjectKeys['host:dst:8.8.8.8'], 'FF_HOST_8_8_8_8');

  const cli = validateAndGenerate(analyzed, finalized, config, flows);
  assert.match(cli, /edit "FF_HOST_8_8_8_8"[\s\S]*set subnet 8\.8\.8\.8 255\.255\.255\.255/);
  assert.doesNotMatch(cli, /set dstaddr "all"/);
});

test('la collision du nom déterministe d’adresse reste non résolue', () => {
  const config = fortiConfig(`
config firewall address
    edit "FF_10_0_0_0_24"
        set subnet 10.99.0.0 255.255.255.0
    next
end
`);
  const { finalized } = analyzedAndFinalized([policy()], config, [observedFlow()]);

  assert.equal(finalized[0]._srcAddrName || '', '');
  assert.equal(finalized[0]._resolvedObjectKeys?.['addr:src'], undefined);
});

test('un même CIDR garde le même nom déterministe dans toutes les représentations', () => {
  const config = fortiConfig();
  const flows = [observedFlow()];
  const analyzed = analyzePolicies([policy(), policy()], config, 'WAN', flows);
  analyzed[1]._multiSrcSubnets = [{
    subnet: '10.0.0.0/24', hosts: ['10.0.0.10'], useSubnet: true,
    addrFound: false, addrName: 'FF_NET_10_0_0_0_24', suggestedName: 'FF_NET_10_0_0_0_24',
  }];

  const finalized = autoFinalizeExactObjectDecisions(analyzed, config, flows);

  assert.equal(finalized[0]._srcAddrName, 'FF_10_0_0_0_24');
  assert.equal(finalized[1]._multiSrcSubnets[0].addrName, 'FF_10_0_0_0_24');
});

test('auto-finalise un service simple strictement spécifique', () => {
  const config = fortiConfig();
  const input = policy({ services: ['TEAMVIEWER-TEAMVIEWER'], ports: [5938] });
  const flows = [observedFlow({ service: 'TEAMVIEWER-TEAMVIEWER', dstport: '5938' })];
  const { analyzed, finalized } = analyzedAndFinalized([input], config, flows);
  const service = finalized[0].analysis.services[0];

  assert.equal(service.suggestedName, 'FF_SVC_5938_TCP');
  assert.equal(finalized[0]._resolvedServiceKeys['TCP/5938'], 'specific');

  const cli = validateAndGenerate(analyzed, finalized, config, flows);
  assert.match(cli, /edit "FF_SVC_5938_TCP"[\s\S]*set tcp-portrange 5938/);
});

test('auto-finalise un service exact composé de plusieurs ports observés', () => {
  const config = fortiConfig(`
config firewall service custom
    edit "APP-WIDE"
        set tcp-portrange 400-9000
    next
end
`);
  const input = policy({ services: ['APP-WIDE'], ports: [443, 8443] });
  const flows = [
    observedFlow({ service: 'APP-WIDE', dstport: '443' }),
    observedFlow({ service: 'APP-WIDE', dstport: '8443' }),
  ];
  const { analyzed, finalized } = analyzedAndFinalized([input], config, flows);
  const service = finalized[0].analysis.services[0];

  assert.equal(service.suggestedName, 'FF_SVC_TCP_443_8443');
  assert.deepEqual(service.ports, [443, 8443]);
  assert.deepEqual(finalized[0]._resolvedServiceKeys, {
    'TCP/443': 'specific',
    'TCP/8443': 'specific',
  });

  const cli = validateAndGenerate(analyzed, finalized, config, flows);
  assert.match(cli, /edit "FF_SVC_TCP_443_8443"[\s\S]*set tcp-portrange 443 8443/);
});

test('un service existant plus large n’est jamais auto-réutilisé', () => {
  const config = fortiConfig(`
config firewall service custom
    edit "DNS"
        set tcp-portrange 53
        set udp-portrange 53
    next
end
`);
  const input = policy({ services: ['GOOGLE-DNS'], ports: [53], protos: ['UDP'] });
  const flows = [observedFlow({ service: 'GOOGLE-DNS', dstport: '53', proto: '17', protoName: 'UDP' })];
  const { analyzed, finalized } = analyzedAndFinalized([input], config, flows);
  const service = finalized[0].analysis.services[0];

  assert.equal(service.found, false);
  assert.equal(service.suggestedName, 'FF_SVC_53_UDP');
  assert.equal(finalized[0]._serviceReuse?.['UDP/53'], undefined);
  assert.equal(finalized[0]._resolvedServiceKeys['UDP/53'], 'specific');

  const cli = validateAndGenerate(analyzed, finalized, config, flows);
  assert.match(cli, /edit "FF_SVC_53_UDP"[\s\S]*set udp-portrange 53/);
  assert.doesNotMatch(cli, /set service "DNS"/);
});

test('la collision du nom technique d’un service reste non résolue', () => {
  const config = fortiConfig(`
config firewall service custom
    edit "FF_SVC_53_UDP"
        set udp-portrange 54
    next
end
`);
  const input = policy({ services: ['GOOGLE-DNS'], ports: [53], protos: ['UDP'] });
  const flows = [observedFlow({ service: 'GOOGLE-DNS', dstport: '53', proto: '17', protoName: 'UDP' })];
  const { finalized } = analyzedAndFinalized([input], config, flows);

  assert.equal(finalized[0]._resolvedServiceKeys?.['UDP/53'], undefined);
  assert.equal(finalized[0].analysis.services[0].suggestedName, 'GOOGLE-DNS');
});

test('les objets et services strictement équivalents existants restent réutilisés', () => {
  const config = fortiConfig(`
config firewall address
    edit "SRC-EXACT"
        set subnet 10.0.0.0 255.255.255.0
    next
    edit "DST-EXACT"
        set subnet 10.0.1.0 255.255.255.0
    next
end
config firewall service custom
    edit "APP-EXACT"
        set udp-portrange 5353
    next
end
`);
  const input = policy({ services: ['OBSERVED-APP'], ports: [5353], protos: ['UDP'] });
  const flows = [observedFlow({ service: 'OBSERVED-APP', dstport: '5353', proto: '17', protoName: 'UDP' })];
  const { finalized } = analyzedAndFinalized([input], config, flows);

  assert.equal(finalized[0].analysis.srcAddr.name, 'SRC-EXACT');
  assert.equal(finalized[0].analysis.dstAddr.name, 'DST-EXACT');
  assert.equal(finalized[0].analysis.services[0].name, 'APP-EXACT');
  assert.equal(finalized[0]._resolvedObjectKeys, undefined);
  assert.equal(finalized[0]._resolvedServiceKeys, undefined);
});

test('un /32 exact existant reste marqué trouvé après reconstruction de stratégie', () => {
  const config = fortiConfig(`
config firewall address
    edit "EXACT-HOST"
        set subnet 10.0.1.20 255.255.255.255
    next
end
`);
  const flows = [observedFlow()];
  const analyzed = analyzePolicies([policy({ _dstMode: 'hosts', _use32Dst: true })], config, undefined, flows);
  const reconstructed = [{
    ...analyzed[0],
    _dstHostsFound: [],
    _dstHostNames: {},
  }];
  const finalized = autoFinalizeExactObjectDecisions(reconstructed, config, flows);

  assert.deepEqual(finalized[0]._dstHostsFound, ['10.0.1.20']);
  assert.equal(finalized[0]._dstHostNames['10.0.1.20'], 'EXACT-HOST');
  assert.equal(finalized[0]._resolvedObjectKeys?.['host:dst:10.0.1.20'], undefined);
});

test('les services ICMP insuffisamment prouvés restent manuels et fail-closed', () => {
  const config = fortiConfig(`
config firewall service custom
    edit "PING"
        set protocol ICMP
        set icmptype 8
    next
end
`);

  for (const label of ['PING', 'ICMP/0/8', 'GOOGLE-ICMP']) {
    const input = policy({ services: [label], ports: [], protos: ['ICMP'] });
    const flows = [observedFlow({ service: label, dstport: '', proto: '1', protoName: 'ICMP' })];
    const { analyzed, finalized } = analyzedAndFinalized([input], config, flows);

    assert.equal(finalized[0]._resolvedServiceKeys, undefined, label);
    const decision = applyPolicyUserDecisions(analyzed, finalized, config, flows);
    assert.equal(decision.ok, false, label);
    assert.ok(decision.issues.some(issue =>
      ['SERVICE_DECISION_AMBIGUOUS', 'SERVICE_DECISION_UNPROVEN'].includes(issue.code)),
    `${label}: ${JSON.stringify(decision.issues)}`);
  }
});

test('les labels ICMP réservés restent manuels même avec un tuple TCP ou UDP apparent', () => {
  const config = fortiConfig();

  for (const label of ['PING', 'ICMP/0/8', 'GOOGLE-ICMP']) {
    const input = policy({ services: [label], ports: [443], protos: ['TCP'] });
    const flows = [observedFlow({ service: label, dstport: '443', proto: '6', protoName: 'TCP' })];
    const { finalized } = analyzedAndFinalized([input], config, flows);

    assert.equal(finalized[0]._resolvedServiceKeys, undefined, label);
    assert.equal(finalized[0].analysis.services[0].suggestedName, label, label);
  }
});

test('une plage IP couvrante ne remplace jamais la création exacte d’un hôte /32', () => {
  const config = fortiConfig(`
config firewall address
    edit "WIDE-RANGE"
        set type iprange
        set start-ip 10.0.0.1
        set end-ip 10.0.0.254
    next
end
`);
  const input = policy({ _use32Src: true, _srcMode: 'hosts' });
  const flows = [observedFlow()];
  const { finalized } = analyzedAndFinalized([input], config, flows);

  assert.equal(finalized[0]._srcHostNames['10.0.0.10'], 'FF_HOST_10_0_0_10');
  assert.equal(finalized[0]._resolvedObjectKeys['host:src:10.0.0.10'], 'FF_HOST_10_0_0_10');
  assert.equal((finalized[0]._srcHostsFound || []).includes('10.0.0.10'), false);

  const decision = applyPolicyUserDecisions(finalized, finalized, config, flows);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    serviceGroups: config.serviceGroups,
    zones: config.zones,
  });
  assert.match(cli, /edit "FF_HOST_10_0_0_10"[\s\S]*set subnet 10\.0\.0\.10 255\.255\.255\.255/);
  assert.doesNotMatch(cli, /set srcaddr "WIDE-RANGE"/);
});

test('une plage IP couvrante ne remplace pas un /32 utilisé en représentation subnet', () => {
  const config = fortiConfig(`
config firewall address
    edit "WIDE-RANGE"
        set type iprange
        set start-ip 10.0.0.1
        set end-ip 10.0.0.254
    next
end
`);
  const input = policy({
    srcSubnet: '10.0.0.10/32',
    _use32Src: false,
    _srcMode: 'subnet',
  });
  const flows = [observedFlow({ srcSubnet: '10.0.0.10/32' })];
  const { finalized } = analyzedAndFinalized([input], config, flows);

  assert.equal(finalized[0]._srcAddrName, 'FF_HOST_10_0_0_10');
  assert.equal(finalized[0]._resolvedObjectKeys['addr:src'], 'FF_HOST_10_0_0_10');
  assert.equal(finalized[0].analysis.srcAddr.found, false);

  const decision = applyPolicyUserDecisions(finalized, finalized, config, flows);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    serviceGroups: config.serviceGroups,
    zones: config.zones,
  });
  assert.match(cli, /edit "FF_HOST_10_0_0_10"[\s\S]*set subnet 10\.0\.0\.10 255\.255\.255\.255/);
  assert.doesNotMatch(cli, /set srcaddr "WIDE-RANGE"/);
});

test('une policy multi-hôtes auto-finalise uniquement chaque /32 observé', () => {
  const config = fortiConfig();
  const input = policy({
    _dstMode: 'hosts',
    _use32Dst: false,
    dstHosts: ['10.0.1.20', '10.0.1.21'],
    _multiDstSubnets: [{
      subnet: '10.0.1.0/24',
      hosts: ['10.0.1.20', '10.0.1.21'],
      useSubnet: false,
      addrFound: false,
    }],
  });
  const flows = [observedFlow()];
  const { finalized } = analyzedAndFinalized([input], config, flows);

  assert.equal(finalized[0]._resolvedObjectKeys['host:dst:10.0.1.20'], 'FF_HOST_10_0_1_20');
  assert.equal(finalized[0]._resolvedObjectKeys['host:dst:10.0.1.21'], undefined);
});

test('un subnet multi-scope forgé par un hôte hors CIDR reste non résolu et refusé', () => {
  const config = fortiConfig();
  for (const side of ['src', 'dst']) {
    const input = policy();
    const item = {
      subnet: '10.99.0.0/24',
      hosts: [side === 'src' ? '10.0.0.10' : '10.0.1.20'],
      useSubnet: true,
      addrFound: false,
      addrName: '',
      suggestedName: 'FF_10_99_0_0_24',
    };
    input[side === 'src' ? '_multiSrcSubnets' : '_multiDstSubnets'] = [item];
    const analyzed = analyzePolicies([input], config, undefined, [observedFlow()]);
    const finalized = autoFinalizeExactObjectDecisions(analyzed, config, [observedFlow()]);

    assert.equal(finalized[0]._resolvedObjectKeys?.[`multi-${side}:0`], undefined, side);
    assert.equal(finalized[0][side === 'src' ? '_multiSrcSubnets' : '_multiDstSubnets'][0].addrName, '', side);
    const decision = applyPolicyUserDecisions(analyzed, finalized, config, [observedFlow()]);
    assert.equal(decision.ok, false, `${side}: ${JSON.stringify(decision.issues)}`);
  }
});

test('une édition de nom invalide les marqueurs automatiques au prochain passage backend', () => {
  const config = fortiConfig();
  const flows = [observedFlow()];
  const analyzed = analyzePolicies([policy({ _dstMode: 'hosts', _use32Dst: true })], config, undefined, flows);
  const first = autoFinalizeExactObjectDecisions(analyzed, config, flows);
  const edited = structuredClone(first);
  edited[0]._srcAddrName = 'CUSTOM-SRC';
  edited[0]._dstHostNames['10.0.1.20'] = 'CUSTOM-HOST';
  edited[0].analysis.services[0].suggestedName = 'CUSTOM-SVC';

  const second = autoFinalizeExactObjectDecisions(edited, config, flows);
  assert.equal(second[0]._srcAddrName, 'CUSTOM-SRC');
  assert.equal(second[0]._resolvedObjectKeys?.['addr:src'], 'CUSTOM-SRC');
  assert.equal(second[0]._dstHostNames['10.0.1.20'], 'CUSTOM-HOST');
  assert.equal(second[0]._resolvedObjectKeys?.['host:dst:10.0.1.20'], 'CUSTOM-HOST');
  assert.equal(second[0].analysis.services[0].suggestedName, 'CUSTOM-SVC');
  assert.equal(second[0]._resolvedServiceKeys?.['TCP/443'], 'specific');
});

test('la suppression d’un scope multi ne transfère pas le marqueur indexé au suivant', () => {
  const config = fortiConfig();
  const flows = [
    observedFlow(),
    observedFlow({ srcip: '10.0.2.10', srcSubnet: '10.0.2.0/24' }),
  ];
  const input = policy({
    srcSubnets: ['10.0.0.0/24', '10.0.2.0/24'],
    _multiSrcSubnets: [
      { subnet: '10.0.0.0/24', hosts: ['10.0.0.10'], useSubnet: true, addrFound: false, addrName: '' },
      { subnet: '10.0.2.0/24', hosts: ['10.0.2.10'], useSubnet: true, addrFound: false, addrName: '' },
    ],
  });
  const analyzed = analyzePolicies([input], config, undefined, flows);
  const first = autoFinalizeExactObjectDecisions(analyzed, config, flows);
  const edited = structuredClone(first);
  edited[0]._multiSrcSubnets.shift();
  edited[0].srcSubnets = ['10.0.2.0/24'];

  const second = autoFinalizeExactObjectDecisions(edited, config, flows);
  assert.equal(second[0]._multiSrcSubnets[0].addrName, 'FF_10_0_2_0_24');
  assert.notEqual(second[0]._resolvedObjectKeys?.['multi-src:0'], 'FF_10_0_0_0_24');
});

test('les previews de stratégie conservent les noms exacts auto-finalisés', () => {
  const config = fortiConfig();
  const flows = [observedFlow()];
  const analyzed = autoFinalizeExactObjectDecisions(
    analyzePolicies([policy()], config, undefined, flows), config, flows,
  );
  const previews = buildPolicyStrategyPreviews(analyzed, { scope: 'all' });

  for (const strategy of Object.values(previews.strategies)) {
    const [result] = autoFinalizeExactObjectDecisions(strategy.policies, config, flows);
    assert.equal(result._srcAddrName, 'FF_10_0_0_0_24');
    assert.equal(result._dstAddrName, 'FF_10_0_1_0_24');
    assert.equal(result._resolvedObjectKeys['addr:src'], 'FF_10_0_0_0_24');
    assert.equal(result._resolvedObjectKeys['addr:dst'], 'FF_10_0_1_0_24');
  }
});

function frontendFunction(name, nextMarker, context = {}) {
  const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
  const start = source.indexOf(`function ${name}`);
  const end = source.indexOf(nextMarker, start + 20);
  assert.ok(start >= 0 && end > start, `${name} introuvable`);
  vm.createContext(context);
  vm.runInContext(source.slice(start, end), context);
  return context[name];
}

test('les marqueurs frontend suivent les renommages et sont purgés par côté', () => {
  const context = { Object };
  const update = frontendFunction(
    'updateDrawerObjectResolution', '\nfunction clearDrawerObjectResolution', context,
  );
  const clear = frontendFunction(
    'clearDrawerObjectResolution', '\nfunction clearDrawerObjectResolutionsForSide', context,
  );
  const clearSide = frontendFunction(
    'clearDrawerObjectResolutionsForSide', '\nfunction markDrawerObjectResolved', context,
  );
  const input = {
    _resolvedObjectKeys: {
      'addr:src': 'AUTO-SRC',
      'host:src:10.0.0.10': 'AUTO-HOST',
      'multi-src:0': 'AUTO-MULTI',
      'addr:dst': 'AUTO-DST',
    },
  };

  update(input, 'addr:src', 'CUSTOM-SRC');
  assert.equal(input._resolvedObjectKeys['addr:src'], 'CUSTOM-SRC');
  clear(input, 'host:src:10.0.0.10');
  assert.equal(input._resolvedObjectKeys['host:src:10.0.0.10'], undefined);
  clearSide(input, 'src');
  assert.deepEqual(input._resolvedObjectKeys, { 'addr:dst': 'AUTO-DST' });
});

test('les handlers de nom, mode et suppression maintiennent les marqueurs cohérents', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
  assert.match(source, /drawer-src-name[\s\S]{0,300}updateDrawerObjectResolution\(p, 'addr:src'/);
  assert.match(source, /drawer-host-input[\s\S]{0,600}updateDrawerObjectResolution\(p, `host:\$\{type\}:\$\{host\}`/);
  assert.match(source, /drawer-multidst-name[\s\S]{0,350}updateDrawerObjectResolution\(p, `multi-dst:\$\{si\}`/);
  assert.match(source, /drawer-multisrc-name[\s\S]{0,450}updateDrawerObjectResolution\(p, `multi-src:\$\{si\}`/);
  assert.match(source, /drawer-mode-btn[\s\S]{0,500}clearDrawerObjectResolutionsForSide\(p, type\)/);
  assert.match(source, /btn-del-item[\s\S]{0,1600}clearDrawerObjectResolutionsForSide\(p, 'src'\)/);
  assert.match(source, /btn-del-item[\s\S]{0,1800}clearDrawerObjectResolutionsForSide\(p, 'dst'\)/);
});

test('la complétude frontend reconnaît un /32 auto-finalisé par le backend', () => {
  const policyMissingMandatoryFields = frontendFunction(
    'policyMissingMandatoryFields', '\nfunction isPolicyComplete', { Set },
  );
  const input = {
    _srcintf: 'LAN',
    _dstintf: 'WAN',
    _use32Dst: true,
    _dstMode: 'hosts',
    dstType: 'public',
    dstHosts: ['8.8.8.8'],
    _dstHostNames: { '8.8.8.8': 'FF_HOST_8_8_8_8' },
    _resolvedObjectKeys: { 'host:dst:8.8.8.8': 'FF_HOST_8_8_8_8' },
    analysis: {
      srcAddr: { found: true },
      dstAddr: { found: false },
      services: [{ found: true, label: 'HTTPS' }],
    },
  };

  assert.deepEqual([...policyMissingMandatoryFields(input)], []);
});

test('le gate de génération frontend reconnaît un /32 auto-finalisé par le backend', () => {
  const context = {
    Set,
    console,
    cleanHostName(host, name) { return name; },
    isCompatibleServiceSelected() { return false; },
  };
  const isPolicyComplete = frontendFunction(
    'isPolicyComplete', '\nfunction syncRowStatus', context,
  );
  const input = {
    _srcintf: 'LAN',
    _dstintf: 'WAN',
    _use32Dst: true,
    _dstMode: 'hosts',
    dstType: 'public',
    dstHosts: ['8.8.8.8'],
    _dstHostNames: { '8.8.8.8': 'FF_HOST_8_8_8_8' },
    _resolvedObjectKeys: { 'host:dst:8.8.8.8': 'FF_HOST_8_8_8_8' },
    analysis: {
      srcAddr: { found: true },
      dstAddr: { found: false },
      services: [{ found: true, label: 'HTTPS' }],
    },
  };

  assert.equal(isPolicyComplete(input), true);
});

test('l’enrichissement frontend conserve les noms exacts fournis par le backend', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
  assert.match(source, /_srcAddrName:\s+p\._srcAddrName\s*\|\|\s*p\.analysis\?\.srcAddr\?\.name\s*\|\|\s*''/);
  assert.match(source, /_dstAddrName:\s+p\._dstAddrName\s*\|\|\s*p\.analysis\?\.dstAddr\?\.name\s*\|\|\s*''/);
});

test('un changement de représentation destination invalide les décisions d’objet devenues obsolètes', () => {
  const context = {
    destinationDetectedForPolicy() { return []; },
    destinationAggregateSubnet() { return '10.0.1.0/24'; },
  };
  const setDestinationRepresentation = frontendFunction(
    'setDestinationRepresentation', '\nfunction destinationProvenanceLabel', context,
  );
  const input = {
    dstTarget: '10.0.1.0/24',
    dstTargets: ['10.0.1.0/24'],
    dstHosts: ['10.0.1.20'],
    _dstAddrName: 'FF_10_0_1_0_24',
    _resolvedObjectKeys: {
      'addr:dst': 'FF_10_0_1_0_24',
      'host:dst:10.0.1.20': 'FF_HOST_10_0_1_20',
      'addr:src': 'FF_10_0_0_0_24',
    },
  };

  assert.equal(setDestinationRepresentation(input, 'hosts'), true);
  assert.equal(input._resolvedObjectKeys['addr:dst'], undefined);
  assert.equal(input._resolvedObjectKeys['host:dst:10.0.1.20'], undefined);
  assert.equal(input._resolvedObjectKeys['addr:src'], 'FF_10_0_0_0_24');
});

test('une représentation destination indisponible ne modifie aucune décision existante', () => {
  const context = {
    destinationDetectedForPolicy() { return []; },
    destinationAggregateSubnet() { return '10.0.1.0/24'; },
  };
  const setDestinationRepresentation = frontendFunction(
    'setDestinationRepresentation', '\nfunction destinationProvenanceLabel', context,
  );
  const input = {
    _resolvedObjectKeys: { 'addr:dst': 'FF_10_0_1_0_24' },
  };

  assert.equal(setDestinationRepresentation(input, 'detected-subnets'), false);
  assert.equal(input._resolvedObjectKeys['addr:dst'], 'FF_10_0_1_0_24');
});

test('une édition de CIDR destination invalide le marqueur exact associé', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
  assert.match(source, /drawer-destination-cidr[\s\S]{0,700}delete p\._resolvedObjectKeys\[`multi-dst:\$\{si\}`\]/);
  assert.match(source, /drawer-destination-aggregate-cidr[\s\S]{0,900}delete p\._resolvedObjectKeys\['addr:dst'\]/);
});

test('l’inventaire frontend ne liste que les décisions effectives non auto-finalisées', () => {
  const context = {
    Set,
    Map,
    deployState: { analyzed: null },
    cleanHostName(host, name) { return name; },
    isDrawerObjectResolved(policyValue, key) {
      return !!policyValue?._resolvedObjectKeys?.[key];
    },
    serviceReuseKeys(service) { return service.reuseKeys || []; },
    isCompatibleServiceSelected() { return false; },
    isServiceDecisionResolved(policyValue, service) {
      const keys = service.reuseKeys || [];
      return keys.length > 0 && keys.every(key => policyValue?._resolvedServiceKeys?.[key] === 'specific');
    },
  };
  frontendFunction('serviceDecisionIdentityKey', '\nfunction serviceReuseKey', context);
  const collectMissingObjects = frontendFunction(
    'collectMissingObjects', '\n// ── Objects modal helpers', context,
  );
  const input = {
    _srcMode: 'subnet',
    _srcAddrName: 'FF_10_0_0_0_24',
    srcHosts: ['10.0.0.10'],
    dstType: 'public',
    _dstUseAll: false,
    _dstMode: 'hosts',
    _use32Dst: true,
    dstHosts: ['8.8.8.8'],
    _dstHostNames: { '8.8.8.8': 'FF_HOST_8_8_8_8' },
    _resolvedObjectKeys: {
      'addr:src': 'FF_10_0_0_0_24',
      'host:dst:8.8.8.8': 'FF_HOST_8_8_8_8',
    },
    _resolvedServiceKeys: { 'UDP/53': 'specific' },
    analysis: {
      srcAddr: { found: false, cidr: '10.0.0.0/24', suggestedName: 'FF_10_0_0_0_24' },
      dstAddr: { found: false, cidr: '8.8.8.8/32', suggestedName: 'FF_8_8_8_8_32' },
      services: [
        { found: false, label: 'GOOGLE-DNS', suggestedName: 'FF_SVC_53_UDP', reuseKeys: ['UDP/53'], isNamed: true },
        { found: false, label: 'LEGACY-LABEL', suggestedName: 'CONFIG-NAME', reuseKeys: ['TCP/9443'], isNamed: true },
        { found: false, label: 'MMS', suggestedName: 'MMS', reuseKeys: ['UDP/3478'], isNamed: true },
        { found: false, label: 'MMS', suggestedName: 'MMS', reuseKeys: ['UDP/3001', 'UDP/3004'], isNamed: true },
        { found: false, label: 'PING', suggestedName: 'PING', technicalConflict: true, isNamed: true },
      ],
    },
  };

  context.deployState.analyzed = [input];
  const missing = collectMissingObjects();
  assert.equal(missing.total, 3);
  assert.equal(missing.addresses.length, 0);
  assert.equal(missing.hosts.length, 0);
  assert.equal(missing.services.length, 3);
  assert.deepEqual([...missing.services].map(service => service.label).sort(), ['MMS', 'MMS', 'PING']);
  assert.deepEqual([...missing.services].map(service => service.key).sort(), [
    'label:MMS|UDP/3001,UDP/3004',
    'label:MMS|UDP/3478',
    'label:PING|untyped',
  ]);
});

test('l’application frontend distingue deux services de même label par leur définition technique', () => {
  const context = {
    deployState: {
      analyzed: [{
        analysis: {
          services: [
            { found: false, isNamed: true, label: 'MMS', suggestedName: 'MMS', reuseKeys: ['UDP/3478'] },
            { found: false, isNamed: true, label: 'MMS', suggestedName: 'MMS', reuseKeys: ['UDP/3001', 'UDP/3004'] },
          ],
        },
      }],
    },
    renderDeployPolicies() {},
    filterDeployPolicies() { return []; },
  };
  frontendFunction('serviceReuseKeys', '\nfunction serviceDecisionIdentityKey', context);
  frontendFunction('serviceDecisionIdentityKey', '\nfunction serviceReuseKey', context);
  const applyObjectNames = frontendFunction(
    'applyObjectNames', '\n// ── Policy Drawer', context,
  );

  applyObjectNames({}, {}, { 'label:MMS|UDP/3478': 'MMS-3478-EXACT' });

  assert.equal(context.deployState.analyzed[0].analysis.services[0].suggestedName, 'MMS-3478-EXACT');
  assert.equal(context.deployState.analyzed[0].analysis.services[1].suggestedName, 'MMS');
});
