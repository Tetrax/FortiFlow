'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  analyzePolicies,
  buildPolicyStrategyPreviews,
  generateConfig,
  validatePolicyDecisionShapes,
  validatePolicyStrategyBatch,
} = require('../lib/forticonfig');

function httpsService() {
  return { label: 'HTTPS', name: 'HTTPS', found: true, isNamed: true, reuseKeys: ['TCP/443'] };
}

function policy(destination, overrides = {}) {
  return {
    srcSubnet: '10.41.0.0/16',
    srcSubnets: ['10.41.0.0/16'],
    dstTarget: destination,
    dstTargets: [destination],
    dstType: 'public',
    _isWan: true,
    _dstUseAll: false,
    _use32Src: false,
    _use32Dst: false,
    srcHosts: ['10.41.10.3'],
    dstHosts: [],
    services: ['HTTPS'],
    ports: [443],
    protos: ['TCP'],
    srcintf: 'LAN',
    dstintf: 'WAN',
    _srcintf: 'LAN',
    _dstintf: 'WAN',
    action: 'accept',
    analysis: { services: [httpsService()] },
    ...overrides,
  };
}

function fortiConfig(addresses = {}) {
  return {
    addresses,
    addressGroups: {},
    customServices: {},
    serviceGroups: {},
    interfaces: {
      LAN: { name: 'LAN', subnet: '10.41.0.0/16', isWan: false },
      WAN: { name: 'WAN', subnet: null, isWan: true },
    },
    zones: {},
    fullRoutes: [
      { dst: '10.41.0.0/16', device: 'LAN', distance: 0 },
      { dst: '0.0.0.0/0', device: 'WAN', distance: 10 },
    ],
    staticRoutes: [],
    sdwanEnabled: false,
    sdwanMembers: [],
    existingPolicies: [],
    securityProfiles: {},
  };
}

test('LAN vers Internet générique conserve les IP observées mais recommande all', () => {
  const policies = Array.from({ length: 12 }, (_, index) =>
    policy(`203.0.113.${index + 1}`));

  const preview = buildPolicyStrategyPreviews(policies, { scope: 'internet' });
  const balanced = preview.strategies.balanced;
  const result = balanced.policies[0];

  assert.equal(result._dstUseAll, true);
  assert.equal(result._internetAllExpansion, true);
  assert.equal(result.dstHosts.length, 12);
  assert.deepEqual(result.dstHosts, Array.from({ length: 12 }, (_, index) => `203.0.113.${index + 1}`).sort());
  assert.ok(result._multiDstSubnets.every(item => item.useSubnet === false));
  assert.ok(result._multiDstSubnets.every(item => item.hosts.length === 1));
  assert.equal(balanced.metrics.additional, 0, 'Additional reste la métrique de fusion bornée');
  assert.equal(balanced.metrics.representationExpansions, 1, 'Internet/all est compté séparément');
  assert.equal(validatePolicyDecisionShapes([result]).ok, true);
});

test('un service Internet borné à quelques IP reste en destinations spécifiques /32', () => {
  const preview = buildPolicyStrategyPreviews([
    policy('198.51.100.10'),
    policy('198.51.100.11'),
  ], { scope: 'internet' });
  const result = preview.strategies.balanced.policies[0];

  assert.equal(result._dstUseAll, false);
  assert.equal(result._internetAllExpansion, false);
  assert.deepEqual(result.dstHosts, ['198.51.100.10', '198.51.100.11']);
  assert.ok(result._multiDstSubnets.every(item => item.useSubnet === false));
  assert.ok(result._multiDstSubnets.every(item => item.hosts[0] + '/32' === `${item.subnet}/32`));
});

test('les trois stratégies gardent leurs comptes et évitent all si les services Internet diffèrent', () => {
  const ssh = { label: 'SSH', name: 'SSH', found: true, isNamed: true, reuseKeys: ['TCP/22'] };
  const policies = Array.from({ length: 12 }, (_, index) => index % 2 === 0
    ? policy(`192.0.2.${index + 1}`)
    : policy(`192.0.2.${index + 1}`, {
      services: ['SSH'], ports: [22], analysis: { services: [ssh] },
    }));
  const preview = buildPolicyStrategyPreviews(policies, { scope: 'internet' });

  assert.deepEqual(
    Object.values(preview.strategies).map(strategy => strategy.policyCount),
    [2, 2, 1],
  );
  assert.equal(preview.strategies.synthetic.policies[0]._dstUseAll, false);
  for (const result of Object.values(preview.strategies)) {
    assert.equal(validatePolicyDecisionShapes(result.policies).ok, true, result.id);
  }
});

test('le compteur d’expansion de représentation Internet/all est validé par le contrat de stratégie', () => {
  const original = analyzePolicies(
    Array.from({ length: 12 }, (_, index) => policy(`203.0.113.${index + 1}`)),
    fortiConfig(),
  );
  const preview = buildPolicyStrategyPreviews(original, { scope: 'all' });
  const candidate = preview.strategies.balanced;
  for (const item of candidate.policies) {
    item._generationStrategy = 'balanced';
    item._generationScope = preview.scope;
    item._generationMetrics = candidate.metrics;
  }
  const tampered = structuredClone(candidate);
  tampered.metrics.representationExpansions += 1;
  for (const item of tampered.policies) item._generationMetrics = tampered.metrics;
  assert.equal(validatePolicyStrategyBatch(tampered.policies, {
    scope: preview.scope,
    strategy: 'balanced',
    metrics: tampered.metrics,
  }).ok, false);
});

test('une IP publique observée devient /32 et réutilise un objet FortiGate exact', () => {
  const analyzed = analyzePolicies(
    [policy('104.18.18.203')],
    fortiConfig({ CF_EDGE: { cidr: '104.18.18.203/32' } }),
  )[0];

  assert.deepEqual(analyzed.dstHosts, ['104.18.18.203']);
  assert.deepEqual(analyzed._dstHostsFound, ['104.18.18.203']);
  assert.equal(analyzed._dstHostNames['104.18.18.203'], 'CF_EDGE');
  assert.equal(analyzed.analysis.dstAddr.name, 'CF_EDGE');
  assert.equal(analyzed.analysis.dstAddr.cidr, '104.18.18.203/32');
});

test('un réseau public réellement connu conserve son préfixe', () => {
  const analyzed = analyzePolicies(
    [policy('198.51.100.0/24')],
    fortiConfig({ PARTNER_NET: { cidr: '198.51.100.0/24' } }),
  )[0];
  const result = buildPolicyStrategyPreviews([analyzed], { scope: 'internet' })
    .strategies.balanced.policies[0];

  assert.equal(result.dstTarget, '198.51.100.0/24');
  assert.equal(result._use32Dst, false);
  assert.deepEqual(result.dstHosts, []);
  assert.equal(result.analysis.dstAddr.name, 'PARTNER_NET');
});

test('la génération spécifique émet les noms éditables /32 et réutilise les objets exacts', () => {
  const selected = policy('104.18.18.203', {
    _use32Dst: true,
    dstHosts: ['104.18.18.203', '20.50.201.203'],
    _dstHostsFound: ['104.18.18.203'],
    _dstHostNames: {
      '104.18.18.203': 'CF_EDGE',
      '20.50.201.203': 'MS_UPDATE_01',
    },
    _srcAddrName: 'LAN_10_41',
    analysis: {
      srcAddr: { found: true, name: 'LAN_10_41', cidr: '10.41.0.0/16' },
      dstAddr: { found: true, name: 'CF_EDGE', cidr: '104.18.18.203/32' },
      services: [httpsService()],
    },
  });

  const cli = generateConfig([selected], {
    addresses: {
      LAN_10_41: { cidr: '10.41.0.0/16' },
      CF_EDGE: { cidr: '104.18.18.203/32' },
    },
    addressGroups: {}, serviceGroups: {}, zones: {}, securityProfiles: {},
  });

  assert.match(cli, /set dstaddr "CF_EDGE" "MS_UPDATE_01"/);
  assert.match(cli, /edit "MS_UPDATE_01"[\s\S]*set subnet 20\.50\.201\.203 255\.255\.255\.255/);
  assert.doesNotMatch(cli, /104\.18\.18\.0 255\.255\.255\.0/);
});

test('LAN vers LAN conserve son comportement et ne reçoit aucun mode Internet', () => {
  const lan = policy('10.42.0.0/16', {
    dstType: 'private', _isWan: false, dstintf: 'SERVERS', _dstintf: 'SERVERS',
    dstHosts: ['10.42.1.10'],
  });
  const result = buildPolicyStrategyPreviews([lan], { scope: 'lan' }).strategies.balanced.policies[0];

  assert.equal(result.dstType, 'private');
  assert.equal(result._dstUseAll, false);
  assert.equal(result._internetAllExpansion, false);
  assert.deepEqual(result.dstHosts, ['10.42.1.10']);
});
