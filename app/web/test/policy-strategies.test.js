'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  buildPolicyStrategyPreviews,
} = require('../lib/forticonfig');

function service(label, key) {
  return { label, name: label, found: true, isNamed: true, reuseKeys: [key] };
}

function policy(destination, services, overrides = {}) {
  return {
    srcSubnet: '10.10.0.0/24',
    dstTarget: destination,
    dstType: 'private',
    srcintf: 'STATIONS',
    dstintf: 'SERVERS',
    _srcintf: 'STATIONS',
    _dstintf: 'SERVERS',
    action: 'accept',
    _action: 'accept',
    sessions: 1,
    srcHosts: [],
    dstHosts: [],
    services: services.map(item => item.label),
    ports: services.map(item => Number(item.reuseKeys[0].split('/')[1])).sort((a, b) => a - b),
    protos: ['TCP'],
    analysis: { services },
    ...overrides,
  };
}

function referencePolicies() {
  const ping = service('PING', 'TCP/1');
  return [
    policy('AD', [ping, service('Kerberos', 'TCP/88')]),
    policy('MAIL', [ping, service('SMTP', 'TCP/25')]),
    policy('FTP', [ping, service('FTP', 'TCP/21')]),
  ];
}

test('stratégies de policies : le cas de référence expose trois previews métriques', () => {
  const result = buildPolicyStrategyPreviews(referencePolicies(), { scope: 'all' });

  assert.deepEqual(Object.keys(result.strategies), ['balanced', 'compact', 'synthetic']);
  assert.deepEqual(
    Object.values(result.strategies).map(strategy => [strategy.id, strategy.label, strategy.policyCount]),
    [['balanced', 'Équilibrée', 4], ['compact', 'Compacte', 3], ['synthetic', 'Synthétique', 1]],
  );
  assert.equal(result.strategies.balanced.metrics.before, 3);
  assert.equal(result.strategies.balanced.metrics.after, 4);
  assert.equal(result.strategies.balanced.metrics.observed, 6);
  assert.equal(result.strategies.balanced.metrics.allowed, 6);
  assert.equal(result.strategies.balanced.metrics.additional, 0);
  assert.equal(result.strategies.compact.metrics.after, 3);
  assert.equal(result.strategies.compact.metrics.additional, 0);
  assert.equal(result.strategies.synthetic.metrics.after, 1);
  assert.ok(result.strategies.synthetic.metrics.additional > 0);
  assert.equal(result.strategies.synthetic.metrics.allowed, 12);
  assert.equal(result.strategies.synthetic.metrics.expansion, 1);
});

test('Équilibrée et Compacte restent exactes, Synthétique compte chaque tuple ajouté', () => {
  const result = buildPolicyStrategyPreviews(referencePolicies(), { scope: 'all' });

  for (const name of ['balanced', 'compact']) {
    assert.equal(result.strategies[name].metrics.additional, 0, name);
    assert.equal(result.strategies[name].metrics.allowed, result.strategies[name].metrics.observed, name);
  }
  assert.equal(result.strategies.synthetic.metrics.additional, 6);
  assert.equal(result.strategies.synthetic.metrics.expansionPercent, 100);
  assert.deepEqual(result.strategies.synthetic.metrics.examples[0], {
    source: '10.10.0.0/24', destination: 'AD', service: 'FTP|TCP/21',
  });
});

test('les stratégies sont déterministes et Compacte ne dépasse jamais Équilibrée', () => {
  const forward = buildPolicyStrategyPreviews(referencePolicies(), { scope: 'all' });
  const reversed = buildPolicyStrategyPreviews(referencePolicies().reverse(), { scope: 'all' });

  assert.deepEqual(reversed, forward);
  assert.ok(forward.strategies.compact.metrics.after <= forward.strategies.balanced.metrics.after);
});

test('Compacte fusionne un rectangle exact partageant le même ensemble complet de services', () => {
  const https = service('HTTPS', 'TCP/443');
  const policies = [
    policy('APP-A', [https], { srcSubnet: 'SRC-A' }),
    policy('APP-B', [https], { srcSubnet: 'SRC-A' }),
    policy('APP-A', [https], { srcSubnet: 'SRC-B' }),
    policy('APP-B', [https], { srcSubnet: 'SRC-B' }),
  ];
  const compact = buildPolicyStrategyPreviews(policies).strategies.compact;

  assert.equal(compact.metrics.after, 1);
  assert.equal(compact.metrics.additional, 0);
  assert.deepEqual(compact.policies[0].srcSubnets, ['SRC-A', 'SRC-B']);
  assert.deepEqual(compact.policies[0].dstTargets, ['APP-A', 'APP-B']);
});

test('le périmètre recalcule les previews sans retirer les policies hors périmètre', () => {
  const lan = referencePolicies();
  const internet = [
    policy('203.0.113.10', [service('HTTPS', 'TCP/443')], { dstType: 'public', _isWan: true, _dstintf: 'WAN' }),
    policy('198.51.100.20', [service('HTTPS', 'TCP/443')], { dstType: 'public', _isWan: true, _dstintf: 'WAN' }),
  ];
  const policies = [...lan, ...internet];
  const all = buildPolicyStrategyPreviews(policies, { scope: 'all' });
  const lanOnly = buildPolicyStrategyPreviews(policies, { scope: 'lan' });
  const internetOnly = buildPolicyStrategyPreviews(policies, { scope: 'internet' });

  assert.notDeepEqual(lanOnly.strategies, internetOnly.strategies);
  assert.notEqual(all.strategies.synthetic.metrics.after, lanOnly.strategies.synthetic.metrics.after);
  for (const previews of [all, lanOnly, internetOnly]) {
    for (const result of Object.values(previews.strategies)) {
      assert.equal(result.metrics.after, result.policies.length);
    }
  }
});

test('Synthétique conserve les frontières action et interfaces', () => {
  const policies = [
    policy('APP-A', [service('HTTPS', 'TCP/443')]),
    policy('APP-B', [service('SSH', 'TCP/22')], { action: 'deny', _action: 'deny' }),
  ];
  const synthetic = buildPolicyStrategyPreviews(policies).strategies.synthetic;

  assert.equal(synthetic.metrics.after, 2);
  assert.equal(synthetic.metrics.additional, 0);
});
