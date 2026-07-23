'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { buildPoliciesByPlan, inferPreset, normalizePlan } = require('../public/segmentation-plan.js');

const services = [
  { label: 'HTTPS', name: 'HTTPS' },
  { label: 'DNS', name: 'DNS' },
];

function fixture() {
  const policies = [{
    srcSubnet: '10.0.1.0/24',
    dstTarget: '10.0.2.0/24',
    dstType: 'private',
    sessions: 120,
    services: ['HTTPS', 'DNS'],
    ports: [443, 53],
    protos: ['TCP', 'UDP'],
    serviceTuples: [
      { proto: '6', port: '443', service: 'HTTPS', sessions: 2 },
      { proto: '17', port: '53', service: 'DNS', sessions: 2 },
    ],
    srcHosts: ['10.0.1.10', '10.0.1.11'],
    dstHosts: ['10.0.2.10', '10.0.2.11'],
    analysis: { services },
  }];
  const hostPairServices = {
    '10.0.1.10|10.0.2.10': ['HTTPS'],
    '10.0.1.11|10.0.2.10': ['HTTPS', 'DNS'],
    '10.0.1.11|10.0.2.11': ['DNS'],
  };
  const getServicesForPair = (src, dst, policy) =>
    (hostPairServices[src + '|' + dst] || [])
      .map(name => policy.analysis.services.find(service => service.label === name))
      .filter(Boolean);
  return { policies, hostPairServices, getServicesForPair };
}

function build(plan) {
  const data = fixture();
  return buildPoliciesByPlan(data.policies, plan, data);
}

test('normalizes plans and identifies the three simple presets', () => {
  assert.deepEqual(normalizePlan({}), { source: 'network', destination: 'network', services: 'grouped' });
  assert.equal(inferPreset({ source: 'network', destination: 'network', services: 'grouped' }), 'wide');
  assert.equal(inferPreset({ source: 'network', destination: 'host', services: 'grouped' }), 'targeted');
  assert.equal(inferPreset({ source: 'host', destination: 'host', services: 'separate' }), 'strict');
  assert.equal(inferPreset({ source: 'network', destination: 'host', services: 'separate' }), 'custom');
});

test('wide mode keeps one network-to-network rule with grouped services', () => {
  const result = build({ source: 'network', destination: 'network', services: 'grouped' });
  assert.equal(result.length, 1);
  assert.equal(result[0].srcSubnet, '10.0.1.0/24');
  assert.equal(result[0].dstTarget, '10.0.2.0/24');
  assert.deepEqual(result[0].analysis.services.map(service => service.label).sort(), ['DNS', 'HTTPS']);
  assert.deepEqual(result[0].services.sort(), ['DNS', 'HTTPS']);
  assert.equal(result[0].serviceTuples.length, 2);
});

test('targeted mode creates one grouped rule per observed server', () => {
  const result = build({ source: 'network', destination: 'host', services: 'grouped' });
  assert.equal(result.length, 2);
  assert.deepEqual(result.map(policy => policy.dstTarget).sort(), ['10.0.2.10/32', '10.0.2.11/32']);
  const server10 = result.find(policy => policy.dstTarget === '10.0.2.10/32');
  const server11 = result.find(policy => policy.dstTarget === '10.0.2.11/32');
  assert.deepEqual(server10.analysis.services.map(service => service.label).sort(), ['DNS', 'HTTPS']);
  assert.deepEqual(server11.services, ['DNS']);
  assert.deepEqual(server11.serviceTuples.map(tuple => tuple.service), ['DNS']);
});

test('custom service mode separates services while retaining network objects', () => {
  const result = build({ source: 'network', destination: 'network', services: 'separate' });
  assert.equal(result.length, 2);
  assert.ok(result.every(policy => policy._srcMode === 'subnet' && policy._dstMode === 'subnet'));
  assert.deepEqual(result.map(policy => policy.analysis.services[0].label).sort(), ['DNS', 'HTTPS']);
  assert.ok(result.every(policy => policy.services.length === 1));
  assert.ok(result.every(policy =>
    policy.serviceTuples.length === 1
    && policy.serviceTuples[0].service === policy.analysis.services[0].label
  ));
});

test('strict mode creates exact observed host/service tuples without phantom pairs', () => {
  const result = build({ source: 'host', destination: 'host', services: 'separate' });
  assert.equal(result.length, 4);
  assert.ok(result.every(policy => policy._srcMode === 'hosts' && policy._dstMode === 'hosts'));
  assert.equal(result.some(policy =>
    policy.srcSubnet === '10.0.1.10/32' && policy.dstTarget === '10.0.2.11/32'
  ), false);
});

test('unnamed protocol/port tuples remain exact when services are separated', () => {
  const policies = [{
    srcSubnet: '10.0.1.0/24',
    dstTarget: '10.0.2.0/24',
    services: [],
    ports: [853],
    protos: ['TCP'],
    serviceTuples: [{ proto: '6', port: '853', service: '', sessions: 1 }],
    srcHosts: ['10.0.1.10'],
    dstHosts: ['10.0.2.10'],
    analysis: { services: [{ label: '853/TCP', port: 853, proto: 'TCP' }] },
  }];
  const result = buildPoliciesByPlan(policies, {
    source: 'host',
    destination: 'host',
    services: 'separate',
  }, {
    hostPairServices: { '10.0.1.10|10.0.2.10': ['853/TCP'] },
    getServicesForPair: (_src, _dst, policy) => policy.analysis.services,
  });
  assert.equal(result.length, 1);
  assert.deepEqual(result[0].services, []);
  assert.deepEqual(result[0].serviceTuples, [{ proto: '6', port: '853', service: '', sessions: 1 }]);
});

test('WAN destinations stay exact even when the selected destination scope is network', () => {
  const policies = [{
    srcSubnet: '10.0.1.0/24',
    dstTarget: '8.8.8.8',
    dstType: 'public',
    _isWan: true,
    sessions: 10,
    srcHosts: ['10.0.1.10'],
    dstHosts: ['8.8.8.8'],
    analysis: { services: [{ label: 'DNS' }] },
  }];
  const result = buildPoliciesByPlan(policies, {
    source: 'network',
    destination: 'network',
    services: 'grouped',
  });
  assert.equal(result[0].dstTarget, '8.8.8.8/32');
  assert.equal(result[0]._dstMode, 'hosts');
});
