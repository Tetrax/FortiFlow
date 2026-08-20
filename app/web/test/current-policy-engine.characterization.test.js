'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { buildPoliciesByPlan } = require('../public/segmentation-plan.js');

function allowedTuples(policy) {
  const sources = policy.srcHosts || [];
  const destinations = policy.dstHosts || [];
  const services = (policy.analysis?.services || []).map(service => service.label || service.name);
  return new Set(sources.flatMap(source =>
    destinations.flatMap(destination =>
      services.map(service => `${source}|${destination}|${service}`)
    )
  ));
}

test('characterization: wide mode unions services across destinations and creates phantom tuples', () => {
  const policy = {
    srcSubnet: '192.0.2.0/24',
    dstTarget: '198.51.100.0/24',
    dstType: 'private',
    srcHosts: ['192.0.2.10'],
    dstHosts: ['198.51.100.10', '198.51.100.20'],
    services: ['DNS', 'HTTPS', 'LDAP', 'SMB'],
    serviceTuples: [
      { proto: '17', port: '53', service: 'DNS' },
      { proto: '6', port: '443', service: 'HTTPS' },
      { proto: '6', port: '389', service: 'LDAP' },
      { proto: '6', port: '445', service: 'SMB' },
    ],
    analysis: {
      services: ['DNS', 'HTTPS', 'LDAP', 'SMB'].map(label => ({ label, name: label })),
    },
  };
  const hostPairServices = {
    '192.0.2.10|198.51.100.10': ['DNS', 'HTTPS', 'LDAP'],
    '192.0.2.10|198.51.100.20': ['DNS', 'HTTPS', 'SMB'],
  };

  const result = buildPoliciesByPlan([policy], {
    source: 'network',
    destination: 'network',
    services: 'grouped',
  }, {
    hostPairServices,
    getServicesForPair: (source, destination) =>
      (hostPairServices[`${source}|${destination}`] || []).map(label => ({ label, name: label })),
  });

  assert.equal(result.length, 1);
  const allowed = allowedTuples(result[0]);
  assert.equal(allowed.has('192.0.2.10|198.51.100.10|SMB'), true);
  assert.equal(allowed.has('192.0.2.10|198.51.100.20|LDAP'), true);
});

test('characterization: network profiles generalize sparse observed hosts to their containing networks', () => {
  const policy = {
    srcSubnet: '192.0.2.0/24',
    dstTarget: '198.51.100.0/24',
    dstType: 'private',
    srcHosts: ['192.0.2.10'],
    dstHosts: ['198.51.100.20'],
    services: ['HTTPS'],
    serviceTuples: [{ proto: '6', port: '443', service: 'HTTPS' }],
    analysis: { services: [{ label: 'HTTPS', name: 'HTTPS' }] },
  };

  const [result] = buildPoliciesByPlan([policy], {
    source: 'network',
    destination: 'network',
    services: 'grouped',
  });

  assert.equal(result.srcSubnet, '192.0.2.0/24');
  assert.equal(result.dstTarget, '198.51.100.0/24');
  assert.equal(result._srcMode, 'subnet');
  assert.equal(result._dstMode, 'subnet');
});
