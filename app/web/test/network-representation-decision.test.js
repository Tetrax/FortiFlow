'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { buildPolicyEngineV2 } = require('../lib/policy-engine-v2');
const { resolveNetworkRepresentations } = require('../lib/network-representation-resolver');
const {
  applyNetworkRepresentationDecision,
  revalidateNetworkUserDecision,
  validateNetworkUserDecision,
} = require('../lib/network-representation-decision');

function flow(source, destination, extra = {}) {
  return {
    srcip: source,
    dstip: destination,
    proto: '6',
    dstport: '443',
    service: 'HTTPS',
    action: 'accept',
    decision: 'allow',
    deploymentEligible: true,
    srcintf: 'users',
    dstintf: 'servers',
    devid: 'FGT-A',
    vdom: 'root',
    count: 1,
    sentBytes: 100,
    rcvdBytes: 200,
    ...extra,
  };
}

function fixture(overrides = {}) {
  const flows = overrides.flows || [
    flow('192.0.2.0', '198.51.100.10'),
    flow('192.0.2.1', '198.51.100.10'),
  ];
  const fortiConfig = overrides.fortiConfig || {
    selectedVdom: 'root',
    addresses: {
      SOURCE_NET: { name: 'SOURCE_NET', cidr: '192.0.2.0/31' },
      DESTINATION_HOST: { name: 'DESTINATION_HOST', cidr: '198.51.100.10/32' },
    },
    addressGroups: {},
    customServices: {},
    serviceGroups: {},
    interfaces: {
      users: { name: 'users', role: 'lan', isWan: false, cidr: '192.0.2.0/24' },
      servers: { name: 'servers', role: 'lan', isWan: false, cidr: '198.51.100.0/24' },
    },
    zones: {},
    staticRoutes: [],
    fullRoutes: [],
    existingPolicies: [],
  };
  const engine = buildPolicyEngineV2(flows, {
    profile: 'recommended', fortiConfig, trafficScope: { mode: 'all' },
  });
  const policy = engine.policies[0];
  const resolution = resolveNetworkRepresentations(policy, fortiConfig, { side: 'source' });
  const candidate = resolution.candidates.find(item => item.kind === 'existing-object');
  return { flows, fortiConfig, engine, policy, resolution, candidate };
}

test('exact object decision applies to a copy and completes metrics, analysis and preflight', () => {
  const { flows, fortiConfig, engine, policy, resolution, candidate } = fixture();
  const policyBefore = structuredClone(policy);
  const metricsBefore = structuredClone(engine.metrics);

  const result = applyNetworkRepresentationDecision({
    engineResult: engine,
    fortiConfig,
    observedFlows: flows,
    policyId: policy.id,
    side: 'source',
    candidateId: candidate.candidateId,
    resolverInputHash: resolution.resolverInputHash,
    now: '2026-08-21T12:00:00.000Z',
  });

  assert.deepEqual(policy, policyBefore);
  assert.deepEqual(engine.metrics, metricsBefore);
  assert.notEqual(result.appliedPolicy, policy);
  assert.equal(result.appliedPolicy._srcAddrName, 'SOURCE_NET');
  assert.deepEqual(result.appliedPolicy.allowedSources, ['192.0.2.0', '192.0.2.1']);
  assert.deepEqual(result.metrics, engine.metrics);
  assert.equal(result.metrics.coverageRatio, 1);
  assert.equal(result.metrics.missingRequiredTuples, 0);
  assert.equal(result.metrics.unexpectedAllowedTuples, 0);
  assert.equal(result.metrics.expansionRatio, 0);
  assert.ok(result.analyzedPolicy.analysis);
  assert.equal(result.preflight.selectionMetrics.missingRequiredTuples, 0);
  assert.equal(result.preflight.selectionMetrics.unexpectedAllowedTuples, 0);
  assert.equal(result.generationEligible, result.preflight.ok);
  assert.equal(result.decision.status, 'accepted');
  assert.equal(result.decision.profile, 'recommended');
  assert.equal(result.decision.resolverInputHash, resolution.resolverInputHash);
  assert.equal(validateNetworkUserDecision(result.decision, {
    resolution,
    candidate,
    policy,
  }).valid, true);
});

test('exact existing group decision preserves every required tuple', () => {
  const fortiConfig = {
    selectedVdom: 'root',
    addresses: {
      HOST_A: { name: 'HOST_A', cidr: '192.0.2.0/32' },
      HOST_B: { name: 'HOST_B', cidr: '192.0.2.1/32' },
      DESTINATION_HOST: { name: 'DESTINATION_HOST', cidr: '198.51.100.10/32' },
    },
    addressGroups: { SOURCE_GROUP: { name: 'SOURCE_GROUP', members: ['HOST_A', 'HOST_B'] } },
    customServices: {}, serviceGroups: {}, zones: {},
    interfaces: {
      users: { name: 'users', role: 'lan', isWan: false, cidr: '192.0.2.0/24' },
      servers: { name: 'servers', role: 'lan', isWan: false, cidr: '198.51.100.0/24' },
    },
    staticRoutes: [], fullRoutes: [], existingPolicies: [],
  };
  const context = fixture({ fortiConfig });
  const resolution = resolveNetworkRepresentations(context.policy, fortiConfig, { side: 'source' });
  const candidate = resolution.candidates.find(item => item.kind === 'existing-group');

  const result = applyNetworkRepresentationDecision({
    engineResult: context.engine,
    fortiConfig,
    observedFlows: context.flows,
    policyId: context.policy.id,
    side: 'source',
    candidateId: candidate.candidateId,
    resolverInputHash: resolution.resolverInputHash,
  });

  assert.equal(result.appliedPolicy._srcAddrName, 'SOURCE_GROUP');
  assert.equal(result.appliedPolicy._srcAddrGrpFound, true);
  assert.equal(result.appliedPolicy._useSrcGroup, true);
  assert.equal(result.metrics.coverageRatio, 1);
  assert.equal(result.metrics.missingRequiredTuples, 0);
  assert.equal(result.metrics.unexpectedAllowedTuples, 0);
  assert.equal(result.metrics.expansionRatio, 0);
  assert.equal(result.preflight.selectionMetrics.missingRequiredTuples, 0);
  assert.equal(result.preflight.selectionMetrics.unexpectedAllowedTuples, 0);
});

test('new exact group decision remains zero-expansion and describes only host members', () => {
  const fortiConfig = {
    selectedVdom: 'root',
    addresses: {
      DESTINATION_HOST: { name: 'DESTINATION_HOST', cidr: '198.51.100.10/32' },
    },
    addressGroups: {}, customServices: {}, serviceGroups: {}, zones: {},
    interfaces: {
      users: { name: 'users', role: 'lan', isWan: false, cidr: '192.0.2.0/24' },
      servers: { name: 'servers', role: 'lan', isWan: false, cidr: '198.51.100.0/24' },
    },
    staticRoutes: [], fullRoutes: [], existingPolicies: [],
  };
  const context = fixture({ fortiConfig });
  const resolution = resolveNetworkRepresentations(context.policy, fortiConfig, { side: 'source' });
  const candidate = resolution.candidates.find(item => item.kind === 'new-exact-group');

  const result = applyNetworkRepresentationDecision({
    engineResult: context.engine,
    fortiConfig,
    observedFlows: context.flows,
    policyId: context.policy.id,
    side: 'source',
    candidateId: candidate.candidateId,
    resolverInputHash: resolution.resolverInputHash,
  });

  assert.equal(result.appliedPolicy._useSrcGroup, true);
  assert.equal(result.appliedPolicy._use32Src, false);
  assert.deepEqual(result.appliedPolicy._multiSrcSubnets, [
    { subnet: '192.0.2.0/32', hosts: ['192.0.2.0'], useSubnet: false, addrFound: false, addrName: '' },
    { subnet: '192.0.2.1/32', hosts: ['192.0.2.1'], useSubnet: false, addrFound: false, addrName: '' },
  ]);
  assert.equal(result.metrics.missingRequiredTuples, 0);
  assert.equal(result.metrics.unexpectedAllowedTuples, 0);
  assert.equal(result.metrics.expansionRatio, 0);
});

test('CIDR decision is refused when it introduces expansion', () => {
  const fortiConfig = {
    selectedVdom: 'root',
    addresses: {
      SPARSE_NET: { name: 'SPARSE_NET', cidr: '192.0.2.0/24' },
      DESTINATION_HOST: { name: 'DESTINATION_HOST', cidr: '198.51.100.10/32' },
    },
    addressGroups: {}, customServices: {}, serviceGroups: {}, zones: {},
    interfaces: {
      users: { name: 'users', role: 'lan', isWan: false, cidr: '192.0.2.0/24' },
      servers: { name: 'servers', role: 'lan', isWan: false, cidr: '198.51.100.0/24' },
    },
    staticRoutes: [], fullRoutes: [], existingPolicies: [],
  };
  const context = fixture({ fortiConfig });
  const resolution = resolveNetworkRepresentations(context.policy, fortiConfig, { side: 'source' });
  const candidate = resolution.candidates.find(item =>
    item.kind === 'cidr-suggestion' && item.cidrCandidate.cidr === '192.0.2.0/24'
  );

  assert.throws(
    () => applyNetworkRepresentationDecision({
      engineResult: context.engine,
      fortiConfig,
      observedFlows: context.flows,
      policyId: context.policy.id,
      side: 'source',
      candidateId: candidate.candidateId,
      resolverInputHash: resolution.resolverInputHash,
    }),
    error => {
      assert.equal(error.code, 'UNSAFE_NETWORK_REPRESENTATION');
      assert.equal(error.statusCode, 422);
      assert.equal(error.details.metrics.missingRequiredTuples, 0);
      assert.equal(error.details.metrics.unexpectedAllowedTuples, 254);
      assert.equal(error.details.metrics.expansionRatio, 127);
      return true;
    },
  );
  assert.deepEqual(context.engine.metrics, {
    observedRequiredTuples: 2,
    coveredRequiredTuples: 2,
    missingRequiredTuples: 0,
    allowedTuples: 2,
    unexpectedAllowedTuples: 0,
    coverageRatio: 1,
    expansionRatio: 0,
    blockedRequiredTuples: 0,
    deployableRequiredTuples: 2,
  });
});

test('stale decision is refused after config, Traffic Scope or policy fingerprint changes', () => {
  const context = fixture();
  const request = {
    observedFlows: context.flows,
    policyId: context.policy.id,
    side: 'source',
    candidateId: context.candidate.candidateId,
    resolverInputHash: context.resolution.resolverInputHash,
  };
  const assertStale = callback => assert.throws(callback, error => {
    assert.equal(error.code, 'STALE_DECISION_CONTEXT');
    assert.equal(error.statusCode, 409);
    return true;
  });

  const changedConfig = structuredClone(context.fortiConfig);
  changedConfig.addresses.SOURCE_NET.name = 'RENAMED_SOURCE_NET';
  assertStale(() => applyNetworkRepresentationDecision({
    ...request, engineResult: context.engine, fortiConfig: changedConfig,
  }));

  const changedScopeEngine = buildPolicyEngineV2(context.flows, {
    profile: 'recommended',
    fortiConfig: context.fortiConfig,
    trafficScope: {
      mode: 'custom',
      custom: { srcClasses: ['lan'], dstClasses: ['lan'] },
    },
  });
  assertStale(() => applyNetworkRepresentationDecision({
    ...request, engineResult: changedScopeEngine, fortiConfig: context.fortiConfig,
  }));

  const changedPolicyEngine = structuredClone(context.engine);
  changedPolicyEngine.policies[0].sources = ['192.0.2.0'];
  changedPolicyEngine.policies[0].srcHosts = ['192.0.2.0'];
  assertStale(() => applyNetworkRepresentationDecision({
    ...request, engineResult: changedPolicyEngine, fortiConfig: context.fortiConfig,
  }));
});

test('persisted decision is marked invalidated when its current context changes', () => {
  const context = fixture();
  const applied = applyNetworkRepresentationDecision({
    engineResult: context.engine,
    fortiConfig: context.fortiConfig,
    observedFlows: context.flows,
    policyId: context.policy.id,
    side: 'source',
    candidateId: context.candidate.candidateId,
    resolverInputHash: context.resolution.resolverInputHash,
  });
  const current = revalidateNetworkUserDecision({
    decision: applied.decision,
    engineResult: context.engine,
    fortiConfig: context.fortiConfig,
  });
  assert.equal(current.valid, true);
  assert.equal(current.decision.status, 'accepted');

  const changedConfig = structuredClone(context.fortiConfig);
  changedConfig.addresses.SOURCE_NET.name = 'RENAMED_SOURCE_NET';
  const stale = revalidateNetworkUserDecision({
    decision: applied.decision,
    engineResult: context.engine,
    fortiConfig: changedConfig,
    now: '2026-08-21T13:00:00.000Z',
  });
  assert.equal(stale.valid, false);
  assert.equal(stale.decision.status, 'invalidated');
  assert.equal(stale.decision.invalidatedAt, '2026-08-21T13:00:00.000Z');
  assert.ok(stale.decision.invalidationReasons.includes('RESOLVER_INPUT_HASH_MISMATCH'));
  assert.ok(stale.decision.invalidationReasons.includes('CONFIG_FINGERPRINT_MISMATCH'));
  const cannotRevive = revalidateNetworkUserDecision({
    decision: stale.decision,
    engineResult: context.engine,
    fortiConfig: context.fortiConfig,
  });
  assert.equal(cannotRevive.valid, false);
  assert.ok(cannotRevive.reasons.includes('DECISION_ALREADY_INVALIDATED'));
});

test('decision analysis never mutates nested fields on multiple unselected policies', () => {
  const flows = [
    flow('192.0.2.0', '198.51.100.10'),
    flow('192.0.2.1', '198.51.100.10'),
    ...['198.51.100.20', '198.51.100.21', '198.51.100.22'].map(destination =>
      flow('192.0.2.50', destination, { proto: '17', dstport: '53', service: 'DNS' })
    ),
    ...['198.51.100.30', '198.51.100.31'].map(destination =>
      flow('192.0.2.60', destination, { proto: '6', dstport: '22', service: 'SSH' })
    ),
  ];
  const addresses = {
    SOURCE_NET: { name: 'SOURCE_NET', cidr: '192.0.2.0/31' },
  };
  for (const destination of [...new Set(flows.map(item => item.dstip))]) {
    addresses[`HOST_${destination.replaceAll('.', '_')}`] = {
      name: `HOST_${destination.replaceAll('.', '_')}`,
      cidr: `${destination}/32`,
    };
  }
  const fortiConfig = {
    selectedVdom: 'root', addresses, addressGroups: {}, customServices: {}, serviceGroups: {}, zones: {},
    interfaces: {
      users: { name: 'users', role: 'lan', isWan: false, cidr: '192.0.2.0/24' },
      servers: { name: 'servers', role: 'lan', isWan: false, cidr: '198.51.100.0/24' },
    },
    staticRoutes: [], fullRoutes: [], existingPolicies: [],
  };
  const engine = buildPolicyEngineV2(flows, {
    profile: 'recommended', fortiConfig, trafficScope: { mode: 'all' },
  });
  assert.ok(engine.policies.length >= 3);
  assert.ok(engine.policies.filter(item => item._multiDstSubnets?.length > 1).length >= 2);
  const selected = engine.policies.find(item =>
    item.sources.length === 2 && item.destinations.length === 1
  );
  const resolution = resolveNetworkRepresentations(selected, fortiConfig, { side: 'source' });
  const candidate = resolution.candidates.find(item => item.kind === 'existing-object');
  const before = structuredClone(engine.policies);
  const beforeHash = crypto.createHash('sha256').update(JSON.stringify(engine.policies)).digest('hex');

  applyNetworkRepresentationDecision({
    engineResult: engine,
    fortiConfig,
    observedFlows: flows,
    policyId: selected.id,
    side: 'source',
    candidateId: candidate.candidateId,
    resolverInputHash: resolution.resolverInputHash,
  });

  const afterHash = crypto.createHash('sha256').update(JSON.stringify(engine.policies)).digest('hex');
  assert.equal(afterHash, beforeHash);
  assert.deepEqual(engine.policies, before);
});

test('two concurrent decisions keep the shared original policy context immutable', async () => {
  const flows = [
    flow('192.0.2.0', '198.51.100.10'),
    flow('192.0.2.1', '198.51.100.10'),
    ...['198.51.100.20', '198.51.100.21', '198.51.100.22'].map(destination =>
      flow('192.0.2.50', destination, { proto: '17', dstport: '53', service: 'DNS' })
    ),
  ];
  const addresses = { SOURCE_NET: { name: 'SOURCE_NET', cidr: '192.0.2.0/31' } };
  for (const destination of [...new Set(flows.map(item => item.dstip))]) {
    addresses[`HOST_${destination.replaceAll('.', '_')}`] = {
      name: `HOST_${destination.replaceAll('.', '_')}`,
      cidr: `${destination}/32`,
    };
  }
  const fortiConfig = {
    selectedVdom: 'root', addresses, addressGroups: {}, customServices: {}, serviceGroups: {}, zones: {},
    interfaces: {
      users: { name: 'users', role: 'lan', isWan: false, cidr: '192.0.2.0/24' },
      servers: { name: 'servers', role: 'lan', isWan: false, cidr: '198.51.100.0/24' },
    },
    staticRoutes: [], fullRoutes: [], existingPolicies: [],
  };
  const engine = buildPolicyEngineV2(flows, {
    profile: 'recommended', fortiConfig, trafficScope: { mode: 'all' },
  });
  const sourcePolicy = engine.policies.find(item => item.sources.length === 2);
  const destinationPolicy = engine.policies.find(item => item.destinations.length === 3);
  const sourceResolution = resolveNetworkRepresentations(sourcePolicy, fortiConfig, { side: 'source' });
  const destinationResolution = resolveNetworkRepresentations(destinationPolicy, fortiConfig, { side: 'destination' });
  const sourceCandidate = sourceResolution.candidates.find(item => item.kind === 'existing-object');
  const destinationCandidate = destinationResolution.candidates.find(item => item.kind === 'new-exact-group');
  const before = structuredClone(engine.policies);
  const beforeHash = crypto.createHash('sha256').update(JSON.stringify(engine.policies)).digest('hex');

  const [sourceResult, destinationResult] = await Promise.all([
    Promise.resolve().then(() => applyNetworkRepresentationDecision({
      engineResult: engine, fortiConfig, observedFlows: flows,
      policyId: sourcePolicy.id, side: 'source', candidateId: sourceCandidate.candidateId,
      resolverInputHash: sourceResolution.resolverInputHash,
    })),
    Promise.resolve().then(() => applyNetworkRepresentationDecision({
      engineResult: engine, fortiConfig, observedFlows: flows,
      policyId: destinationPolicy.id, side: 'destination', candidateId: destinationCandidate.candidateId,
      resolverInputHash: destinationResolution.resolverInputHash,
    })),
  ]);

  assert.equal(sourceResult.metrics.unexpectedAllowedTuples, 0);
  assert.equal(destinationResult.metrics.unexpectedAllowedTuples, 0);
  assert.equal(crypto.createHash('sha256').update(JSON.stringify(engine.policies)).digest('hex'), beforeHash);
  assert.deepEqual(engine.policies, before);
});
