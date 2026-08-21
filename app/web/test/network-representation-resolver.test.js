'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  resolveNetworkRepresentations,
  validateCIDRCandidate,
  validateExactGroupCandidate,
  validateExistingFortiObjectMatch,
  validateNetworkCandidate,
  validateResolutionResult,
} = require('../lib/network-representation-resolver');
const { parseFortiConfig } = require('../lib/forticonfig');

function policy(overrides = {}) {
  return {
    id: 'P-00001',
    partitionKey: 'FGT-A::root||users||servers',
    scope: { devid: 'FGT-A', devname: 'edge-a', vdom: 'root' },
    sourceInterface: 'users',
    destinationInterface: 'servers',
    sources: ['192.0.2.0', '192.0.2.1', '192.0.2.2', '192.0.2.3'],
    destinations: ['198.51.100.10'],
    serviceKeys: ['TCP:443'],
    trace: { atomIds: ['A-000001', 'A-000002', 'A-000003', 'A-000004'] },
    ...overrides,
  };
}

test('resolver suggests an exact existing FortiGate CIDR object without mutating the policy', () => {
  const inputPolicy = policy();
  const before = structuredClone(inputPolicy);
  const result = resolveNetworkRepresentations(inputPolicy, {
    addresses: {
      RENAMABLE_OBJECT: { name: 'RENAMABLE_OBJECT', type: 'ipmask', cidr: '192.0.2.0/30' },
    },
    addressGroups: {},
  }, { side: 'source' });

  assert.deepEqual(inputPolicy, before);
  assert.equal(validateResolutionResult(result), true);
  const candidate = result.candidates.find(item => item.kind === 'existing-object');
  assert.ok(candidate);
  assert.equal(validateNetworkCandidate(candidate), true);
  assert.equal(candidate.side, 'source');
  assert.equal(candidate.rank, 1);
  assert.equal(candidate.eligibility, 'safe-exact');
  assert.equal(candidate.autoApplicable, true);
  assert.deepEqual(candidate.representedCidrs, ['192.0.2.0/30']);
  assert.deepEqual(candidate.existingObjectMatch.objectNames, ['RENAMABLE_OBJECT']);
  assert.equal(candidate.existingObjectMatch.matchKind, 'exact-membership');
  assert.equal(validateExistingFortiObjectMatch(candidate.existingObjectMatch), true);
  assert.deepEqual(candidate.previewMetrics, {
    observedRequiredTuples: 4,
    coveredRequiredTuples: 4,
    missingRequiredTuples: 0,
    allowedTuples: 4,
    unexpectedAllowedTuples: 0,
    coverageRatio: 1,
    expansionRatio: 0,
  });
  assert.ok(result.candidates.some(item => item.kind === 'host-list'));
  assert.equal(result.recommendedCandidateId, candidate.candidateId);
});

test('resolver expands nested FortiGate groups and suggests only an exact final membership', () => {
  const result = resolveNetworkRepresentations(policy({
    sources: ['192.0.2.10', '192.0.2.20'],
    trace: { atomIds: ['A-000001', 'A-000002'] },
  }), {
    addresses: {
      HOST_A: { name: 'HOST_A', type: 'ipmask', cidr: '192.0.2.10/32' },
      HOST_B: { name: 'HOST_B', type: 'ipmask', cidr: '192.0.2.20/32' },
    },
    addressGroups: {
      INNER: { name: 'INNER', members: ['HOST_A'] },
      OUTER: { name: 'OUTER', members: ['INNER', 'HOST_B'] },
    },
  }, { side: 'source' });

  const candidate = result.candidates.find(item => item.kind === 'existing-group');
  assert.ok(candidate);
  assert.equal(candidate.rank, 2);
  assert.equal(candidate.autoApplicable, true);
  assert.equal(candidate.exactGroupCandidate.mode, 'reuse-existing');
  assert.equal(validateExactGroupCandidate(candidate.exactGroupCandidate), true);
  assert.equal(candidate.exactGroupCandidate.groupName, 'OUTER');
  assert.deepEqual(candidate.exactGroupCandidate.memberObjectNames, ['HOST_A', 'HOST_B']);
  assert.equal(candidate.exactGroupCandidate.cyclesDetected, false);
  assert.deepEqual(candidate.exactGroupCandidate.danglingMembers, []);
  assert.equal(candidate.previewMetrics.unexpectedAllowedTuples, 0);
  assert.equal(result.recommendedCandidateId, candidate.candidateId);
});

test('resolver rejects an address group containing an additional member', () => {
  const result = resolveNetworkRepresentations(policy({
    sources: ['192.0.2.10', '192.0.2.20'],
  }), {
    addresses: {
      HOST_A: { name: 'HOST_A', cidr: '192.0.2.10/32' },
      HOST_B: { name: 'HOST_B', cidr: '192.0.2.20/32' },
      HOST_EXTRA: { name: 'HOST_EXTRA', cidr: '192.0.2.30/32' },
    },
    addressGroups: {
      TOO_LARGE: { name: 'TOO_LARGE', members: ['HOST_A', 'HOST_B', 'HOST_EXTRA'] },
    },
  }, { side: 'source' });

  assert.equal(result.candidates.some(item => item.kind === 'existing-group'), false);
  assert.deepEqual(
    result.blockers.filter(item => item.code === 'ADDRESS_GROUP_MEMBERSHIP_NOT_EXACT'),
    [{
      code: 'ADDRESS_GROUP_MEMBERSHIP_NOT_EXACT',
      groupName: 'TOO_LARGE',
      additionalIpCount: 1,
      missingIpCount: 0,
      message: 'La membership du groupe diffère des adresses observées.',
    }],
  );
});

test('resolver blocks cyclic groups and reports deterministic cycle paths', () => {
  const result = resolveNetworkRepresentations(policy({
    sources: ['192.0.2.10'],
  }), {
    addresses: {},
    addressGroups: {
      GROUP_A: { name: 'GROUP_A', members: ['GROUP_B'] },
      GROUP_B: { name: 'GROUP_B', members: ['GROUP_A'] },
    },
  }, { side: 'source' });

  assert.equal(result.candidates.some(item => item.kind === 'existing-group'), false);
  assert.deepEqual(
    result.blockers.filter(item => item.code === 'ADDRESS_GROUP_CYCLE'),
    [
      {
        code: 'ADDRESS_GROUP_CYCLE',
        groupName: 'GROUP_A',
        cyclePaths: [['GROUP_A', 'GROUP_B', 'GROUP_A']],
        message: 'Le groupe contient un cycle et ne peut pas être résolu de façon sûre.',
      },
      {
        code: 'ADDRESS_GROUP_CYCLE',
        groupName: 'GROUP_B',
        cyclePaths: [['GROUP_B', 'GROUP_A', 'GROUP_B']],
        message: 'Le groupe contient un cycle et ne peut pas être résolu de façon sûre.',
      },
    ],
  );
});

test('resolver proposes a new exact group by reusing hosts and creating only missing host objects', () => {
  const result = resolveNetworkRepresentations(policy({
    sources: ['192.0.2.10', '192.0.2.20'],
  }), {
    addresses: {
      EXISTING_HOST: { name: 'EXISTING_HOST', cidr: '192.0.2.10/32' },
    },
    addressGroups: {},
  }, { side: 'source' });

  const candidate = result.candidates.find(item => item.kind === 'new-exact-group');
  assert.ok(candidate);
  assert.equal(candidate.rank, 3);
  assert.equal(candidate.eligibility, 'safe-exact');
  assert.equal(candidate.autoApplicable, true);
  assert.equal(candidate.exactGroupCandidate.mode, 'create-new');
  assert.deepEqual(candidate.exactGroupCandidate.reusedHostObjects, [
    { ip: '192.0.2.10', objectNames: ['EXISTING_HOST'] },
  ]);
  assert.deepEqual(candidate.exactGroupCandidate.missingHostObjects, ['192.0.2.20/32']);
  assert.deepEqual(candidate.exactGroupCandidate.objectsToCreate, [
    { objectType: 'address', cidr: '192.0.2.20/32' },
    {
      objectType: 'address-group',
      memberReferences: [
        { type: 'existing-object', objectName: 'EXISTING_HOST', cidr: '192.0.2.10/32' },
        { type: 'new-object', cidr: '192.0.2.20/32' },
      ],
    },
  ]);
  assert.equal(candidate.previewMetrics.expansionRatio, 0);
  assert.equal(result.recommendedCandidateId, candidate.candidateId);
});

test('resolver exposes a sparse existing subnet as measured non-auto-applicable suggestion', () => {
  const sources = Array.from({ length: 70 }, (_unused, index) => `10.252.16.${index + 1}`);
  const result = resolveNetworkRepresentations(policy({ sources }), {
    addresses: {
      EXISTING_NETWORK: { name: 'EXISTING_NETWORK', type: 'ipmask', cidr: '10.252.16.0/23' },
    },
    addressGroups: {},
    interfaces: {},
  }, { side: 'source' });

  const candidate = result.candidates.find(item =>
    item.kind === 'cidr-suggestion' && item.cidrCandidate.cidr === '10.252.16.0/23'
  );
  assert.ok(candidate);
  assert.equal(candidate.rank, 4);
  assert.equal(candidate.eligibility, 'explicit-generalization');
  assert.equal(candidate.autoApplicable, false);
  assert.equal(candidate.cidrCandidate.derivation, 'existing-object');
  assert.equal(candidate.cidrCandidate.observedIpCount, 70);
  assert.equal(candidate.cidrCandidate.totalAddressCount, 512);
  assert.equal(candidate.cidrCandidate.additionalIpCount, 442);
  assert.equal(candidate.cidrCandidate.additionalTupleCount, 442);
  assert.equal(validateCIDRCandidate(candidate.cidrCandidate), true);
  assert.equal(candidate.previewMetrics.unexpectedAllowedTuples, 442);
  assert.equal(candidate.previewMetrics.expansionRatio, 442 / 70);
  assert.deepEqual(candidate.cidrCandidate.existingMatches[0].objectNames, ['EXISTING_NETWORK']);
  assert.notEqual(result.recommendedCandidateId, candidate.candidateId);
});

test('resolver recognizes an exact FortiGate IP range from the parsed configuration', () => {
  const config = parseFortiConfig(`
config firewall address
    edit "RANGE_OBJECT"
        set type iprange
        set start-ip 192.0.2.10
        set end-ip 192.0.2.12
    next
end
`);
  const result = resolveNetworkRepresentations(policy({
    sources: ['192.0.2.10', '192.0.2.11', '192.0.2.12'],
  }), config, { side: 'source' });

  const candidate = result.candidates.find(item => item.kind === 'existing-object');
  assert.ok(candidate);
  assert.equal(candidate.existingObjectMatch.objectType, 'ip-range');
  assert.equal(candidate.existingObjectMatch.rangeStart, '192.0.2.10');
  assert.equal(candidate.existingObjectMatch.rangeEnd, '192.0.2.12');
  assert.equal(candidate.previewMetrics.unexpectedAllowedTuples, 0);
});

test('resolver blocks an address group with a missing member', () => {
  const result = resolveNetworkRepresentations(policy({ sources: ['192.0.2.10'] }), {
    addresses: {},
    addressGroups: { BROKEN: { name: 'BROKEN', members: ['MISSING_OBJECT'] } },
  }, { side: 'source' });

  assert.deepEqual(result.blockers.filter(item => item.code === 'ADDRESS_GROUP_DANGLING_MEMBER'), [{
    code: 'ADDRESS_GROUP_DANGLING_MEMBER',
    groupName: 'BROKEN',
    members: ['MISSING_OBJECT'],
    message: 'Le groupe référence un membre absent ou non représentable.',
  }]);
});

test('duplicate exact objects are explicit ambiguity and never auto-selected', () => {
  const result = resolveNetworkRepresentations(policy(), {
    addresses: {
      FIRST: { name: 'FIRST', cidr: '192.0.2.0/30' },
      SECOND: { name: 'SECOND', cidr: '192.0.2.0/30' },
    },
    addressGroups: {},
  }, { side: 'source' });

  const candidate = result.candidates.find(item => item.kind === 'existing-object');
  assert.deepEqual(candidate.existingObjectMatch.objectNames, ['FIRST', 'SECOND']);
  assert.equal(candidate.existingObjectMatch.ambiguous, true);
  assert.equal(candidate.autoApplicable, false);
  assert.equal(result.recommendedCandidateId, result.currentRepresentation.candidateId);
});

test('renaming an exact object does not change candidate identity, rank or metrics', () => {
  const first = resolveNetworkRepresentations(policy(), {
    addresses: { BEFORE: { name: 'BEFORE', cidr: '192.0.2.0/30' } }, addressGroups: {},
  }, { side: 'source' });
  const second = resolveNetworkRepresentations(policy(), {
    addresses: { AFTER: { name: 'AFTER', cidr: '192.0.2.0/30' } }, addressGroups: {},
  }, { side: 'source' });
  const firstCandidate = first.candidates.find(item => item.kind === 'existing-object');
  const secondCandidate = second.candidates.find(item => item.kind === 'existing-object');

  assert.equal(firstCandidate.candidateId, secondCandidate.candidateId);
  assert.equal(firstCandidate.rank, secondCandidate.rank);
  assert.deepEqual(firstCandidate.previewMetrics, secondCandidate.previewMetrics);
  assert.notEqual(first.resolverInputHash, second.resolverInputHash);
});

test('resolver output is deterministic across policy and configuration input order', () => {
  const firstPolicy = policy({
    sources: ['192.0.2.20', '192.0.2.10'],
    serviceKeys: ['UDP:53', 'TCP:443'],
  });
  const secondPolicy = policy({
    sources: ['192.0.2.10', '192.0.2.20'],
    serviceKeys: ['TCP:443', 'UDP:53'],
  });
  const firstConfig = {
    addresses: {
      HOST_B: { name: 'HOST_B', cidr: '192.0.2.20/32' },
      HOST_A: { name: 'HOST_A', cidr: '192.0.2.10/32' },
    },
    addressGroups: { EXACT: { name: 'EXACT', members: ['HOST_B', 'HOST_A'] } },
  };
  const secondConfig = {
    addresses: {
      HOST_A: { name: 'HOST_A', cidr: '192.0.2.10/32' },
      HOST_B: { name: 'HOST_B', cidr: '192.0.2.20/32' },
    },
    addressGroups: { EXACT: { name: 'EXACT', members: ['HOST_A', 'HOST_B'] } },
  };

  assert.deepEqual(
    resolveNetworkRepresentations(firstPolicy, firstConfig, { side: 'source' }),
    resolveNetworkRepresentations(secondPolicy, secondConfig, { side: 'source' }),
  );
});

test('runtime contracts reject incomplete kind-specific candidates and unsafe auto-application', () => {
  const exactResult = resolveNetworkRepresentations(policy(), {
    addresses: { EXACT: { name: 'EXACT', cidr: '192.0.2.0/30' } }, addressGroups: {},
  }, { side: 'source' });
  const incompleteObject = structuredClone(
    exactResult.candidates.find(item => item.kind === 'existing-object')
  );
  delete incompleteObject.existingObjectMatch;
  assert.equal(validateNetworkCandidate(incompleteObject), false);

  const sparseResult = resolveNetworkRepresentations(policy({
    sources: ['192.0.2.10', '192.0.2.20'],
  }), { addresses: {}, addressGroups: {} }, { side: 'source' });
  const unsafeAuto = structuredClone(
    sparseResult.candidates.find(item => item.kind === 'cidr-suggestion')
  );
  unsafeAuto.autoApplicable = true;
  assert.equal(validateNetworkCandidate(unsafeAuto), false);
});

test('resolver applies the same exact semantics on the destination side', () => {
  const inputPolicy = policy({
    sources: ['192.0.2.10'],
    destinations: ['198.51.100.10', '198.51.100.11'],
    trace: { atomIds: ['A-000001', 'A-000002'] },
  });
  const result = resolveNetworkRepresentations(inputPolicy, {
    addresses: { DESTINATION_NET: { name: 'DESTINATION_NET', cidr: '198.51.100.10/31' } },
    addressGroups: {},
  }, { side: 'destination' });

  const candidate = result.candidates.find(item => item.kind === 'existing-object');
  assert.equal(candidate.side, 'destination');
  assert.equal(candidate.affectedSourceCount, 1);
  assert.equal(candidate.affectedDestinationCount, 0);
  assert.equal(candidate.previewMetrics.observedRequiredTuples, 2);
  assert.equal(candidate.previewMetrics.unexpectedAllowedTuples, 0);
});

test('resolver bounds CIDR candidates and ignores configured subnets that are too large', () => {
  const result = resolveNetworkRepresentations(policy({
    sources: ['10.0.0.10', '10.0.0.11'],
  }), {
    addresses: { TOO_LARGE: { name: 'TOO_LARGE', cidr: '10.0.0.0/16' } },
    addressGroups: {},
  }, { side: 'source', maxCandidateAddresses: 4096 });

  const cidrCandidates = result.candidates.filter(item => item.kind === 'cidr-suggestion');
  assert.equal(cidrCandidates.some(item => item.cidrCandidate.cidr === '10.0.0.0/16'), false);
  assert.ok(cidrCandidates.every(item => item.cidrCandidate.totalAddressCount <= 4096));
  assert.doesNotThrow(() => JSON.stringify(result));
});

test('null range bounds are never interpreted as the IPv4 zero address', () => {
  const result = resolveNetworkRepresentations(policy({
    sources: ['0.0.0.0'],
  }), {
    addresses: { INVALID: { name: 'INVALID', cidr: null, startInt: null, endInt: null } },
    addressGroups: {},
  }, { side: 'source' });

  assert.equal(result.candidates.some(item => item.kind === 'existing-object'), false);
});
