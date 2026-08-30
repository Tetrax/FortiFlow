'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');
const { validatePolicyDecisionShapes } = require('../lib/forticonfig');

const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');

function functionBlock(name, nextName) {
  const start = source.indexOf(`function ${name}`);
  const end = source.indexOf(`function ${nextName}`, start);
  assert.ok(start >= 0 && end > start, `${name} introuvable`);
  return source.slice(start, end);
}

function frontendContext(...blocks) {
  const context = {
    serviceReuseKeys(service) { return service.reuseKeys || []; },
    deployState: { addrGroups: {} },
    AUTO32_THRESHOLD: 4,
    escSlug(value) { return String(value); },
    cidrSupernet() { return null; },
    mergeDestinationDetectionCandidates(policies) {
      return (policies || []).flatMap(policy => policy._dstDetectedSubnets || []);
    },
    destinationAggregateForPolicies(_policies, fallback = '') { return fallback; },
    alert() {},
    _savePolicySnapshot() {},
    defaultSelectedSet() { return new Set(); },
    el() { return null; },
    _updateMergeSelectionBtn() {},
    renderDeployPolicies() {},
    filterDeployPolicies() { return []; },
  };
  vm.createContext(context);
  vm.runInContext(blocks.join('\n'), context);
  return context;
}

function policy(srcSubnet, dstTarget, label, key) {
  return {
    srcSubnet, dstTarget, dstType: 'private', policyIds: [1], sessions: 1,
    srcHosts: [], dstHosts: [], _srcintf: 'LAN', _dstintf: 'DMZ',
    analysis: { services: [{ label, name: label, found: true, isNamed: true, reuseKeys: [key] }] },
  };
}

test('FF2-02 les identités frontend incluent les tuples techniques des services', () => {
  const setKey = functionBlock('serviceSetKey', 'groupByInterfacePair');
  const merge = functionBlock('mergeServices', 'updateNoRcvdToggleBtn');
  assert.match(setKey, /serviceReuseKeys\(s\)/);
  assert.match(merge, /serviceReuseKeys\(svc\)/);
});

test('FF2-02 les fusions frontend conservent une dimension fixe sûre', () => {
  const byService = functionBlock('mergeByService', 'mergeByDestination');
  const byDestination = functionBlock('mergeByDestination', 'applyMerge');
  assert.match(byService, /destinationKey/);
  assert.match(byService, /serviceKey\|\|srcintf\|\|dstintf\|\|destination/);
  assert.match(byDestination, /serviceSetKey\(p\)/);
});

test('FF2-02 la fusion par policyId ne mélange pas destinations et empreintes', () => {
  const byPolicy = functionBlock('mergeByPolicyId', 'normalizeInternetMerge');
  assert.match(byPolicy, /serviceSetKey\(p\)/);
  assert.match(byPolicy, /destinationKey/);
});

test('les fusions multi-destination conservent tous les candidats détectés', () => {
  assert.ok(source.includes('function mergeDestinationDetectionCandidates'), 'fusion des candidats absente');
  const context = frontendContext(
    functionBlock('mergeByPolicyId', 'normalizeInternetMerge'),
    functionBlock('mergeDestinationDetectionCandidates', 'syncHostCell'),
    functionBlock('serviceSetKey', 'groupByInterfacePair'),
    functionBlock('mergeServices', 'syncMergedServiceMetadata'),
    functionBlock('syncMergedServiceMetadata', 'updateNoRcvdToggleBtn'),
    functionBlock('normalizeInternetMerge', 'mergeByService'),
    functionBlock('mergeByService', 'mergeByDestination'),
    functionBlock('mergeByDestination', 'applyMerge'),
  );
  const first = policy('SRC', '10.42.0.0/23', 'SSH', 'TCP/22');
  first.dstHosts = ['10.42.1.252'];
  first._dstDetectedSubnets = [{ subnet: '10.42.0.0/23', hosts: first.dstHosts, useSubnet: true }];
  const second = policy('SRC', '10.44.2.0/24', 'SSH', 'TCP/22');
  second.dstHosts = ['10.44.2.1'];
  second._dstDetectedSubnets = [{ subnet: '10.44.2.0/24', hosts: second.dstHosts, useSubnet: true }];

  const [merged] = context.mergeByPolicyId([first, second]);
  assert.deepEqual(JSON.parse(JSON.stringify(merged._dstDetectedSubnets.map(item => [item.subnet, item.hosts]))), [
    ['10.42.0.0/23', ['10.42.1.252']],
    ['10.44.2.0/24', ['10.44.2.1']],
  ]);
});

test('FF2-02 les fusions frontend restent séparées sur des tuples non rectangulaires', () => {
  const context = frontendContext(
    functionBlock('mergeAnalyzedPolicies', 'mergeServices'),
    functionBlock('serviceSetKey', 'groupByInterfacePair'),
    functionBlock('mergeServices', 'syncMergedServiceMetadata'),
    functionBlock('syncMergedServiceMetadata', 'updateNoRcvdToggleBtn'),
    functionBlock('normalizeInternetMerge', 'mergeByService'),
    functionBlock('mergeByService', 'mergeByDestination'),
    functionBlock('mergeByDestination', 'applyMerge'),
    functionBlock('mergeByPolicyId', 'normalizeInternetMerge'),
  );
  const aDnsX = policy('A', 'X', 'DNS', 'UDP/53');
  const bDnsY = policy('B', 'Y', 'DNS', 'UDP/53');
  const bSshX = policy('B', 'X', 'SSH', 'TCP/22');

  assert.equal(context.mergeByService([aDnsX, bDnsY]).length, 2);
  assert.equal(context.mergeByDestination([aDnsX, bSshX]).length, 2);
  assert.equal(context.mergeByPolicyId([aDnsX, bDnsY]).length, 2);
  assert.notEqual(context.serviceSetKey(aDnsX), context.serviceSetKey(policy('A', 'X', 'DNS', 'TCP/53')));

  const maxMerged = context.mergeAnalyzedPolicies([
    policy('A', 'X', 'HTTPS', 'TCP/443'),
    policy('A', 'X', 'SSH', 'TCP/22'),
  ], 'lan');
  assert.equal(maxMerged.length, 1);
  assert.deepEqual(Array.from(maxMerged[0].services).sort(), ['HTTPS', 'SSH']);
  assert.deepEqual(Array.from(maxMerged[0].ports), [22, 443]);
  assert.deepEqual(Array.from(maxMerged[0].protos), ['TCP']);
});

test('FF2-02 les fusions Internet produisent le contrat all explicite', () => {
  const context = frontendContext(
    functionBlock('mergeAnalyzedPolicies', 'mergeServices'),
    functionBlock('serviceSetKey', 'groupByInterfacePair'),
    functionBlock('mergeServices', 'syncMergedServiceMetadata'),
    functionBlock('syncMergedServiceMetadata', 'updateNoRcvdToggleBtn'),
    functionBlock('normalizeInternetMerge', 'mergeByService'),
    functionBlock('mergeByService', 'mergeByDestination'),
    functionBlock('mergeByDestination', 'applyMerge'),
    functionBlock('mergeByPolicyId', 'normalizeInternetMerge'),
  );
  const first = { ...policy('A', '203.0.113.10', 'HTTPS', 'TCP/443'), dstType: 'public', _isWan: true };
  const second = { ...policy('A', '198.51.100.20', 'HTTPS', 'TCP/443'), dstType: 'public', _isWan: true };
  const maxSingleton = context.mergeAnalyzedPolicies([structuredClone(first)], 'internet');
  assert.equal(maxSingleton[0].dstTarget, '203.0.113.10');
  assert.notEqual(maxSingleton[0]._dstUseAll, true);
  for (const merge of [context.mergeByService, context.mergeByDestination, context.mergeByPolicyId]) {
    const singleton = merge([structuredClone(first)]);
    assert.equal(singleton[0].dstTarget, '203.0.113.10');
    assert.notEqual(singleton[0]._dstUseAll, true);

    const result = merge([structuredClone(first), structuredClone(second)]);
    assert.equal(result.length, 1);
    assert.equal(result[0].dstTarget, 'all');
    assert.deepEqual(Array.from(result[0].dstTargets), ['all']);
    assert.equal(result[0]._dstUseAll, true);
    assert.equal(result[0]._isMultiDst, false);
    assert.equal(result[0]._multiDstSubnets, undefined);
    assert.equal(result[0]._use32Dst, false);
    const shape = validatePolicyDecisionShapes(JSON.parse(JSON.stringify(result)));
    assert.equal(shape.ok, true, JSON.stringify(shape.issues));
  }
});

test('FF2-02 les fusions séparent actions et paires d’interfaces', () => {
  const context = frontendContext(
    functionBlock('mergeAnalyzedPolicies', 'mergeServices'),
    functionBlock('serviceSetKey', 'groupByInterfacePair'),
    functionBlock('mergeServices', 'syncMergedServiceMetadata'),
    functionBlock('syncMergedServiceMetadata', 'updateNoRcvdToggleBtn'),
    functionBlock('normalizeInternetMerge', 'mergeByService'),
    functionBlock('mergeByService', 'mergeByDestination'),
    functionBlock('mergeByDestination', 'applyMerge'),
    functionBlock('mergeByPolicyId', 'normalizeInternetMerge'),
  );
  const accept = { ...policy('A', 'X', 'HTTPS', 'TCP/443'), action: 'accept', _action: 'accept' };
  const deny = { ...policy('A', 'X', 'HTTPS', 'TCP/443'), action: 'deny', _action: 'deny' };
  for (const merge of [
    policies => context.mergeAnalyzedPolicies(policies, 'lan'),
    context.mergeByService,
    context.mergeByDestination,
    context.mergeByPolicyId,
  ]) {
    assert.equal(merge([structuredClone(accept), structuredClone(deny)]).length, 2);
  }

  const otherPair = { ...accept, _srcintf: 'LAN-B', _dstintf: 'DMZ-B' };
  for (const merge of [
    policies => context.mergeAnalyzedPolicies(policies, 'lan'),
    context.mergeByService,
    context.mergeByDestination,
    context.mergeByPolicyId,
  ]) {
    assert.equal(merge([structuredClone(accept), structuredClone(otherPair)]).length, 2);
  }
});

test('FF2-02 les fusions multi-subnet sans hôtes restent en mode subnet', () => {
  const context = frontendContext(
    functionBlock('serviceSetKey', 'groupByInterfacePair'),
    functionBlock('mergeServices', 'syncMergedServiceMetadata'),
    functionBlock('syncMergedServiceMetadata', 'updateNoRcvdToggleBtn'),
    functionBlock('normalizeInternetMerge', 'mergeByService'),
    functionBlock('mergeByService', 'mergeByDestination'),
    functionBlock('mergeByDestination', 'applyMerge'),
    functionBlock('mergeByPolicyId', 'normalizeInternetMerge'),
  );
  const first = policy('10.0.0.0/24', '10.0.10.0/24', 'HTTPS', 'TCP/443');
  const second = policy('10.0.1.0/24', '10.0.10.0/24', 'HTTPS', 'TCP/443');
  for (const [name, merge] of [
    ['service', context.mergeByService],
    ['destination', context.mergeByDestination],
    ['policy', context.mergeByPolicyId],
  ]) {
    const result = merge([structuredClone(first), structuredClone(second)]);
    assert.equal(result.length, 1, name);
    assert.ok(result[0]._multiSrcSubnets.every(item => item.useSubnet === true), name);
    const shape = validatePolicyDecisionShapes(JSON.parse(JSON.stringify(result)));
    assert.equal(shape.ok, true, `${name}: ${JSON.stringify(shape.issues)}`);
  }
});

test('FF2-02 les fusions multi-scope conservent les modes hôtes valides', () => {
  const context = frontendContext(
    functionBlock('serviceSetKey', 'groupByInterfacePair'),
    functionBlock('mergeServices', 'syncMergedServiceMetadata'),
    functionBlock('syncMergedServiceMetadata', 'updateNoRcvdToggleBtn'),
    functionBlock('normalizeInternetMerge', 'mergeByService'),
    functionBlock('mergeByService', 'mergeByDestination'),
    functionBlock('mergeByDestination', 'applyMerge'),
    functionBlock('mergeByPolicyId', 'normalizeInternetMerge'),
  );
  const first = { ...policy('10.0.0.0/24', '10.0.10.0/24', 'HTTPS', 'TCP/443'), srcHosts: ['10.0.0.10'], _srcMode: 'hosts' };
  const second = { ...policy('10.0.1.0/24', '10.0.10.0/24', 'HTTPS', 'TCP/443'), srcHosts: ['10.0.1.10'], _srcMode: 'hosts' };
  for (const [name, merge] of [
    ['service', context.mergeByService],
    ['destination', context.mergeByDestination],
    ['policy', context.mergeByPolicyId],
  ]) {
    const result = merge([structuredClone(first), structuredClone(second)]);
    assert.equal(result.length, 1, name);
    assert.ok(result[0]._multiSrcSubnets.every(item => item.useSubnet === false), name);
    const shape = validatePolicyDecisionShapes(JSON.parse(JSON.stringify(result)));
    assert.equal(shape.ok, true, `${name}: ${JSON.stringify(shape.issues)}`);
  }

  const dstFirst = { ...policy('10.0.0.0/24', '10.0.10.0/24', 'HTTPS', 'TCP/443'), dstHosts: ['10.0.10.10'], _dstMode: 'hosts' };
  const dstSecond = { ...policy('10.0.0.0/24', '10.0.20.0/24', 'HTTPS', 'TCP/443'), dstHosts: ['10.0.20.10'], _dstMode: 'hosts' };
  const dstResult = context.mergeByPolicyId([dstFirst, dstSecond]);
  assert.equal(dstResult.length, 1);
  assert.ok(dstResult[0]._multiDstSubnets.every(item => item.useSubnet === false));
  assert.equal(validatePolicyDecisionShapes(JSON.parse(JSON.stringify(dstResult))).ok, true);
});

test('FF2-02 les fusions conservent NAT et noms d’adresses décidés', () => {
  const context = frontendContext(
    functionBlock('serviceSetKey', 'groupByInterfacePair'),
    functionBlock('mergeServices', 'syncMergedServiceMetadata'),
    functionBlock('syncMergedServiceMetadata', 'updateNoRcvdToggleBtn'),
    functionBlock('normalizeInternetMerge', 'mergeByService'),
    functionBlock('mergeByService', 'mergeByDestination'),
    functionBlock('mergeByDestination', 'applyMerge'),
    functionBlock('mergeByPolicyId', 'normalizeInternetMerge'),
  );
  const first = { ...policy('10.0.0.0/24', '10.0.10.0/24', 'HTTPS', 'TCP/443'), _nat: true, _srcAddrName: 'CUSTOM-SRC', _dstAddrName: 'CUSTOM-DST' };
  const second = { ...policy('10.0.1.0/24', '10.0.10.0/24', 'HTTPS', 'TCP/443'), _nat: true, _srcAddrName: 'CUSTOM-SRC', _dstAddrName: 'CUSTOM-DST' };
  for (const merge of [context.mergeByService, context.mergeByDestination, context.mergeByPolicyId]) {
    const [result] = merge([structuredClone(first), structuredClone(second)]);
    assert.equal(result._nat, true);
    assert.equal(result._srcAddrName, 'CUSTOM-SRC');
    assert.equal(result._dstAddrName, 'CUSTOM-DST');
  }

  const wanFirst = { ...first, dstTarget: '203.0.113.10', dstType: 'public', _isWan: true, _nat: false };
  const wanSecond = { ...first, dstTarget: '198.51.100.20', dstType: 'public', _isWan: true, _nat: false };
  assert.equal(context.mergeByService([wanFirst, wanSecond])[0]._nat, false);
});

test('FF2-02 la fusion policyId sépare strictement LAN et WAN', () => {
  const context = frontendContext(
    functionBlock('serviceSetKey', 'groupByInterfacePair'),
    functionBlock('mergeServices', 'syncMergedServiceMetadata'),
    functionBlock('syncMergedServiceMetadata', 'updateNoRcvdToggleBtn'),
    functionBlock('normalizeInternetMerge', 'mergeByService'),
    functionBlock('mergeByPolicyId', 'normalizeInternetMerge'),
  );
  const lan = policy('10.0.0.0/24', '10.0.10.0/24', 'HTTPS', 'TCP/443');
  const wan = { ...policy('10.0.0.0/24', '203.0.113.10', 'HTTPS', 'TCP/443'), dstType: 'public', _isWan: true };
  assert.equal(context.mergeByPolicyId([lan, wan]).length, 2);
});

test('FF2-02 la fusion manuelle WAN conserve toutes les sources subnet', () => {
  const context = frontendContext(
    functionBlock('serviceSetKey', 'groupByInterfacePair'),
    functionBlock('mergeServices', 'syncMergedServiceMetadata'),
    functionBlock('syncMergedServiceMetadata', 'updateNoRcvdToggleBtn'),
    functionBlock('normalizeInternetMerge', 'mergeByService'),
    functionBlock('mergeSelectedDeployPolicies', 'mergeAnalyzedPolicies'),
  );
  const first = { ...policy('10.0.0.0/24', '203.0.113.10', 'HTTPS', 'TCP/443'), dstType: 'public', _isWan: true };
  const second = { ...policy('10.0.1.0/24', '198.51.100.20', 'HTTPS', 'TCP/443'), dstType: 'public', _isWan: true };
  context.deployState.analyzed = [first, second];
  context.deployState.mergeSelected = new Set([0, 1]);
  context.deployState.hostPairServices = {};
  context.deployState.pageSize = 20;
  context.mergeSelectedDeployPolicies();
  assert.equal(context.deployState.analyzed.length, 1);
  assert.deepEqual(Array.from(context.deployState.analyzed[0].srcSubnets).sort(), ['10.0.0.0/24', '10.0.1.0/24']);
  assert.equal(context.deployState.analyzed[0]._multiSrcSubnets.length, 2);
  assert.ok(context.deployState.analyzed[0]._multiSrcSubnets.every(item => item.useSubnet === true));
});

test('FF2-02 la fusion Internet sépare les ensembles de services distincts', () => {
  const context = frontendContext(
    functionBlock('mergeAnalyzedPolicies', 'mergeServices'),
    functionBlock('serviceSetKey', 'groupByInterfacePair'),
    functionBlock('mergeServices', 'syncMergedServiceMetadata'),
    functionBlock('syncMergedServiceMetadata', 'updateNoRcvdToggleBtn'),
    functionBlock('normalizeInternetMerge', 'mergeByService'),
  );
  const https = { ...policy('10.0.0.0/24', '203.0.113.10', 'HTTPS', 'TCP/443'), dstType: 'public', _isWan: true };
  const ssh = { ...policy('10.0.0.0/24', '198.51.100.20', 'SSH', 'TCP/22'), dstType: 'public', _isWan: true };
  const result = context.mergeAnalyzedPolicies([https, ssh], 'internet');
  assert.equal(result.length, 2);
  assert.ok(result.every(item => item.dstTarget !== 'all'));
});

test('FF2-02 la fusion manuelle WAN refuse des services distincts par destination', () => {
  const context = frontendContext(
    functionBlock('serviceSetKey', 'groupByInterfacePair'),
    functionBlock('mergeServices', 'syncMergedServiceMetadata'),
    functionBlock('syncMergedServiceMetadata', 'updateNoRcvdToggleBtn'),
    functionBlock('normalizeInternetMerge', 'mergeByService'),
    functionBlock('mergeSelectedDeployPolicies', 'mergeAnalyzedPolicies'),
  );
  const https = { ...policy('10.0.0.0/24', '203.0.113.10', 'HTTPS', 'TCP/443'), dstType: 'public', _isWan: true };
  const ssh = { ...policy('10.0.0.0/24', '198.51.100.20', 'SSH', 'TCP/22'), dstType: 'public', _isWan: true };
  context.deployState.analyzed = [https, ssh];
  context.deployState.mergeSelected = new Set([0, 1]);
  context.deployState.hostPairServices = {};
  context.deployState.pageSize = 20;
  context.mergeSelectedDeployPolicies();
  assert.equal(context.deployState.analyzed.length, 2);
});
