'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const analyzer = require('../lib/analyzer');
const { analyzePolicies, generateConfig, preflightValidation } = require('../lib/forticonfig');

let binding = {};
try { binding = require('../lib/policy-binding'); } catch {}

function flow(overrides = {}) {
  return {
    srcip: '10.0.0.10',
    dstip: '10.0.1.20',
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
    ...overrides,
  };
}

function fortiConfig() {
  return {
    addresses: {
      USERS: { name: 'USERS', cidr: '10.0.0.0/24' },
      SERVERS: { name: 'SERVERS', cidr: '10.0.1.0/24' },
    },
    addressGroups: {},
    customServices: {},
    serviceGroups: {},
    interfaces: { users: {}, servers: {}, dmz: {} },
    zones: {},
  };
}

test('reconstruit une policy V2 depuis le résultat serveur et ignore les champs techniques client', () => {
  assert.equal(typeof binding.bindPolicyEngineV2Selections, 'function');
  const config = fortiConfig();
  const serverResult = analyzer.buildPolicyEngineV2([flow()], { profile: 'recommended', fortiConfig: config });
  const serverPolicy = serverResult.policies[0];
  const submitted = {
    ...serverPolicy,
    srcintf: 'dmz',
    dstintf: 'users',
    partitionKey: 'FORGED-PARTITION',
    serviceKeys: ['TCP:8443'],
    serviceTuples: [{ proto: '6', port: '8443', service: 'HTTPS' }],
    services: ['HTTPS'],
    _mergedServices: [{ name: 'EVIL-9999', proto: 'TCP', ports: [9999] }],
    _policyEngineV2: { ...serverPolicy._policyEngineV2 },
    action: 'deny',
    log: 'utm',
    nat: true,
    policyName: 'USER-NAME',
  };
  const calls = [];
  const result = binding.bindPolicyEngineV2Selections([submitted], {
    fortiConfig: config,
    getPolicyEngineResult: (profile, scope) => {
      calls.push({ profile, scope });
      return serverResult;
    },
  });

  assert.equal(result.ok, true);
  assert.equal(calls.length, 1);
  const bound = result.policies[0];
  assert.equal(bound.id, serverPolicy.id);
  assert.equal(bound.srcintf, serverPolicy.srcintf);
  assert.equal(bound.dstintf, serverPolicy.dstintf);
  assert.equal(bound.partitionKey, serverPolicy.partitionKey);
  assert.deepEqual(bound.serviceKeys, serverPolicy.serviceKeys);
  assert.deepEqual(bound.serviceTuples, serverPolicy.serviceTuples);
  assert.equal(bound._mergedServices, undefined);
  assert.equal(bound.action, 'deny');
  assert.equal(bound.log, 'utm');
  assert.equal(bound.nat, true);
  assert.equal(bound.policyName, 'USER-NAME');
  assert.equal(bound._serverPolicyBinding, true);
});

test('la policy liée contient une analyse technique serveur utilisable directement au preflight', () => {
  const config = fortiConfig();
  const flows = [flow()];
  const serverResult = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended', fortiConfig: config });
  const result = binding.bindPolicyEngineV2Selections([serverResult.policies[0]], {
    fortiConfig: config,
    getPolicyEngineResult: () => serverResult,
  });
  assert.equal(result.ok, true);
  assert.ok(result.policies[0].analysis?.services?.length > 0);
  const preflight = preflightValidation(result.policies, config, flows, serverResult.atoms);
  assert.equal(preflight.ok, true, JSON.stringify(preflight.issues));
});

test('refuse une policy V2 sans provenance complète ou avec un identifiant inconnu', () => {
  assert.equal(typeof binding.bindPolicyEngineV2Selections, 'function');
  const serverResult = analyzer.buildPolicyEngineV2([flow()], { profile: 'recommended', fortiConfig: fortiConfig() });
  const provenance = serverResult.policies[0]._policyEngineV2;
  const getResult = () => serverResult;

  const missing = binding.bindPolicyEngineV2Selections([{
    id: serverResult.policies[0].id,
    profile: 'recommended',
  }], { fortiConfig: fortiConfig(), getPolicyEngineResult: getResult });
  assert.equal(missing.ok, false);
  assert.ok(missing.issues.some(issue => issue.code === 'POLICY_ENGINE_PROVENANCE_INVALID'));

  const unknown = binding.bindPolicyEngineV2Selections([{
    _policyEngineV2: { ...provenance, id: 'P-UNKNOWN' },
  }], { fortiConfig: fortiConfig(), getPolicyEngineResult: getResult });
  assert.equal(unknown.ok, false);
  assert.ok(unknown.issues.some(issue => issue.code === 'POLICY_ENGINE_PROVENANCE_INVALID'));
});

test('refuse aussi une policy sans aucune provenance V2 au lieu de basculer en legacy', () => {
  const result = binding.bindPolicyEngineV2Selections([{
    id: 'LEGACY-FORGED',
    srcintf: 'dmz',
    dstintf: 'users',
    services: ['HTTPS'],
  }], {
    fortiConfig: fortiConfig(),
    getPolicyEngineResult: () => ({ policies: [], atoms: [] }),
  });
  assert.equal(result.ok, false);
  assert.ok(result.issues.some(issue => issue.code === 'POLICY_ENGINE_PROVENANCE_INVALID'));
});

test('valide les sélections d’adresse contre la policy serveur et ignore les overrides CIDR client', () => {
  assert.equal(typeof binding.bindPolicyEngineV2Selections, 'function');
  const config = fortiConfig();
  const serverResult = analyzer.buildPolicyEngineV2([flow()], { profile: 'recommended', fortiConfig: config });
  const serverPolicy = serverResult.policies[0];
  const submitted = {
    ...serverPolicy,
    srcHosts: ['10.0.99.10'],
    _srcCidrOverride: '10.0.0.0/8',
    addressSelections: {
      source: { mode: 'existing-object', objectName: 'USERS', confirmed: true },
    },
    _policyEngineV2: { ...serverPolicy._policyEngineV2 },
  };
  const result = binding.bindPolicyEngineV2Selections([submitted], {
    fortiConfig: config,
    getPolicyEngineResult: () => serverResult,
  });

  assert.equal(result.ok, true);
  const bound = result.policies[0];
  assert.deepEqual(bound.srcHosts, serverPolicy.srcHosts);
  assert.equal(bound._srcCidrOverride, undefined);
  assert.deepEqual(bound.addressSelections, submitted.addressSelections);
});

test('la chaîne liaison → preflight → CLI ne laisse pas passer les interfaces ou ports forgés', () => {
  const config = fortiConfig();
  const flows = [flow()];
  const serverResult = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended', fortiConfig: config });
  const serverPolicy = serverResult.policies[0];
  const submitted = {
    ...serverPolicy,
    srcintf: 'dmz',
    dstintf: 'users',
    serviceTuples: [{ proto: '6', port: '8443', service: 'HTTPS' }],
    _mergedServices: [{ name: 'EVIL-9999', proto: 'TCP', ports: [9999] }],
    _policyEngineV2: { ...serverPolicy._policyEngineV2 },
  };
  const bindingResult = binding.bindPolicyEngineV2Selections([submitted], {
    fortiConfig: config,
    getPolicyEngineResult: () => serverResult,
  });
  assert.equal(bindingResult.ok, true);
  const analyzed = analyzePolicies(bindingResult.policies, config, null);
  const preflight = preflightValidation(analyzed, config, flows, serverResult.atoms);
  assert.equal(preflight.ok, true);
  const cli = generateConfig(analyzed, config);
  assert.match(cli, /set srcintf "users"/);
  assert.match(cli, /set dstintf "servers"/);
  assert.doesNotMatch(cli, /dmz|EVIL-9999|8443|9999/);
});
