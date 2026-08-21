'use strict';

const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');

const appSource = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
const styleSource = fs.readFileSync(path.join(__dirname, '..', 'public', 'style.css'), 'utf8');

function loadNetworkDecisionGuards() {
  const start = appSource.indexOf('function validateNetworkDecisionOutcome(');
  const end = appSource.indexOf('async function applyPolicyNetworkRepresentation(', start);
  assert.ok(start >= 0 && end > start, 'gardes UserDecision introuvables');
  const sandbox = {};
  vm.runInNewContext(`${appSource.slice(start, end)}; guards = { validateNetworkDecisionOutcome, resolveNetworkDecisionTarget };`, sandbox);
  return sandbox.guards;
}

test('Deploy uses Policy Engine V2 recommended profile and safety metrics', () => {
  assert.match(appSource, /api\/policy-engine\/v2\?profile=/);
  for (const label of ['Recommandé', 'Strict', 'Synthétique', 'Expert']) {
    assert.ok(appSource.includes(label), `profil ${label} absent`);
  }
  for (const metric of ['missingRequiredTuples', 'unexpectedAllowedTuples', 'expansionRatio']) {
    assert.ok(appSource.includes(metric), `métrique ${metric} absente`);
  }
  assert.match(appSource, /id="btn-toggle-advanced" style="display:none"/);
  assert.ok(appSource.includes("!v2ProfileActive && members.length > 1"));
  assert.ok(appSource.includes('Périmètre V2 verrouillé'));
});

test('Deploy exposes a destination-service affinity matrix in policy details', () => {
  assert.match(appSource, /function buildPolicyAffinityHtml\(policy\)/);
  assert.ok(appSource.includes('Affinité destination × service'));
  assert.ok(appSource.includes('commonServiceKeys'));
  assert.ok(appSource.includes('residualServiceKeysByDestination'));
  assert.match(styleSource, /\.affinity-matrix/);
  assert.match(styleSource, /\.pe-metrics/);
});

test('Deploy exposes source optimization policy counts and safety metrics', () => {
  assert.ok(appSource.includes('policyEngineOptimization'));
  assert.ok(appSource.includes('Avant optimisation'));
  assert.ok(appSource.includes('Après optimisation'));
  assert.ok(appSource.includes('sourceObjectsReused'));
});

test('Deploy integrates network representation candidates in the existing policy drawer', () => {
  assert.match(appSource, /function buildPolicyNetworkRepresentationHtml\(policy\)/);
  assert.ok(appSource.includes('Représentation réseau'));
  assert.ok(appSource.includes('Représentation actuelle'));
  assert.ok(appSource.includes('Suggestions FortiFlow'));
  for (const label of [
    'Objet FortiGate existant', 'Groupe exact existant', 'Nouveau groupe exact',
    'Subnet suggéré', 'Hosts /32',
  ]) assert.ok(appSource.includes(label), `type ${label} absent`);
  for (const field of [
    'Hôtes observés', 'Représentation proposée', 'Expansion', 'Coverage',
    'Missing', 'Unexpected', 'Justification',
  ]) assert.ok(appSource.includes(field), `champ ${field} absent`);
  assert.match(styleSource, /\.network-representation-card/);
  assert.match(styleSource, /\.network-representation-metrics/);
});

test('network representation actions use UserDecision before updating the current generation workflow', () => {
  assert.match(appSource, /api\/policy-engine\/v2\/representations\?profile=/);
  assert.match(appSource, /api\/policy-engine\/v2\/representations\/decisions/);
  assert.match(appSource, /method:\s*'POST'/);
  assert.ok(appSource.includes('resolverInputHash'));
  assert.ok(appSource.includes('Conserver'));
  assert.ok(appSource.includes('Utiliser cette représentation'));
  assert.ok(appSource.includes('Avant / Après'));
  assert.ok(appSource.includes('Objets réutilisés'));
  assert.ok(appSource.includes('Objets créés'));
  assert.ok(appSource.includes('Statut preflight'));
  assert.ok(appSource.includes('Une décision est déjà validée sur l’autre côté'));
  assert.ok(appSource.includes('deployState.networkRepresentationStates?.[policyId] !== networkState'));
  assert.match(appSource, /outcome\.analyzedPolicy/);
});

test('UserDecision rejects malformed successful responses before any policy reconciliation', () => {
  const { validateNetworkDecisionOutcome } = loadNetworkDecisionGuards();
  const valid = {
    decision: { status: 'accepted' },
    analyzedPolicy: { id: 'P-1' },
    metrics: {
      observedRequiredTuples: 1, coveredRequiredTuples: 1, missingRequiredTuples: 0,
      allowedTuples: 1, unexpectedAllowedTuples: 0, coverageRatio: 1, expansionRatio: 0,
    },
    preflight: { ok: true, errors: 0, warnings: 0 },
  };
  assert.equal(validateNetworkDecisionOutcome(valid, 'P-1'), valid);
  assert.throws(() => validateNetworkDecisionOutcome({}, 'P-1'), /incomplète/);
  assert.throws(() => validateNetworkDecisionOutcome({ ...valid, analyzedPolicy: { id: 'P-2' } }, 'P-1'), /autre policy/);
  assert.throws(() => validateNetworkDecisionOutcome({ ...valid, metrics: {} }, 'P-1'), /métriques/);
  assert.throws(() => validateNetworkDecisionOutcome({ ...valid, preflight: null }, 'P-1'), /preflight/);
});

test('UserDecision reconciles by policy ID and rejects deleted or changed contexts', () => {
  const { resolveNetworkDecisionTarget } = loadNetworkDecisionGuards();
  const policies = [
    { id: 'P-2' },
    { id: 'P-1' },
  ];
  const target = resolveNetworkDecisionTarget(policies, 'P-1', policies[1]);
  assert.equal(target.index, 1);
  assert.equal(target.policy.id, 'P-1');
  assert.throws(() => resolveNetworkDecisionTarget(policies, 'P-3', null), /n’existe plus/);
  assert.throws(() => resolveNetworkDecisionTarget(policies, 'P-1', { id: 'P-1' }), /contexte.*changé/);
});

test('network candidate state is invalidated across sessions, workspaces and FortiGate contexts', () => {
  assert.match(appSource, /function resetNetworkRepresentationStates\(\)/);
  assert.match(appSource, /state\.session = sessionId;\s*resetNetworkRepresentationStates\(\)/);
  assert.match(appSource, /btn-reload-conf[\s\S]{0,160}resetNetworkRepresentationStates\(\)/);
  assert.match(appSource, /config-vdom[\s\S]{0,500}resetNetworkRepresentationStates\(\)/);
  assert.match(appSource, /async function analyzeDeployPolicies\(\)\s*{\s*resetNetworkRepresentationStates\(\)/);
  assert.match(appSource, /state\.session = null;\s*resetNetworkRepresentationStates\(\)/);
});
