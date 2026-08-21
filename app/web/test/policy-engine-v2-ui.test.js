'use strict';

const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const appSource = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
const styleSource = fs.readFileSync(path.join(__dirname, '..', 'public', 'style.css'), 'utf8');

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
  assert.equal(appSource.includes('Périmètre V2 verrouillé'), false);
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

test('le drawer historique propose uniquement les choix d’adresse simples', () => {
  for (const label of ['Utiliser cet objet', 'Créer un subnet', 'Créer les hôtes /32', 'CIDR', 'hôtes observés', 'IP non observées', 'Confirmer', 'Subnet choisi', 'Hôtes /32 choisis']) {
    assert.ok(appSource.includes(label), `libellé absent: ${label}`);
  }
  assert.match(appSource, /function buildSimpleAddressChoiceHtml\(/);
  assert.ok(appSource.includes('addressSelections'));
  assert.match(styleSource, /\.address-choice/);
  for (const internalTerm of ['NetworkCandidate', 'UserDecision', 'networkDecisions']) {
    assert.equal(appSource.includes(internalTerm), false, `terme interne exposé: ${internalTerm}`);
  }
  assert.match(appSource, /mode === 'hosts'[\s\S]{0,180}confirmed: true/);
  assert.match(appSource, /p\._multiSrcSubnets\?\.length && simpleSourceMode/);
  assert.match(appSource, /p\._isMultiDst && p\._multiDstSubnets\?\.length && simpleDestinationMode/);
  assert.match(appSource, /!simpleAddressMode && p\.metrics/);
  assert.match(appSource, /!simpleAddressMode \? buildPolicyAffinityHtml\(p\) : ''/);
  assert.match(appSource, /!simpleDestinationMode \? `<div class="drawer-field">/);
});

test('un mismatch de cohérence reste bloquant avant l’étape Règles', () => {
  assert.ok(appSource.includes('CONFIG_TELEMETRY_MISMATCH'));
  assert.ok(appSource.includes('addressSelectionMismatch'));
  assert.ok(appSource.includes('Aucune règle ne peut être construite'));
});
