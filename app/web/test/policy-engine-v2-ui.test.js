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
