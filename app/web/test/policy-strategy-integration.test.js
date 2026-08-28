'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  buildPolicyStrategyPreviews,
  preserveDestinationServiceAffinity,
  validatePolicyDecisionShapes,
  validatePolicyStrategyBatch,
} = require('../lib/forticonfig');

const serverSource = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const appSource = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
const styleSource = fs.readFileSync(path.join(__dirname, '..', 'public', 'style.css'), 'utf8');

function functionBlock(name, nextName) {
  const start = appSource.indexOf(`function ${name}`);
  const end = nextName ? appSource.indexOf(`function ${nextName}`, start + 1) : appSource.length;
  assert.ok(start >= 0 && end > start, `${name} introuvable`);
  return appSource.slice(start, end);
}

// RED: le serveur doit exposer la preview calculée depuis le payload analysé.
test('la barre principale expose les stratégies et vues compactes sans l’ancien modal', () => {
  assert.match(appSource, /id="deploy-strategy-toolbar"/);
  for (const label of ['Équilibrée ★', 'Compacte', 'Synthétique', 'Tout', 'Internet', 'LAN', 'Synthèse', 'Services', 'IP à IP', 'Réseau → Serveur', 'Appliquer']) {
    assert.match(appSource, new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
  assert.match(appSource, /preview\.strategies\[name\]\.policies/);
  assert.match(appSource, /additional/);
  assert.match(appSource, /expansion/);
  assert.match(appSource, /Pré-déploiement/);
  assert.match(appSource, /hors périmètre non modifiées/);
  assert.doesNotMatch(appSource, /function showMergeDiff/);
  assert.doesNotMatch(appSource, /data-merge="apply"/);
  assert.doesNotMatch(appSource, /Détailler/);
  assert.match(styleSource, /\.strategy-preview/);
  assert.match(serverSource, /app\.post\('\/api\/deploy\/preview'/);
  assert.match(serverSource, /validatePolicyDecisionShapes\(selectedPolicies\)/);
  assert.match(serverSource, /buildPolicyStrategyPreviews\(selectedPolicies, \{ scope \}\)/);
  assert.match(serverSource, /strategyMetrics:\s*decision\.strategyMetrics/);
  assert.doesNotMatch(appSource, /id="deploy-missing-bar"|id="no-rcvd-bar"/);
});

test('Vue reste une projection indépendante de la stratégie et de la génération', () => {
  const applyView = functionBlock('refreshDeployViewPolicies', '_updateMergeSelectionBtn');
  const applyStrategy = functionBlock('applyPolicyStrategyPreview', 'collectMissingObjects');
  const generate = functionBlock('generateDeployConf');

  assert.match(applyView, /deployState\.viewPolicies\s*=/);
  assert.doesNotMatch(applyView, /deployState\.analyzed\s*=/);
  assert.match(applyStrategy, /preview\.strategies\[name\]\.policies/);
  assert.doesNotMatch(applyStrategy, /bruteMode\s*=\s*'off'/);
  assert.match(generate, /deployState\.analyzed/);
  assert.doesNotMatch(generate, /viewPolicies/);
  assert.match(appSource, /loadPolicyStrategyPreviews\(scopeBtn\.dataset\.strategyScope\)/);
});

test('une preview synthétique marquée est validée puis conservée sans re-split silencieux', () => {
  const service = (label, key) => ({ label, name: label, found: true, isNamed: true, reuseKeys: [key] });
  const policies = ['APP-A', 'APP-B'].map(destination => ({
    srcSubnet: '10.10.0.0/24', dstTarget: destination, dstType: 'private',
    _srcintf: 'LAN', _dstintf: 'SERVERS', action: 'accept', _action: 'accept',
    srcHosts: [], dstHosts: [],
    analysis: { services: [service('HTTPS', 'TCP/443')] },
  }));
  const preview = buildPolicyStrategyPreviews(policies, { scope: 'all' });
  const synthetic = preview.strategies.synthetic;
  for (const policy of synthetic.policies) {
    policy._generationMetrics = synthetic.metrics;
    policy._generationScope = preview.scope;
  }

  assert.equal(typeof validatePolicyStrategyBatch, 'function');
  const validation = validatePolicyStrategyBatch(synthetic.policies, {
    scope: preview.scope,
    strategy: 'synthetic',
    metrics: synthetic.metrics,
  });
  assert.equal(validation.ok, true, JSON.stringify(validation.issues));
  assert.deepEqual(preserveDestinationServiceAffinity(synthetic.policies), synthetic.policies);

  const forged = structuredClone(synthetic.policies);
  forged[0]._generationMetrics = { ...synthetic.metrics, allowed: 1 };
  assert.equal(validatePolicyStrategyBatch(forged, {
    scope: preview.scope,
    strategy: 'synthetic',
    metrics: forged[0]._generationMetrics,
  }).ok, false);
});

test('Synthétique exclut les policies hors périmètre de la preview et de l’application', () => {
  const https = { label: 'HTTPS', name: 'HTTPS', found: true, isNamed: true, reuseKeys: ['TCP/443'] };
  const policies = [
    { srcSubnet: 'LAN-A', dstTarget: 'APP-A', dstType: 'private', _srcintf: 'LAN', _dstintf: 'SERVERS', action: 'accept', analysis: { services: [https] } },
    { srcSubnet: 'LAN-A', dstTarget: 'APP-B', dstType: 'private', _srcintf: 'LAN', _dstintf: 'SERVERS', action: 'accept', analysis: { services: [https] } },
    { srcSubnet: 'LAN-A', dstTarget: '203.0.113.10', dstType: 'public', _srcintf: 'LAN', _dstintf: 'WAN', action: 'accept', analysis: { services: [https] } },
  ];
  const preview = buildPolicyStrategyPreviews(policies, { scope: 'lan' });
  const synthetic = preview.strategies.synthetic;
  for (const policy of synthetic.policies) {
    policy._generationStrategy = 'synthetic';
    policy._generationScope = 'lan';
    policy._generationMetrics = synthetic.metrics;
  }

  assert.equal(preview.scopedPolicyCount, 2);
  assert.equal(preview.outsideScopeCount, 1);
  assert.equal(synthetic.metrics.before, 2);
  assert.ok(synthetic.policies.every(policy => policy._generationPassThrough !== true));
  const validation = validatePolicyStrategyBatch(synthetic.policies);
  assert.equal(validation.ok, true, JSON.stringify(validation.issues));
  assert.equal(validation.metrics.observed, synthetic.metrics.observed);
  assert.equal(validation.metrics.allowed, synthetic.metrics.allowed);
});

test('la provenance volumineuse reste bornée et réservée aux stratégies revalidées', () => {
  const https = { label: 'HTTPS', name: 'HTTPS', found: true, isNamed: true, reuseKeys: ['TCP/443'] };
  const input = Array.from({ length: 1001 }, (_, index) => ({
    srcSubnet: 'LAN-A', dstTarget: `PUBLIC-${String(index).padStart(4, '0')}`, dstType: 'public',
    _srcintf: 'LAN', _dstintf: 'WAN', action: 'accept', analysis: { services: [https] },
  }));
  const result = buildPolicyStrategyPreviews(input).strategies.synthetic;
  for (const policy of result.policies) {
    policy._generationStrategy = 'synthetic';
    policy._generationScope = 'all';
    policy._generationMetrics = result.metrics;
  }
  assert.equal(validatePolicyDecisionShapes(result.policies).ok, true);
  assert.equal(validatePolicyStrategyBatch(result.policies).ok, true);

  const unmarked = structuredClone(result.policies);
  for (const policy of unmarked) delete policy._generationStrategy;
  assert.equal(validatePolicyDecisionShapes(unmarked).ok, false);
});
