'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

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
test('la barre principale compare les trois stratégies par nombre final de policies', () => {
  const toolbar = functionBlock('renderStrategyToolbar', 'updateStrategyToolbar');

  assert.match(appSource, /id="deploy-strategy-toolbar"/);
  for (const label of ['Équilibrée', 'Compacte', 'Synthétique', 'Recommandée', 'Tout', 'LAN', 'Internet']) {
    assert.match(toolbar, new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
  for (const description of [
    'Réduit le nombre de règles tout en conservant une segmentation raisonnable.',
    'Réduit davantage le nombre de règles tout en restant fidèle aux communications.',
    'Regroupe fortement les communications pour obtenir un jeu de règles très synthétique.',
  ]) {
    assert.ok(toolbar.includes(description), `description absente: ${description}`);
  }
  assert.match(toolbar, /result\?\.policyCount/);
  assert.match(toolbar, /strategy-preview-count/);
  assert.doesNotMatch(toolbar, /Observed|Allowed|Additional|expansion|observés|autorisés|flux supplémentaires/i);
  assert.doesNotMatch(toolbar, /data-strategy-action="apply"|data-detail-action="apply"|id="detail-dropdown-wrap"/);
  assert.match(appSource, /Pré-déploiement/);
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

test('les cartes de stratégie occupent trois colonnes équilibrées puis se replient', () => {
  const gridRule = styleSource.match(/\.strategy-preview-grid\s*\{[^}]+\}/)?.[0] || '';

  assert.match(gridRule, /repeat\(3,\s*minmax\(0,\s*1fr\)\)/);
  assert.match(styleSource, /@media \(max-width: 900px\)[\s\S]*?\.strategy-preview-grid\s*\{\s*grid-template-columns:\s*repeat\(2,\s*minmax\(0,\s*1fr\)\)/);
  assert.match(styleSource, /@media \(max-width: 580px\)[\s\S]*?\.strategy-preview-grid\s*\{\s*grid-template-columns:\s*minmax\(0,\s*1fr\)/);
});

test('Périmètre et Stratégie appliquent immédiatement le dernier choix utilisateur', () => {
  const loadPreviews = functionBlock('loadPolicyStrategyPreviews', 'activatePolicyStrategyScope');
  const activateScope = functionBlock('activatePolicyStrategyScope', 'activatePolicyStrategy');
  const activateStrategy = functionBlock('activatePolicyStrategy', 'applyPolicyStrategyPreview');
  const analyze = functionBlock('analyzeDeployPolicies', 'suggestAddrNameFE');

  assert.match(loadPreviews, /const requestId = \+\+deployState\.strategyPreviewRequest/);
  assert.match(loadPreviews, /requestId !== deployState\.strategyPreviewRequest/);
  assert.match(activateScope, /await loadPolicyStrategyPreviews\(scope\)/);
  assert.match(activateScope, /if \(!loaded\) return false/);
  assert.match(activateScope, /applyPolicyStrategyPreview\(deployState\.strategyName \|\| 'balanced'\)/);
  assert.match(activateStrategy, /deployState\.strategyName = name/);
  assert.match(activateStrategy, /if \(deployState\.strategyPreviewLoading\) return false/);
  assert.match(activateStrategy, /applyPolicyStrategyPreview\(name\)/);
  assert.match(appSource, /activatePolicyStrategyScope\(scopeBtn\.dataset\.strategyScope\)/);
  assert.match(appSource, /activatePolicyStrategy\(strategyBtn\.dataset\.strategyName\)/);
  assert.match(analyze, /deployState\.strategyName\s*=\s*'balanced'/);
  assert.match(analyze, /await activatePolicyStrategyScope\('all'\)/);
});

test('une réponse de périmètre obsolète ne remplace ni la preview ni la stratégie la plus récente', async () => {
  const pending = [];
  const applied = [];
  const context = {
    deployState: {
      analyzed: [{ id: 1 }], strategyScope: 'all', strategyName: 'balanced',
      strategyPreviews: null, strategyMetrics: null, strategyPreviewRequest: 0,
      strategyPreviewLoading: false, strategyPreviewError: '',
    },
    state: { session: 'test-session' },
    serializeAnalyzed: value => value,
    updateStrategyToolbar: () => {},
    fetch: (_url, options) => new Promise(resolve => pending.push({
      scope: JSON.parse(options.body).scope,
      resolve,
    })),
    applyPolicyStrategyPreview: name => {
      applied.push({ name, scope: context.deployState.strategyPreviews.scope });
      return true;
    },
  };
  const loadFunction = functionBlock('loadPolicyStrategyPreviews', 'activatePolicyStrategyScope').replace(/\s+async\s*$/, '');
  const activateScopeFunction = functionBlock('activatePolicyStrategyScope', 'activatePolicyStrategy');
  vm.createContext(context);
  vm.runInContext(
    `async ${loadFunction}\n`
      + `async ${activateScopeFunction}\n`
      + 'globalThis.activateScope = activatePolicyStrategyScope;',
    context,
  );
  const response = scope => ({
    ok: true,
    json: async () => ({ scope, strategies: { balanced: {}, compact: {}, synthetic: {} } }),
  });

  const lan = context.activateScope('lan');
  const internet = context.activateScope('internet');
  pending.find(item => item.scope === 'internet').resolve(response('internet'));
  assert.equal(await internet, true);
  pending.find(item => item.scope === 'lan').resolve(response('lan'));
  assert.equal(await lan, false);

  assert.equal(context.deployState.strategyPreviews.scope, 'internet');
  assert.deepEqual(applied, [{ name: 'balanced', scope: 'internet' }]);
});

test('Vue et Analyse disparaissent entièrement de cet écran', () => {
  const toolbar = functionBlock('renderStrategyToolbar', 'updateStrategyToolbar');
  const deployView = functionBlock('deploy', 'uploadConf');

  assert.doesNotMatch(toolbar, /Vue|Synthèse|IP à IP|Réseau → Serveur|strategy-view|detail-mode/);
  assert.doesNotMatch(toolbar, /Analyse|analyse-dropdown|btn-analyse|btn-risk/);
  assert.doesNotMatch(deployView, /btn-analyze|Analyser les policies|deploy-risk-panel/);
  for (const obsoleteUiSymbol of [
    'bruteMode', 'viewPolicies', 'refreshDeployViewPolicies',
    'splitPoliciesByService', 'splitPoliciesByHostAndService', 'splitPoliciesBySrcAggDstDetail',
    'riskPanelOpen', 'renderRiskPanel', 'loadRiskPanel', 'showRiskPortsModal',
  ]) {
    assert.equal(appSource.includes(obsoleteUiSymbol), false, `logique UI obsolète conservée: ${obsoleteUiSymbol}`);
  }
});

test('les actions secondaires restent câblées après chaque nouveau rendu de la toolbar', () => {
  const toolbar = functionBlock('renderStrategyToolbar', 'updateStrategyToolbar');
  const toolbarEvents = appSource.slice(
    appSource.indexOf('// Strategy toolbar'),
    appSource.indexOf('// Close dropdowns on outside click'),
  );

  assert.match(toolbar, /id="btn-policy-undo"[^>]*\$\{_policyUndo\.length/);
  assert.match(toolbar, /id="btn-policy-redo"[^>]*\$\{_policyRedo\.length/);
  assert.match(toolbarEvents, /closest\('#btn-policy-undo'\)[\s\S]{0,160}_policyUndoStep\(\)/);
  assert.match(toolbarEvents, /closest\('#btn-policy-redo'\)[\s\S]{0,160}_policyRedoStep\(\)/);
  assert.match(toolbarEvents, /closest\('#btn-merge-selection'\)[\s\S]{0,160}mergeSelectedDeployPolicies\(\)/);
});

test('la préparation des policies devient automatique sans changer la génération', () => {
  const deployView = functionBlock('deploy', 'uploadConf');
  const applyStrategy = functionBlock('applyPolicyStrategyPreview', 'collectMissingObjects');
  const generate = functionBlock('generateDeployConf');

  assert.match(deployView, /ws === 4[\s\S]{0,220}analyzeDeployPolicies\(\)/);
  assert.match(applyStrategy, /preview\.strategies\[name\]\.policies/);
  assert.match(generate, /deployState\.analyzed/);
  assert.match(appSource, /activatePolicyStrategyScope\(scopeBtn\.dataset\.strategyScope\)/);
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
