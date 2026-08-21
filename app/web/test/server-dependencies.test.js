'use strict';

const fs = require('fs');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert/strict');

test('server imports every analyzer function used by deployment re-analysis', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const analyzerImport = source.match(
    /const\s*\{([^}]+)\}\s*=\s*require\(['"]\.\/lib\/analyzer['"]\)/,
  );

  assert.ok(analyzerImport, 'server.js must import its analyzer dependencies');

  const importedNames = new Set(
    analyzerImport[1]
      .split(',')
      .map(name => name.trim())
      .filter(Boolean),
  );

  for (const requiredName of ['buildAnalysis', 'consolidatePolicies', 'flowDecision', 'buildPolicyEngineV2']) {
    assert.ok(
      importedNames.has(requiredName),
      `${requiredName} is used by server.js but is missing from the analyzer import`,
    );
  }
});

test('server exposes the Policy Engine V2 endpoint', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.match(source, /app\.get\(['"]\/api\/policy-engine\/v2['"]/);
  assert.match(source, /optimization:\s*result\.optimization/);
});

test('Policy Engine V2 API parses Traffic Scope, keys the cache, and returns scope metrics', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.match(source, /require\(['"]\.\/lib\/traffic-scope['"]\)/);
  assert.match(source, /parseTrafficScopeQuery\(req\.query\)/);
  assert.match(source, /trafficScopeKey/);
  assert.match(source, /trafficScope:\s*result\.trafficScope/);
});

test('deployment preflight receives the complete V2 atom set after user selection', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const wiredCalls = source.match(/preflightValidation\([^\n]+requiredPolicyEngineAtoms\)/g) || [];
  assert.equal(wiredCalls.length, 3);
});

const nginxConfigPath = path.resolve(
  __dirname,
  '../../..',
  'infra',
  'nginx',
  'fortiflow.conf',
);

test('le chargement de configuration passe le gate de cohérence avant toute mutation de session', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.match(source, /\.\/lib\/config-consistency/);
  assert.match(source, /CONFIG_TELEMETRY_MISMATCH/);
  const gate = source.indexOf('validateConfigTelemetryConsistency');
  const mutation = source.indexOf('s.fortiConfig = fortiConfig');
  assert.ok(gate >= 0, 'le gate de cohérence doit être appelé');
  assert.ok(mutation >= 0, 'la mutation de session doit rester identifiable');
  assert.ok(gate < mutation, 'la configuration ne doit pas muter avant la validation');
  assert.match(source, /sendConfigTelemetryMismatch\(res/);
});

test('les chemins policy-engine, preflight, génération et workspace revalident la cohérence', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  for (const marker of [
    "app.get('/api/policy-engine/v2'",
    "app.post('/api/deploy/preflight'",
    "app.post('/api/deploy/generate'",
    "app.post('/api/import/workspace'",
  ]) {
    const start = source.indexOf(marker);
    assert.ok(start >= 0, `route absente: ${marker}`);
    const end = source.indexOf('\n});', start);
    const route = source.slice(start, end >= 0 ? end : source.length);
    assert.match(route, /configTelemetry|validateConfigTelemetryConsistency|validateWorkspaceConfigTelemetry|assertConfigTelemetry/);
  }
});

test('le gate de cohérence filtre la télémétrie sur le VDOM explicitement sélectionné', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const start = source.indexOf('function validateConfigTelemetryForSession');
  const end = source.indexOf('\n}', start);
  const helper = source.slice(start, end >= 0 ? end : source.length);
  assert.match(helper, /flowsForFortiConfig\([^,]+,\s*fortiConfig/);
});

test('la sauvegarde et l’export workspace restent possibles avant le chargement FortiGate', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  for (const marker of ["app.get('/api/export/workspace'", "app.post('/api/workspaces'"]) {
    const start = source.indexOf(marker);
    const end = source.indexOf('\n});', start);
    const route = source.slice(start, end >= 0 ? end : source.length);
    assert.match(route, /if \(s\.fortiConfig\)[\s\S]*assertConfigTelemetry/);
  }
});

test('le serveur valide les sélections d’adresse avant le preflight et la génération', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.match(source, /validatePolicyAddressSelections/);
  for (const marker of ["app.post('/api/deploy/preflight'", "app.post('/api/deploy/generate'"]) {
    const start = source.indexOf(marker);
    const end = source.indexOf('\n});', start);
    const route = source.slice(start, end >= 0 ? end : source.length);
    assert.match(route, /assertAddressSelections|validatePolicyAddressSelections/);
  }
});

test('les routes de déploiement rebâtissent les policies V2 depuis la provenance serveur', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.match(source, /\.\/lib\/policy-binding/);
  for (const marker of ["app.post('/api/deploy/preflight'", "app.post('/api/deploy/generate'"]) {
    const start = source.indexOf(marker);
    const end = source.indexOf('\n});', start);
    const route = source.slice(start, end >= 0 ? end : source.length);
    const binding = route.indexOf('bindSubmittedPolicies');
    assert.ok(binding >= 0, `provenance absente de ${marker}`);
    assert.ok(binding < route.indexOf('preflightValidation'), `preflight avant binding dans ${marker}`);
  }
});

test('l’import workspace ignore networkDecisions avant la restauration de session', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.match(source, /stripLegacyNetworkDecisions/);
  const importStart = source.indexOf("app.post('/api/import/workspace'");
  const importEnd = source.indexOf("app.get('/api/workspaces'", importStart);
  assert.ok(importStart >= 0 && importEnd > importStart);
  const route = source.slice(importStart, importEnd);
  assert.ok(route.indexOf('stripLegacyNetworkDecisions') < route.indexOf('setSessionData'));
  const deleteIndex = source.indexOf('delete sanitized.networkDecisions');
  assert.ok(deleteIndex >= 0 && deleteIndex < importStart);
});

test(
  'le reverse proxy écrase X-Forwarded-For avec l’adresse TCP réelle',
  {
    skip: !fs.existsSync(nginxConfigPath)
      ? 'infra/nginx/fortiflow.conf is outside the application image'
      : false,
  },
  () => {
    const nginxConfig = fs.readFileSync(nginxConfigPath, 'utf8');
    assert.ok(nginxConfig.includes('proxy_set_header X-Forwarded-For $remote_addr;'));
    assert.ok(!nginxConfig.includes('proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;'));
  },
);
