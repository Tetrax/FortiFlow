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

test('server exposes a read-only network representation candidates endpoint', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.match(source, /require\(['"]\.\/lib\/network-representation-integration['"]\)/);
  assert.match(source, /app\.get\(['"]\/api\/policy-engine\/v2\/representations['"]/);
  assert.match(source, /buildPolicyRepresentationCandidates\(result,\s*s\.fortiConfig\s*\|\|\s*\{\},\s*policyId\)/);
  const routeStart = source.indexOf("app.get('/api/policy-engine/v2/representations'");
  const routeEnd = source.indexOf("app.post('/api/policy-engine/v2/representations/decisions'", routeStart);
  const routeSource = source.slice(routeStart, routeEnd);
  assert.doesNotMatch(routeSource, /preflightValidation|generateConfig|analyzePolicies|UserDecision/);
});

test('server exposes persisted network decisions without invoking CLI generation', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.match(source, /app\.post\(['"]\/api\/policy-engine\/v2\/representations\/decisions['"]/);
  assert.match(source, /app\.get\(['"]\/api\/policy-engine\/v2\/representations\/decisions['"]/);
  assert.match(source, /setNetworkDecisions\(s\.id,\s*decisions\)/);
  assert.match(source, /applyNetworkRepresentationDecision\(/);
  const routeStart = source.indexOf("app.post('/api/policy-engine/v2/representations/decisions'");
  const routeEnd = source.indexOf("// GET /api/policy-engine/v2", routeStart);
  const routeSource = source.slice(routeStart, routeEnd);
  assert.doesNotMatch(routeSource, /generateConfig|\/api\/deploy\/generate/);
});

test('workspace export and import preserve persisted network decisions', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const exports = source.match(/networkDecisions:\s*s\.networkDecisions\s*\|\|\s*\{\}/g) || [];
  const imports = source.match(/setNetworkDecisions\([^,]+,\s*body\.networkDecisions\)/g) || [];
  assert.equal(exports.length, 2);
  assert.equal(imports.length, 2);
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
