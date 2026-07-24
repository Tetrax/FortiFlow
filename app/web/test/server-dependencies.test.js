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

  for (const requiredName of ['buildAnalysis', 'consolidatePolicies', 'flowDecision']) {
    assert.ok(
      importedNames.has(requiredName),
      `${requiredName} is used by server.js but is missing from the analyzer import`,
    );
  }
});
