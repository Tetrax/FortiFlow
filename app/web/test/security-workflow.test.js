'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const WORKFLOW = path.resolve(__dirname, '../../../.github/workflows/security-tests.yml');
const TRIVY_SHA = 'ed142fd0673e97e23eac54620cfb913e5ce36c25';

test(
  'toutes les occurrences Trivy du workflow sont épinglées au SHA vérifié',
  {
    skip: !fs.existsSync(WORKFLOW)
      ? '.github/workflows/security-tests.yml is outside the application image'
      : false,
  },
  () => {
    const workflow = fs.readFileSync(WORKFLOW, 'utf8');
    const occurrences = [...workflow.matchAll(
      /^\s*uses:\s*aquasecurity\/trivy-action@([^\s#]+)(?:\s+#\s*(v[^\s]+))?\s*$/gm,
    )];

    assert.equal(occurrences.length, 2, 'le workflow doit conserver ses deux contrôles Trivy');
    for (const [, ref, comment] of occurrences) {
      assert.equal(ref, TRIVY_SHA);
      assert.equal(comment, 'v0.36.0');
    }
  },
);
