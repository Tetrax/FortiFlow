'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const APP = fs.readFileSync(path.join(__dirname, '../public/app.js'), 'utf8');
const CSS = fs.readFileSync(path.join(__dirname, '../public/style.css'), 'utf8');

function sourceBlock(start, end) {
  const from = APP.indexOf(start);
  assert.notEqual(from, -1, `bloc absent: ${start}`);
  const to = APP.indexOf(end, from + start.length);
  assert.notEqual(to, -1, `fin absente: ${end}`);
  return APP.slice(from, to);
}

test('la table de policies garde uniquement DISABLED et porte le statut sur le bord droit', () => {
  const render = sourceBlock('function renderDeployPolicies(', 'function syncNoRcvdInfoBtn(');

  assert.doesNotMatch(render, />ENA</);
  assert.match(render, />DISABLED</);
  assert.doesNotMatch(render, /<th[^>]*>État<\/th>/);
  assert.doesNotMatch(render, /policy-state-cell/);
  assert.match(render, /policy-complete-row/);
  assert.match(render, /policy-incomplete-row/);
  assert.match(CSS, /\.policy-complete-row[^}]*inset\s+-[4-6]px/);
  assert.match(CSS, /\.policy-incomplete-row[^}]*inset\s+-[4-6]px/);
});

test('la table masque ROUTE, calme les provenances et aligne checkbox puis chevron', () => {
  const render = sourceBlock('function renderDeployPolicies(', 'function syncNoRcvdInfoBtn(');
  const status = sourceBlock('function objectStatusTag(', 'function addrCell(');
  const services = sourceBlock('function _buildSvcCellHtml(', 'function syncSvcCell(');
  const group = render.slice(render.indexOf('intf-pair-header-inner'), render.indexOf('intf-pair-header-inner') + 900);

  assert.doesNotMatch(render, />ROUTE</);
  assert.match(render, /interface-provenance-dot sdwan/);
  assert.doesNotMatch(status, />EXACT</);
  assert.doesNotMatch(status, />AUTO</);
  assert.match(status, /object-provenance-dot/);
  assert.match(services, /service-summary-separator/);
  assert.ok(group.indexOf('deploy-chk intf-group-chk') < group.indexOf('intf-pair-toggle'));
});

test('sélection, fusion, drawer et pagination restent câblés après la simplification', () => {
  const render = sourceBlock('function renderDeployPolicies(', 'function syncNoRcvdInfoBtn(');
  const wiring = sourceBlock('function wireDeployTable(', 'function resetDeployTableWiring(');

  assert.match(render, /chk-all-deploy/);
  assert.match(render, /deploy-merge-chk/);
  assert.match(render, /pg-next/);
  assert.match(wiring, /openDrawer/);
  assert.match(wiring, /mergeSelectedDeployPolicies|btn-merge-group/);
});

test('le drawer Internet recommande all tout en gardant les IP observées inspectables', () => {
  const drawer = sourceBlock('function populateDrawer(', 'function renderConfSummary(');

  assert.match(drawer, /Internet \(all\) — Recommandé/);
  assert.match(drawer, /IPs spécifiques/);
  assert.match(drawer, /IP publiques observées/);
  assert.match(drawer, /Voir les .* IP observées/);
  assert.match(drawer, /hors du calcul borné d’Additional/);
  assert.match(drawer, /drawerHostControl/);
});

test('les preuves Internet incluent les cibles publiques des stratégies', () => {
  const evidence = sourceBlock('function destinationObservedHosts(', 'function normalizeDestinationCidr(');
  assert.match(evidence, /dstTargets/);
  assert.match(evidence, /_multiDstSubnets/);
  assert.match(evidence, /\/32/);
});

test('le passage manuel à all marque explicitement l’expansion de représentation', () => {
  assert.match(APP, /_internetAllExpansion\s*=\s*useAll/);
});
