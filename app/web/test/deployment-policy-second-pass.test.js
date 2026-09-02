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

test('les valeurs multi-IP restent tronquées sur une ligne sans modifier la hauteur des policies', () => {
  const srcObjects = sourceBlock('function _buildSrcAddrCell(', 'function _buildDstAddrCell(');
  const dstObjects = sourceBlock('function _buildDstAddrCell(', 'function syncAddrCell(');

  assert.match(srcObjects, /class=\"object-name\"/);
  assert.match(dstObjects, /class=\"object-name\"/);
  assert.match(CSS, /\.policy-interface-pair\s*>\s*span:not\(\.policy-interface-arrow\)[^}]*white-space:\s*nowrap/);
  assert.match(CSS, /\.policy-object-pair\s+\.inline-editable[^}]*overflow:\s*hidden/);
});

test('le compteur de sessions occupe une micro-colonne centrée entre source et destination', () => {
  const render = sourceBlock('function renderDeployPolicies(', 'function syncNoRcvdInfoBtn(');

  assert.match(render, /const sessionCount = p\.sessions \|\| 0/);
  assert.match(render, /session\$\{sessionCount === 1 \? '' : 's'\} observée\$\{sessionCount === 1 \? '' : 's'\}/);
  assert.match(render, /<th class="policy-session-header" title="Sessions observées">SESS\.<\/th>/);
  assert.match(render, /<td class="policy-session-cell"><span class="policy-session-inline" title="\$\{sessionTitle\}">\$\{fmtNum\(sessionCount\)\}<\/span><\/td>/);
  assert.doesNotMatch(render, /\$\{fmtNum\(sessionCount\)\} sess\./);
  assert.match(CSS, /\.policy-session-header,\s*\.policy-session-cell\s*{[^}]*width:\s*52px[^}]*text-align:\s*center\s*!important[^}]*white-space:\s*nowrap/);
});

test('le passage manuel à all marque explicitement l’expansion de représentation', () => {
  assert.match(APP, /_internetAllExpansion\s*=\s*useAll/);
});

test('la table harmonise la typographie et réserve le monospace aux valeurs techniques', () => {
  const render = sourceBlock('function renderDeployPolicies(', 'function syncNoRcvdInfoBtn(');
  const destination = sourceBlock('function dstTargetCell(', 'function dstTargetCellFull(');

  assert.match(destination, /class="policy-network-value"/);
  assert.match(render, /class="policy-interface-value/);
  assert.match(CSS, /\.deploy-policy-table td\s*{[^}]*font-size:\s*12px[^}]*line-height:\s*1\.4/);
  assert.match(CSS, /\.service-summary-item\s*{[^}]*font-size:\s*12px/);
  assert.match(CSS, /\.policy-interface-value\s*{[^}]*font-size:\s*12px/);
  assert.match(CSS, /\.policy-session-inline\s*{[^}]*font-family:\s*inherit/);
  assert.match(CSS, /\.policy-network-value\s*{[^}]*font-family:\s*var\(--mono\)[^}]*font-size:\s*12px/);
  assert.match(CSS, /\.policy-object-pair\s*{[^}]*font-family:\s*var\(--mono\)[^}]*font-size:\s*12px/);
});

test('le groupe Objets FortiGate est centré sans centrer ses libellés longs', () => {
  const render = sourceBlock('function renderDeployPolicies(', 'function syncNoRcvdInfoBtn(');

  assert.match(render, /<th class="policy-objects-header">Objets FortiGate<\/th>/);
  assert.match(CSS, /\.policy-objects-header\s*{[^}]*text-align:\s*center/);
  assert.match(CSS, /\.policy-objects-cell\s*{[^}]*text-align:\s*center/);
  assert.match(CSS, /\.policy-object-pair\s*{[^}]*width:\s*fit-content[^}]*max-width:\s*100%[^}]*margin-inline:\s*auto/);
  assert.match(CSS, /\.policy-object-pair \.inline-editable\s*{[^}]*text-align:\s*left/);
});

test('les compteurs et finitions visuelles restent explicites et secondaires', () => {
  const render = sourceBlock('function renderDeployPolicies(', 'function syncNoRcvdInfoBtn(');
  const destination = sourceBlock('function dstTargetCell(', 'function dstTargetCellFull(');

  assert.match(render, /hôtes source observés/);
  assert.match(render, /\$\{srcHostCount\} hôte/);
  assert.doesNotMatch(render, /\$\{srcHostCount\}h/);
  assert.match(destination, /destinations supplémentaires/);
  assert.match(CSS, /\.dir-badge\.wan\s*{[^}]*opacity:\s*\.72[^}]*padding:\s*1px 5px/);
  assert.match(CSS, /\.object-provenance-dot,[\s\S]*?\.interface-provenance-dot\s*{[^}]*width:\s*6px[^}]*height:\s*6px/);
  assert.match(CSS, /#btn-merge-selection\s*{[^}]*font-size:\s*10px/);
  assert.match(CSS, /\.btn-merge-group\s*{[^}]*opacity:\s*\.55/);
});
