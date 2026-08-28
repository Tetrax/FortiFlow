'use strict';

const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const appSource = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
const styleSource = fs.readFileSync(path.join(__dirname, '..', 'public', 'style.css'), 'utf8');
const populateDrawer = appSource.match(/function populateDrawer\(idx\) \{[\s\S]*?\n\}/)?.[0] || '';

function cssRule(selector, source = styleSource) {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = source.match(new RegExp(`${escaped}\\s*\\{([^}]*)\\}`, 's'));
  assert.ok(match, `règle CSS introuvable: ${selector}`);
  return match[1];
}

test('le header du drawer expose Annuler, Ctrl+Z, fermeture et Voir les flux', () => {
  assert.match(appSource, /title\.textContent\s*=\s*`Policy \$\{/);
  assert.match(appSource, /drawer-undo/);
  assert.match(appSource, /Annuler/);
  assert.match(appSource, /<kbd[^>]*>Ctrl\+Z<\/kbd>/);
  assert.match(appSource, /aria-label="Annuler la dernière modification"/);
  assert.match(appSource, /id="drawer-close"/);
  assert.match(appSource, /drawer-header-actions/);
  assert.match(populateDrawer, /drawer-header-actions[\s\S]*Voir les flux/);
});

test('les informations générales sont des lignes compactes et l’action réelle est exposée', () => {
  assert.ok(populateDrawer.includes('drawer-general-lines'));
  assert.equal(populateDrawer.includes('drawer-general-grid'), false);
  for (const label of ['Direction', 'Sessions', 'Policy ID', 'Log', 'NAT', 'Nom']) {
    assert.ok(populateDrawer.includes(label), `information générale absente: ${label}`);
  }
  assert.match(populateDrawer, /p\._action\s*\|\|\s*p\.action\s*\|\|\s*'accept'/);
  assert.match(populateDrawer, /data-action="accept"[\s\S]*ACCEPT/);
  assert.match(populateDrawer, /data-action="deny"[\s\S]*DENY/);
});

test('les états ACCEPT et DENY ont une couleur active sémantique et un focus visible', () => {
  assert.match(populateDrawer, /drawer-action-btn accept/);
  assert.match(populateDrawer, /drawer-action-btn deny/);
  assert.match(styleSource, /\.drawer-action-btn\.accept\.active[\s\S]*background:\s*var\(--success\)/);
  assert.match(styleSource, /\.drawer-action-btn\.deny\.active[\s\S]*background:\s*var\(--danger\)/);
  assert.match(styleSource, /\.drawer-action-btn:focus-visible|\.policy-drawer button:focus-visible/);
});

test('la destination utilise un seul groupe de trois modes homogènes', () => {
  assert.match(populateDrawer, /drawer-destination-mode-group[\s\S]*role="group"/);
  for (const mode of ['hosts', 'detected-subnets', 'aggregate']) {
    assert.match(populateDrawer, new RegExp(`modeButton\\('${mode}'`));
  }
  assert.match(populateDrawer, /Hôtes \/32/);
  assert.match(populateDrawer, /Sous-réseaux détectés/);
  assert.match(populateDrawer, /Réseau agrégé/);
  assert.equal(populateDrawer.includes('Agréger</button>'), false);
  assert.match(styleSource, /\.drawer-destination-mode-group\s*\{[\s\S]*grid-template-columns:\s*repeat\(3,/);
});

test('le changement de mode destination conserve le mécanisme et le nombre d’hôtes', () => {
  assert.match(appSource, /setDestinationRepresentation\(p, destinationModeBtn\.dataset\.mode\)/);
  assert.match(populateDrawer, /Destination[^`]*visibleDstHosts\.length/);
  assert.match(populateDrawer, /Hôtes \/32 \(\$\{visibleDstHosts\.length\}\)/);
  assert.match(appSource, /function destinationDetectedForPolicy/);
  assert.match(appSource, /function destinationAggregateSubnet/);
});

test('source et destination gardent leurs valeurs, objets, badges et interfaces', () => {
  for (const token of [
    'p.srcSubnet', 'drawer-src-name', 'drawer-srcintf',
    'visibleDstHosts', 'drawer-destination-cidr', 'drawer-dst-name', 'drawer-dstintf',
    "badgeHtml('config')", "badgeHtml('auto')",
  ]) {
    assert.ok(populateDrawer.includes(token), `élément réseau absent: ${token}`);
  }
});

test('les services restent denses, sans checkbox par ligne, avec leurs badges', () => {
  assert.ok(populateDrawer.includes('drawer-services-grid'));
  assert.equal(populateDrawer.includes('svc-sel-chk'), false);
  assert.ok(populateDrawer.includes('svc-sel-all'), 'Tout sélectionner doit rester accessible');
  for (const badge of ["badgeHtml('config')", "badgeHtml('auto')"]) {
    assert.ok(populateDrawer.includes(badge), `badge service absent: ${badge}`);
  }
  assert.ok(populateDrawer.includes("svc.source === 'predefined'"));
  assert.ok(populateDrawer.includes("badgeHtml(svc.source === 'predefined' ? 'predefined' : 'config')"));
  assert.match(styleSource, /\.drawer-services-grid\s*\{[\s\S]*grid-template-columns:\s*repeat\((2|3),/);
});

test('le service compatible observé tient sur une ligne et garde les deux décisions', () => {
  assert.match(populateDrawer, /drawer-service-compatibility-line/);
  assert.match(populateDrawer, /compatibleMatch\.name/);
  assert.match(populateDrawer, /compatibleMatch\.extraPortCount/);
  assert.ok(populateDrawer.includes('drawer-use-compatible-service'));
  assert.ok(populateDrawer.includes('drawer-create-specific-service'));
  assert.match(styleSource, /\.drawer-service-compatibility-line\s*\{[\s\S]*display:\s*flex/);
});

test('Security Profiles est ouvert par défaut, accessible et optionnel', () => {
  assert.match(appSource, /<details class="drawer-security-profiles" open>/);
  assert.match(appSource, /<summary>Security Profiles<\/summary>/);
  for (const label of ['Antivirus', 'Web Filter', 'IPS', 'SSL Inspection']) {
    assert.ok(appSource.includes(label), `profil absent: ${label}`);
  }
  assert.match(appSource, /if \(!sp \|\|/);
});

test('les interactions existantes restent branchées sur les décisions et la génération', () => {
  assert.match(appSource, /e\.target\.matches\('\.drawer-action-btn'\)[\s\S]*p\._action\s*=\s*e\.target\.dataset\.action/);
  assert.match(appSource, /drawer-use-compatible-service[\s\S]*markServiceDecisionResolved/);
  assert.match(appSource, /drawer-create-specific-service[\s\S]*markServiceDecisionResolved/);
  assert.match(appSource, /setDestinationRepresentation\(p, destinationModeBtn\.dataset\.mode\)/);
  assert.match(appSource, /function generateDeployConf/);
});

test('Général aligne les informations sans cellules vides de demi-largeur', () => {
  assert.match(styleSource, /\.drawer-general-lines\s*\{[\s\S]*display:\s*flex/);
  assert.doesNotMatch(cssRule('.drawer-general-lines'), /grid-template-columns/);
  assert.match(populateDrawer, /drawer-general-line[\s\S]*Direction[\s\S]*Sessions[\s\S]*drawer-general-action/);
  assert.match(populateDrawer, /drawer-general-name/);
});

test('les services sont séparés entre configurés et services à traiter', () => {
  assert.match(populateDrawer, /resolvedServiceEntries/);
  assert.match(populateDrawer, /pendingServiceEntries/);
  assert.match(populateDrawer, /drawer-services-configured/);
  assert.match(populateDrawer, /drawer-services-pending/);
  assert.match(populateDrawer, /Configurés/);
  assert.match(populateDrawer, /À traiter/);
  assert.match(styleSource, /\.drawer-services-group\s*\{[\s\S]*display:\s*block/);
});

test('les entrées services configurées restent sur une ligne compacte', () => {
  assert.match(populateDrawer, /isServiceDecisionResolved\(p, svc\)/);
  assert.match(populateDrawer, /svc\._isMerged|svc\.found|serviceDecision === 'specific'/);
  assert.match(styleSource, /\.drawer-services-configured \.drawer-services-grid[\s\S]*align-items:\s*start/);
  assert.match(styleSource, /\.drawer-services-configured \.drawer-field[\s\S]*white-space:\s*nowrap/);
});

test('Security Profiles est ouvert par défaut sans suffixe Optionnels et passe en 2x2', () => {
  assert.match(appSource, /<details class="drawer-security-profiles" open>/);
  assert.match(appSource, /<summary>Security Profiles<\/summary>/);
  assert.doesNotMatch(appSource, /<summary>Security Profiles[^<]*Optionnels/);
  assert.match(styleSource, /\.drawer-security-profiles-body\s*\{[\s\S]*display:\s*grid[\s\S]*repeat\(2,/);
  assert.match(styleSource, /@media \(max-width: 820px\)[\s\S]*\.drawer-security-profiles-body\s*\{[\s\S]*grid-template-columns:\s*1fr/);
});

test('les cartes compatibles restent dans la zone à traiter sans créer de trous de grille', () => {
  assert.match(populateDrawer, /drawer-service-compatibility-line/);
  assert.match(populateDrawer, /pendingServiceEntries[\s\S]*compatibleSelectionHtml/);
  assert.match(styleSource, /\.drawer-services-pending \.drawer-services-grid[\s\S]*grid-auto-rows:\s*max-content/);
  assert.doesNotMatch(styleSource, /\.drawer-services-grid[\s\S]*align-items:\s*stretch/);
});

test('le bandeau DCE-RPC utilise toute la largeur et neutralise la colonne héritée', () => {
  const bannerRule = cssRule('.svc-selected-compatible');
  const copyRule = cssRule('.svc-selected-compatible-copy');
  assert.match(bannerRule, /width:\s*100%/);
  assert.match(copyRule, /grid-column:\s*1/);
  assert.match(styleSource, /\.svc-selected-compatible\s*>\s*\.svc-selected-compatible-copy\s*\{[\s\S]*grid-column:\s*1/);
});

test('le contenu du bandeau précède les actions et les actions restent dynamiques', () => {
  const bannerStart = populateDrawer.indexOf('const compatibleSelectionHtml');
  const copyStart = populateDrawer.indexOf('svc-selected-compatible-copy', bannerStart);
  const actionStart = populateDrawer.indexOf('svc-use-compatible-selected', copyStart);
  assert.ok(bannerStart >= 0 && copyStart > bannerStart && actionStart > copyStart);
  assert.match(populateDrawer, /commonCompatibleService\.name/);
  assert.match(populateDrawer, /selectedPortLabels[\s\S]*commonCompatibleService\?\.ports\?\.map/);
  assert.match(populateDrawer, /commonCompatibleService\.extraPortCount/);
});

test('la suggestion groupée affiche le nom dynamique du service dans le bouton principal', () => {
  assert.match(populateDrawer, /commonCompatibleService\.name[^`]*couvre les ports sélectionnés/);
  assert.match(populateDrawer, /Utiliser \$\{escHtml\(commonCompatibleService\.name\)\}/);
  assert.match(populateDrawer, /Crée[r]? un nouveau service/);
});

test('Voir les flux rejoint l’en-tête sans seconde ligne vide', () => {
  assert.match(appSource, /drawer-header-actions/);
  assert.match(populateDrawer, /drawer-header-actions[\s\S]*Voir les flux/);
  assert.doesNotMatch(populateDrawer, /drawer-top-actions/);
  assert.match(styleSource, /\.drawer-header-actions\s*\{[\s\S]*display:\s*flex/);
});

test('le bandeau compatible hiérarchise le service, le range et les ports sélectionnés', () => {
  assert.match(populateDrawer, /commonCompatibleService\.name[\s\S]{0,100}couvre les ports sélectionnés/);
  assert.match(populateDrawer, /compatiblePortSpec/);
  assert.match(populateDrawer, /selectedPortSummary/);
  assert.match(populateDrawer, /selectedPortTitle/);
  assert.match(populateDrawer, /Ports sélectionnés/);
  assert.doesNotMatch(populateDrawer, /commonCompatibleService\.name\) peut couvrir les ports sélectionnés/);
  assert.match(styleSource, /\.svc-selected-compatible \.svc-use-compatible-selected\s*\{[\s\S]*var\(--accent\)/);
});

test('la décision compatible multiport réutilise l’historique batch et la propagation Oui/Non', () => {
  for (const token of [
    'servicePropagationPlan',
    '_snapDrawerIndexes',
    'last.entries || [last]',
    'svc-service-prop-yes',
    'svc-service-prop-no',
    'compatiblePolicyServiceKeys',
  ]) assert.ok(appSource.includes(token), `contrat multi-policy absent: ${token}`);
  assert.match(appSource, /_setDrawerServicePropagationPending\(p, propagationTargets\.length/);
  assert.match(appSource, /eligibleKeys\.forEach[\s\S]*existing:\$\{pending\.serviceName\}/);
});
