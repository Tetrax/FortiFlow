'use strict';

const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const appSource = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
const styleSource = fs.readFileSync(path.join(__dirname, '..', 'public', 'style.css'), 'utf8');
const populateDrawer = appSource.match(/function populateDrawer\(idx\) \{[\s\S]*?\n\}/)?.[0] || '';

test('le drawer conserve objets et interfaces dans les cartes Source et Destination', () => {
  assert.ok(populateDrawer, 'fonction populateDrawer introuvable');
  assert.equal(populateDrawer.includes('drawer-interfaces-section'), false);
  assert.equal(populateDrawer.includes('drawer-objects-section'), false);
  assert.equal(populateDrawer.includes("querySelectorAll('.drawer-object-field')"), false);
  assert.equal(populateDrawer.includes("querySelectorAll('.drawer-source-interface-field')"), false);

  assert.equal((populateDrawer.match(/drawer-network-card drawer-source-card/g) || []).length, 2);
  assert.equal((populateDrawer.match(/drawer-network-card drawer-destination-card/g) || []).length, 2);
  assert.equal((populateDrawer.match(/drawer-srcintf/g) || []).length, 2);
  assert.equal((populateDrawer.match(/drawer-dstintf/g) || []).length, 2);
});

test('le drawer suit l’ordre Général, réseau, Services, Security Profiles', () => {
  const generalPos = populateDrawer.indexOf('drawer-general-summary');
  const networkPos = populateDrawer.indexOf('drawer-network-grid');
  const servicesPos = populateDrawer.indexOf('drawer-services-section');
  const securityPos = populateDrawer.indexOf('${buildDrawerSecProfiles(p, idx)}');

  assert.ok(generalPos >= 0, 'section Général absente');
  assert.ok(networkPos >= 0, 'grille réseau absente');
  assert.ok(generalPos < networkPos, 'Général doit précéder la grille réseau');
  assert.ok(networkPos < servicesPos, 'la grille réseau doit précéder Services');
  assert.ok(servicesPos < securityPos, 'Services doit précéder Security Profiles');
  assert.match(styleSource, /\.drawer-network-grid\s*\{[^}]*grid-template-columns:\s*repeat\(2,/s);
  assert.match(styleSource, /\.policy-drawer\s*\{[^}]*width:\s*min\((7[0-9]{2}|8[0-9]{2})px,/s);
});

test('Général conserve les valeurs par défaut Accept et log all', () => {
  assert.match(populateDrawer, /drawer-general-summary[\s\S]*\(p\._action\|\|'accept'\)===\s*'accept'/);
  assert.match(populateDrawer, /drawer-general-summary[\s\S]*\(p\._log\|\|'all'\)===\s*'all'/);
});

test('tous les services sont visibles dans une grille sans bouton +X autres', () => {
  assert.equal(populateDrawer.includes('servicesMore'), false);
  assert.equal(populateDrawer.includes('drawer-services-toggle'), false);
  assert.ok(populateDrawer.includes('drawer-services-grid'));
  assert.match(styleSource, /\.drawer-services-grid\s*\{[^}]*grid-template-columns:\s*repeat\(2,/s);
});

test('Security Profiles est une section dédiée et repliable', () => {
  assert.match(appSource, /<details class="drawer-security-profiles">/);
  assert.match(appSource, /<summary>Security Profiles<\/summary>/);
  for (const label of ['Antivirus', 'Web Filter', 'IPS', 'SSL Inspection']) {
    assert.ok(appSource.includes(label), `profil absent: ${label}`);
  }
});

test('le drawer propose explicitement le service compatible ou la création spécifique', () => {
  for (const label of [
    'Service observé',
    'Service compatible',
    'Extension possible',
    'Utiliser ce service',
    'Créer un service spécifique',
  ]) {
    assert.ok(appSource.includes(label), `libellé absent: ${label}`);
  }
  assert.ok(appSource.includes('svc.compatibleMatch'));
  assert.ok(appSource.includes('drawer-use-compatible-service'));
  assert.ok(appSource.includes('drawer-create-specific-service'));
  assert.match(appSource, /_serviceReuse[\s\S]*compatibleMatch\.name/);
  assert.match(styleSource, /\.drawer-service-compatibility/);
});

test('le drawer ne contient plus aucune détection dynamique automatique', () => {
  for (const removed of [
    'Ports dynamiques détectés',
    'dynamicServiceSuggestions',
    'drawer-use-dynamic-existing',
    'drawer-create-dynamic-range',
    'drawer-dynamic-service-name',
  ]) {
    assert.equal(appSource.includes(removed), false, `fonction dynamique encore présente: ${removed}`);
  }
  assert.equal(styleSource.includes('.drawer-dynamic-service-suggestion'), false);
});

test('la sélection manuelle propose un service FortiGate commun sans remplacer le workflow historique', () => {
  assert.ok(appSource.includes('Un service FortiGate existant peut couvrir ces ports'));
  assert.ok(appSource.includes('svc-use-compatible-selected'));
  assert.ok(appSource.includes('svc-create-new-selected'));
  assert.ok(appSource.includes('selectedCompatibleService'));
  for (const historical of ['Ports individ.', 'Range', 'Fusionner', 'svc-do-merge']) {
    assert.ok(appSource.includes(historical), `contrôle historique absent: ${historical}`);
  }
});

test('la décision globale masque les ports et cartes compatibles individuels jusqu’au choix utilisateur', () => {
  assert.ok(appSource.includes('showGlobalCompatibleDecision'));
  assert.ok(appSource.includes('selectedGlobalServiceKeys'));
  assert.match(appSource, /visibleSvcList\s*=\s*showGlobalCompatibleDecision[\s\S]*servicesWithoutResolvedExisting\.filter\(service\s*=>[\s\S]*serviceReuseKeys\(service\)\.some\(key\s*=>\s*selectedGlobalServiceKeys\.has\(key\)\)/);
  assert.match(appSource, /compatibilityHtml\s*=\s*compatibleMatch[\s\S]*!commonCompatibleService/);
  assert.ok(appSource.includes('Ports sélectionnés'));
  assert.ok(appSource.includes('Service existant compatible'));
});

test('les ports décidés sont exclus des sélections et suggestions suivantes', () => {
  assert.ok(appSource.includes('_resolvedServiceKeys'));
  assert.ok(appSource.includes('isServiceDecisionResolved'));
  assert.ok(appSource.includes('markServiceDecisionResolved'));
  assert.ok(appSource.includes('clearSelectedServiceKey'));
  assert.match(appSource, /selectableSvcs[\s\S]*isServiceDecisionResolved\(p, s\)/);
  assert.match(appSource, /_selectable[\s\S]*isServiceDecisionResolved\(p, s\)/);
  assert.match(appSource, /compatibilityHtml\s*=\s*compatibleMatch[\s\S]*!serviceDecisionResolved[\s\S]*!commonCompatibleService/);
});

test('les décisions validées sont projetées en vert CONFIG et dédupliquées', () => {
  assert.ok(appSource.includes('resolvedExistingGroups'));
  assert.ok(appSource.includes('resolvedExistingHtml'));
  assert.ok(appSource.includes("serviceDecision === 'specific'"));
  assert.match(appSource, /serviceDecision === 'specific'[\s\S]*badgeHtml\('config'\)/);
  assert.match(appSource, /resolvedExistingGroups[\s\S]*Ports couverts[\s\S]*badgeHtml\('config'\)/);
});

test('les chemins service existant et service spécifique sont mutuellement exclusifs', () => {
  assert.match(appSource, /markServiceDecisionResolved[\s\S]*decision === 'specific'[\s\S]*delete policy\._serviceReuse\[serviceKey\]/);
  assert.match(appSource, /markServiceDecisionResolved[\s\S]*decision\.startsWith\('existing:'\)[\s\S]*policy\._serviceReuse\[serviceKey\]/);
  assert.match(appSource, /resolvedExistingGroups[\s\S]*keys\.every\(key\s*=>\s*p\._serviceReuse\?\.\[key\]\s*===\s*serviceName\)/);
  assert.ok(appSource.includes('FF_SVC_${proto}_${port}'));
});

test('nommer manuellement un port sans suggestion valide immédiatement le service spécifique', () => {
  assert.match(appSource, /focusout[\s\S]*drawer-svc-name[\s\S]*serviceReuseKeys\(svc\)[\s\S]*decisionKeys\.forEach\(key\s*=>\s*markServiceDecisionResolved\(p, key, 'specific'\)\)/);
  assert.match(appSource, /decisionKeys\.forEach\(key\s*=>\s*markServiceDecisionResolved\(p, key, 'specific'\)\)[\s\S]*populateDrawer\(_drawerIdx\)/);
});

test('tous les objets créés depuis le drawer deviennent des valeurs vertes CONFIG', () => {
  assert.ok(appSource.includes('_resolvedObjectKeys'));
  assert.ok(appSource.includes('markDrawerObjectResolved'));
  assert.ok(appSource.includes('isDrawerObjectResolved'));
  assert.ok(appSource.includes('host:${type}:'));
  assert.ok(appSource.includes("drawerHostControl(p, h, 'src')"));
  assert.ok(appSource.includes("drawerHostControl(p, h, 'dst')"));
  for (const keyPrefix of ['addr:src', 'addr:dst', 'multi-src:', 'multi-dst:', 'group:src', 'group:dst']) {
    assert.ok(appSource.includes(keyPrefix), `clé objet absente: ${keyPrefix}`);
  }
  assert.match(appSource, /focusout[\s\S]*resolvedObjectKey[\s\S]*markDrawerObjectResolved/);
  assert.match(appSource, /drawerHostControl[\s\S]*badgeHtml\('config'\)/);
});

test('un service range fusionné est immédiatement validé en vert CONFIG', () => {
  assert.match(appSource, /svc-do-merge[\s\S]*_isMerged:\s*true/);
  assert.match(appSource, /function _buildSvcCellHtml[\s\S]*if \(svc\._isMerged\)[\s\S]{0,600}badgeHtml\('config'\)/);
  assert.match(populateDrawer, /if \(svc\._isMerged\)[\s\S]{0,800}badgeHtml\('config'\)/);
  assert.match(populateDrawer, /svc\._isMerged[\s\S]{0,500}svc\.portRange/);
});

test('Options avancées est supprimé et Voir les flux est placé tout en haut', () => {
  assert.equal(appSource.includes('<details class="drawer-advanced">'), false);
  assert.equal(appSource.includes('<summary>Options avancées</summary>'), false);
  const topActionsPos = populateDrawer.indexOf('drawer-top-actions');
  const generalPos = populateDrawer.indexOf('drawer-general-summary');
  assert.ok(topActionsPos >= 0 && topActionsPos < generalPos);
  assert.match(populateDrawer, /drawer-general-summary[\s\S]*Policy ID/);
  assert.match(styleSource, /\.drawer-top-actions/);
});
