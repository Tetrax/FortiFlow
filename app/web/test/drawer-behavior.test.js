'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');
const { validatePolicyDecisionShapes } = require('../lib/forticonfig');

const appSource = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
const styleSource = fs.readFileSync(path.join(__dirname, '..', 'public', 'style.css'), 'utf8');

function sourceBlock(start, end, from = 0) {
  const startAt = appSource.indexOf(start, from);
  assert.notEqual(startAt, -1, `bloc introuvable: ${start}`);
  const endAt = appSource.indexOf(end, startAt);
  assert.notEqual(endAt, -1, `fin de bloc introuvable: ${end}`);
  return appSource.slice(startAt, endAt);
}

class FakeElement {
  constructor(document, tagName = 'div') {
    this.document = document;
    this.tagName = tagName.toUpperCase();
    this.listeners = new Map();
    this.children = [];
    this.dataset = {};
    this.style = {};
    this.disabled = false;
    this.className = '';
    this._id = '';
    this._innerHTML = '';
  }

  set id(value) {
    this._id = value;
    if (value) this.document.elements.set(value, this);
  }

  get id() { return this._id; }

  set innerHTML(value) {
    this._innerHTML = value;
    if (value.includes('id="drawer-header-actions"')) this.document.ensure('drawer-header-actions');
    if (value.includes('id="drawer-undo"')) this.document.ensure('drawer-undo');
    if (this.id === 'policy-drawer' && value.includes('id="drawer-body"')) {
      this.document.ensure('drawer-header');
      this.document.ensure('drawer-title');
      this.document.ensure('drawer-close');
      this.document.ensure('drawer-body');
    }
  }

  get innerHTML() { return this._innerHTML; }

  addEventListener(type, handler) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(handler);
  }

  dispatch(type, target) {
    const event = {
      target,
      ctrlKey: false,
      key: '',
      preventDefault() {},
      stopPropagation() {},
    };
    for (const handler of this.listeners.get(type) || []) handler(event);
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  insertBefore(child) {
    this.children.push(child);
    return child;
  }

  querySelector(selector) {
    if (selector === '#drawer-close') return this.document.ensure('drawer-close');
    if (selector === '.drawer-header') return this.document.ensure('drawer-header');
    return null;
  }
}

class FakeDocument {
  constructor() {
    this.elements = new Map();
    this.listeners = new Map();
    this.selectors = new Map();
    this.body = new FakeElement(this, 'body');
  }

  ensure(id) {
    if (!this.elements.has(id)) {
      const element = new FakeElement(this);
      element.id = id;
    }
    return this.elements.get(id);
  }

  createElement(tagName) { return new FakeElement(this, tagName); }
  getElementById(id) { return this.elements.get(id) || null; }
  querySelector(selector) { return this.selectors.get(selector) || null; }

  addEventListener(type, handler) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(handler);
  }
}

class FakeTarget {
  constructor(classes, dataset = {}, parent = null) {
    this.classes = new Set(classes.split(/\s+/).filter(Boolean));
    this.dataset = dataset;
    this.parent = parent;
    this.value = '';
    this.checked = false;
  }

  matches(selector) {
    return selector.startsWith('.') && this.classes.has(selector.slice(1));
  }

  closest(selector) {
    if (this.matches(selector)) return this;
    if (selector === '.drawer-service-item') return this.parent;
    return null;
  }
}

function compatibleService() {
  return {
    name: 'MS-RPC-DYNAMIC',
    source: 'custom',
    proto: 'TCP',
    portSpec: 'TCP/49152-65535',
    coverageCount: 16384,
    extraPortCount: 16383,
  };
}

function unresolvedService(port) {
  const compatible = compatibleService();
  return {
    found: false,
    label: `TCP/${port}`,
    proto: 'TCP',
    port,
    isNamed: false,
    compatibleMatch: compatible,
    compatibleMatches: [compatible],
  };
}

function drawerPolicy(ports = [52980, 52981]) {
  return {
    policyIds: [100],
    sessions: 4,
    srcSubnet: '10.0.0.0/24',
    dstTarget: '10.0.1.0/24',
    dstType: 'private',
    srcHosts: [],
    dstHosts: [],
    _srcintf: 'LAN',
    _dstintf: 'DMZ',
    analysis: {
      srcAddr: { found: true, name: 'SRC_NET', cidr: '10.0.0.0/24' },
      dstAddr: { found: true, name: 'DST_NET', cidr: '10.0.1.0/24' },
      services: [
        { found: true, label: 'DNS', name: 'DNS', source: 'predefined', portHint: 'UDP/53' },
        { found: true, label: 'HTTPS', name: 'HTTPS', source: 'predefined', portHint: 'TCP/443' },
        ...ports.map(unresolvedService),
      ],
    },
  };
}

function createDrawerHarness(policy, viewportWidth = 1440) {
  const document = new FakeDocument();
  const context = {
    console,
    structuredClone,
    Set,
    Map,
    document,
    window: { innerWidth: viewportWidth, _undoWired: false },
    deployState: { analyzed: [policy], ifaceOpts: [], availableProfiles: {} },
    _drawerMounted: false,
    _drawerIdx: 0,
    _drawerHistory: [],
    DRAWER_HISTORY_MAX: 20,
    closeDrawer() {},
    syncAddrCell() {},
    syncSvcCell() {},
    syncRowStatus() {},
    renderDeployPolicies() {},
    filterDeployPolicies() { return []; },
    escHtml(value) {
      return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
      })[char]);
    },
    suggestAddrNameFE(value) { return `AUTO_${String(value).replace(/[^A-Za-z0-9]/g, '_')}`; },
    drawerNamedObjectControl(_policy, _key, name, _found, input) { return input || String(name || ''); },
    drawerHostControl(_policy, host) { return String(host); },
    cleanHostName(_host, name) { return name || ''; },
    badgeHtml(kind) { return `<b data-badge="${kind}"></b>`; },
    cidrSupernet(cidrs) { return cidrs?.[0] || ''; },
    fmtNum(value) { return String(value); },
    buildDrawerSecProfiles() { return '<details class="drawer-security-profiles"></details>'; },
    isDrawerObjectResolved() { return false; },
    filterFlowsByPolicy() {},
  };
  vm.createContext(context);
  vm.runInContext([
    sourceBlock('const DRAWER_SNAPSHOT_KEYS', 'function buildDrawerSecProfiles'),
    sourceBlock('function serviceReuseKey', 'function syncHostCell'),
    sourceBlock(
      'function populateDrawer',
      '// ═══════════════════════════════════════════════════════════════',
      appSource.indexOf('function populateDrawer'),
    ),
  ].join('\n'), context);
  context.mountDrawer();
  context.populateDrawer(0);

  const drawer = document.getElementById('policy-drawer');
  const body = document.getElementById('drawer-body');
  return {
    context,
    policy,
    drawer,
    body,
    setInput(selector, value) { document.selectors.set(selector, { value }); },
    click(target) { drawer.dispatch('click', target); },
    input(target) { drawer.dispatch('input', target); },
    blur(target) { drawer.dispatch('focusout', target); },
    keydown(key = 'z', ctrlKey = true) {
      const event = { key, ctrlKey, preventDefault() {} };
      for (const handler of document.listeners.get('keydown') || []) handler(event);
    },
  };
}

function serviceRow(serviceKey) {
  return new FakeTarget('svc-selectable', { svcKey: serviceKey });
}

function globalCompatibleButton(ports) {
  return new FakeTarget('svc-use-compatible-selected', {
    proto: 'TCP',
    ports: ports.join(','),
    serviceName: 'MS-RPC-DYNAMIC',
  });
}

function compatiblePolicy(ports, name = 'DCE-RPC-RANGE') {
  const policy = drawerPolicy(ports);
  const compatible = {
    name, source: 'custom', proto: 'TCP',
    portSpec: 'TCP/10000-65535', coverageCount: 55536, extraPortCount: 55534,
  };
  for (const service of policy.analysis.services.filter(item => ports.includes(item.port))) {
    service.compatibleMatch = compatible;
    service.compatibleMatches = [compatible];
  }
  return policy;
}

function compatibleDecisionButton(ports, serviceName = 'DCE-RPC-RANGE') {
  return new FakeTarget('svc-use-compatible-selected', {
    proto: 'TCP',
    ports: ports.join(','),
    serviceName,
  });
}

function specificButton(serviceKey, typedName = '') {
  const parent = {
    querySelector(selector) {
      return selector === '.drawer-svc-name' ? { value: typedName } : null;
    },
  };
  return new FakeTarget('drawer-create-specific-service', { serviceKey }, parent);
}

function cssRule(selector, source = styleSource) {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = source.match(new RegExp(`${escaped}\\s*\\{([^}]*)\\}`, 's'));
  assert.ok(match, `règle CSS introuvable: ${selector}`);
  return match[1];
}

function mediaBlock(maxWidth) {
  const marker = `@media (max-width: ${maxWidth}px)`;
  const start = styleSource.indexOf(marker);
  assert.notEqual(start, -1, `media query introuvable: ${marker}`);
  const open = styleSource.indexOf('{', start);
  let depth = 0;
  for (let index = open; index < styleSource.length; index++) {
    if (styleSource[index] === '{') depth++;
    if (styleSource[index] === '}') depth--;
    if (depth === 0) return styleSource.slice(open + 1, index);
  }
  throw new Error(`media query non terminée: ${marker}`);
}

test('le choix compatible global exige un clic et conserve DNS/HTTPS après rerender', () => {
  const policy = drawerPolicy();
  const harness = createDrawerHarness(policy);

  assert.match(harness.body.innerHTML, />DNS</);
  assert.match(harness.body.innerHTML, />HTTPS</);
  assert.equal(policy._serviceReuse, undefined);

  harness.click(serviceRow('52980/TCP'));
  harness.click(serviceRow('52981/TCP'));

  assert.equal(policy._selectedSvcKeys.size, 2);
  assert.equal(policy._serviceReuse, undefined, 'le rendu de la suggestion ne doit pas décider');
  assert.match(harness.body.innerHTML, /svc-selected-compatible/);
  assert.match(harness.body.innerHTML, /Utiliser MS-RPC-DYNAMIC/);
  assert.match(harness.body.innerHTML, /Créer un nouveau service/);
  assert.match(harness.body.innerHTML, />DNS</);
  assert.match(harness.body.innerHTML, />HTTPS</);

  harness.click(globalCompatibleButton([52980, 52981]));

  assert.equal(policy._serviceReuse['TCP/52980'], 'MS-RPC-DYNAMIC');
  assert.equal(policy._serviceReuse['TCP/52981'], 'MS-RPC-DYNAMIC');
  assert.equal(policy._selectedSvcKeys.size, 0);
  assert.doesNotMatch(harness.body.innerHTML, /data-svc-key="52980\/TCP"/);
  assert.doesNotMatch(harness.body.innerHTML, /data-svc-key="52981\/TCP"/);
  assert.equal((harness.body.innerHTML.match(/MS-RPC-DYNAMIC/g) || []).length, 1);
  assert.match(harness.body.innerHTML, />DNS</);
  assert.match(harness.body.innerHTML, />HTTPS</);
});

test('Ctrl+Z annule atomiquement l’utilisation d’un service compatible multiport', () => {
  const policy = drawerPolicy();
  const compatible = compatibleService();
  policy.analysis.services.push(
    { found: false, label: 'TCP/52121', proto: 'TCP', port: 52121, compatibleMatch: compatible, compatibleMatches: [compatible] },
    { found: false, label: 'TCP/52134', proto: 'TCP', port: 52134, compatibleMatch: compatible, compatibleMatches: [compatible] },
  );
  const harness = createDrawerHarness(policy);
  harness.click(serviceRow('52121/TCP'));
  harness.click(serviceRow('52134/TCP'));
  const beforeServices = JSON.stringify(policy.analysis.services);

  harness.click(globalCompatibleButton([52121, 52134]));
  assert.equal(policy._serviceReuse['TCP/52121'], 'MS-RPC-DYNAMIC');
  assert.equal(policy._serviceReuse['TCP/52134'], 'MS-RPC-DYNAMIC');

  harness.keydown();

  assert.equal(JSON.stringify(policy.analysis.services), beforeServices);
  assert.equal(policy._serviceReuse, undefined);
  assert.equal(policy._resolvedServiceKeys, undefined);
  assert.deepEqual([...policy._selectedSvcKeys].sort(), ['52121/TCP', '52134/TCP']);
  assert.match(harness.body.innerHTML, /svc-selected-compatible/);
  assert.match(harness.body.innerHTML, /TCP\/52121, TCP\/52134/);
  assert.doesNotMatch(harness.body.innerHTML, /Ports couverts/);
});

test('le bouton Annuler du header est accessible, partagé avec Ctrl+Z et désactivé sans historique', () => {
  assert.match(appSource, /function _undoDrawer\(\)/);
  assert.match(appSource, /drawer-undo/);
  assert.match(appSource, /aria-label="Annuler la dernière modification"/);
  assert.match(appSource, /<kbd[^>]*>Ctrl\+Z<\/kbd>/);
  assert.match(appSource, /drawer-undo[\s\S]*disabled/);
  assert.match(appSource, /drawer-undo[\s\S]*_undoDrawer\(\)/);
  assert.match(appSource, /document\.addEventListener\('keydown'[\s\S]*_undoDrawer\(\)/);
  assert.match(styleSource, /\.drawer-undo\s*\{[\s\S]*display:\s*inline-flex/);
  assert.match(styleSource, /\.drawer-undo kbd\s*\{[\s\S]*border:/);

  const harness = createDrawerHarness(drawerPolicy());
  const headerActions = harness.context.document.getElementById('drawer-header-actions');
  const undoButton = harness.context.document.getElementById('drawer-undo');
  assert.ok(headerActions);
  assert.ok(undoButton);
  assert.match(headerActions.innerHTML, /Voir les flux[\s\S]*Annuler[\s\S]*<kbd[^>]*>Ctrl\+Z<\/kbd>/);
  assert.match(headerActions.innerHTML, /aria-label="Annuler la dernière modification"/);
  assert.equal(undoButton.disabled, true);
});

test('le clic sur Annuler et Ctrl+Z restaurent le même historique du drawer', () => {
  const policy = drawerPolicy();
  const harness = createDrawerHarness(policy);
  const nameInput = new FakeTarget('drawer-policy-name');
  nameInput.value = 'POLICY_EDITED';
  harness.input(nameInput);

  assert.equal(policy._policyName, 'POLICY_EDITED');
  assert.equal(harness.context.document.getElementById('drawer-undo').disabled, false);

  harness.click(new FakeTarget('drawer-undo'));

  assert.equal(policy._policyName, undefined);
  assert.equal(harness.context.document.getElementById('drawer-undo').disabled, true);

  nameInput.value = 'POLICY_EDITED_AGAIN';
  harness.input(nameInput);
  harness.keydown();

  assert.equal(policy._policyName, undefined);
  assert.equal(harness.context.document.getElementById('drawer-undo').disabled, true);
});

test('supprimer un service puis cliquer sur Annuler restaure exactement la liste précédente', () => {
  const policy = drawerPolicy([8530]);
  const harness = createDrawerHarness(policy);
  const beforeServices = JSON.stringify(policy.analysis.services);

  harness.click(new FakeTarget('btn-del-item', {
    delType: 'svc',
    svcKey: '8530/TCP',
  }));

  assert.equal(policy.analysis.services.some(service => service.label === 'TCP/8530'), false);
  assert.equal(harness.context.document.getElementById('drawer-undo').disabled, false);

  harness.click(new FakeTarget('drawer-undo'));

  assert.equal(JSON.stringify(policy.analysis.services), beforeServices);
  assert.equal(harness.context.document.getElementById('drawer-undo').disabled, true);
});

test('les croix de services sont discrètes sans supprimer leur espace ni leur accessibilité', () => {
  const harness = createDrawerHarness(drawerPolicy([8530]));

  assert.match(harness.body.innerHTML, /class="drawer-field drawer-service-row[^\"]*"[\s\S]*aria-label="Retirer DNS"/);
  assert.match(harness.body.innerHTML, /class="drawer-field drawer-service-row[^\"]*"[\s\S]*aria-label="Retirer TCP\/8530"/);
  assert.match(styleSource, /\.drawer-service-row \.btn-del-item\s*\{[\s\S]*opacity:/);
  assert.match(styleSource, /\.drawer-service-row \.btn-del-item\s*\{[\s\S]*width:/);
  assert.match(styleSource, /\.drawer-service-row:hover \.btn-del-item[\s\S]*opacity:\s*1/);
  assert.match(styleSource, /\.drawer-service-row:focus-within \.btn-del-item[\s\S]*opacity:\s*1/);
  assert.match(styleSource, /\.drawer-service-row \.btn-del-item:focus-visible[\s\S]*outline/);
  assert.match(styleSource, /@media \(hover: none\)[\s\S]*\.drawer-service-row \.btn-del-item[\s\S]*opacity:/);
  assert.doesNotMatch(cssRule('.drawer-service-row .btn-del-item'), /display:\s*none/);
});

test('une propagation compatible multiport refusée ne modifie que la policy courante', () => {
  const current = compatiblePolicy([52121, 52134]);
  const other = compatiblePolicy([52121, 52134], 'DCE-RPC-RANGE');
  other._backendIssues = ['issue à conserver'];
  other._backendIssueKind = 'incomplete';
  other._backendValidated = true;
  const harness = createDrawerHarness(current);
  harness.context.deployState.analyzed.push(other);
  current._selectedSvcKeys = new Set(['52121/TCP', '52134/TCP']);
  harness.context.populateDrawer(0);

  harness.click(compatibleDecisionButton([52121, 52134]));

  assert.match(harness.body.innerHTML, /svc-service-prop-no/);
  assert.match(harness.body.innerHTML, /1 autre policy/);
  assert.deepEqual(other._backendIssues, ['issue à conserver']);
  assert.equal(other._backendIssueKind, 'incomplete');
  assert.equal(other._backendValidated, true);
  harness.click(new FakeTarget('svc-service-prop-no'));

  assert.equal(current._serviceReuse['TCP/52121'], 'DCE-RPC-RANGE');
  assert.equal(current._serviceReuse['TCP/52134'], 'DCE-RPC-RANGE');
  assert.equal(other._serviceReuse, undefined);
  assert.equal(other._resolvedServiceKeys, undefined);
});

test('Ctrl+Z restaure l’absence initiale de analysis.services', () => {
  const policy = drawerPolicy();
  delete policy.analysis.services;
  const harness = createDrawerHarness(policy);
  const nameInput = new FakeTarget('drawer-policy-name');
  nameInput.value = 'POLICY_EDITED';
  harness.input(nameInput);
  policy.analysis.services = [{ label: 'TCP/52121', found: false, proto: 'TCP', port: 52121 }];

  harness.keydown();

  assert.equal(Object.hasOwn(policy.analysis, 'services'), false);
  assert.equal(policy._policyName, undefined);
});

test('une propagation compatible multiport accepte les ports propres à chaque policy et s’annule en une fois', () => {
  const current = compatiblePolicy([52121, 52134]);
  const other = compatiblePolicy([52121, 52134, 62966]);
  const unrelated = drawerPolicy([8530]);
  other._backendIssues = ['issue avant propagation'];
  other._backendIssueKind = 'risk';
  other._backendValidated = true;
  const beforeCurrent = JSON.stringify(current.analysis.services);
  const beforeOther = JSON.stringify(other.analysis.services);
  const harness = createDrawerHarness(current);
  harness.context.deployState.analyzed.push(other, unrelated);
  current._selectedSvcKeys = new Set(['52121/TCP', '52134/TCP']);
  harness.context.populateDrawer(0);

  harness.click(compatibleDecisionButton([52121, 52134]));
  harness.click(new FakeTarget('svc-service-prop-yes'));

  assert.equal(other._serviceReuse['TCP/52121'], 'DCE-RPC-RANGE');
  assert.equal(other._serviceReuse['TCP/52134'], 'DCE-RPC-RANGE');
  assert.equal(other._serviceReuse['TCP/62966'], 'DCE-RPC-RANGE');
  assert.equal(unrelated._serviceReuse, undefined);
  assert.equal(other.analysis.services.length, 5);
  assert.equal(other._backendIssues, undefined);
  assert.equal(JSON.stringify(current).includes('_propagateServicePending'), false);
  assert.equal(validatePolicyDecisionShapes([current, other]).ok, true);

  harness.keydown();

  assert.equal(JSON.stringify(current.analysis.services), beforeCurrent);
  assert.equal(JSON.stringify(other.analysis.services), beforeOther);
  assert.equal(current._serviceReuse, undefined);
  assert.equal(other._serviceReuse, undefined);
  assert.equal(other._resolvedServiceKeys, undefined);
  assert.deepEqual([...other._backendIssues], ['issue avant propagation']);
  assert.equal(other._backendIssueKind, 'risk');
  assert.equal(other._backendValidated, true);
  assert.equal(unrelated._serviceReuse, undefined);
});

test('l’historique reste LIFO après une décision DCE-RPC', () => {
  const policy = compatiblePolicy([52121, 52134]);
  policy._selectedSvcKeys = new Set(['52121/TCP', '52134/TCP']);
  const harness = createDrawerHarness(policy);
  const nameInput = new FakeTarget('drawer-policy-name');
  nameInput.value = 'POLICY_EDITED';
  harness.input(nameInput);

  harness.click(compatibleDecisionButton([52121, 52134]));
  harness.keydown();
  assert.equal(policy._policyName, 'POLICY_EDITED');
  assert.equal(policy._serviceReuse, undefined);

  harness.keydown();
  assert.equal(policy._policyName, undefined);
  assert.deepEqual([...policy._selectedSvcKeys].sort(), ['52121/TCP', '52134/TCP']);
});

test('la propagation mono-port utilise TCP/port, ignore l’ordre et UDP, puis s’annule atomiquement', () => {
  const current = drawerPolicy([3268, 8530]);
  const reordered = drawerPolicy([8530, 3268]);
  const udpOnly = drawerPolicy([]);
  udpOnly.analysis.services.push({ found: false, label: 'UDP/3268', proto: 'UDP', port: 3268, isNamed: false });
  const harness = createDrawerHarness(current);
  harness.context.deployState.analyzed.push(reordered, udpOnly);
  const input = new FakeTarget('drawer-svc-name', { svcKey: '3268/TCP' });
  input.value = 'tcp3268';

  harness.blur(input);
  harness.click(new FakeTarget('svc-prop-yes'));

  const reordered3268 = reordered.analysis.services.find(service => service.label === 'TCP/3268');
  const reordered8530 = reordered.analysis.services.find(service => service.label === 'TCP/8530');
  const udp3268 = udpOnly.analysis.services.find(service => service.label === 'UDP/3268');
  assert.equal(reordered3268.suggestedName, 'tcp3268');
  assert.equal(reordered._resolvedServiceKeys['TCP/3268'], 'specific');
  assert.notEqual(reordered8530.suggestedName, 'tcp3268');
  assert.notEqual(udp3268.suggestedName, 'tcp3268');

  harness.keydown();

  assert.equal(reordered.analysis.services.find(service => service.label === 'TCP/3268').suggestedName, undefined);
  assert.equal(reordered._resolvedServiceKeys, undefined);
  assert.notEqual(reordered.analysis.services.find(service => service.label === 'TCP/8530').suggestedName, 'tcp3268');
});

test('la propagation mono-port remplace les objets partagés par des décisions indépendantes', () => {
  const current = drawerPolicy([3268]);
  const shared = { found: false, label: 'TCP/3268', proto: 'TCP', port: 3268, isNamed: false };
  const first = drawerPolicy([]);
  const second = drawerPolicy([]);
  first.analysis.services.push(shared);
  second.analysis.services.push(shared);
  const harness = createDrawerHarness(current);
  harness.context.deployState.analyzed.push(first, second);
  const input = new FakeTarget('drawer-svc-name', { svcKey: '3268/TCP' });
  input.value = 'tcp3268';

  harness.blur(input);
  harness.click(new FakeTarget('svc-prop-yes'));

  const firstDecision = first.analysis.services.find(service => service.label === 'TCP/3268');
  const secondDecision = second.analysis.services.find(service => service.label === 'TCP/3268');
  assert.notEqual(firstDecision, secondDecision);
  firstDecision.suggestedName = 'changed-only-here';
  assert.equal(secondDecision.suggestedName, 'tcp3268');
});

test('la récupération ciblée retire TCP/8530 → tcp3268 sans toucher aux autres décisions', () => {
  const policy = drawerPolicy([3268, 8530]);
  const service3268 = policy.analysis.services.find(service => service.label === 'TCP/3268');
  const service8530 = policy.analysis.services.find(service => service.label === 'TCP/8530');
  service3268.suggestedName = 'tcp3268';
  service8530.suggestedName = 'tcp3268';
  policy._resolvedServiceKeys = { 'TCP/3268': 'specific', 'TCP/8530': 'specific' };
  policy._serviceReuse = { 'TCP/52121': 'DCE-RPC-RANGE' };
  policy._policyName = 'PRESERVE_ME';
  policy.analysis.services.push({
    found: false, label: 'DCE-RPC-RANGE', suggestedName: 'DCE-RPC-RANGE',
    proto: 'TCP', portRange: '10000-65535', sourcePorts: [10080, 52121], _isMerged: true,
  });
  const harness = createDrawerHarness(policy);

  const plan = harness.context.planInvalidSpecificServiceAssociations([policy]);
  assert.deepEqual(Array.from(plan.repairs, item => item.serviceKey), ['TCP/8530']);
  harness.context.applyInvalidSpecificServiceRecovery([policy], plan);

  assert.equal(service3268.suggestedName, 'tcp3268');
  assert.equal(policy.analysis.services.find(service => service.label === 'TCP/8530').suggestedName, '');
  assert.equal(policy._resolvedServiceKeys['TCP/3268'], 'specific');
  assert.equal(policy._resolvedServiceKeys['TCP/8530'], undefined);
  assert.equal(policy._serviceReuse['TCP/52121'], 'DCE-RPC-RANGE');
  assert.equal(policy._policyName, 'PRESERVE_ME');
  const range = policy.analysis.services.find(service => service._isMerged);
  assert.equal(range.suggestedName, 'DCE-RPC-RANGE');
  assert.equal(range.portRange, '10000-65535');
  assert.deepEqual([...range.sourcePorts], [10080, 52121]);
});

test('la récupération réutilise tcp8530 uniquement si cette décision canonique existe déjà', () => {
  const contaminated = drawerPolicy([8530]);
  const valid = drawerPolicy([3268, 8530]);
  contaminated.analysis.services.find(service => service.label === 'TCP/8530').suggestedName = 'tcp3268';
  contaminated._resolvedServiceKeys = { 'TCP/8530': 'specific' };
  valid.analysis.services.find(service => service.label === 'TCP/3268').suggestedName = 'tcp3268';
  valid.analysis.services.find(service => service.label === 'TCP/8530').suggestedName = 'tcp8530';
  valid._resolvedServiceKeys = { 'TCP/3268': 'specific', 'TCP/8530': 'specific' };
  const harness = createDrawerHarness(contaminated);

  const plan = harness.context.planInvalidSpecificServiceAssociations([contaminated, valid]);
  assert.equal(plan.repairs[0].replacementName, 'tcp8530');
  harness.context.applyInvalidSpecificServiceRecovery([contaminated, valid], plan);

  assert.equal(contaminated.analysis.services.find(service => service.label === 'TCP/8530').suggestedName, 'tcp8530');
  assert.equal(contaminated._resolvedServiceKeys['TCP/8530'], 'specific');
});

test('la récupération automatique ignore une association isolée sans conflit de nom prouvé', () => {
  const policy = drawerPolicy([8530]);
  policy.analysis.services.find(service => service.label === 'TCP/8530').suggestedName = 'tcp3268';
  policy._resolvedServiceKeys = { 'TCP/8530': 'specific' };
  const harness = createDrawerHarness(policy);

  const plan = harness.context.planInvalidSpecificServiceAssociations([policy]);

  assert.equal(plan.repairs.length, 0);
  assert.equal(policy.analysis.services.find(service => service.label === 'TCP/8530').suggestedName, 'tcp3268');
});

test('la récupération automatique ignore aussi les autres conflits canoniques', () => {
  const owner = drawerPolicy([80]);
  const unrelated = drawerPolicy([443]);
  owner.analysis.services.find(service => service.label === 'TCP/80').suggestedName = 'tcp80';
  owner._resolvedServiceKeys = { 'TCP/80': 'specific' };
  unrelated.analysis.services.find(service => service.label === 'TCP/443').suggestedName = 'tcp80';
  unrelated._resolvedServiceKeys = { 'TCP/443': 'specific' };
  const harness = createDrawerHarness(owner);

  const plan = harness.context.planInvalidSpecificServiceAssociations([owner, unrelated]);

  assert.equal(plan.repairs.length, 0);
  assert.equal(unrelated.analysis.services.find(service => service.label === 'TCP/443').suggestedName, 'tcp80');
});

test('une fusion range du drawer produit un analysis.services valide', () => {
  const rangePorts = [10080, 52121, 52134, 62966];
  const policy = drawerPolicy([...rangePorts, 3268, 8530]);
  const harness = createDrawerHarness(policy);

  harness.click(specificButton('TCP/3268', 'tcp3268'));
  harness.click(specificButton('TCP/8530', 'tcp8530'));
  rangePorts.forEach(port => harness.click(serviceRow(`${port}/TCP`)));
  harness.click(new FakeTarget('svc-merge-type', { mode: 'range' }));
  harness.setInput('.svc-merge-name', 'dcp-rpc-range');
  harness.setInput('.svc-merge-range', '10080-62966');
  harness.click(new FakeTarget('svc-do-merge'));

  const merged = policy.analysis.services.find(service => service._isMerged);
  assert.equal(policy.analysis.services.length, 5);
  assert.equal(merged.suggestedName, 'dcp-rpc-range');
  assert.equal(merged.portRange, '10080-62966');
  assert.deepEqual([...merged.sourcePorts], rangePorts);
  assert.equal(Object.hasOwn(merged, 'ports'), false);
  assert.equal(validatePolicyDecisionShapes([policy]).ok, true);
  assert.doesNotMatch(appSource, /ports:\s*portRange\s*\?\s*null\s*:\s*ports/);
  const serializedMerged = harness.context.serializeMergedServiceDecisions(policy);
  assert.equal(Object.hasOwn(serializedMerged[0], 'ports'), false);
  assert.equal(serializedMerged[0].portRange, '10080-62966');
  assert.deepEqual([...serializedMerged[0].sourcePorts], rangePorts);
  assert.doesNotMatch(appSource, /ports:\s*s\.ports\s*\|\|\s*null/);
});

test('DCE-RPC-RANGE couvre trois ports sélectionnés mais pas une sélection mixte avec 8530', () => {
  const ports = [52121, 52134, 62966];
  const candidate = {
    name: 'DCE-RPC-RANGE', source: 'custom', proto: 'TCP',
    portSpec: 'TCP/10000-65535', coverageCount: 55536, extraPortCount: 55535,
  };
  const policy = drawerPolicy(ports);
  for (const service of policy.analysis.services.filter(item => ports.includes(item.port))) {
    service.compatibleMatch = candidate;
    service.compatibleMatches = [candidate];
  }
  const harness = createDrawerHarness(policy);
  ports.forEach(port => harness.click(serviceRow(`${port}/TCP`)));

  assert.match(harness.body.innerHTML, /svc-selected-compatible/);
  assert.match(harness.body.innerHTML, /DCE-RPC-RANGE/);
  assert.match(harness.body.innerHTML, /TCP\/10000-65535/);
  assert.match(harness.body.innerHTML, /TCP\/52121, TCP\/52134, TCP\/62966/);
  assert.doesNotMatch(harness.body.innerHTML, /FF_SVC_TCP_MULTI/);

  harness.click(new FakeTarget('svc-use-compatible-selected', {
    proto: 'TCP',
    ports: ports.join(','),
    serviceName: 'DCE-RPC-RANGE',
  }));
  for (const port of ports) {
    assert.equal(policy._serviceReuse[`TCP/${port}`], 'DCE-RPC-RANGE');
    assert.equal(policy._resolvedServiceKeys[`TCP/${port}`], 'existing:DCE-RPC-RANGE');
  }
  assert.equal((harness.body.innerHTML.match(/DCE-RPC-RANGE/g) || []).length, 1);
  assert.doesNotMatch(harness.body.innerHTML, /FF_SVC_TCP_MULTI/);

  const mixedPolicy = drawerPolicy([...ports, 8530]);
  for (const service of mixedPolicy.analysis.services.filter(item => ports.includes(item.port))) {
    service.compatibleMatch = candidate;
    service.compatibleMatches = [candidate];
  }
  const mixedHarness = createDrawerHarness(mixedPolicy);
  [...ports, 8530].forEach(port => mixedHarness.click(serviceRow(`${port}/TCP`)));
  assert.doesNotMatch(mixedHarness.body.innerHTML, /svc-selected-compatible/);
  assert.match(mixedHarness.body.innerHTML, /FF_SVC_TCP_MULTI/);
  assert.match(mixedHarness.body.innerHTML, /svc-do-merge/);
});

test('_serviceReuse est créé uniquement par l’action utiliser service existant', () => {
  const policy = drawerPolicy([52980]);
  const harness = createDrawerHarness(policy);

  assert.equal(policy._serviceReuse, undefined);
  assert.match(harness.body.innerHTML, /drawer-use-compatible-service/);

  harness.click(new FakeTarget('drawer-use-compatible-service', {
    serviceKey: 'TCP/52980',
    serviceName: 'MS-RPC-DYNAMIC',
  }));

  assert.equal(policy._serviceReuse['TCP/52980'], 'MS-RPC-DYNAMIC');
  assert.equal(policy._resolvedServiceKeys['TCP/52980'], 'existing:MS-RPC-DYNAMIC');
  assert.doesNotMatch(harness.body.innerHTML, /drawer-use-compatible-service/);
});

test('une policy incomplète reste ouvrable et éditable dans le drawer', () => {
  const policy = drawerPolicy([52980]);
  policy.analysis.srcAddr = { found: false, cidr: '10.0.0.0/24', suggestedName: 'FF_10_0_0_0_24' };
  const harness = createDrawerHarness(policy);

  assert.match(harness.body.innerHTML, /drawer-src-name/);
  assert.match(harness.body.innerHTML, /drawer-svc-name/);
  assert.match(harness.body.innerHTML, /MS-RPC-DYNAMIC/);
  assert.equal(harness.drawer.classList?.contains?.('open') ?? true, true);
});

test('créer un service spécifique retire toute réutilisation compatible du même port', () => {
  const policy = drawerPolicy([52980]);
  policy._serviceReuse = { 'TCP/52980': 'MS-RPC-DYNAMIC' };
  const harness = createDrawerHarness(policy);

  harness.click(specificButton('TCP/52980', 'CUSTOM_52980'));

  assert.equal(policy._serviceReuse['TCP/52980'], undefined);
  assert.equal(policy._resolvedServiceKeys['TCP/52980'], 'specific');
  assert.equal(policy.analysis.services.at(-1).suggestedName, 'CUSTOM_52980');
  assert.doesNotMatch(harness.body.innerHTML, /MS-RPC-DYNAMIC/);
  assert.match(harness.body.innerHTML, /CUSTOM_52980/);
  assert.match(harness.body.innerHTML, />DNS</);
  assert.match(harness.body.innerHTML, />HTTPS</);
});

test('le drawer applique explicitement un service ICMP compatible sans clé vide', () => {
  const policy = drawerPolicy([]);
  const compatible = {
    name: 'PING-TYPE', source: 'custom', proto: 'ICMP',
    portSpec: 'ICMP/8/*', coverageCount: 256, extraPortCount: 255,
  };
  policy.analysis.services.push({
    found: false,
    label: 'ICMP/8/0',
    proto: 'ICMP',
    isNamed: true,
    compatibleMatch: compatible,
    compatibleMatches: [compatible],
  });
  const harness = createDrawerHarness(policy);

  assert.equal(policy._serviceReuse, undefined);
  assert.match(harness.body.innerHTML, /PING-TYPE/);
  assert.doesNotMatch(harness.body.innerHTML, /ICMP\/undefined/);
  assert.doesNotMatch(harness.body.innerHTML, /drawer-create-specific-service/);

  harness.click(new FakeTarget('drawer-use-compatible-service', {
    serviceKey: 'ICMP/8/0',
    serviceName: 'PING-TYPE',
  }));

  assert.equal(policy._serviceReuse['ICMP/8/0'], 'PING-TYPE');
  assert.equal(policy._resolvedServiceKeys['ICMP/8/0'], 'existing:PING-TYPE');
  assert.doesNotMatch(harness.body.innerHTML, /drawer-use-compatible-service/);
});

test('le drawer applique toutes les clés d’un service compatible multiport', () => {
  const policy = drawerPolicy([]);
  const compatible = {
    name: 'APP-WIDE', source: 'custom', proto: 'TCP',
    portSpec: 'TCP/400-500,8443', coverageCount: 102, extraPortCount: 100,
  };
  policy.analysis.services.push({
    found: false,
    label: 'APP-WIDE',
    proto: 'TCP',
    isNamed: true,
    reuseKeys: ['TCP/443', 'TCP/8443'],
    compatibleMatch: compatible,
    compatibleMatches: [compatible],
  });
  const harness = createDrawerHarness(policy);

  assert.equal(policy._serviceReuse, undefined);
  assert.match(harness.body.innerHTML, /data-service-keys="TCP\/443,TCP\/8443"/);
  harness.click(new FakeTarget('drawer-use-compatible-service', {
    serviceKeys: 'TCP/443,TCP/8443',
    serviceName: 'APP-WIDE',
  }));

  assert.equal(policy._serviceReuse['TCP/443'], 'APP-WIDE');
  assert.equal(policy._serviceReuse['TCP/8443'], 'APP-WIDE');
  assert.equal(policy._resolvedServiceKeys['TCP/443'], 'existing:APP-WIDE');
  assert.equal(policy._resolvedServiceKeys['TCP/8443'], 'existing:APP-WIDE');
  assert.equal((harness.body.innerHTML.match(/drawer-field-value[^>]*>[^<]*APP-WIDE/g) || []).length, 1);
  assert.doesNotMatch(harness.body.innerHTML, /drawer-use-compatible-service/);
});

test('créer un service spécifique multiport résout toutes ses clés', () => {
  const policy = drawerPolicy([]);
  const compatible = {
    name: 'APP-WIDE', source: 'custom', proto: 'TCP',
    portSpec: 'TCP/400-500,8443', coverageCount: 102, extraPortCount: 100,
  };
  policy.analysis.services.push({
    found: false,
    label: 'APP-WIDE',
    proto: 'TCP',
    isNamed: true,
    reuseKeys: ['TCP/443', 'TCP/8443'],
    compatibleMatch: compatible,
    compatibleMatches: [compatible],
  });
  const harness = createDrawerHarness(policy);
  const parent = {
    querySelector(selector) {
      return selector === '.drawer-svc-name' ? { value: 'APP-SPECIFIC' } : null;
    },
  };
  harness.click(new FakeTarget('drawer-create-specific-service', {
    serviceKey: 'TCP/443', serviceKeys: 'TCP/443,TCP/8443',
  }, parent));

  assert.equal(policy._resolvedServiceKeys['TCP/443'], 'specific');
  assert.equal(policy._resolvedServiceKeys['TCP/8443'], 'specific');
  assert.deepEqual(Array.from(policy.analysis.services.at(-1).ports), [443, 8443]);
  assert.equal(policy.analysis.services.at(-1).suggestedName, 'APP-SPECIFIC');
  assert.doesNotMatch(harness.body.innerHTML, /drawer-service-compatibility/);
});

test('nommer au blur un service inconnu multiport résout toutes ses clés', () => {
  const policy = drawerPolicy([]);
  policy.analysis.services.push({
    found: false,
    label: 'APP-MULTI',
    isNamed: true,
    proto: 'TCP',
    reuseKeys: ['TCP/12000', 'TCP/12001'],
  });
  const harness = createDrawerHarness(policy);
  const input = new FakeTarget('drawer-svc-name', { svcKey: 'label:APP-MULTI' });
  input.value = 'APP-SPECIFIC';
  harness.blur(input);

  assert.equal(policy._resolvedServiceKeys['TCP/12000'], 'specific');
  assert.equal(policy._resolvedServiceKeys['TCP/12001'], 'specific');
  assert.deepEqual(Array.from(policy.analysis.services.at(-1).ports), [12000, 12001]);
  assert.equal(policy.analysis.services.at(-1).suggestedName, 'APP-SPECIFIC');
});

test('le contrat responsive garde le drawer et les actions visibles sans chevauchement', () => {
  const drawerWidth = cssRule('.policy-drawer').match(/width:\s*min\((\d+)px,\s*(\d+)vw\)/);
  assert.ok(drawerWidth, 'largeur desktop du drawer introuvable');
  const desktopWidth = Math.min(Number(drawerWidth[1]), 1440 * Number(drawerWidth[2]) / 100);
  assert.equal(desktopWidth, 780);
  assert.match(cssRule('.drawer-network-grid'), /grid-template-columns:\s*repeat\(2,/);
  assert.match(cssRule('.drawer-services-grid'), /grid-template-columns:\s*repeat\(2,/);

  const mobileCss = mediaBlock(820);
  assert.match(cssRule('.policy-drawer', mobileCss), /width:\s*100vw/);
  assert.match(cssRule('.drawer-network-grid', mobileCss), /grid-template-columns:\s*1fr/);
  assert.match(cssRule('.drawer-services-grid', mobileCss), /grid-template-columns:\s*1fr/);
  assert.match(cssRule('.svc-selected-compatible', mobileCss), /grid-template-columns:\s*1fr/);

  for (const selector of ['.drawer-service-compatibility-actions', '.svc-selected-compatible > div']) {
    const rule = cssRule(selector);
    assert.match(rule, /display:\s*flex/);
    assert.match(rule, /flex-wrap:\s*wrap/);
    assert.doesNotMatch(rule, /display:\s*none/);
  }

  for (const width of [1440, 700]) {
    const policy = drawerPolicy();
    policy._selectedSvcKeys = new Set(['52980/TCP', '52981/TCP']);
    const harness = createDrawerHarness(policy, width);
    assert.match(harness.body.innerHTML, /svc-use-compatible-selected/);
    assert.match(harness.body.innerHTML, /svc-create-new-selected/);
  }
});

test('l’action réelle de la policy pilote l’état ACCEPT ou DENY du drawer', () => {
  const policy = drawerPolicy();
  policy.action = 'deny';
  const harness = createDrawerHarness(policy);

  assert.match(harness.body.innerHTML, /drawer-action-btn deny active/);
  assert.doesNotMatch(harness.body.innerHTML, /drawer-action-btn accept active/);
  assert.match(harness.body.innerHTML, /aria-pressed="true"[^>]*>✕ DENY/);

  harness.click(new FakeTarget('drawer-action-btn', { action: 'accept' }));

  assert.equal(policy._action, 'accept');
  assert.match(harness.body.innerHTML, /drawer-action-btn accept active/);
  assert.doesNotMatch(harness.body.innerHTML, /drawer-action-btn deny active/);
});

test('le groupe destination garde trois modes et le même nombre d’hôtes', () => {
  const policy = drawerPolicy();
  policy.dstHosts = ['10.0.1.10', '10.0.1.11'];
  policy._dstMode = 'hosts';
  policy._use32Dst = true;
  policy._dstDetectedSubnets = [{
    subnet: '10.0.1.0/24',
    hosts: [...policy.dstHosts],
    useSubnet: true,
    addrFound: false,
    addrName: '',
  }];
  const harness = createDrawerHarness(policy);
  const modes = () => harness.body.innerHTML.match(/drawer-destination-mode /g) || [];

  assert.equal(modes().length, 3);
  assert.match(harness.body.innerHTML, /Hôtes \/32 \(2\)/);
  assert.match(harness.body.innerHTML, /Sous-réseaux détectés \(1\)/);

  for (const mode of ['hosts', 'detected-subnets', 'aggregate']) {
    harness.click(new FakeTarget('drawer-destination-mode', { mode }));
    assert.equal(policy.dstHosts.length, 2);
    assert.equal(policy._dstDetectedSubnets[0].hosts.length, 2);
    assert.equal(modes().length, 3);
  }
});

test('un drawer dense sépare les services configurés des services à traiter', () => {
  const policy = drawerPolicy();
  policy.analysis.services = Array.from({ length: 15 }, (_, index) => ({
    found: true,
    label: `SVC_${index + 1}`,
    name: `SVC_${index + 1}`,
    source: index % 2 ? 'custom' : 'predefined',
    portHint: `TCP/${1000 + index}`,
  }));
  policy.analysis.services.push(unresolvedService(3268), unresolvedService(8530));
  const harness = createDrawerHarness(policy);

  assert.match(harness.body.innerHTML, /drawer-services-configured/);
  assert.match(harness.body.innerHTML, /Configurés[\s\S]*\(15\)/);
  assert.match(harness.body.innerHTML, /drawer-services-pending/);
  assert.match(harness.body.innerHTML, /À traiter[\s\S]*\(2\)/);
  assert.match(harness.body.innerHTML, /drawer-service-compatibility-line/);
  assert.doesNotMatch(harness.body.innerHTML, /svc-sel-chk/);
});
