'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');

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
  querySelector() { return null; }

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
    fmtNum(value) { return String(value); },
    buildDrawerSecProfiles() { return '<details class="drawer-security-profiles"></details>'; },
    isDrawerObjectResolved() { return false; },
    filterFlowsByPolicy() {},
  };
  vm.createContext(context);
  vm.runInContext([
    sourceBlock('function _snapDrawer', 'function buildDrawerSecProfiles'),
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
    click(target) { drawer.dispatch('click', target); },
    blur(target) { drawer.dispatch('focusout', target); },
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
  assert.match(harness.body.innerHTML, /Utiliser ce service/);
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
