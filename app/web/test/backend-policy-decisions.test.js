'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const {
  parseFortiConfig,
  analyzePolicies,
  generateConfig,
  applyPolicyUserDecisions,
  validateGenerationOptions,
  preflightValidation,
  validatePolicyDecisionShapes,
} = require('../lib/forticonfig');

function fortiConfig(extra = '') {
  return parseFortiConfig(`
config firewall address
    edit "SRC"
        set subnet 10.0.0.0 255.255.255.0
    next
    edit "DST"
        set subnet 10.0.1.0 255.255.255.0
    next
end
config system interface
    edit "LAN"
        set ip 10.0.0.1 255.255.255.0
    next
    edit "DMZ"
        set ip 10.0.1.1 255.255.255.0
    next
end
${extra}
`);
}

function policy(overrides = {}) {
  return {
    srcSubnet: '10.0.0.0/24',
    dstTarget: '10.0.1.0/24',
    dstType: 'private',
    services: ['APPX'],
    ports: [5555],
    protos: ['TCP'],
    srcHosts: ['10.0.0.10'],
    dstHosts: ['10.0.1.20'],
    flowSrcintf: 'LAN',
    sessions: 1,
    action: 'accept',
    ...overrides,
  };
}

function observedFlow(overrides = {}) {
  return {
    srcip: '10.0.0.10',
    dstip: '10.0.1.20',
    srcSubnet: '10.0.0.0/24',
    dstSubnet: '10.0.1.0/24',
    dstType: 'private',
    srcintf: 'LAN',
    dstintf: 'DMZ',
    service: 'APPX',
    dstport: '5555',
    proto: '6',
    protoName: 'TCP',
    action: 'accept',
    ...overrides,
  };
}

test('FF2-15 crée le service nommé avec le tuple unique observé', () => {
  assert.equal(typeof applyPolicyUserDecisions, 'function');
  const config = fortiConfig();
  const authoritative = analyzePolicies([policy()], config);
  const submitted = structuredClone(authoritative);
  submitted[0].analysis.services[0].suggestedName = 'MyApp';

  const decision = applyPolicyUserDecisions(
    authoritative,
    submitted,
    config,
    [observedFlow()],
  );

  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  const service = decision.policies[0].analysis.services[0];
  assert.equal(service.suggestedName, 'MyApp');
  assert.equal(service.port, 5555);
  assert.equal(service.proto, 'TCP');

  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.match(cli, /edit "MyApp"/);
  assert.match(cli, /set tcp-portrange 5555/);
  assert.match(cli, /set service "MyApp"/);
});

test('les actions terminales FortiOS prouvent les décisions de policy', () => {
  const config = fortiConfig();
  const authoritative = analyzePolicies([policy()], config);
  const submitted = structuredClone(authoritative);

  for (const action of ['close', 'timeout', 'client-rst', 'server-rst']) {
    const decision = applyPolicyUserDecisions(
      authoritative,
      submitted,
      config,
      [observedFlow({ action })],
    );

    assert.equal(decision.ok, true, `${action}: ${JSON.stringify(decision.issues)}`);
  }
});

test('une policy complète sélectionnée génère seule malgré une policy non sélectionnée invalide', () => {
  const config = fortiConfig(`
config firewall service custom
    edit "APPX"
        set tcp-portrange 5555
    next
end
  `);
  const selected = policy({ srcintf: 'LAN', dstintf: 'DMZ' });
  const authoritative = analyzePolicies([selected], config, undefined, [observedFlow()]);
  const decision = applyPolicyUserDecisions(authoritative, [selected], config, [observedFlow()]);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));

  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.match(cli, /set service "APPX"/);
  assert.equal((cli.match(/edit 0/g) || []).length, 1);

  const unselectedInvalid = policy({
    dstTarget: '10.99.99.0/24',
    dstHosts: ['10.99.99.10'],
    srcintf: 'LAN',
    dstintf: 'FORGED',
  });
  const withUnselected = applyPolicyUserDecisions(
    analyzePolicies([selected, unselectedInvalid], config, undefined, [observedFlow()]),
    [selected, unselectedInvalid],
    config,
    [observedFlow()],
  );
  assert.equal(withUnselected.ok, false, 'la fixture non sélectionnée est volontairement bloquante si elle est transmise');
});

test('FF2-04 conserve action, log et profils de sécurité jusqu’à la CLI', () => {
  const config = fortiConfig(`
config ips sensor
    edit "STRICT_IPS"
    next
end
`);
  const authoritative = analyzePolicies([policy({ services: ['SSH'], ports: [22] })], config);
  const submitted = structuredClone(authoritative);
  submitted[0].action = 'deny';
  submitted[0].log = 'disable';
  submitted[0].securityProfiles = { ips: 'STRICT_IPS' };

  const decision = applyPolicyUserDecisions(
    authoritative,
    submitted,
    config,
    [observedFlow({ service: 'SSH', dstport: '22' })],
  );

  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
    actionVerb: 'accept',
    logTraffic: 'all',
  });
  assert.match(cli, /set action deny/);
  assert.match(cli, /set logtraffic disable/);
  assert.match(cli, /set utm-status enable/);
  assert.match(cli, /set ips-sensor "STRICT_IPS"/);
  assert.doesNotMatch(cli, /set action accept/);
});

test('FF2-04 sérialise les décisions du drawer dans les deux modes de vue', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
  const start = source.indexOf('async function generateDeployConf()');
  const end = source.length;
  assert.ok(start >= 0 && end > start);
  const generate = source.slice(start, end);

  assert.equal((generate.match(/securityProfiles:\s*p\._secProfiles\s*\|\|\s*null/g) || []).length, 2);
  assert.equal((generate.match(/action:\s*p\._action\s*\|\|\s*null/g) || []).length, 2);
  assert.equal((generate.match(/log:\s*p\._log\s*\|\|\s*null/g) || []).length, 2);
  assert.match(generate, /body:\s*JSON\.stringify\(\{\s*selectedPolicies,\s*opts\s*\}\)/);
});

test('le payload de génération conserve les tuples sources d’un service fusionné', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
  const start = source.indexOf('function serializePolicyServiceLabels');
  const end = source.indexOf('\nfunction ', start + 20);
  assert.ok(start >= 0 && end > start, 'sérialiseur des services introuvable');
  const context = { Set };
  vm.createContext(context);
  vm.runInContext(source.slice(start, end), context);

  assert.deepEqual(
    [...context.serializePolicyServiceLabels({
      analysis: {
        services: [
          { label: 'DNS', found: true },
          { label: 'dce-rpc-range', _isMerged: true, proto: 'tcp', sourcePorts: [52121, 52134, 62966] },
        ],
      },
    })],
    ['DNS', 'TCP/52121', 'TCP/52134', 'TCP/62966'],
  );
});

test('la génération restitue les causes backend et marque uniquement les policies sélectionnées', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
  const start = source.indexOf('function isNonBlockingPolicyIssue');
  const end = source.indexOf('\nfunction markSelectedPolicyIssues', start);
  assert.ok(start >= 0 && end > start, 'formatter de validation introuvable');
  const context = {};
  vm.createContext(context);
  vm.runInContext(source.slice(start, end), context);

  const message = context.formatPolicyValidationError({
    error: 'Décision utilisateur invalide',
    issues: [
      { code: 'SERVICE_REUSE_DECISION_INVALID', msg: 'Policy #1: service LDAP stale' },
      { code: 'POLICY_AFFINITY_UNPROVEN', msg: 'Policy #1: combinaison non prouvée' },
    ],
  });
  assert.match(message, /Décision utilisateur invalide/);
  assert.match(message, /Policy #1: service LDAP stale/);
  assert.match(message, /Policy #1: combinaison non prouvée/);
  const mixedMessage = context.formatPolicyValidationError({
    error: 'Décision utilisateur invalide',
    issues: [
      { level: 'error', code: 'SERVICE_NAME_CONFLICT', msg: 'Policy #1: conflit service' },
      { level: 'risk', code: 'POLICY_AFFINITY_UNPROVEN', msg: 'Policy #1: affinité non prouvée' },
    ],
  });
  assert.match(mixedMessage, /Erreur technique[\s\S]*conflit service/);
  assert.match(mixedMessage, /Avertissement non bloquant[\s\S]*affinité non prouvée/);
  const incompleteMessage = context.formatPolicyValidationError({
    error: 'Preflight refusé',
    preflight: { issues: [{ level: 'error', msg: 'Policy #1: interface destination manquante' }] },
  });
  assert.match(incompleteMessage, /À compléter/);
  assert.match(incompleteMessage, /Policy #1: interface destination manquante/);
  const markStart = source.indexOf('function isNonBlockingPolicyIssue');
  const markEnd = source.indexOf('\nasync function generateDeployConf', markStart);
  const markContext = {
    deployState: { analyzed: [{}, {}] },
    renderDeployPolicies() {},
    filterDeployPolicies() { return []; },
  };
  vm.createContext(markContext);
  vm.runInContext(source.slice(markStart, markEnd), markContext);
  markContext.markSelectedPolicyIssues([
    { code: 'POLICY_AFFINITY_UNPROVEN', msg: 'Policy #1: combinaison non prouvée' },
  ], [0]);
  assert.deepEqual(
    [...markContext.deployState.analyzed[0]._backendIssues],
    ['[POLICY_AFFINITY_UNPROVEN] Policy #1: combinaison non prouvée'],
  );
  assert.equal(markContext.deployState.analyzed[1]._backendIssues, undefined);

  markContext.deployState.analyzed = [{}, {}, {}];
  markContext.markSelectedPolicyIssues([
    { code: 'POLICY_AFFINITY_UNPROVEN', msg: 'Policy #1: combinaison non prouvée' },
  ], [[0, 2], [1]], 'risk');
  assert.ok(markContext.deployState.analyzed[0]._backendIssues);
  assert.equal(markContext.deployState.analyzed[1]._backendIssues, undefined);
  assert.ok(markContext.deployState.analyzed[2]._backendIssues);

  markContext.deployState.analyzed = [{}];
  markContext.markSelectedPolicyIssues([
    { level: 'error', code: 'SERVICE_NAME_CONFLICT', msg: 'Policy #1: conflit service' },
    { level: 'risk', code: 'POLICY_AFFINITY_UNPROVEN', msg: 'Policy #1: affinité non prouvée' },
  ], [0], 'security');
  assert.deepEqual(
    [...markContext.deployState.analyzed[0]._backendIssues],
    ['[SERVICE_NAME_CONFLICT] Policy #1: conflit service'],
  );

  const generateStart = source.indexOf('async function generateDeployConf()');
  const generateEnd = source.length;
  const generate = source.slice(generateStart, generateEnd);
  assert.match(generate, /if \(!pfRes\.ok\)[\s\S]*formatPolicyValidationError[\s\S]*return;/);
  assert.match(generate, /if \(!pfRes\.ok\)[\s\S]*resetGenerateButton\(\)[\s\S]*return;/);
  assert.match(generate, /pf\.preflight\?\.issues/);
  assert.doesNotMatch(generate, /catch \{ \/\* non-bloquant \*\//);
  assert.match(generate, /Validation backend indisponible/);
  assert.match(generate, /catch \(err\)[\s\S]*resetGenerateButton\(\)[\s\S]*return;/);
  assert.match(generate, /if \(!r\.ok\)[\s\S]*formatPolicyValidationError/);
  assert.match(generate, /const selectedIndexes = \[\.\.\.deployState\.selected\]/);
  assert.match(generate, /selectedPolicies = selectedCompleteIndexes[\s\S]*\.map\(index => deployState\.analyzed\[index\]\)/);
  assert.doesNotMatch(generate, /selectedPolicies\s*=\s*deployState\.analyzed\.map/);
  assert.match(source, /_backendIssues[\s\S]*Erreur technique/);
  assert.doesNotMatch(source, /_acceptedRiskIssues/);
  assert.doesNotMatch(source, /À risque/);
  assert.doesNotMatch(source, /_backendValidated[\s\S]*Prête/);
  assert.match(source, /Policy complète/);
  assert.match(source, /delete p\._backendIssues/);
});

test('le frontend ne bloque plus la génération pour les risques métier', () => {
  const appSource = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
  const serverSource = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const generateStart = appSource.indexOf('async function generateDeployConf()');
  const generateEnd = appSource.length;
  const generate = appSource.slice(generateStart, generateEnd);

  assert.doesNotMatch(serverSource, /POLICY_RISK_CONFIRMATION_REQUIRED/);
  assert.doesNotMatch(appSource, /function showRiskOverrideModal/);
  assert.doesNotMatch(generate, /POLICY_RISK_CONFIRMATION_REQUIRED/);
  assert.doesNotMatch(generate, /showRiskOverrideModal/);
  assert.doesNotMatch(generate, /acceptSelectedPolicyRisks/);
  assert.match(generate, /incompleteSelectedIndexes/);
  assert.match(generate, /champ obligatoire manquant/);
  assert.doesNotMatch(generate, /showPreflightModal/);
});

test('les champs obligatoires manquants sont exposés précisément', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
  const start = source.indexOf('function policyMissingMandatoryFields');
  const end = source.indexOf('\nfunction ', start + 20);
  assert.ok(start >= 0 && end > start, 'calcul des champs obligatoires introuvable');
  const context = { Set };
  vm.createContext(context);
  vm.runInContext(source.slice(start, end), context);

  assert.deepEqual(
    [...context.policyMissingMandatoryFields({
      analysis: {
        missingFields: ['srcAddr', 'dstAddr', 'svc:TCP/443'],
        services: [{ found: false, label: 'TCP/443' }],
      },
    })],
    ['interface source', 'interface destination', 'source', 'destination', 'service'],
  );
  assert.deepEqual(
    [...context.policyMissingMandatoryFields({
      _srcintf: 'LAN',
      _dstintf: 'DMZ',
      _resolvedServiceKeys: { 'TCP/443': 'existing:HTTPS' },
      _serviceReuse: { 'TCP/443': 'HTTPS' },
      analysis: {
        srcAddr: { found: true },
        dstAddr: { found: true },
        missingFields: ['svc:TCP/443'],
        services: [{ found: false, label: 'TCP/443', reuseKeys: ['TCP/443'] }],
      },
    })],
    [],
  );
  assert.deepEqual(
    [...context.policyMissingMandatoryFields({
      _srcintf: 'LAN',
      _dstintf: 'DMZ',
      _srcAddrName: 'SRC_OVERRIDE',
      _dstAddrName: 'DST_OVERRIDE',
      analysis: {
        srcAddr: { found: true },
        dstAddr: { found: true },
        missingFields: ['srcAddr', 'dstAddr', 'srcIface', 'svc:TCP/443'],
        services: [{ found: true, label: 'HTTPS' }],
      },
    })],
    [],
  );
  assert.deepEqual(
    [...context.policyMissingMandatoryFields({
      _srcintf: 'LAN',
      _dstintf: 'DMZ',
      analysis: { srcAddr: { found: true }, dstAddr: { found: true }, services: [] },
    })],
    ['service'],
  );

  const completeStart = source.indexOf('function isPolicyComplete');
  const completeEnd = source.indexOf('\nfunction syncRowStatus', completeStart);
  assert.ok(completeStart >= 0 && completeEnd > completeStart, 'calcul de complétude introuvable');
  const completeContext = { Set, cleanHostName() { return ''; } };
  vm.createContext(completeContext);
  vm.runInContext(source.slice(completeStart, completeEnd), completeContext);
  assert.equal(completeContext.isPolicyComplete({
    _srcintf: 'LAN',
    _dstintf: 'DMZ',
    analysis: { srcAddr: { found: true }, dstAddr: { found: true }, services: [] },
  }), false);
});

test('les profils de sécurité vides restent optionnels pour une policy complète', () => {
  const config = fortiConfig();
  const authoritative = analyzePolicies([policy()], config);
  const submitted = structuredClone(authoritative);
  delete submitted[0].securityProfiles;

  const options = validateGenerationOptions({ securityProfiles: {} }, config);
  assert.equal(options.ok, true, JSON.stringify(options.issues));
  const decision = applyPolicyUserDecisions(authoritative, submitted, config, [observedFlow()]);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.match(cli, /config firewall policy/);
});

test('FF2-01 refuse une interface utilisateur absente de la configuration', () => {
  const config = fortiConfig();
  const authoritative = analyzePolicies([policy()], config);
  const submitted = structuredClone(authoritative);
  submitted[0].srcintf = 'FORGED-INTERFACE';
  submitted[0].dstintf = 'DMZ';

  const decision = applyPolicyUserDecisions(
    authoritative,
    submitted,
    config,
    [observedFlow()],
  );

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'INTERFACE_DECISION_INVALID'));
});

test('FF2-01 refuse les noms de service globaux, normalisés ou en collision', () => {
  const config = fortiConfig(`
config firewall service custom
    edit "SAFE_NAME"
        set tcp-portrange 9999
    next
end
`);
  const authoritative = analyzePolicies([policy()], config);

  for (const name of ['ALL', 'SAFE"NAME', 'SAFE_NAME', 'HTTPS']) {
    const submitted = structuredClone(authoritative);
    submitted[0].analysis.services[0].suggestedName = name;
    const decision = applyPolicyUserDecisions(
      authoritative,
      submitted,
      config,
      [observedFlow()],
    );
    assert.equal(decision.ok, false, `${name} aurait dû être refusé`);
    assert.ok(decision.issues.some(issue =>
      issue.code === 'SERVICE_NAME_INVALID' || issue.code === 'SERVICE_NAME_CONFLICT'
    ));
  }
});

test('FF2-01 refuse une policy sans service au lieu de générer ALL', () => {
  const config = fortiConfig();
  const authoritative = analyzePolicies([policy({ services: [], ports: [] })], config);
  const submitted = structuredClone(authoritative);

  const decision = applyPolicyUserDecisions(
    authoritative,
    submitted,
    config,
    [observedFlow()],
  );

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'SERVICE_DECISION_EMPTY'));
});

test('FF2-01 accepte un range uniquement depuis les ports sources observés', () => {
  const config = fortiConfig();
  const basePolicy = policy({
    services: [],
    ports: [12000, 12001],
  });
  const authoritative = analyzePolicies([basePolicy], config);
  const submitted = structuredClone(authoritative);
  submitted[0].services = [];
  submitted[0].analysis.services = [];
  submitted[0]._mergedServices = [{
    name: 'CUSTOM_RANGE',
    proto: 'TCP',
    ports: null,
    portRange: '12000-12001',
    sourcePorts: [12000, 12001],
  }];

  const decision = applyPolicyUserDecisions(
    authoritative,
    submitted,
    config,
    [
      observedFlow({ service: 'TCP/12000', dstport: '12000' }),
      observedFlow({ service: 'TCP/12001', dstport: '12001' }),
    ],
  );

  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  assert.deepEqual(decision.policies[0].analysis.services, [{
    label: 'CUSTOM_RANGE',
    found: false,
    name: null,
    source: null,
    suggestedName: 'CUSTOM_RANGE',
    isNamed: false,
    proto: 'TCP',
    ports: null,
    portRange: '12000-12001',
    sourcePorts: [12000, 12001],
    _isMerged: true,
  }]);
});

test('autorise explicitement un range fusionné plus large comme risque ingénieur', () => {
  const config = fortiConfig();
  const selected = policy({
    dstHosts: ['10.0.1.20', '10.0.1.21'],
    _use32Dst: true,
    _dstMode: 'hosts',
    services: ['TCP/12000', 'TCP/12005', 'TCP/13000'],
    ports: [12000, 12005, 13000],
    protos: ['TCP'],
  });
  const flows = [
    observedFlow({ service: 'TCP/12000', dstport: '12000', dstip: '10.0.1.20' }),
    observedFlow({ service: 'TCP/12005', dstport: '12005', dstip: '10.0.1.21' }),
    observedFlow({ service: 'TCP/13000', dstport: '13000', dstip: '10.0.1.20' }),
  ];
  const authoritative = analyzePolicies([selected], config, undefined, flows);
  const submitted = structuredClone(authoritative);
  submitted[0].services = [];
  submitted[0].analysis.services = [{
    label: 'dce-rpc-range',
    found: false,
    name: null,
    source: null,
    suggestedName: 'dce-rpc-range',
    isNamed: false,
    proto: 'tcp',
    portRange: '12000-13000',
    sourcePorts: [12000, 12005, 13000],
    _isMerged: true,
  }];
  submitted[0]._mergedServices = [{
    name: 'dce-rpc-range',
    ports: null,
    portRange: '12000-13000',
    proto: 'tcp',
    sourcePorts: [12000, 12005, 13000],
  }];

  const decision = applyPolicyUserDecisions(authoritative, [submitted[0]], config, flows);
  assert.equal(decision.ok, false);
  const rangeRisk = decision.issues.find(issue => issue.code === 'MERGED_SERVICE_DECISION_INVALID');
  assert.equal(rangeRisk.level, 'risk');
  assert.equal(rangeRisk.overridable, true);
  assert.match(rangeRisk.msg, /dce-rpc-range/);
  assert.match(rangeRisk.detail, /12000-13000/);
  const affinityRisk = decision.issues.find(issue => issue.code === 'POLICY_AFFINITY_UNPROVEN');
  assert.equal(affinityRisk.level, 'risk');

  submitted[0]._acceptedRisks = [
    'MERGED_SERVICE_DECISION_INVALID',
    'POLICY_AFFINITY_UNPROVEN',
  ];
  const accepted = applyPolicyUserDecisions(authoritative, [submitted[0]], config, flows);
  assert.equal(accepted.ok, true, JSON.stringify(accepted.issues));
  assert.ok(accepted.issues.some(issue =>
    issue.code === 'MERGED_SERVICE_DECISION_INVALID' && issue.accepted === true && issue.level === 'warn'
  ));
  assert.ok(accepted.issues.some(issue =>
    issue.code === 'POLICY_AFFINITY_UNPROVEN' && issue.accepted === true && issue.level === 'warn'
  ));

  const cli = generateConfig(accepted.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.match(cli, /edit "dce-rpc-range"/);
  assert.match(cli, /set tcp-portrange 12000-13000/);
  assert.match(cli, /set service "dce-rpc-range"/);
});

test('FF2-01 refuse les fusions de services forgées ou non prouvées', () => {
  const config = fortiConfig();
  const authoritative = analyzePolicies([policy({
    services: ['TCP/12000', 'TCP/13000'],
    ports: [12000, 13000],
  })], config);
  const flows = [
    observedFlow({ service: 'TCP/12000', dstport: '12000' }),
    observedFlow({ service: 'TCP/13000', dstport: '13000' }),
  ];
  const forged = [
    { expectedLevel: 'error', name: 'EVIL-ALL', proto: 'TCP', portRange: '1-65535', sourcePorts: [12000, 13000] },
    { expectedLevel: 'risk', name: 'GAPPED', proto: 'TCP', portRange: '12000-13000', sourcePorts: [12000, 13000] },
    { expectedLevel: 'error', name: 'NO-PROOF', proto: 'TCP', portRange: '12000-13000' },
    { expectedLevel: 'error', name: 'UNOBSERVED', proto: 'TCP', ports: [12000, 14000], sourcePorts: [12000, 14000] },
    { expectedLevel: 'error', name: 'CONTRADICTORY', proto: 'TCP', ports: [12000, 13000], portRange: '1-65535', sourcePorts: [12000, 13000] },
  ];

  for (const merged of forged) {
    const submitted = structuredClone(authoritative);
    submitted[0].analysis.services = [];
    submitted[0].services = [];
    submitted[0]._mergedServices = [merged];
    const decision = applyPolicyUserDecisions(authoritative, submitted, config, flows);
    assert.equal(decision.ok, false, `${merged.name} aurait dû être refusé`);
    const issue = decision.issues.find(item => item.code === 'MERGED_SERVICE_DECISION_INVALID');
    assert.equal(issue.level, merged.expectedLevel, `${merged.name}: ${JSON.stringify(decision.issues)}`);
  }

  const forgedAcceptance = structuredClone(authoritative);
  forgedAcceptance[0].analysis.services = [];
  forgedAcceptance[0].services = [];
  forgedAcceptance[0]._mergedServices = [{
    name: 'EVIL-ALL', proto: 'TCP', portRange: '1-65535', sourcePorts: [12000, 13000],
  }];
  forgedAcceptance[0]._acceptedRisks = ['MERGED_SERVICE_DECISION_INVALID'];
  const forgedDecision = applyPolicyUserDecisions(authoritative, forgedAcceptance, config, flows);
  assert.equal(forgedDecision.ok, false);
  assert.ok(forgedDecision.issues.some(issue =>
    issue.code === 'MERGED_SERVICE_DECISION_INVALID' && issue.level === 'error'
  ));

  const malformedRange = structuredClone(authoritative);
  malformedRange[0].analysis.services = [];
  malformedRange[0].services = [];
  malformedRange[0]._mergedServices = [{
    name: 'BAD-PORTS', proto: 'TCP', ports: '12000', portRange: '12000-13000',
    sourcePorts: [12000, 13000],
  }];
  const malformedDecision = applyPolicyUserDecisions(authoritative, malformedRange, config, flows);
  assert.equal(malformedDecision.ok, false);
  assert.ok(malformedDecision.issues.some(issue =>
    issue.code === 'MERGED_SERVICE_DECISION_INVALID' && issue.level === 'error'
  ));
});

test('FF2-01 refuse une fusion dont les labels ne correspondent pas aux flux', () => {
  const config = fortiConfig();
  const authoritative = analyzePolicies([policy({
    services: ['TCP/12000', 'TCP/12001'],
    ports: [12000, 12001],
  })], config);
  const submitted = structuredClone(authoritative);
  submitted[0].services = [];
  submitted[0].analysis.services = [];
  submitted[0]._mergedServices = [{
    name: 'MERGED_REAL', proto: 'TCP', portRange: '12000-12001', sourcePorts: [12000, 12001],
  }];
  const decision = applyPolicyUserDecisions(authoritative, submitted, config, [
    observedFlow({ service: 'REAL12000', dstport: '12000' }),
    observedFlow({ service: 'REAL12001', dstport: '12001' }),
  ]);

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'SERVICE_DECISION_UNPROVEN'));
});

test('FF2-01 transmet la preuve des ports sources pour chaque fusion UI', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
  assert.equal((source.match(/sourcePorts:\s*ports/g) || []).length, 2);
  assert.match(source, /function serializeMergedServiceDecisions[\s\S]*sourcePorts:\s*\[\.\.\.\(service\.sourcePorts\s*\|\|\s*\[\]\)\]/);
  assert.equal((source.match(/_mergedServices:\s*serializeMergedServiceDecisions\(p\)/g) || []).length, 2);
  assert.doesNotMatch(source, /ports:\s*s\.ports\s*\|\|\s*null/);
});

test('FF2-01 ignore les champs techniques forgés d’un service standard', () => {
  const config = fortiConfig();
  const authoritative = analyzePolicies([policy()], config);
  const submitted = structuredClone(authoritative);
  Object.assign(submitted[0].analysis.services[0], {
    suggestedName: 'MyApp',
    port: 9999,
    proto: 'UDP',
    ports: [9999],
    portRange: '1-65535',
  });

  const decision = applyPolicyUserDecisions(authoritative, submitted, config, [observedFlow()]);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  assert.equal(decision.policies[0].analysis.services[0].port, 5555);
  assert.equal(decision.policies[0].analysis.services[0].proto, 'TCP');
  assert.equal(decision.policies[0].analysis.services[0].ports, undefined);
  assert.equal(decision.policies[0].analysis.services[0].portRange, undefined);
});

test('FF2-01 applique le validateur autoritatif au preflight et à la génération', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.match(source, /applyPolicyUserDecisions/);
  assert.match(source, /analysisInput\s*=\s*structuredClone\(submittedPolicies\)/);
  assert.match(source, /delete policy\._mergedServices/);
  for (const marker of ["app.post('/api/deploy/preflight'", "app.post('/api/deploy/generate'"]) {
    const start = source.indexOf(marker);
    const end = source.indexOf('\n});', start);
    assert.ok(start >= 0 && end > start);
    const route = source.slice(start, end);
    assert.match(route, /preparePolicyDecisions\(/);
    assert.match(route, /sendPolicyDecisionFailure\(/);
  }
  assert.match(source, /POLICY_DECISION_INVALID/);
  assert.doesNotMatch(source, /POLICY_RISK_CONFIRMATION_REQUIRED/);
  const generateStart = source.indexOf("app.post('/api/deploy/generate'");
  const generateEnd = source.indexOf('\n});', generateStart);
  const generateRoute = source.slice(generateStart, generateEnd);
  assert.match(generateRoute, /preflightValidation\(validatedPolicies/);
  assert.match(generateRoute, /Génération refusée par le preflight/);
  const preflightStart = source.indexOf("app.post('/api/deploy/preflight'");
  const preflightEnd = source.indexOf('\n});', preflightStart);
  assert.match(source.slice(preflightStart, preflightEnd), /Preflight refusé/);
});

test('la récupération sauvegarde le deployState contaminé avant toute correction automatique', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const marker = "app.post('/api/deploy/recovery-backup'";
  const start = source.indexOf(marker);
  const end = source.indexOf('\n});', start);
  assert.ok(start >= 0 && end > start, 'route de sauvegarde de récupération absente');
  const route = source.slice(start, end);
  assert.match(route, /requireSession\(/);
  assert.match(route, /SERVICE_RECOVERY_BACKUP_DIR/);
  assert.match(route, /fs\.promises\.writeFile/);
  assert.match(route, /fs\.promises\.rename/);
  assert.match(route, /analyzed/);
});

test('FF2-01 refuse un service trouvé mais absent des flux observés de la policy', () => {
  const config = fortiConfig();
  const authoritative = analyzePolicies([policy({ services: ['HTTPS'], ports: [443] })], config);
  const submitted = structuredClone(authoritative);

  const decision = applyPolicyUserDecisions(
    authoritative,
    submitted,
    config,
    [observedFlow()],
  );

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'SERVICE_DECISION_UNPROVEN'));
});

test('FF2-01 refuse deux définitions différentes portant le même nom', () => {
  const config = fortiConfig();
  const authoritative = analyzePolicies([policy({
    services: ['TCP/1000', 'TCP/2000'],
    ports: [1000, 2000],
  })], config);
  const submitted = structuredClone(authoritative);
  submitted[0].analysis.services.forEach(service => { service.suggestedName = 'SAME'; });

  const decision = applyPolicyUserDecisions(authoritative, submitted, config, [
    observedFlow({ service: 'TCP/1000', dstport: '1000' }),
    observedFlow({ service: 'TCP/2000', dstport: '2000' }),
  ]);

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'SERVICE_NAME_CONFLICT'));
});

test('FF2-01 le générateur refuse toute policy sans service validé', () => {
  const config = fortiConfig();
  const empty = analyzePolicies([policy({ services: [], ports: [] })], config);
  assert.throws(() => generateConfig(empty, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  }), /sans service validé/);
});

test('FF2-01 refuse aussi une interface WAN préférée inconnue', () => {
  const config = fortiConfig();
  const wanPolicy = policy({ dstTarget: '8.8.8.8', dstType: 'public', dstHosts: [] });
  const authoritative = analyzePolicies([wanPolicy], config, 'FORGED-WAN');
  const decision = applyPolicyUserDecisions(
    authoritative,
    [wanPolicy],
    config,
    [observedFlow({ dstip: '8.8.8.8', dstSubnet: null, dstType: 'public' })],
  );

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'INTERFACE_DECISION_INVALID'));
});

test('FF2-01 conserve la preuve de service pour une destination multi-subnet mixte', () => {
  const config = fortiConfig();
  const mixedPolicy = policy({
    dstTargets: ['10.0.1.0/24', '10.0.2.0/24'],
    dstHosts: ['10.0.2.20'],
    _multiDstSubnets: [
      { subnet: '10.0.1.0/24', useSubnet: true, hosts: ['10.0.1.20', '10.0.1.30'] },
      { subnet: '10.0.2.0/24', useSubnet: false, hosts: ['10.0.2.20'] },
    ],
  });
  const authoritative = analyzePolicies([mixedPolicy], config);
  const decision = applyPolicyUserDecisions(
    authoritative,
    [mixedPolicy],
    config,
    [
      observedFlow({ dstip: '10.0.1.30' }),
      observedFlow({ dstip: '10.0.2.20', dstSubnet: '10.0.2.0/24' }),
    ],
  );

  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
});

test('FF2-01 accepte une zone SD-WAN secondaire présente dans la configuration', () => {
  const config = fortiConfig();
  config.sdwanIntfName = 'virtual-wan-link';
  config.sdwanZoneNames = ['virtual-wan-link', 'overlay-wan'];
  config.sdwanMembers = ['DMZ'];
  const wanPolicy = policy({ dstTarget: '8.8.8.8', dstType: 'public', dstHosts: [] });
  const authoritative = analyzePolicies([wanPolicy], config, 'overlay-wan');
  const decision = applyPolicyUserDecisions(
    authoritative,
    [wanPolicy],
    config,
    [observedFlow({ dstip: '8.8.8.8', dstSubnet: null, dstType: 'public' })],
  );

  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
});

test('FF2-15 crée deux noms distincts pour un même tuple utilisé par deux policies', () => {
  const config = fortiConfig();
  const input = [policy({ services: ['APPX'] }), policy({ services: ['APPY'] })];
  const authoritative = analyzePolicies(input, config);
  const submitted = structuredClone(authoritative);
  submitted[0].analysis.services[0].suggestedName = 'MyApp';
  submitted[1].analysis.services[0].suggestedName = 'MyOther';
  const decision = applyPolicyUserDecisions(authoritative, submitted, config, [
    observedFlow({ service: 'APPX' }),
    observedFlow({ service: 'APPY' }),
  ]);

  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.match(cli, /edit "MyApp"[\s\S]*set tcp-portrange 5555/);
  assert.match(cli, /edit "MyOther"[\s\S]*set tcp-portrange 5555/);
});

test('FF2-01 refuse explicitement un choix de réutilisation forgé ou stale', () => {
  const config = fortiConfig(`
config firewall service custom
    edit "MS-RPC-DYNAMIC"
        set tcp-portrange 49152-65535
    next
end
`);
  const submitted = policy({
    services: ['TCP/52980'],
    ports: [52980],
    _serviceReuse: { 'TCP/52980': 'FORGED-SERVICE' },
  });
  const authoritative = analyzePolicies([submitted], config);
  const decision = applyPolicyUserDecisions(authoritative, [submitted], config, [
    observedFlow({ service: 'TCP/52980', dstport: '52980' }),
  ]);

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'SERVICE_REUSE_DECISION_INVALID'));
});

test('FF2-01 conserve une réutilisation compatible explicitement revalidée', () => {
  const config = fortiConfig(`
config firewall service custom
    edit "MS-RPC-DYNAMIC"
        set tcp-portrange 49152-65535
    next
end
`);
  const submitted = policy({
    services: ['TCP/52980'],
    ports: [52980],
    _serviceReuse: { 'TCP/52980': 'MS-RPC-DYNAMIC' },
  });
  const authoritative = analyzePolicies([submitted], config);
  const decision = applyPolicyUserDecisions(authoritative, [submitted], config, [
    observedFlow({ service: 'TCP/52980', dstport: '52980' }),
  ]);

  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  assert.equal(decision.policies[0].analysis.services[0].name, 'MS-RPC-DYNAMIC');
  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.match(cli, /set service "MS-RPC-DYNAMIC"/);
  assert.doesNotMatch(cli, /edit "MS-RPC-DYNAMIC"/);
});

test('FF2-01 ignore la table legacy serviceNames fournie par le navigateur', () => {
  const config = fortiConfig();
  const authoritative = analyzePolicies([policy({ serviceNames: { APPX: 'ALL' } })], config);
  const submitted = structuredClone(authoritative);
  submitted[0].analysis.services[0].suggestedName = 'MyApp';

  const decision = applyPolicyUserDecisions(authoritative, submitted, config, [observedFlow()]);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.match(cli, /edit "MyApp"/);
  assert.doesNotMatch(cli, /edit "ALL"/);
  assert.doesNotMatch(cli, /set service "ALL"/);
});

test('FF2-01 ignore un groupe d’adresse client non prouvé', () => {
  const config = fortiConfig();
  const authoritative = analyzePolicies([policy()], config);
  authoritative[0]._srcAddrGrpFound = true;
  authoritative[0]._srcAddrName = 'EVIL';
  authoritative[0].srcAddrName = 'EVIL';
  const decision = applyPolicyUserDecisions(authoritative, authoritative, config, [observedFlow()]);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.match(cli, /set srcaddr "SRC"/);
  assert.doesNotMatch(cli, /set srcaddr "EVIL"/);
});

test('FF2-01 refuse deux noms différents pour le même CIDR à créer', () => {
  const config = parseFortiConfig(`
config system interface
    edit "LAN"
        set ip 10.0.0.1 255.255.255.0
    next
    edit "DMZ"
        set ip 10.0.1.1 255.255.255.0
    next
end
`);
  const authoritative = analyzePolicies([policy(), policy()], config);
  authoritative[0].srcAddrName = 'SRC-A';
  authoritative[1].srcAddrName = 'SRC-B';
  const decision = applyPolicyUserDecisions(authoritative, authoritative, config, [observedFlow()]);

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'ADDRESS_NAME_CONFLICT'));
});

test('FF2-01 refuse les métadonnées imbriquées d’adresse ou groupe forgées', () => {
  const config = fortiConfig();
  config.addressGroups.SAFEGRP = { name: 'SAFEGRP', members: ['SRC', 'DST'] };
  const forged = policy({
    _isMultiDst: true,
    _multiDstSubnets: [
      { subnet: '10.0.1.0/24', useSubnet: true, addrFound: true, addrName: 'EVIL_ADDR', hosts: ['10.0.1.20'] },
    ],
    _useDstGroup: true,
    dstAddrName: 'SAFEGRP',
  });
  const authoritative = analyzePolicies([forged], config);
  const decision = applyPolicyUserDecisions(authoritative, [forged], config, [observedFlow()]);

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'ADDRESS_NAME_CONFLICT'));
});

test('FF2-01 refuse les noms d’hôtes réservés ou en collision', () => {
  const config = parseFortiConfig(`
config system interface
    edit "LAN"
        set ip 10.0.0.1 255.255.255.0
    next
    edit "DMZ"
        set ip 10.0.1.1 255.255.255.0
    next
end
`);
  const forged = policy({
    _use32Src: true,
    srcHosts: ['10.0.0.10', '10.0.0.11'],
    _srcHostNames: { '10.0.0.10': 'all', '10.0.0.11': 'all' },
  });
  const authoritative = analyzePolicies([forged], config);
  const decision = applyPolicyUserDecisions(authoritative, [forged], config, [
    observedFlow(),
    observedFlow({ srcip: '10.0.0.11' }),
  ]);

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue =>
    issue.code === 'ADDRESS_NAME_INVALID' || issue.code === 'ADDRESS_NAME_CONFLICT'
  ));
});

test('FF2-01 refuse un subnet forgé même si un hôte observé est conservé', () => {
  const config = fortiConfig();
  const forged = policy({ srcSubnet: '10.0.0.0/8' });
  const authoritative = analyzePolicies([forged], config);
  const decision = applyPolicyUserDecisions(authoritative, [forged], config, [observedFlow()]);

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'SCOPE_DECISION_INVALID'));
});

test('FF2-01 refuse les représentations de scope contradictoires', () => {
  const config = fortiConfig();
  const forgedPolicies = [
    policy({ srcSubnet: '10.0.0.0/8', srcSubnets: ['10.0.0.0/24'] }),
    policy({ _srcMode: 'hosts', _use32Src: false }),
    policy({ _use32Src: 'true', srcHosts: ['10.0.0.10', '10.0.0.99'] }),
    policy({ _use32Dst: 'true', dstHosts: ['10.0.1.20', '10.0.1.99'] }),
    policy({ _isWan: true }),
    policy({ dstType: 'public', dstTarget: '8.8.8.8', dstHosts: [], _dstUseAll: 'false' }),
    policy({ _isMultiDst: true, _multiDstSubnets: [{ subnet: '10.0.1.0/24', useSubnet: 'false', hosts: ['10.0.1.20'] }] }),
    policy({ _useDstGroup: 'true' }),
    policy({ _multiSrcSubnets: [{ subnet: '10.0.0.0/24', useSubnet: true, addrFound: 'true', hosts: ['10.0.0.10'] }] }),
    policy({ _multiDstSubnets: [{ subnet: '10.0.1.0/24', useSubnet: true, addrName: 42, hosts: ['10.0.1.20'] }] }),
    policy({ _multiSrcSubnets: [{ subnet: '10.0.0.0/24', useSubnet: false, hosts: '10.0.0.10' }] }),
    policy({ _multiDstSubnets: [{ subnet: '10.0.1.0/24', useSubnet: false, hosts: 42 }] }),
  ];
  for (const forged of forgedPolicies) {
    const submitted = structuredClone(forged);
    const shapeDecision = validatePolicyDecisionShapes([submitted]);
    if (!shapeDecision.ok) {
      assert.ok(shapeDecision.issues.some(issue => issue.code === 'SCOPE_DECISION_INVALID'));
      continue;
    }
    const authoritative = analyzePolicies([structuredClone(forged)], config);
    const decision = applyPolicyUserDecisions(authoritative, [submitted], config, [observedFlow()]);
    assert.equal(decision.ok, false, JSON.stringify(forged));
    assert.ok(decision.issues.some(issue => issue.code === 'SCOPE_DECISION_INVALID'));
  }
});

test('FF2-01 conserve une destination WAN spécifique quand all n’est pas demandé', () => {
  const config = fortiConfig();
  const submitted = policy({ dstTarget: '8.8.8.8', dstType: 'public', dstHosts: [] });
  const authoritative = analyzePolicies([submitted], config, 'DMZ');
  const decision = applyPolicyUserDecisions(authoritative, [submitted], config, [
    observedFlow({ dstip: '8.8.8.8', dstSubnet: null, dstType: 'public' }),
  ]);
  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.doesNotMatch(cli, /set dstaddr "all"/);
});

test('FF2-01 refuse un hôte /32 sans preuve ajouté au scope', () => {
  const config = fortiConfig();
  const forged = policy({ _use32Src: true, srcHosts: ['10.0.0.10', '10.0.0.99'] });
  const authoritative = analyzePolicies([forged], config);
  const decision = applyPolicyUserDecisions(authoritative, [forged], config, [observedFlow()]);

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'SCOPE_DECISION_INVALID'));
});

test('FF2-01 refuse une paire d’interfaces existante mais hors du scope observé', () => {
  const config = fortiConfig();
  const authoritative = analyzePolicies([policy()], config);
  const submitted = structuredClone(authoritative);
  submitted[0].srcintf = 'DMZ';
  submitted[0].dstintf = 'LAN';
  const decision = applyPolicyUserDecisions(authoritative, submitted, config, [observedFlow()]);

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'INTERFACE_DECISION_INVALID'));
});

test('FF2-01 refuse une paire croisée jamais observée', () => {
  const config = fortiConfig();
  config.interfaces['ALT-SRC'] = { name: 'ALT-SRC' };
  config.interfaces['ALT-DST'] = { name: 'ALT-DST' };
  const authoritative = analyzePolicies([policy()], config);
  const submitted = structuredClone(authoritative);
  submitted[0].srcintf = 'LAN';
  submitted[0].dstintf = 'ALT-DST';
  const decision = applyPolicyUserDecisions(authoritative, submitted, config, [
    observedFlow(),
    observedFlow({ srcintf: 'ALT-SRC', dstintf: 'ALT-DST' }),
  ]);

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'INTERFACE_DECISION_INVALID'));
});

test('FF2-01 lie le label technique et le tuple au même flux observé', () => {
  const config = fortiConfig();
  const forged = policy({ services: ['TCP/9999'], ports: [9999] });
  const authoritative = analyzePolicies([forged], config);
  const decision = applyPolicyUserDecisions(authoritative, [forged], config, [
    observedFlow({ service: 'APPX', dstport: '9999' }),
  ]);

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'SERVICE_DECISION_UNPROVEN'));
});

test('FF2-01 refuse un service found dont le tuple ne correspond pas au flux', () => {
  const config = fortiConfig();
  const forged = policy({ services: ['HTTPS'], ports: [9999] });
  const authoritative = analyzePolicies([forged], config);
  const decision = applyPolicyUserDecisions(authoritative, [forged], config, [
    observedFlow({ service: 'HTTPS', dstport: '5555' }),
  ]);

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'SERVICE_DECISION_UNPROVEN'));
});

test('FF2-01 conserve un service custom exact TCP ou UDP', () => {
  for (const [proto, configLine, protoNumber] of [
    ['TCP', 'set tcp-portrange 5555', '6'],
    ['UDP', 'set udp-portrange 5555', '17'],
  ]) {
    const config = fortiConfig(`
config firewall service custom
    edit "EXACT"
        ${configLine}
    next
end
`);
    const submitted = policy({ services: ['EXACT'], ports: [5555], protos: [proto] });
    const authoritative = analyzePolicies([submitted], config);
    const decision = applyPolicyUserDecisions(authoritative, [submitted], config, [
      observedFlow({ service: 'EXACT', proto: protoNumber, protoName: proto }),
    ]);
    assert.equal(decision.ok, true, `${proto}: ${JSON.stringify(decision.issues)}`);
    assert.equal(decision.policies[0].analysis.services[0].name, 'EXACT');
  }
});

test('FF2-04 refuse les options globales forgées avant la génération', () => {
  const config = fortiConfig();
  const validation = validateGenerationOptions({
    action: 'accept\nset admin enable',
    log: 'all\nnext',
    nat: 'yes',
    securityProfiles: { ips: 'MISSING_IPS' },
  }, config);

  assert.equal(validation.ok, false);
  assert.deepEqual(new Set(validation.issues.map(issue => issue.code)), new Set([
    'ACTION_DECISION_INVALID',
    'LOG_DECISION_INVALID',
    'NAT_DECISION_INVALID',
    'SECURITY_PROFILE_DECISION_INVALID',
  ]));
  const malformed = validateGenerationOptions('FORGED', config);
  assert.equal(malformed.ok, false);
  assert.ok(malformed.issues.some(issue => issue.code === 'OPTIONS_DECISION_INVALID'));
});

test('FF2-04 refuse les profils par-policy mal formés ou inconnus', () => {
  const config = fortiConfig();
  for (const securityProfiles of ['FORGED', { bogus: 'FORGED' }]) {
    const authoritative = analyzePolicies([policy({ securityProfiles })], config);
    const decision = applyPolicyUserDecisions(authoritative, authoritative, config, [observedFlow()]);
    assert.equal(decision.ok, false);
    assert.ok(decision.issues.some(issue => issue.code === 'SECURITY_PROFILE_DECISION_INVALID'));
  }
});

test('FF2-01 refuse les overrides WAN absents ou non-WAN', () => {
  const config = fortiConfig();
  const validation = validateGenerationOptions({
    preferredWanIntf: 'LAN',
    wanOverrides: ['MISSING'],
  }, config);

  assert.equal(validation.ok, false);
  assert.ok(validation.issues.some(issue => issue.code === 'WAN_DECISION_INVALID'));
});

test('FF2-04 applique les choix globaux quand aucun override par-policy n’existe', () => {
  const config = fortiConfig();
  const authoritative = analyzePolicies([policy()], config);
  const submitted = structuredClone(authoritative);
  submitted[0].action = null;
  submitted[0].log = null;
  const decision = applyPolicyUserDecisions(authoritative, submitted, config, [observedFlow()]);
  const optionDecision = validateGenerationOptions({ action: 'deny', log: 'disable' }, config);

  assert.equal(decision.ok, true, JSON.stringify(decision.issues));
  assert.equal(optionDecision.ok, true, JSON.stringify(optionDecision.issues));
  const cli = generateConfig(decision.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
    actionVerb: optionDecision.opts.action,
    logTraffic: optionDecision.opts.log,
  });
  assert.match(cli, /set action deny/);
  assert.match(cli, /set logtraffic disable/);
});

test('FF2-01 refuse une décision NAT par-policy non booléenne', () => {
  const config = fortiConfig();
  const authoritative = analyzePolicies([policy({ nat: 'enable\nset action accept' })], config);
  const decision = applyPolicyUserDecisions(authoritative, authoritative, config, [observedFlow()]);

  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'NAT_DECISION_INVALID'));
});

test('FF2-01 le preflight lit les interfaces normalisées utilisées par le générateur', () => {
  const config = fortiConfig();
  const analyzed = analyzePolicies([policy()], config);
  analyzed[0].srcintf = 'LAN';
  analyzed[0].dstintf = 'LAN';
  const result = preflightValidation(analyzed, config);

  assert.equal(result.warnings, 1);
  assert.ok(result.issues.some(issue => issue.msg.includes('même interface')));
});

test('FF2-03 refuse un champ ports non-tableau avant toute analyse', () => {
  const forged = policy({ ports: '443' });
  const shape = validatePolicyDecisionShapes([forged]);
  assert.equal(shape.ok, false);
  assert.ok(shape.issues.some(issue => issue.code === 'SCOPE_DECISION_INVALID'));

  const config = fortiConfig();
  assert.doesNotThrow(() => analyzePolicies([forged], config));
  const analyzed = analyzePolicies([forged], config);
  assert.ok(analyzed[0].analysis.services.every(service => service.found === false));
});

test('FF2-02 refuse de reclasser une destination privée en WAN', () => {
  const config = fortiConfig();
  const forged = policy({ dstType: 'public', _isWan: true, _dstUseAll: false });
  const authoritative = analyzePolicies([forged], config);
  const submitted = structuredClone(authoritative);
  submitted[0].dstType = 'public';
  submitted[0]._isWan = true;
  submitted[0]._dstUseAll = false;
  const decision = applyPolicyUserDecisions(authoritative, submitted, config, [observedFlow()]);
  assert.equal(decision.ok, false);
  assert.ok(decision.issues.some(issue => issue.code === 'SCOPE_DECISION_INVALID'));
});

test('FF2-02 refuse une provenance Internet all qui forge les services par destination', () => {
  const config = fortiConfig();
  const selected = policy({
    dstTarget: 'all', dstType: 'public', _isWan: true, _dstUseAll: true,
    services: ['TCP/443', 'TCP/22'], ports: [22, 443], protos: ['TCP'],
  });
  const bothServices = analyzePolicies([selected], config)[0].analysis.services;
  selected._mergedFrom = [
    { srcSubnet: '10.0.0.0/24', dstTarget: '203.0.113.10', analysis: { services: bothServices } },
    { srcSubnet: '10.0.0.0/24', dstTarget: '198.51.100.20', analysis: { services: bothServices } },
  ];
  const authoritative = analyzePolicies([selected], config);
  const submitted = structuredClone(authoritative);
  authoritative[0].srcintf = submitted[0].srcintf = 'LAN';
  authoritative[0].dstintf = submitted[0].dstintf = 'DMZ';
  const flows = [
    observedFlow({ dstip: '203.0.113.10', dstSubnet: null, dstType: 'public', service: 'TCP/443', dstport: '443' }),
    observedFlow({ dstip: '198.51.100.20', dstSubnet: null, dstType: 'public', service: 'TCP/22', dstport: '22' }),
  ];
  const decision = applyPolicyUserDecisions(authoritative, submitted, config, flows);
  assert.equal(decision.ok, false);
  const risk = decision.issues.find(issue => issue.code === 'POLICY_AFFINITY_UNPROVEN');
  assert.equal(risk.level, 'risk');
  assert.equal(risk.overridable, true);
  assert.match(risk.detail, /destination/i);
  assert.match(risk.recommendation, /sépar/i);

  submitted[0]._acceptedRisks = ['POLICY_AFFINITY_UNPROVEN'];
  const accepted = applyPolicyUserDecisions(authoritative, submitted, config, flows);
  assert.equal(accepted.ok, true, JSON.stringify(accepted.issues));
  assert.ok(accepted.issues.some(issue =>
    issue.code === 'POLICY_AFFINITY_UNPROVEN' && issue.accepted === true && issue.level === 'warn'
  ));
  const cli = generateConfig(accepted.policies, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    zones: config.zones,
  });
  assert.match(cli, /config firewall policy/);
  assert.match(cli, /set dstaddr "all"/);
});

test('refuse un override de risque mal formé ou inconnu', () => {
  const config = fortiConfig(`
config firewall service custom
    edit "APPX"
        set tcp-portrange 5555
    next
end
  `);
  const selected = policy({ srcintf: 'LAN', dstintf: 'DMZ' });
  const authoritative = analyzePolicies([selected], config, undefined, [observedFlow()]);

  for (const invalid of ['POLICY_AFFINITY_UNPROVEN', ['UNKNOWN_RISK']]) {
    const submitted = structuredClone(authoritative);
    submitted[0]._acceptedRisks = invalid;
    const decision = applyPolicyUserDecisions(authoritative, submitted, config, [observedFlow()]);
    assert.equal(decision.ok, false);
    assert.ok(decision.issues.some(issue => issue.code === 'RISK_DECISION_INVALID'));
  }

  const forgedAcceptance = structuredClone(authoritative);
  forgedAcceptance[0]._acceptedRisks = ['MERGED_SERVICE_DECISION_INVALID'];
  const forgedDecision = applyPolicyUserDecisions(authoritative, forgedAcceptance, config, [observedFlow()]);
  assert.equal(forgedDecision.ok, false);
  assert.ok(forgedDecision.issues.some(issue => issue.code === 'RISK_DECISION_INVALID'));
});
