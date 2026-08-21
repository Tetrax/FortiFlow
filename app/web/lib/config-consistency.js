'use strict';

const CONFIG_TELEMETRY_MISMATCH = 'CONFIG_TELEMETRY_MISMATCH';
const CONFIG_TELEMETRY_MISMATCH_MESSAGE = 'La télémétrie et la configuration FortiGate ne correspondent pas.';

function text(value) {
  return value == null ? '' : String(value).trim().replace(/^"|"$/g, '');
}

function unique(values) {
  return [...new Set(values.map(text).filter(Boolean))].sort((a, b) => a.localeCompare(b));
}

function firstDefined(object, keys) {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(object || {}, key)) return object[key];
  }
  return undefined;
}

function normalizeConfigIdentity(fortiConfig = {}) {
  const configured = fortiConfig.identity && typeof fortiConfig.identity === 'object'
    ? fortiConfig.identity
    : {};
  const vdomList = unique([
    ...(Array.isArray(configured.vdomList) ? configured.vdomList : []),
    ...(Array.isArray(fortiConfig.vdomList) ? fortiConfig.vdomList : []),
  ]);
  const selectedVdom = firstDefined(configured, ['selectedVdom', 'vdom'])
    ?? firstDefined(fortiConfig, ['selectedVdom', 'vdom'])
    ?? null;
  const ha = {
    ...(fortiConfig.ha && typeof fortiConfig.ha === 'object' ? fortiConfig.ha : {}),
    ...(configured.ha && typeof configured.ha === 'object' ? configured.ha : {}),
  };
  const members = [
    ...(Array.isArray(configured.authorizedDeviceIds) ? configured.authorizedDeviceIds : []),
    ...(Array.isArray(configured.allowedDeviceIds) ? configured.allowedDeviceIds : []),
    ...(Array.isArray(fortiConfig.authorizedDeviceIds) ? fortiConfig.authorizedDeviceIds : []),
    ...(Array.isArray(fortiConfig.allowedDeviceIds) ? fortiConfig.allowedDeviceIds : []),
    ...(Array.isArray(ha.memberDeviceIds) ? ha.memberDeviceIds : []),
    ...(Array.isArray(ha.serials) ? ha.serials : []),
    ...(Array.isArray(ha.members)
      ? ha.members.map(member => member && typeof member === 'object'
        ? (member.devid || member.deviceId || member.serial)
        : member)
      : []),
  ];
  const authorizedDeviceIds = unique([
    ...members,
    configured.devid,
    configured.serial,
    fortiConfig.devid,
    fortiConfig.serial,
  ]);
  const selectedDeviceId = text(
    ha.selectedDeviceId
      || ha.selectedDevid
      || configured.selectedDeviceId
      || configured.selectedDevid
      || fortiConfig.selectedDeviceId,
  ) || null;
  const vdomSelectionRequired = Boolean(
    firstDefined(configured, ['vdomSelectionRequired'])
      ?? firstDefined(fortiConfig, ['vdomSelectionRequired'])
      ?? (vdomList.length > 1 && !selectedVdom),
  );

  return {
    hostname: text(configured.hostname ?? fortiConfig.hostname) || null,
    devid: text(configured.devid ?? configured.deviceId ?? fortiConfig.devid ?? fortiConfig.deviceId) || null,
    serial: text(configured.serial ?? fortiConfig.serial) || null,
    vdom: text(selectedVdom) || null,
    selectedVdom: text(selectedVdom) || null,
    vdomList,
    vdomSelectionRequired,
    ha: {
      enabled: Boolean(ha.enabled || authorizedDeviceIds.length > 1 || selectedDeviceId),
      selectedDeviceId,
      memberDeviceIds: authorizedDeviceIds,
    },
  };
}

function normalizeTelemetryFlows(flows) {
  if (Array.isArray(flows)) return flows;
  if (Array.isArray(flows?.flows)) return flows.flows;
  return [];
}

function collectTelemetryIdentity(flows) {
  const devnames = new Set();
  const devids = new Set();
  const vdoms = new Set();
  const deviceKeys = new Set();
  const maxDistinctValues = 256;
  let flowCount = 0;
  let incompleteFlows = 0;
  let missingDevnameFlows = 0;
  let missingDevidFlows = 0;
  let missingVdomFlows = 0;
  const addBounded = (set, value) => {
    if (set.size < maxDistinctValues) set.add(value);
  };
  for (const flow of normalizeTelemetryFlows(flows)) {
    flowCount++;
    const scope = flow?.scope && typeof flow.scope === 'object' ? flow.scope : {};
    const devname = text(flow?.devname || scope.devname);
    const devid = text(flow?.devid || scope.devid);
    const vdom = text(flow?.vdom || flow?.vd || scope.vdom);
    if (devname) addBounded(devnames, devname);
    else missingDevnameFlows++;
    if (devid) addBounded(devids, devid);
    else missingDevidFlows++;
    if (vdom) addBounded(vdoms, vdom);
    else missingVdomFlows++;
    if (devid || devname) addBounded(deviceKeys, `${devid.toLowerCase()}::${devname.toLowerCase()}`);
    if (!devname || !devid || !vdom) incompleteFlows++;
  }
  return {
    devnames: unique([...devnames]),
    devids: unique([...devids]),
    vdoms: unique([...vdoms]),
    deviceKeys: unique([...deviceKeys]),
    flowCount,
    incompleteFlows,
    missingDevnameFlows,
    missingDevidFlows,
    missingVdomFlows,
  };
}

function selectTelemetryVdom(flows, vdomList) {
  const available = new Set(unique(Array.isArray(vdomList) ? vdomList : []));
  const observed = collectTelemetryIdentity(flows).vdoms;
  if (observed.length !== 1 || !available.has(observed[0])) return null;
  return observed[0];
}

function parseCidr(value) {
  const raw = text(value);
  if (!raw) return null;
  const parts = raw.split(/\s+/);
  let ip = parts[0];
  let prefix = parts.length > 1 ? maskToPrefix(parts[1]) : null;
  if (prefix == null && ip.includes('/')) {
    const [address, prefixText] = ip.split('/');
    ip = address;
    prefix = Number(prefixText);
  }
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => !Number.isInteger(o) || o < 0 || o > 255)) return null;
  const valueInt = (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  return { cidr: `${intToIp(valueInt & mask)}/${prefix}`, prefix, network: (valueInt & mask) >>> 0 };
}

function maskToPrefix(mask) {
  const raw = text(mask);
  if (/^\d+$/.test(raw)) return Number(raw);
  const octets = raw.split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => !Number.isInteger(o) || o < 0 || o > 255)) return null;
  const value = (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0;
  const inverted = (~value) >>> 0;
  if ((inverted & (inverted + 1)) !== 0) return null;
  let count = 0;
  for (let n = value; n; n = (n >>> 1)) count += n & 1;
  return count;
}

function parseIp(value) {
  const octets = text(value).split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => !Number.isInteger(o) || o < 0 || o > 255)) return null;
  return (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0;
}

function intToIp(value) {
  return [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join('.');
}

function configuredNetwork(entry) {
  if (!entry || typeof entry !== 'object') return null;
  return parseCidr(entry.cidr || entry.network || entry.subnet || entry.rawIp || entry.ip);
}

function buildInterfaceCandidates(interfaceName, fortiConfig) {
  const interfaces = fortiConfig.interfaces || {};
  const zones = fortiConfig.zones || {};
  if (interfaces[interfaceName]) return [{ name: interfaceName, entry: interfaces[interfaceName] }];
  const zone = zones[interfaceName];
  if (!zone || !Array.isArray(zone.members)) return [];
  return zone.members.map(name => ({ name, entry: interfaces[name] })).filter(candidate => candidate.entry);
}

function checkInterfaceEndpoint(flow, side, fortiConfig) {
  const ip = text(flow?.[side === 'src' ? 'srcip' : 'dstip']);
  const interfaceName = text(flow?.[side === 'src' ? 'srcintf' : 'dstintf']);
  if (!ip || !interfaceName) return null;
  const ipInt = parseIp(ip);
  const candidates = buildInterfaceCandidates(interfaceName, fortiConfig);
  const networks = candidates.map(candidate => ({
    ...candidate,
    network: configuredNetwork(candidate.entry),
  }));
  const knownNetworks = networks.filter(candidate => candidate.network);
  if (ipInt == null || candidates.length === 0 || knownNetworks.length === 0) {
    return {
      side,
      interface: interfaceName,
      ip,
      configuredCidrs: knownNetworks.map(candidate => candidate.network.cidr),
      ok: null,
      reason: 'network-interface-unknown',
    };
  }
  const matches = knownNetworks.filter(candidate => {
    const mask = candidate.network.prefix === 0 ? 0 : (0xFFFFFFFF << (32 - candidate.network.prefix)) >>> 0;
    return ((ipInt & mask) >>> 0) === candidate.network.network;
  });
  return {
    side,
    interface: interfaceName,
    ip,
    configuredCidrs: knownNetworks.map(candidate => candidate.network.cidr),
    ok: matches.length > 0,
    reason: matches.length > 0 ? 'contained' : 'outside-interface-network',
  };
}

function validateConfigTelemetryConsistency(flows, fortiConfig = {}) {
  const telemetryIdentity = collectTelemetryIdentity(flows);
  const configIdentity = normalizeConfigIdentity(fortiConfig);
  const mismatchDetails = [];
  const warnings = [];
  let positiveProof = false;
  const warn = (code, msg) => {
    if (!warnings.some(item => item.code === code && item.msg === msg)) warnings.push({ code, msg });
  };
  const mismatch = (detail) => {
    if (detail && !mismatchDetails.includes(detail)) mismatchDetails.push(detail);
  };

  if (telemetryIdentity.devnames.length > 1) {
    mismatch(`plusieurs hostnames télémétrie: ${telemetryIdentity.devnames.join(', ')}`);
  }
  if (configIdentity.hostname && telemetryIdentity.devnames.length > 0
      && !telemetryIdentity.devnames.some(name => name.toLowerCase() === configIdentity.hostname.toLowerCase())) {
    mismatch(`hostname config=${configIdentity.hostname}; télémétrie=${telemetryIdentity.devnames.join(', ')}`);
  } else if (configIdentity.hostname && telemetryIdentity.devnames.length > 0) {
    positiveProof = true;
  } else if (!configIdentity.hostname || telemetryIdentity.devnames.length === 0) {
    warn('TELEMETRY_IDENTITY_UNKNOWN', 'Hostname ou devname absent : la cohérence est établie par les invariants disponibles.');
  }

  const configuredDeviceIds = new Set([
    configIdentity.devid,
    configIdentity.serial,
    ...configIdentity.ha.memberDeviceIds,
  ].map(value => text(value)).filter(Boolean).map(value => value.toLowerCase()));
  const telemetryDeviceIds = telemetryIdentity.devids.map(value => value.toLowerCase());
  const selectedDeviceId = text(configIdentity.ha.selectedDeviceId).toLowerCase();
  const explicitHaSelection = configIdentity.ha.enabled
    && Boolean(selectedDeviceId)
    && configuredDeviceIds.has(selectedDeviceId);

  if (telemetryDeviceIds.length > 1) {
    if (!explicitHaSelection || telemetryDeviceIds.some(id => !configuredDeviceIds.has(id))) {
      mismatch(`serials télémétrie ambigus: ${telemetryIdentity.devids.join(', ')}`);
    } else if (telemetryDeviceIds.includes(selectedDeviceId)) {
      positiveProof = true;
    }
  } else if (telemetryDeviceIds.length === 1) {
    const observedDeviceId = telemetryDeviceIds[0];
    const haSelectionRequired = configIdentity.ha.enabled
      && configIdentity.ha.memberDeviceIds.length > 1;
    if (haSelectionRequired && !selectedDeviceId) {
      mismatch(`sélection HA absente parmi: ${configIdentity.ha.memberDeviceIds.join(', ')}`);
    } else if (selectedDeviceId && (!explicitHaSelection || observedDeviceId !== selectedDeviceId)) {
      mismatch(`serial sélectionné=${selectedDeviceId || '?'}; télémétrie=${telemetryIdentity.devids.join(', ')}`);
    } else if (configuredDeviceIds.size > 0 && !configuredDeviceIds.has(observedDeviceId)) {
      mismatch(`serial config=${[...configuredDeviceIds].join(', ')}; télémétrie=${telemetryIdentity.devids.join(', ')}`);
    } else if (configuredDeviceIds.has(observedDeviceId)) {
      positiveProof = true;
    }
  } else if (telemetryDeviceIds.length === 0 || configuredDeviceIds.size === 0) {
    warn('DEVICE_SERIAL_UNKNOWN', 'Serial/devid absent d’une des sources : aucune identité inventée.');
  }

  if (configIdentity.vdomSelectionRequired) {
    mismatch(`sélection VDOM absente parmi: ${configIdentity.vdomList.join(', ')}`);
  }
  if (telemetryIdentity.vdoms.length > 1) {
    mismatch(`plusieurs VDOM télémétrie: ${telemetryIdentity.vdoms.join(', ')}`);
  } else if (telemetryIdentity.vdoms.length === 1 && configIdentity.selectedVdom
      && telemetryIdentity.vdoms[0].toLowerCase() !== configIdentity.selectedVdom.toLowerCase()) {
    mismatch(`VDOM config=${configIdentity.selectedVdom}; télémétrie=${telemetryIdentity.vdoms[0]}`);
  } else if (telemetryIdentity.vdoms.length === 1 && configIdentity.selectedVdom) {
    positiveProof = true;
  } else if (telemetryIdentity.vdoms.length === 0 || !configIdentity.selectedVdom) {
    warn('VDOM_IDENTITY_UNKNOWN', 'VDOM absent d’une des sources : aucune portée VDOM n’est inventée.');
  }

  if (telemetryIdentity.incompleteFlows > 0) {
    warn(
      'TELEMETRY_IDENTITY_INCOMPLETE',
      `${telemetryIdentity.incompleteFlows} flux ne portent pas une identité complète `
        + `(devname=${telemetryIdentity.missingDevnameFlows}, devid=${telemetryIdentity.missingDevidFlows}, `
        + `vdom=${telemetryIdentity.missingVdomFlows}).`,
    );
  }

  const interfaceSummary = new Map();
  for (const flow of normalizeTelemetryFlows(flows)) {
    for (const side of ['src', 'dst']) {
      const check = checkInterfaceEndpoint(flow, side, fortiConfig);
      if (!check) continue;
      const key = [check.side, check.interface, String(check.ok), check.reason, ...check.configuredCidrs].join('|');
      if (!interfaceSummary.has(key)) {
        interfaceSummary.set(key, { ...check, flowCount: 0, sampleIps: [] });
      }
      const summary = interfaceSummary.get(key);
      summary.flowCount++;
      if (summary.sampleIps.length < 3 && !summary.sampleIps.includes(check.ip)) summary.sampleIps.push(check.ip);
      if (check.ok === false) mismatch(`${side} ${check.interface}: IP observées hors ${check.configuredCidrs.join(', ')}`);
      if (check.ok === null) warn('INTERFACE_NETWORK_UNKNOWN', `Réseau de l’interface ${check.interface} non prouvé pour ${check.ip}.`);
    }
  }
  const interfaceChecks = [...interfaceSummary.values()];
  if (interfaceChecks.some(check => check.ok === true)) positiveProof = true;
  if (!positiveProof) {
    mismatch('aucune preuve positive d’identité ou de correspondance interface-réseau');
  }

  const errors = mismatchDetails.length > 0
    ? [{
      code: CONFIG_TELEMETRY_MISMATCH,
      message: CONFIG_TELEMETRY_MISMATCH_MESSAGE,
      msg: CONFIG_TELEMETRY_MISMATCH_MESSAGE,
      details: mismatchDetails,
    }]
    : [];
  return {
    ok: errors.length === 0,
    errors,
    warnings,
    message: errors.length > 0 ? CONFIG_TELEMETRY_MISMATCH_MESSAGE : null,
    telemetryIdentity,
    configIdentity,
    interfaceChecks,
  };
}

module.exports = {
  CONFIG_TELEMETRY_MISMATCH,
  CONFIG_TELEMETRY_MISMATCH_MESSAGE,
  validateConfigTelemetryConsistency,
  normalizeConfigIdentity,
  collectTelemetryIdentity,
  selectTelemetryVdom,
};
