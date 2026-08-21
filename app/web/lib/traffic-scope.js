'use strict';

const TRAFFIC_SCOPE_SCHEMA_VERSION = 1;
const TRAFFIC_SCOPE_MODES = new Set([
  'all',
  'lan-lan',
  'lan-internet',
  'internet-lan',
  'lan-dmz',
  'dmz-lan',
  'custom',
]);
const ENDPOINT_CLASSES = new Set(['lan', 'dmz', 'internet', 'unknown']);

function sortedUnique(values) {
  return [...new Set((values || []).map(value => String(value).trim()).filter(Boolean))].sort();
}

function normalizeTrafficScope(input = {}) {
  const schemaVersion = input.schemaVersion == null
    ? TRAFFIC_SCOPE_SCHEMA_VERSION
    : Number(input.schemaVersion);
  if (schemaVersion !== TRAFFIC_SCOPE_SCHEMA_VERSION) {
    throw new Error(`Version TrafficScope non supportée : ${input.schemaVersion}`);
  }
  const mode = String(input.mode || 'all').trim().toLowerCase();
  if (!TRAFFIC_SCOPE_MODES.has(mode)) throw new Error(`TrafficScope invalide : ${mode}`);
  const custom = {
    srcClasses: sortedUnique(input.custom?.srcClasses),
    dstClasses: sortedUnique(input.custom?.dstClasses),
    srcInterfaces: sortedUnique(input.custom?.srcInterfaces),
    dstInterfaces: sortedUnique(input.custom?.dstInterfaces),
    srcZones: sortedUnique(input.custom?.srcZones),
    dstZones: sortedUnique(input.custom?.dstZones),
  };
  for (const className of [...custom.srcClasses, ...custom.dstClasses]) {
    if (!ENDPOINT_CLASSES.has(className)) throw new Error(`TrafficScope classe technique invalide : ${className}`);
  }
  if (mode === 'custom'
    && Object.values(custom).every(values => values.length === 0)) {
    throw new Error('TrafficScope custom sans critère');
  }
  return {
    schemaVersion,
    mode,
    dmz: {
      interfaceNames: sortedUnique(input.dmz?.interfaceNames),
      zoneNames: sortedUnique(input.dmz?.zoneNames),
      useFortiGateRole: input.dmz?.useFortiGateRole !== false,
    },
    custom,
  };
}

function trafficScopeKey(scope) {
  return JSON.stringify(normalizeTrafficScope(scope));
}

function parseTrafficScopeQuery(query = {}) {
  const raw = query.traffic_scope;
  if (raw == null || raw === '') return normalizeTrafficScope({ mode: 'all' });
  if (Array.isArray(raw) || typeof raw === 'object') {
    throw new Error('Paramètre traffic_scope invalide');
  }
  const value = String(raw).trim();
  if (!value.startsWith('{')) return normalizeTrafficScope({ mode: value });
  try {
    return normalizeTrafficScope(JSON.parse(value));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error('JSON traffic_scope invalide');
    throw error;
  }
}

function flowSessions(flow) {
  const count = Number(flow?.count ?? 1);
  return Number.isFinite(count) && count >= 0 ? count : 0;
}

function isPrivateIpv4(ip) {
  const address = ipv4ToInt(ip);
  if (address == null) return false;
  return (address >= ipv4ToInt('10.0.0.0') && address <= ipv4ToInt('10.255.255.255'))
    || (address >= ipv4ToInt('172.16.0.0') && address <= ipv4ToInt('172.31.255.255'))
    || (address >= ipv4ToInt('192.168.0.0') && address <= ipv4ToInt('192.168.255.255'));
}

function endpointFields(flow, side) {
  return side === 'source'
    ? { ip: flow?.srcip, interfaceName: String(flow?.srcintf || '') }
    : { ip: flow?.dstip, interfaceName: String(flow?.dstintf || '') };
}

function ipv4ToInt(ip) {
  const parts = String(ip || '').split('.').map(Number);
  if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return parts.reduce((value, part) => ((value * 256) + part) >>> 0, 0) >>> 0;
}

function cidrContains(cidr, ip) {
  const match = String(cidr || '').match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d|[12]\d|3[0-2])$/);
  const address = ipv4ToInt(ip);
  if (!match || address == null) return null;
  const networkAddress = ipv4ToInt(match[1]);
  if (networkAddress == null) return null;
  const prefix = Number(match[2]);
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  return { contains: ((address & mask) >>> 0) === ((networkAddress & mask) >>> 0), prefix };
}

function interfaceClass(iface, scope) {
  if (!iface) return 'unknown';
  if (scope.dmz.interfaceNames.includes(iface.name)) return 'dmz';
  if (scope.dmz.useFortiGateRole && String(iface.role || '').toLowerCase() === 'dmz') return 'dmz';
  if (iface.isWan) return 'internet';
  return 'lan';
}

function configuredNetworkClass(ip, scope, fortiConfig) {
  const candidates = Object.values(fortiConfig.interfaces || {}).flatMap(iface => {
    const match = cidrContains(iface.cidr, ip);
    return match?.contains ? [{ prefix: match.prefix, className: interfaceClass(iface, scope) }] : [];
  });
  if (candidates.length === 0) return null;
  const longestPrefix = Math.max(...candidates.map(candidate => candidate.prefix));
  const classes = new Set(candidates
    .filter(candidate => candidate.prefix === longestPrefix)
    .map(candidate => candidate.className));
  return classes.size === 1 ? [...classes][0] : 'unknown';
}

function classifyEndpoint(flow, side, scope, fortiConfig = {}) {
  const { ip, interfaceName } = endpointFields(flow, side);
  const interfaces = fortiConfig.interfaces || {};
  const zones = fortiConfig.zones || {};
  const iface = interfaces[interfaceName] || null;
  const zone = zones[interfaceName] || null;
  const zoneMembers = (zone?.members || []).map(name => interfaces[name]).filter(Boolean);
  const selectedDmzZoneContainsInterface = scope.dmz.zoneNames.some(zoneName =>
    (zones[zoneName]?.members || []).includes(interfaceName)
  );

  if (scope.dmz.interfaceNames.includes(interfaceName)
    || scope.dmz.zoneNames.includes(interfaceName)
    || selectedDmzZoneContainsInterface) return 'dmz';
  if (scope.dmz.useFortiGateRole) {
    if (String(iface?.role || '').toLowerCase() === 'dmz') return 'dmz';
    if (zoneMembers.length > 0 && zoneMembers.length === zone.members.length
      && zoneMembers.every(member => String(member.role || '').toLowerCase() === 'dmz')) return 'dmz';
  }
  if (iface?.isWan || zone?.isWan) return 'internet';
  if (iface && !iface.isWan) return 'lan';
  if (zoneMembers.length > 0 && zoneMembers.length === zone.members.length
    && zoneMembers.every(member => !member.isWan)) return 'lan';
  const networkClass = configuredNetworkClass(ip, scope, fortiConfig);
  if (networkClass) return networkClass;
  if (isPrivateIpv4(ip)) return 'lan';
  if (ipv4ToInt(ip) != null) return 'internet';
  return 'unknown';
}

function customSideMatches(flow, side, endpointClass, custom, fortiConfig) {
  const prefix = side === 'source' ? 'src' : 'dst';
  const classes = custom[`${prefix}Classes`];
  const interfaces = custom[`${prefix}Interfaces`];
  const zoneNames = custom[`${prefix}Zones`];
  const { interfaceName } = endpointFields(flow, side);
  const zoneMatch = zoneNames.includes(interfaceName) || zoneNames.some(zoneName =>
    (fortiConfig.zones?.[zoneName]?.members || []).includes(interfaceName)
  );
  return (classes.length === 0 || classes.includes(endpointClass))
    && (interfaces.length === 0 || interfaces.includes(interfaceName))
    && (zoneNames.length === 0 || zoneMatch);
}

function flowMatchesScope(flow, scope, fortiConfig) {
  const sourceClass = classifyEndpoint(flow, 'source', scope, fortiConfig);
  const destinationClass = classifyEndpoint(flow, 'destination', scope, fortiConfig);
  if (scope.mode === 'all') return true;
  if (scope.mode === 'lan-lan') return sourceClass === 'lan' && destinationClass === 'lan';
  if (scope.mode === 'lan-internet') return sourceClass === 'lan' && destinationClass === 'internet';
  if (scope.mode === 'internet-lan') return sourceClass === 'internet' && destinationClass === 'lan';
  if (scope.mode === 'lan-dmz') return sourceClass === 'lan' && destinationClass === 'dmz';
  if (scope.mode === 'dmz-lan') return sourceClass === 'dmz' && destinationClass === 'lan';
  if (scope.mode === 'custom') {
    const criteria = Object.values(scope.custom).reduce((count, values) => count + values.length, 0);
    if (criteria === 0) throw new Error('TrafficScope custom sans critère');
    return customSideMatches(flow, 'source', sourceClass, scope.custom, fortiConfig)
      && customSideMatches(flow, 'destination', destinationClass, scope.custom, fortiConfig);
  }
  throw new Error(`TrafficScope non implémenté : ${scope.mode}`);
}

function filterTrafficScope(flows, scopeInput = {}, fortiConfig = {}) {
  const scope = normalizeTrafficScope(scopeInput);
  const input = Array.isArray(flows) ? flows : [];
  const inputSessions = input.reduce((sum, flow) => sum + flowSessions(flow), 0);
  const retained = scope.mode === 'all'
    ? input
    : input.filter(flow => flowMatchesScope(flow, scope, fortiConfig));
  const retainedSessions = retained.reduce((sum, flow) => sum + flowSessions(flow), 0);
  return {
    scope,
    flows: retained,
    summary: {
      inputFlows: input.length,
      inputSessions,
      retainedFlows: retained.length,
      retainedSessions,
      excludedFlows: input.length - retained.length,
      excludedSessions: inputSessions - retainedSessions,
    },
  };
}

module.exports = {
  TRAFFIC_SCOPE_SCHEMA_VERSION,
  TRAFFIC_SCOPE_MODES,
  classifyEndpoint,
  filterTrafficScope,
  normalizeTrafficScope,
  parseTrafficScopeQuery,
  trafficScopeKey,
};
