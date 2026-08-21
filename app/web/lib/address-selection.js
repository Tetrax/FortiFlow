'use strict';

const IPV4_ERROR = 'Adresse IPv4 invalide';

function asText(value) {
  return value == null ? '' : String(value).trim().replace(/^"|"$/g, '');
}

function ipToInt(value) {
  const raw = asText(value);
  const octets = raw.split('.');
  if (octets.length !== 4 || octets.some(o => !/^\d{1,3}$/.test(o) || Number(o) > 255)) {
    throw new Error(`${IPV4_ERROR} : ${value}`);
  }
  return (((Number(octets[0]) * 256 + Number(octets[1])) * 256 + Number(octets[2])) * 256 + Number(octets[3])) >>> 0;
}

function intToIp(value) {
  return [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join('.');
}

function maskToPrefix(mask) {
  const raw = asText(mask);
  if (/^\d{1,2}$/.test(raw)) {
    const prefix = Number(raw);
    return prefix >= 0 && prefix <= 32 ? prefix : null;
  }
  const octets = raw.split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => !Number.isInteger(o) || o < 0 || o > 255)) return null;
  const value = (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0;
  const inverted = (~value) >>> 0;
  if ((inverted & (inverted + 1)) !== 0) return null;
  let count = 0;
  for (let n = value; n; n >>>= 1) count += n & 1;
  return count;
}

function normalizeCidr(value) {
  const raw = asText(value);
  if (!raw) return null;
  const parts = raw.split(/\s+/);
  let ip = parts[0];
  let prefix = null;
  if (parts.length === 2) {
    prefix = maskToPrefix(parts[1]);
  } else if (ip.includes('/')) {
    const slash = ip.lastIndexOf('/');
    prefix = maskToPrefix(ip.slice(slash + 1));
    ip = ip.slice(0, slash);
  }
  if (prefix == null) return null;
  const ipInt = ipToInt(ip);
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  const network = (ipInt & mask) >>> 0;
  return { cidr: `${intToIp(network)}/${prefix}`, prefix, network };
}

function normalizeObservedIps(observedIps) {
  const values = observedIps instanceof Set
    ? [...observedIps]
    : Array.isArray(observedIps)
      ? observedIps
      : observedIps == null ? [] : [observedIps];
  const normalized = new Map();
  for (const value of values) {
    const candidate = value && typeof value === 'object' ? (value.ip || value.address) : value;
    const raw = asText(candidate);
    if (raw.includes('/')) {
      const cidr = normalizeCidr(raw);
      if (!cidr || cidr.prefix !== 32) throw new Error(`${IPV4_ERROR} hôte attendu : ${raw}`);
      normalized.set(intToIp(cidr.network), cidr.network);
    } else {
      const integer = ipToInt(raw);
      normalized.set(intToIp(integer), integer);
    }
  }
  if (normalized.size === 0) throw new Error('Au moins une IP observée est requise');
  return [...normalized.entries()]
    .map(([ip, integer]) => ({ ip, integer }))
    .sort((a, b) => a.integer - b.integer);
}

function addressEntries(fortiConfig = {}) {
  const addresses = fortiConfig.addresses || {};
  const pairs = Array.isArray(addresses)
    ? addresses.map((value, index) => [value?.name || String(index), value])
    : Object.entries(addresses);
  const entries = [];
  for (const [key, raw] of pairs) {
    if (!raw || typeof raw !== 'object') continue;
    const type = asText(raw.type).toLowerCase();
    // iprange/FQDN objects are deliberately not subnet evidence.
    if (type === 'iprange' || raw.fqdn) continue;
    const parsed = normalizeCidr(raw.cidr || raw.subnet);
    if (!parsed) continue;
    const name = asText(raw.name || key);
    if (!name) continue;
    entries.push({ key: asText(key), name, ...parsed });
  }
  return entries.sort((a, b) => b.prefix - a.prefix || a.name.localeCompare(b.name) || a.cidr.localeCompare(b.cidr));
}

function contains(network, prefix, ipInteger) {
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  return ((ipInteger & mask) >>> 0) === network;
}

function addressSpaceSize(prefix) {
  // IPv4 space is at most 2^32, which is exactly representable in JS Number.
  return 2 ** (32 - prefix);
}

function minimalCover(observed) {
  let low = observed[0].integer;
  let high = observed[0].integer;
  for (const item of observed) {
    if (item.integer < low) low = item.integer;
    if (item.integer > high) high = item.integer;
  }
  let difference = (low ^ high) >>> 0;
  let prefix = 32;
  while (difference !== 0) {
    prefix--;
    difference >>>= 1;
  }
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  const network = (low & mask) >>> 0;
  return {
    cidr: `${intToIp(network)}/${prefix}`,
    unobservedIpCount: addressSpaceSize(prefix) - observed.length,
  };
}

function buildAddressChoices(observedIps, fortiConfig = {}) {
  const observed = normalizeObservedIps(observedIps);
  const existing = addressEntries(fortiConfig);
  const containing = existing
    .filter(address => observed.every(item => contains(address.network, address.prefix, item.integer)))
    .map(address => ({
      name: address.name,
      cidr: address.cidr,
      unobservedIpCount: addressSpaceSize(address.prefix) - observed.length,
    }));

  const byHost = new Map();
  for (const address of existing.filter(item => item.prefix === 32)) {
    if (!byHost.has(address.network)) byHost.set(address.network, []);
    byHost.get(address.network).push(address.name);
  }
  const existingHosts = observed
    .filter(item => byHost.has(item.integer))
    .map(item => ({ ip: item.ip, objectName: [...byHost.get(item.integer)].sort((a, b) => a.localeCompare(b))[0] }));
  const missingHosts = observed
    .filter(item => !byHost.has(item.integer))
    .map(item => item.ip);

  return {
    observedHostCount: observed.length,
    existingObjects: containing,
    calculatedSubnet: containing.length === 0 ? minimalCover(observed) : null,
    existingHosts,
    missingHosts,
  };
}

function selectionMode(selection) {
  const raw = selection?.mode ?? selection?.type ?? '';
  const mode = asText(raw).toLowerCase().replace(/[_ ]/g, '-');
  if (['existing', 'object', 'existing-object', 'fortigate-object'].includes(mode)) return 'existing-object';
  if (['subnet', 'create-subnet'].includes(mode)) return 'subnet';
  if (['hosts', 'host', 'create-hosts', 'host-32'].includes(mode)) return 'hosts';
  return mode;
}

function validateAddressSelection(observedIps, selection, fortiConfig = {}) {
  const errors = [];
  let observed;
  try {
    observed = normalizeObservedIps(observedIps);
  } catch (error) {
    return { ok: false, errors: [error.message] };
  }
  if (!selection || typeof selection !== 'object' || Array.isArray(selection)) {
    return { ok: false, errors: ['Choix d’adresse manquant'] };
  }
  if (selection.confirmed !== true) errors.push('La confirmation du choix d’adresse est requise');

  const inventory = addressEntries(fortiConfig);
  const mode = selectionMode(selection);
  const observedSet = new Set(observed.map(item => item.ip));
  const containsAll = parsed => parsed && observed.every(item => contains(parsed.network, parsed.prefix, item.integer));

  if (mode === 'existing-object') {
    const wantedName = asText(selection.objectName || selection.name);
    const matches = inventory.filter(address => address.name === wantedName || address.key === wantedName);
    if (matches.length === 0) {
      errors.push(`Objet FortiGate introuvable : ${wantedName || '(sans nom)'}`);
    } else if (matches.length > 1) {
      errors.push(`Objet FortiGate ambigu : ${wantedName}`);
    } else {
      const selected = matches[0];
      if (!containsAll(selected)) errors.push(`L’objet FortiGate ${selected.name} ne contient pas toutes les IP observées`);
      if (selection.cidr && normalizeCidr(selection.cidr)?.cidr !== selected.cidr) {
        errors.push(`Le CIDR sélectionné ne correspond plus à l’objet FortiGate ${selected.name}`);
      }
    }
  } else if (mode === 'subnet') {
    const parsed = normalizeCidr(selection.cidr);
    if (!parsed) {
      errors.push(`CIDR de subnet invalide : ${selection.cidr || '(vide)'}`);
    } else if (!containsAll(parsed)) {
      errors.push('Le subnet sélectionné ne contient pas toutes les IP observées');
    }
  } else if (mode === 'hosts') {
    const values = selection.ips ?? selection.hosts ?? selection.observedIps;
    let selectedHosts;
    try {
      selectedHosts = normalizeObservedIps(values);
    } catch (error) {
      errors.push(error.message);
      selectedHosts = [];
    }
    const selectedSet = new Set(selectedHosts.map(item => item.ip));
    if (selectedSet.size !== observedSet.size || [...observedSet].some(ip => !selectedSet.has(ip))) {
      errors.push('Le choix /32 doit contenir exactement toutes les IP observées');
    }
  } else {
    errors.push(`Mode de choix d’adresse invalide : ${selection.mode || selection.type || '(vide)'}`);
  }

  return {
    ok: errors.length === 0,
    errors,
    observedHostCount: observed.length,
    mode,
  };
}

module.exports = {
  buildAddressChoices,
  validateAddressSelection,
};
