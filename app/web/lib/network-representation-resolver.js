'use strict';

const crypto = require('node:crypto');

const NETWORK_REPRESENTATION_SCHEMA_VERSION = 1;
const NETWORK_RESOLVER_VERSION = '1.0.0';
const CANDIDATE_KINDS = new Set([
  'existing-object',
  'existing-group',
  'new-exact-group',
  'cidr-suggestion',
  'host-list',
]);
const ELIGIBILITY_STATES = new Set(['safe-exact', 'explicit-generalization', 'blocked']);

function sortedUnique(values) {
  return [...new Set((values || []).map(value => String(value).trim()).filter(Boolean))].sort();
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function stableId(prefix, value) {
  return `${prefix}-${crypto.createHash('sha256').update(canonicalJson(value)).digest('hex').slice(0, 16)}`;
}

function ipv4ToInt(ip) {
  const parts = String(ip || '').split('.').map(Number);
  if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return parts.reduce((value, part) => ((value * 256) + part) >>> 0, 0) >>> 0;
}

function intToIpv4(value) {
  const number = value >>> 0;
  return [number >>> 24, (number >>> 16) & 255, (number >>> 8) & 255, number & 255].join('.');
}

function parseCidr(cidr) {
  const match = String(cidr || '').match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d|[12]\d|3[0-2])$/);
  if (!match) return null;
  const address = ipv4ToInt(match[1]);
  if (address == null) return null;
  const prefix = Number(match[2]);
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  const start = (address & mask) >>> 0;
  const size = 2 ** (32 - prefix);
  return { cidr: `${intToIpv4(start)}/${prefix}`, prefix, start, end: start + size - 1, size };
}

function addressInterval(address) {
  const startInt = address?.startInt;
  const endInt = address?.endInt;
  if (Number.isInteger(startInt) && Number.isInteger(endInt)
    && startInt >= 0 && endInt >= startInt && endInt <= 0xFFFFFFFF) {
    return {
      type: 'ip-range',
      start: startInt,
      end: endInt,
      size: endInt - startInt + 1,
      display: `${intToIpv4(startInt)}-${intToIpv4(endInt)}`,
    };
  }
  const parsed = parseCidr(address?.cidr);
  if (!parsed) return null;
  return { type: 'subnet', ...parsed, display: parsed.cidr };
}

function normalizePolicy(policy, side) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) throw new Error('Policy V2 invalide');
  if (!['source', 'destination'].includes(side)) throw new Error(`Côté resolver invalide : ${side}`);
  const sources = sortedUnique(policy.sources);
  const destinations = sortedUnique(policy.destinations);
  const serviceKeys = sortedUnique(policy.serviceKeys);
  if (sources.length === 0 || destinations.length === 0 || serviceKeys.length === 0) {
    throw new Error('Policy V2 incomplète pour la résolution réseau');
  }
  const observedIps = side === 'source' ? sources : destinations;
  if (observedIps.some(ip => ipv4ToInt(ip) == null)) throw new Error('Policy V2 contient une IPv4 invalide');
  const identity = {
    partitionKey: String(policy.partitionKey || ''),
    deviceId: String(policy.scope?.devid || policy.scope?.devname || ''),
    vdom: String(policy.scope?.vdom || ''),
    sourceInterface: String(policy.sourceInterface || policy.srcintf || ''),
    destinationInterface: String(policy.destinationInterface || policy.dstintf || ''),
    sources,
    destinations,
    serviceKeys,
  };
  return {
    id: String(policy.id || ''),
    ...identity,
    observedIps,
    atomIds: sortedUnique(policy.trace?.atomIds),
    fingerprint: stableId('POL', identity),
  };
}

function previewMetrics(policy, side, representedIpCount) {
  const observedRequiredTuples = policy.sources.length * policy.destinations.length * policy.serviceKeys.length;
  const otherSideCount = side === 'source' ? policy.destinations.length : policy.sources.length;
  const allowedTuples = representedIpCount * otherSideCount * policy.serviceKeys.length;
  const coveredRequiredTuples = Math.min(observedRequiredTuples, allowedTuples);
  const missingRequiredTuples = observedRequiredTuples - coveredRequiredTuples;
  const unexpectedAllowedTuples = Math.max(0, allowedTuples - observedRequiredTuples);
  return {
    observedRequiredTuples,
    coveredRequiredTuples,
    missingRequiredTuples,
    allowedTuples,
    unexpectedAllowedTuples,
    coverageRatio: observedRequiredTuples ? coveredRequiredTuples / observedRequiredTuples : 1,
    expansionRatio: observedRequiredTuples ? unexpectedAllowedTuples / observedRequiredTuples : 0,
  };
}

function baseCandidate(policy, side, kind, rank, representedIps, representedCidrs, details = {}) {
  const technicalIdentity = {
    policyFingerprint: policy.fingerprint,
    side,
    kind,
    representedIps,
    representedCidrs,
  };
  const metrics = previewMetrics(policy, side, representedIps.length);
  return {
    schemaVersion: NETWORK_REPRESENTATION_SCHEMA_VERSION,
    resolverVersion: NETWORK_RESOLVER_VERSION,
    candidateId: stableId('NC', technicalIdentity),
    policyId: policy.id,
    policyFingerprint: policy.fingerprint,
    side,
    kind,
    rank,
    eligibility: details.eligibility || 'safe-exact',
    representation: details.representation || {},
    origin: details.origin || { type: 'resolver' },
    objects: details.objects || { existing: [], create: [] },
    representedIps,
    representedCidrs,
    observedIpCount: policy.observedIps.length,
    representedIpCount: representedIps.length,
    additionalIpCount: Math.max(0, representedIps.length - policy.observedIps.length),
    missingIpCount: Math.max(0, policy.observedIps.length - representedIps.length),
    affectedDestinationCount: side === 'source' ? policy.destinations.length : 0,
    affectedSourceCount: side === 'destination' ? policy.sources.length : 0,
    affectedServiceKeys: policy.serviceKeys,
    previewMetrics: metrics,
    autoApplicable: details.autoApplicable === true,
    reasonCodes: details.reasonCodes || [],
    explanation: details.explanation || '',
    ...(details.payload || {}),
  };
}

function hostListCandidate(policy, side) {
  return baseCandidate(
    policy,
    side,
    'host-list',
    5,
    policy.observedIps,
    policy.observedIps.map(ip => `${ip}/32`),
    {
      autoApplicable: true,
      representation: { type: 'host-list', hosts: policy.observedIps },
      reasonCodes: ['EXACT_OBSERVED_HOSTS'],
      explanation: 'Conserve exactement les adresses observées, sans permission supplémentaire.',
    },
  );
}

function exactExistingObjectCandidate(policy, side, fortiConfig) {
  const observedInts = policy.observedIps.map(ipv4ToInt);
  const matches = [];
  for (const [key, address] of Object.entries(fortiConfig?.addresses || {})) {
    const interval = addressInterval(address);
    if (!interval || interval.size !== policy.observedIps.length) continue;
    if (!observedInts.every(value => value >= interval.start && value <= interval.end)) continue;
    matches.push({
      name: String(address.name || key),
      objectType: interval.type,
      cidr: interval.cidr || null,
      rangeStart: interval.type === 'ip-range' ? intToIpv4(interval.start) : null,
      rangeEnd: interval.type === 'ip-range' ? intToIpv4(interval.end) : null,
      display: interval.display,
    });
  }
  if (matches.length === 0) return null;
  matches.sort((a, b) => a.name.localeCompare(b.name));
  const representedCidrs = sortedUnique(matches.map(match => match.display));
  const ambiguous = matches.length > 1;
  const objectNames = matches.map(match => match.name);
  const membershipHash = stableId('MEM', policy.observedIps);
  return baseCandidate(policy, side, 'existing-object', 1, policy.observedIps, representedCidrs, {
    autoApplicable: !ambiguous,
    representation: { type: 'existing-object', objectNames, cidrs: representedCidrs },
    origin: {
      type: 'fortigate-config',
      deviceId: policy.deviceId,
      vdom: policy.vdom,
    },
    objects: { existing: objectNames, create: [] },
    reasonCodes: ambiguous ? ['EXACT_OBJECT_MEMBERSHIP', 'AMBIGUOUS_EXACT_OBJECTS'] : ['EXACT_OBJECT_MEMBERSHIP'],
    explanation: ambiguous
      ? 'Plusieurs objets FortiGate représentent exactement les mêmes adresses ; un choix explicite sera requis.'
      : 'L’objet FortiGate représente exactement toutes les adresses observées.',
    payload: {
      existingObjectMatch: {
        deviceId: policy.deviceId,
        vdom: policy.vdom,
        objectNames,
        objectType: matches.every(match => match.objectType === matches[0].objectType)
          ? matches[0].objectType : 'mixed',
        cidr: matches.length === 1 ? matches[0].cidr : null,
        rangeStart: matches.length === 1 ? matches[0].rangeStart : null,
        rangeEnd: matches.length === 1 ? matches[0].rangeEnd : null,
        normalizedMembershipHash: membershipHash,
        matchKind: 'exact-membership',
        observedIpCount: policy.observedIps.length,
        representedIpCount: policy.observedIps.length,
        additionalIpCount: 0,
        exactMembership: true,
        safeExact: true,
        ambiguous,
      },
    },
  });
}

function mergeIntervals(intervals) {
  const sorted = [...intervals].sort((a, b) => a.start - b.start || a.end - b.end);
  const merged = [];
  for (const interval of sorted) {
    const previous = merged[merged.length - 1];
    if (!previous || interval.start > previous.end + 1) {
      merged.push({ start: interval.start, end: interval.end });
    } else if (interval.end > previous.end) {
      previous.end = interval.end;
    }
  }
  return merged;
}

function intervalSetSize(intervals) {
  return intervals.reduce((sum, interval) => sum + interval.end - interval.start + 1, 0);
}

function expandAddressGroup(groupName, fortiConfig, path = []) {
  if (path.includes(groupName)) {
    return {
      intervals: [], objectNames: [], memberCidrs: [], cycles: [[...path, groupName]],
      danglingMembers: [], maxDepth: path.length,
    };
  }
  const group = fortiConfig.addressGroups?.[groupName];
  if (!group) {
    return {
      intervals: [], objectNames: [], memberCidrs: [], cycles: [],
      danglingMembers: [groupName], maxDepth: path.length,
    };
  }
  const aggregate = {
    intervals: [], objectNames: [], memberCidrs: [], cycles: [],
    danglingMembers: [], maxDepth: path.length + 1,
  };
  for (const memberName of sortedUnique(group.members)) {
    const address = fortiConfig.addresses?.[memberName];
    if (address) {
      const interval = addressInterval(address);
      if (!interval) {
        aggregate.danglingMembers.push(memberName);
        continue;
      }
      aggregate.intervals.push({ start: interval.start, end: interval.end });
      aggregate.objectNames.push(String(address.name || memberName));
      aggregate.memberCidrs.push(interval.display);
      continue;
    }
    if (fortiConfig.addressGroups?.[memberName]) {
      const nested = expandAddressGroup(memberName, fortiConfig, [...path, groupName]);
      aggregate.intervals.push(...nested.intervals);
      aggregate.objectNames.push(...nested.objectNames);
      aggregate.memberCidrs.push(...nested.memberCidrs);
      aggregate.cycles.push(...nested.cycles);
      aggregate.danglingMembers.push(...nested.danglingMembers);
      aggregate.maxDepth = Math.max(aggregate.maxDepth, nested.maxDepth);
      continue;
    }
    aggregate.danglingMembers.push(memberName);
  }
  aggregate.intervals = mergeIntervals(aggregate.intervals);
  aggregate.objectNames = sortedUnique(aggregate.objectNames);
  aggregate.memberCidrs = sortedUnique(aggregate.memberCidrs);
  aggregate.danglingMembers = sortedUnique(aggregate.danglingMembers);
  return aggregate;
}

function exactExistingGroupCandidate(policy, side, fortiConfig) {
  const observedInts = policy.observedIps.map(ipv4ToInt);
  const exactGroups = [];
  const blockers = [];
  for (const groupName of Object.keys(fortiConfig?.addressGroups || {}).sort()) {
    const expansion = expandAddressGroup(groupName, fortiConfig);
    if (expansion.cycles.length > 0) {
      blockers.push({
        code: 'ADDRESS_GROUP_CYCLE', groupName,
        cyclePaths: [...expansion.cycles].sort((a, b) => a.join('|').localeCompare(b.join('|'))),
        message: 'Le groupe contient un cycle et ne peut pas être résolu de façon sûre.',
      });
      continue;
    }
    if (expansion.danglingMembers.length > 0) {
      blockers.push({
        code: 'ADDRESS_GROUP_DANGLING_MEMBER', groupName,
        members: expansion.danglingMembers,
        message: 'Le groupe référence un membre absent ou non représentable.',
      });
      continue;
    }
    const representedIpCount = intervalSetSize(expansion.intervals);
    const coveredObservedCount = observedInts.filter(value =>
      expansion.intervals.some(interval => value >= interval.start && value <= interval.end)
    ).length;
    const containsAll = coveredObservedCount === observedInts.length;
    if (representedIpCount !== policy.observedIps.length || !containsAll) {
      if (containsAll) {
        blockers.push({
          code: 'ADDRESS_GROUP_MEMBERSHIP_NOT_EXACT',
          groupName,
          additionalIpCount: Math.max(0, representedIpCount - coveredObservedCount),
          missingIpCount: policy.observedIps.length - coveredObservedCount,
          message: 'La membership du groupe diffère des adresses observées.',
        });
      }
      continue;
    }
    exactGroups.push({ groupName, expansion });
  }
  if (exactGroups.length === 0) return { candidate: null, blockers };
  const ambiguous = exactGroups.length > 1;
  const groupNames = exactGroups.map(match => match.groupName);
  const memberObjectNames = sortedUnique(exactGroups.flatMap(match => match.expansion.objectNames));
  const memberCidrs = sortedUnique(exactGroups.flatMap(match => match.expansion.memberCidrs));
  const membershipHash = stableId('MEM', policy.observedIps);
  const candidate = baseCandidate(policy, side, 'existing-group', 2, policy.observedIps, memberCidrs, {
    autoApplicable: !ambiguous,
    representation: { type: 'existing-group', groupNames, memberCidrs },
    origin: { type: 'fortigate-config', deviceId: policy.deviceId, vdom: policy.vdom },
    objects: { existing: [...groupNames, ...memberObjectNames].sort(), create: [] },
    reasonCodes: ambiguous ? ['EXACT_GROUP_MEMBERSHIP', 'AMBIGUOUS_EXACT_GROUPS'] : ['EXACT_GROUP_MEMBERSHIP'],
    explanation: ambiguous
      ? 'Plusieurs groupes FortiGate représentent exactement les mêmes adresses ; un choix explicite sera requis.'
      : 'Le groupe FortiGate représente exactement toutes les adresses observées après expansion récursive.',
    payload: {
      exactGroupCandidate: {
        mode: 'reuse-existing',
        groupName: ambiguous ? null : groupNames[0],
        groupNames,
        memberObjectNames,
        memberCidrs,
        expandedCidrs: memberCidrs,
        expandedMembershipHash: membershipHash,
        observedMembershipHash: membershipHash,
        missingHostObjects: [],
        objectsToCreate: [],
        nestedGroupDepth: Math.max(...exactGroups.map(match => match.expansion.maxDepth)),
        cyclesDetected: false,
        danglingMembers: [],
        exactMembership: true,
        safeExact: true,
        ambiguous,
      },
    },
  });
  return { candidate, blockers };
}

function newExactGroupCandidate(policy, side, fortiConfig) {
  if (policy.observedIps.length < 2) return null;
  const reusedHostObjects = [];
  const missingHostObjects = [];
  const memberReferences = [];
  for (const ip of policy.observedIps) {
    const value = ipv4ToInt(ip);
    const objectNames = Object.entries(fortiConfig?.addresses || {})
      .flatMap(([key, address]) => {
        const interval = addressInterval(address);
        return interval && interval.size === 1 && interval.start === value
          ? [String(address.name || key)] : [];
      })
      .sort();
    const cidr = `${ip}/32`;
    if (objectNames.length > 0) {
      reusedHostObjects.push({ ip, objectNames });
      memberReferences.push({ type: 'existing-object', objectName: objectNames[0], cidr });
    } else {
      missingHostObjects.push(cidr);
      memberReferences.push({ type: 'new-object', cidr });
    }
  }
  const ambiguous = reusedHostObjects.some(item => item.objectNames.length > 1);
  const objectsToCreate = [
    ...missingHostObjects.map(cidr => ({ objectType: 'address', cidr })),
    { objectType: 'address-group', memberReferences },
  ];
  const membershipHash = stableId('MEM', policy.observedIps);
  const existingNames = reusedHostObjects.map(item => item.objectNames[0]).sort();
  return baseCandidate(
    policy,
    side,
    'new-exact-group',
    3,
    policy.observedIps,
    policy.observedIps.map(ip => `${ip}/32`),
    {
      autoApplicable: !ambiguous,
      representation: { type: 'new-exact-group', memberReferences },
      objects: { existing: existingNames, create: objectsToCreate },
      reasonCodes: ambiguous
        ? ['NEW_EXACT_GROUP', 'AMBIGUOUS_HOST_OBJECTS'] : ['NEW_EXACT_GROUP'],
      explanation: ambiguous
        ? 'Un groupe exact est possible, mais plusieurs objets représentent au moins un host.'
        : 'Un nouveau groupe peut représenter exactement les hosts en réutilisant les objets existants.',
      payload: {
        exactGroupCandidate: {
          mode: 'create-new',
          groupName: null,
          groupNames: [],
          memberObjectNames: existingNames,
          memberCidrs: policy.observedIps.map(ip => `${ip}/32`),
          expandedCidrs: policy.observedIps.map(ip => `${ip}/32`),
          expandedMembershipHash: membershipHash,
          observedMembershipHash: membershipHash,
          reusedHostObjects,
          missingHostObjects,
          objectsToCreate,
          nestedGroupDepth: 0,
          cyclesDetected: false,
          danglingMembers: [],
          exactMembership: true,
          safeExact: true,
          ambiguous,
        },
      },
    },
  );
}

function cidrContains(parsed, value) {
  return value >= parsed.start && value <= parsed.end;
}

function minimalCoverCidr(observedInts) {
  let first = 0xFFFFFFFF;
  let last = 0;
  for (const value of observedInts) {
    if (value < first) first = value;
    if (value > last) last = value;
  }
  const prefix = Math.clz32((first ^ last) >>> 0);
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  const start = (first & mask) >>> 0;
  return parseCidr(`${intToIpv4(start)}/${prefix}`);
}

function enumerateCidr(parsed) {
  return Array.from({ length: parsed.size }, (_unused, offset) => intToIpv4(parsed.start + offset));
}

function cidrSuggestionCandidates(policy, side, fortiConfig, options) {
  if (policy.observedIps.length < 2) return [];
  const maxAddresses = Number.isInteger(options.maxCandidateAddresses)
    ? Math.max(2, options.maxCandidateAddresses) : 4096;
  const maxCandidates = Number.isInteger(options.maxCidrCandidates)
    ? Math.max(1, options.maxCidrCandidates) : 20;
  const observedInts = policy.observedIps.map(ipv4ToInt);
  const candidatesByCidr = new Map();

  function addCandidate(cidr, derivation, objectName = null) {
    const parsed = parseCidr(cidr);
    if (!parsed || parsed.prefix === 32 || parsed.size > maxAddresses) return;
    if (!observedInts.every(value => cidrContains(parsed, value))) return;
    if (!candidatesByCidr.has(parsed.cidr)) {
      candidatesByCidr.set(parsed.cidr, {
        parsed,
        derivations: new Set(),
        objectNames: new Set(),
      });
    }
    const candidate = candidatesByCidr.get(parsed.cidr);
    candidate.derivations.add(derivation);
    if (objectName) candidate.objectNames.add(String(objectName));
  }

  for (const [key, address] of Object.entries(fortiConfig?.addresses || {})) {
    addCandidate(address?.cidr, 'existing-object', address?.name || key);
  }
  for (const iface of Object.values(fortiConfig?.interfaces || {})) {
    addCandidate(iface?.cidr, 'interface-network');
  }
  for (const network of (options.networks || [])) {
    addCandidate(network?.cidr, 'configured-network');
  }
  const minimal = minimalCoverCidr(observedInts);
  if (minimal) addCandidate(minimal.cidr, 'minimal-cover');

  return [...candidatesByCidr.values()]
    .sort((a, b) => a.parsed.size - b.parsed.size || a.parsed.cidr.localeCompare(b.parsed.cidr))
    .slice(0, maxCandidates)
    .map(({ parsed, derivations, objectNames }) => {
      const representedIps = enumerateCidr(parsed);
      const exactMembership = parsed.size === policy.observedIps.length;
      const names = [...objectNames].sort();
      const derivation = names.length > 0 ? 'existing-object'
        : derivations.has('interface-network') ? 'interface-network'
          : derivations.has('configured-network') ? 'configured-network' : 'minimal-cover';
      const membershipHash = stableId('MEM', representedIps);
      const eligibility = exactMembership ? 'safe-exact' : 'explicit-generalization';
      const candidate = baseCandidate(policy, side, 'cidr-suggestion', 4, representedIps, [parsed.cidr], {
        eligibility,
        autoApplicable: false,
        representation: { type: 'cidr-suggestion', cidr: parsed.cidr, existingObjectNames: names },
        origin: names.length > 0
          ? { type: 'fortigate-config', deviceId: policy.deviceId, vdom: policy.vdom }
          : { type: 'resolver' },
        objects: { existing: names, create: names.length > 0 ? [] : [{ objectType: 'address', cidr: parsed.cidr }] },
        reasonCodes: exactMembership
          ? ['CIDR_EXACT_MEMBERSHIP', 'SUGGESTION_ONLY']
          : ['CIDR_CONTAINS_OBSERVED_HOSTS', 'EXPLICIT_GENERALIZATION', 'SUGGESTION_ONLY'],
        explanation: exactMembership
          ? 'Le CIDR représente exactement les hosts observés, mais reste une suggestion à confirmer.'
          : 'Le CIDR contient tous les hosts observés et des adresses supplémentaires mesurées.',
      });
      const existingMatches = names.length === 0 ? [] : [{
        deviceId: policy.deviceId,
        vdom: policy.vdom,
        objectNames: names,
        objectType: 'subnet',
        cidr: parsed.cidr,
        rangeStart: null,
        rangeEnd: null,
        normalizedMembershipHash: membershipHash,
        matchKind: exactMembership ? 'exact-membership' : 'contains-observed',
        observedIpCount: policy.observedIps.length,
        representedIpCount: parsed.size,
        additionalIpCount: parsed.size - policy.observedIps.length,
        exactMembership,
        safeExact: exactMembership,
        ambiguous: names.length > 1,
      }];
      candidate.cidrCandidate = {
        cidr: parsed.cidr,
        derivation,
        derivations: [...derivations].sort(),
        prefix: parsed.prefix,
        totalAddressCount: parsed.size,
        observedIpCount: policy.observedIps.length,
        density: policy.observedIps.length / parsed.size,
        additionalIpCount: parsed.size - policy.observedIps.length,
        missingObservedIpCount: 0,
        destinationCount: policy.destinations.length,
        sourceCount: policy.sources.length,
        serviceKeys: policy.serviceKeys,
        additionalTupleCount: candidate.previewMetrics.unexpectedAllowedTuples,
        expansionRatio: candidate.previewMetrics.expansionRatio,
        existingMatches,
        exactMembership,
        safeExact: exactMembership,
        bounded: true,
      };
      return candidate;
    });
}

function validateMetrics(metrics) {
  return metrics && [
    'observedRequiredTuples', 'coveredRequiredTuples', 'missingRequiredTuples',
    'allowedTuples', 'unexpectedAllowedTuples', 'coverageRatio', 'expansionRatio',
  ].every(key => Number.isFinite(metrics[key]) && metrics[key] >= 0);
}

function validateExistingFortiObjectMatch(match) {
  if (!match || !Array.isArray(match.objectNames) || match.objectNames.length === 0) return false;
  if (!['subnet', 'ip-range', 'mixed'].includes(match.objectType)) return false;
  if (!['exact-membership', 'contains-observed', 'disjoint'].includes(match.matchKind)) return false;
  if (!match.normalizedMembershipHash) return false;
  if (![match.observedIpCount, match.representedIpCount, match.additionalIpCount]
    .every(value => Number.isInteger(value) && value >= 0)) return false;
  if (match.safeExact && (!match.exactMembership || match.additionalIpCount !== 0)) return false;
  return true;
}

function validateExactGroupCandidate(group) {
  if (!group || !['reuse-existing', 'create-new'].includes(group.mode)) return false;
  if (!Array.isArray(group.memberObjectNames) || !Array.isArray(group.memberCidrs)) return false;
  if (!Array.isArray(group.missingHostObjects) || !Array.isArray(group.objectsToCreate)) return false;
  if (!Array.isArray(group.danglingMembers) || typeof group.cyclesDetected !== 'boolean') return false;
  if (!group.expandedMembershipHash || !group.observedMembershipHash) return false;
  if (group.safeExact && (!group.exactMembership || group.cyclesDetected || group.danglingMembers.length > 0)) return false;
  return true;
}

function validateCIDRCandidate(candidate) {
  if (!candidate || !parseCidr(candidate.cidr)) return false;
  if (!['existing-object', 'interface-network', 'minimal-cover', 'configured-network'].includes(candidate.derivation)) return false;
  if (![candidate.totalAddressCount, candidate.observedIpCount, candidate.additionalIpCount,
    candidate.missingObservedIpCount, candidate.additionalTupleCount]
    .every(value => Number.isInteger(value) && value >= 0)) return false;
  if (!Number.isFinite(candidate.density) || candidate.density < 0 || candidate.density > 1) return false;
  if (!Number.isFinite(candidate.expansionRatio) || candidate.expansionRatio < 0) return false;
  if (!Array.isArray(candidate.existingMatches)
    || !candidate.existingMatches.every(validateExistingFortiObjectMatch)) return false;
  if (candidate.safeExact && (!candidate.exactMembership || candidate.additionalIpCount !== 0)) return false;
  return candidate.bounded === true;
}

function validateNetworkCandidate(candidate) {
  if (!candidate || candidate.schemaVersion !== NETWORK_REPRESENTATION_SCHEMA_VERSION) return false;
  if (candidate.resolverVersion !== NETWORK_RESOLVER_VERSION) return false;
  if (!CANDIDATE_KINDS.has(candidate.kind) || !ELIGIBILITY_STATES.has(candidate.eligibility)) return false;
  if (!['source', 'destination'].includes(candidate.side)) return false;
  if (!candidate.candidateId || !candidate.policyFingerprint || !Array.isArray(candidate.representedIps)) return false;
  if (!Array.isArray(candidate.representedCidrs) || !Array.isArray(candidate.reasonCodes)) return false;
  if (!candidate.representation || !candidate.origin || !candidate.objects) return false;
  if (candidate.representedIpCount !== candidate.representedIps.length) return false;
  if (!validateMetrics(candidate.previewMetrics)) return false;
  const expectedRanks = {
    'existing-object': 1,
    'existing-group': 2,
    'new-exact-group': 3,
    'cidr-suggestion': 4,
    'host-list': 5,
  };
  if (candidate.rank !== expectedRanks[candidate.kind]) return false;
  if (candidate.kind === 'existing-object'
    && !validateExistingFortiObjectMatch(candidate.existingObjectMatch)) return false;
  if (['existing-group', 'new-exact-group'].includes(candidate.kind)
    && !validateExactGroupCandidate(candidate.exactGroupCandidate)) return false;
  if (candidate.kind === 'cidr-suggestion' && !validateCIDRCandidate(candidate.cidrCandidate)) return false;
  if (candidate.kind === 'host-list' && candidate.representation.type !== 'host-list') return false;
  if (candidate.kind === 'cidr-suggestion' && candidate.autoApplicable) return false;
  if (candidate.autoApplicable
    && (candidate.eligibility !== 'safe-exact'
      || candidate.previewMetrics.missingRequiredTuples !== 0
      || candidate.previewMetrics.unexpectedAllowedTuples !== 0)) return false;
  return true;
}

function validateResolutionResult(result) {
  if (!result || result.schemaVersion !== NETWORK_REPRESENTATION_SCHEMA_VERSION) return false;
  if (result.resolverVersion !== NETWORK_RESOLVER_VERSION) return false;
  if (!result.resolutionId || !result.policyFingerprint || !Array.isArray(result.candidates)) return false;
  if (!result.candidates.every(validateNetworkCandidate)) return false;
  const ids = new Set(result.candidates.map(candidate => candidate.candidateId));
  if (ids.size !== result.candidates.length) return false;
  if (!ids.has(result.currentRepresentation.candidateId)) return false;
  if (result.recommendedCandidateId && !ids.has(result.recommendedCandidateId)) return false;
  return true;
}

function configurationIdentity(fortiConfig, options) {
  return {
    addresses: Object.entries(fortiConfig?.addresses || {})
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, address]) => ({
        key,
        name: String(address?.name || key),
        type: String(address?.type || ''),
        cidr: String(address?.cidr || ''),
        startInt: Number.isInteger(address?.startInt) ? address.startInt : null,
        endInt: Number.isInteger(address?.endInt) ? address.endInt : null,
      })),
    addressGroups: Object.entries(fortiConfig?.addressGroups || {})
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, group]) => ({
        key,
        name: String(group?.name || key),
        members: sortedUnique(group?.members),
      })),
    interfaces: Object.entries(fortiConfig?.interfaces || {})
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, iface]) => ({ key, cidr: String(iface?.cidr || '') })),
    networks: (options.networks || [])
      .map(network => ({ cidr: String(network?.cidr || '') }))
      .sort((a, b) => a.cidr.localeCompare(b.cidr)),
    maxCandidateAddresses: Number.isInteger(options.maxCandidateAddresses)
      ? options.maxCandidateAddresses : 4096,
    maxCidrCandidates: Number.isInteger(options.maxCidrCandidates)
      ? options.maxCidrCandidates : 20,
  };
}

function resolveNetworkRepresentations(inputPolicy, fortiConfig = {}, options = {}) {
  const side = options.side || 'source';
  const policy = normalizePolicy(inputPolicy, side);
  const currentRepresentation = hostListCandidate(policy, side);
  const exactObject = exactExistingObjectCandidate(policy, side, fortiConfig);
  const exactGroup = exactExistingGroupCandidate(policy, side, fortiConfig);
  const newExactGroup = !exactObject && !exactGroup.candidate
    ? newExactGroupCandidate(policy, side, fortiConfig)
    : null;
  const cidrSuggestions = cidrSuggestionCandidates(policy, side, fortiConfig, options);
  const candidates = [exactObject, exactGroup.candidate, newExactGroup, ...cidrSuggestions, currentRepresentation]
    .filter(Boolean)
    .sort((a, b) => a.rank - b.rank
      || a.additionalIpCount - b.additionalIpCount
      || (a.representedCidrs[0] || '').localeCompare(b.representedCidrs[0] || '')
      || a.candidateId.localeCompare(b.candidateId));
  const recommended = candidates.find(candidate => candidate.autoApplicable) || currentRepresentation;
  const technicalInput = {
    policyFingerprint: policy.fingerprint,
    side,
    resolverVersion: NETWORK_RESOLVER_VERSION,
    configuration: configurationIdentity(fortiConfig, options),
  };
  return {
    schemaVersion: NETWORK_REPRESENTATION_SCHEMA_VERSION,
    resolverVersion: NETWORK_RESOLVER_VERSION,
    resolutionId: stableId('NR', technicalInput),
    resolverInputHash: stableId('INPUT', technicalInput),
    policyId: policy.id,
    policyFingerprint: policy.fingerprint,
    side,
    currentRepresentation,
    candidates,
    recommendedCandidateId: recommended.candidateId,
    decision: null,
    effectiveCandidateId: currentRepresentation.candidateId,
    previewMetricsByCandidate: Object.fromEntries(candidates.map(candidate => [candidate.candidateId, candidate.previewMetrics])),
    finalMetrics: null,
    status: recommended.candidateId === currentRepresentation.candidateId ? 'resolved' : 'choice-required',
    blockers: exactGroup.blockers,
    trace: {
      flowAtomIds: policy.atomIds,
      configFingerprint: stableId('CFG', technicalInput),
      trafficScopeKey: String(inputPolicy?._policyEngineV2?.trafficScopeKey || ''),
    },
  };
}

module.exports = {
  NETWORK_REPRESENTATION_SCHEMA_VERSION,
  NETWORK_RESOLVER_VERSION,
  resolveNetworkRepresentations,
  validateCIDRCandidate,
  validateExactGroupCandidate,
  validateExistingFortiObjectMatch,
  validateNetworkCandidate,
  validateResolutionResult,
};
