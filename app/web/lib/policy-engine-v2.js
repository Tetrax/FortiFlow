'use strict';

const { PREDEFINED } = require('./forticonfig');

const PROFILE_NAMES = new Set(['recommended', 'strict', 'synthetic', 'expert']);

function normalizeProtocol(proto) {
  const value = String(proto || '').trim().toUpperCase();
  if (value === '6' || value === 'TCP') return 'TCP';
  if (value === '17' || value === 'UDP') return 'UDP';
  if (value === '1' || value === 'ICMP') return 'ICMP';
  return value ? `PROTO-${value}` : 'PROTO-UNKNOWN';
}

function protocolNumber(protocol) {
  if (protocol === 'TCP') return '6';
  if (protocol === 'UDP') return '17';
  if (protocol === 'ICMP') return '1';
  return protocol.replace(/^PROTO-/, '');
}

function canonicalService(flow) {
  const protocol = normalizeProtocol(flow.proto);
  const observedLabel = String(flow.service || '').trim().toUpperCase();
  const icmp = protocol === 'ICMP' ? observedLabel.match(/^ICMP\/(\d+)\/(\d+)$/) : null;
  const explicitIcmp = protocol === 'ICMP'
    && Number.isInteger(flow.icmpType)
    && Number.isInteger(flow.icmpCode);
  const namedIcmp = protocol === 'ICMP'
    && observedLabel
    && observedLabel !== 'ICMP'
    && !icmp
    && !explicitIcmp;
  const icmpType = explicitIcmp ? flow.icmpType : icmp ? Number(icmp[1]) : null;
  const icmpCode = explicitIcmp ? flow.icmpCode : icmp ? Number(icmp[2]) : null;
  const parsedPort = Number(flow.dstport);
  const port = ['TCP', 'UDP'].includes(protocol)
    && Number.isInteger(parsedPort) && parsedPort >= 1 && parsedPort <= 65535
    ? parsedPort
    : null;
  const invalidPort = ['TCP', 'UDP'].includes(protocol) && port === null;
  const key = explicitIcmp || icmp
    ? `${protocol}:${icmpType}:${icmpCode}`
    : namedIcmp ? `${protocol}:NAME:${observedLabel}`
    : port === null ? protocol : `${protocol}:${port}`;
  const label = observedLabel || (port === null ? protocol : `${protocol}/${port}`);
  return { key, protocol, port, label, icmpType, icmpCode, invalidPort };
}

function scopeOf(flow) {
  return {
    devid: String(flow.devid || ''),
    devname: String(flow.devname || ''),
    vdom: String(flow.vdom || ''),
  };
}

function scopeKey(scope) {
  return `${scope.devid || scope.devname || 'unknown-device'}::${scope.vdom || 'root'}`;
}

function isAllowedFlow(flow) {
  const decision = String(flow.decision || '').toLowerCase();
  const action = String(flow.action || '').toLowerCase();
  return decision === 'allow' || ['accept', 'accepted', 'allow', 'pass'].includes(action);
}

function isDeployableAllow(flow) {
  return flow.deploymentEligible === true && isAllowedFlow(flow);
}

function summarizeInput(flows) {
  const summary = {
    inputFlows: 0,
    inputSessions: 0,
    includedFlows: 0,
    includedSessions: 0,
    excludedFlows: 0,
    excludedSessions: 0,
    exclusionReasons: {},
  };
  for (const flow of (flows || [])) {
    const sessions = Number(flow.count || 1);
    summary.inputFlows++;
    summary.inputSessions += sessions;
    let reason = null;
    if (!isAllowedFlow(flow)) reason = 'not_allowed';
    else if (flow.deploymentEligible !== true) reason = 'deployment_ineligible';
    else if (!flow.srcip || !flow.dstip) reason = 'missing_endpoint';
    if (reason) {
      summary.excludedFlows++;
      summary.excludedSessions += sessions;
      summary.exclusionReasons[reason] = (summary.exclusionReasons[reason] || 0) + sessions;
    } else {
      summary.includedFlows++;
      summary.includedSessions += sessions;
    }
  }
  return summary;
}

function atomSortKey(atom) {
  return [atom.partitionKey, atom.source, atom.destination, atom.service.key].join('|');
}

function defaultAddressType(ip) {
  return String(ip).startsWith('10.')
    || String(ip).startsWith('192.168.')
    || /^172\.(1[6-9]|2\d|3[01])\./.test(String(ip))
    ? 'private'
    : 'public';
}

function canonicalizeFlows(flows) {
  const aggregated = new Map();
  for (const flow of (flows || [])) {
    if (!isDeployableAllow(flow) || !flow.srcip || !flow.dstip) continue;
    const scope = scopeOf(flow);
    const sourceInterface = String(flow.srcintf || '');
    const destinationInterface = String(flow.dstintf || '');
    const partitionKey = [scopeKey(scope), sourceInterface, destinationInterface].join('||');
    const service = canonicalService(flow);
    const key = [partitionKey, flow.srcip, flow.dstip, service.key].join('||');
    if (!aggregated.has(key)) {
      aggregated.set(key, {
        id: '',
        source: String(flow.srcip),
        destination: String(flow.dstip),
        sourceType: ['private', 'public'].includes(flow.srcType) ? flow.srcType : defaultAddressType(flow.srcip),
        destinationType: ['private', 'public'].includes(flow.dstType) ? flow.dstType : defaultAddressType(flow.dstip),
        protocol: service.protocol,
        destinationPort: service.port,
        service,
        sourceInterface,
        destinationInterface,
        scope,
        partitionKey,
        count: 0,
        sentBytes: 0,
        receivedBytes: 0,
        firstSeen: null,
        lastSeen: null,
        days: new Set(),
        observedLabels: new Set(),
      });
    }
    const atom = aggregated.get(key);
    atom.count += Number(flow.count || 1);
    atom.sentBytes += Number(flow.sentBytes || 0);
    atom.receivedBytes += Number(flow.rcvdBytes || 0);
    if (flow.firstTs != null && (atom.firstSeen == null || flow.firstTs < atom.firstSeen)) atom.firstSeen = flow.firstTs;
    if (flow.lastTs != null && (atom.lastSeen == null || flow.lastTs > atom.lastSeen)) atom.lastSeen = flow.lastTs;
    for (const day of (flow.days || [])) atom.days.add(String(day));
    if (service.label) atom.observedLabels.add(service.label);
    if (flow.srcType === 'private') atom.sourceType = 'private';
    if (flow.dstType === 'private') atom.destinationType = 'private';
  }

  return [...aggregated.values()]
    .sort((a, b) => atomSortKey(a).localeCompare(atomSortKey(b)))
    .map((atom, index) => {
      const labels = [...atom.observedLabels].sort();
      return {
        ...atom,
        id: `A-${String(index + 1).padStart(6, '0')}`,
        service: { ...atom.service, label: labels[0] || atom.service.label },
        days: [...atom.days].sort(),
        observedLabels: labels,
      };
    });
}

function exactExistingService(service, customServices) {
  if (service.protocol === 'ICMP' && service.icmpType != null && service.icmpCode != null) {
    return Object.values(customServices || {})
      .filter(candidate => candidate.proto === 'ICMP'
        && candidate.icmptype === service.icmpType
        && candidate.icmpcode === service.icmpCode)
      .map(candidate => candidate.name)
      .filter(Boolean)
      .sort()[0] || null;
  }
  if (service.protocol === 'ICMP'
    && service.label
    && !['ICMP', 'ALL_ICMP', 'ALL_ICMP6'].includes(service.label)) {
    return Object.values(customServices || {})
      .filter(candidate => candidate.proto === 'ICMP'
        && String(candidate.name || '').toUpperCase() === service.label)
      .map(candidate => candidate.name)
      .filter(Boolean)
      .sort()[0] || null;
  }
  if (service.port == null || !['TCP', 'UDP'].includes(service.protocol)) return null;
  const expectedField = service.protocol === 'TCP' ? 'tcpPorts' : 'udpPorts';
  const otherField = service.protocol === 'TCP' ? 'udpPorts' : 'tcpPorts';
  return Object.values(customServices || {})
    .filter(candidate => {
      const expected = [...new Set(candidate[expectedField] || [])].sort((a, b) => a - b);
      const other = [...new Set(candidate[otherField] || [])];
      return expected.length === 1 && expected[0] === service.port && other.length === 0;
    })
    .map(candidate => candidate.name)
    .filter(Boolean)
    .sort()[0] || null;
}

function exactPredefinedService(service) {
  if (service.port == null || !['TCP', 'UDP'].includes(service.protocol)) return null;
  const candidate = PREDEFINED[service.port];
  if (!candidate || candidate.proto === 'both') return null;
  if (candidate.proto.toUpperCase() !== service.protocol) return null;
  return candidate.name;
}

function buildServiceInventory(atoms, fortiConfig) {
  const grouped = new Map();
  for (const atom of atoms) {
    if (!grouped.has(atom.service.key)) grouped.set(atom.service.key, []);
    grouped.get(atom.service.key).push(atom);
  }
  return [...grouped.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, serviceAtoms]) => {
    const service = serviceAtoms[0].service;
    const existing = exactExistingService(service, fortiConfig?.customServices || {});
    const predefined = existing ? null : exactPredefinedService(service);
    const count = serviceAtoms.reduce((sum, atom) => sum + atom.count, 0);
    const days = new Set(serviceAtoms.flatMap(atom => atom.days || []));
    const dynamic = service.protocol === 'TCP' && service.port >= 49152 && service.port <= 65535;
    let classification;
    if (existing) classification = 'existing';
    else if (predefined) classification = 'predefined';
    else if (service.invalidPort) classification = 'unresolved-port';
    else if (!['TCP', 'UDP'].includes(service.protocol)) classification = 'unresolved-protocol';
    else if (dynamic) classification = 'dynamic';
    else if (count <= 1) classification = 'rare';
    else if (days.size >= 2 || count >= 10) classification = 'custom-stable';
    else classification = 'application-specific';
    const rpcCandidate = dynamic && serviceAtoms.some(atom =>
      atom.service.label.includes('RPC')
      || atoms.some(other => other.partitionKey === atom.partitionKey
        && other.source === atom.source
        && other.destination === atom.destination
        && other.service.protocol === 'TCP'
        && other.service.port === 135)
    );
    return {
      key,
      protocol: service.protocol,
      port: service.port,
      label: service.label,
      classification,
      selectedObject: existing || predefined || null,
      observedCount: count,
      observedDays: days.size,
      rpcCandidate,
      generalizedRange: null,
      deploymentBlocked: classification === 'unresolved-protocol' || classification === 'unresolved-port',
    };
  });
}

function ipv4ToInt(ip) {
  const parts = String(ip || '').split('.').map(Number);
  if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return parts.reduce((value, part) => ((value * 256) + part) >>> 0, 0) >>> 0;
}

function intToIpv4(value) {
  const n = value >>> 0;
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function parseCidr(cidr) {
  const match = String(cidr || '').match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d|[12]\d|3[0-2])$/);
  if (!match) return null;
  const ip = ipv4ToInt(match[1]);
  const prefix = Number(match[2]);
  if (ip == null) return null;
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  const network = (ip & mask) >>> 0;
  const size = 2 ** (32 - prefix);
  return {
    cidr: `${intToIpv4(network)}/${prefix}`,
    prefix,
    network,
    size,
    contains(address) {
      const candidate = ipv4ToInt(address);
      return candidate != null && ((candidate & mask) >>> 0) === network;
    },
  };
}

function enumerateCidr(parsed) {
  return Array.from({ length: parsed.size }, (_unused, offset) => intToIpv4((parsed.network + offset) >>> 0));
}

function networkCandidates(options) {
  const configured = (options.networks || []).map(network => ({ cidr: network.cidr, name: network.name || null }));
  for (const [name, address] of Object.entries(options.fortiConfig?.addresses || {})) {
    configured.push({ cidr: address.cidr, name });
  }
  const deduped = new Map();
  for (const candidate of configured) {
    const parsed = parseCidr(candidate.cidr);
    if (!parsed || parsed.prefix === 32) continue;
    const existing = deduped.get(parsed.cidr);
    if (!existing || (!existing.name && candidate.name)) deduped.set(parsed.cidr, { ...parsed, name: candidate.name });
  }
  return [...deduped.values()].sort((a, b) => b.prefix - a.prefix || a.cidr.localeCompare(b.cidr));
}

function chooseNetwork(members, candidates, config) {
  if (members.length < config.minHosts) return null;
  for (const candidate of candidates) {
    if (candidate.prefix < config.minPrefix || candidate.size > config.maxAddresses) continue;
    if (!members.every(member => candidate.contains(member))) continue;
    const density = members.length / candidate.size;
    if (density < config.minDensity) continue;
    return { candidate, density };
  }
  return null;
}

function applySyntheticAggregation(policies, options) {
  const requested = options.networkAggregation || {};
  const config = {
    minDensity: Number.isFinite(requested.minDensity) ? requested.minDensity : 0.8,
    minHosts: Number.isInteger(requested.minHosts) ? requested.minHosts : 4,
    minPrefix: Number.isInteger(requested.minPrefix) ? requested.minPrefix : 23,
    maxAddresses: Number.isInteger(requested.maxAddresses) ? requested.maxAddresses : 4096,
  };
  const candidates = networkCandidates(options);
  if (!candidates.length) return policies.map(policy => ({
    ...policy,
    profile: 'synthetic',
    networkAggregation: {},
    _policyEngineV2: { ...policy._policyEngineV2, profile: 'synthetic', safeExact: true },
  }));

  return policies.map(policy => {
    const result = {
      ...policy,
      profile: 'synthetic',
      networkAggregation: {},
      _policyEngineV2: { ...policy._policyEngineV2, profile: 'synthetic', safeExact: true },
    };
    const sourceChoice = chooseNetwork(policy.sources, candidates, config);
    if (sourceChoice) {
      const { candidate, density } = sourceChoice;
      result.allowedSources = enumerateCidr(candidate);
      result.srcSubnet = candidate.cidr;
      result.srcSubnets = [candidate.cidr];
      result._srcCidrOverride = candidate.cidr;
      result._use32Src = false;
      result._srcMode = 'subnet';
      result._useSrcGroup = false;
      result._multiSrcSubnets = null;
      result._segmentationPlan = { ...result._segmentationPlan, source: 'network' };
      result._policyEngineV2.safeExact = false;
      result.networkAggregation.source = {
        cidr: candidate.cidr,
        objectName: candidate.name,
        observedHosts: policy.sources.length,
        possibleHosts: candidate.size,
        density,
        additionalHosts: candidate.size - policy.sources.length,
      };
    }

    const destinationChoice = policy.dstType === 'private'
      ? chooseNetwork(policy.destinations, candidates, config)
      : null;
    if (destinationChoice) {
      const { candidate, density } = destinationChoice;
      result.allowedDestinations = enumerateCidr(candidate);
      result.dstTarget = candidate.cidr;
      result.dstTargets = [candidate.cidr];
      result._dstCidrOverride = candidate.cidr;
      result._use32Dst = false;
      result._dstMode = 'subnet';
      result._useDstGroup = false;
      result._isMultiDst = false;
      result._multiDstSubnets = null;
      result._segmentationPlan = { ...result._segmentationPlan, destination: 'network' };
      result._policyEngineV2.safeExact = false;
      result.networkAggregation.destination = {
        cidr: candidate.cidr,
        objectName: candidate.name,
        observedHosts: policy.destinations.length,
        possibleHosts: candidate.size,
        density,
        additionalHosts: candidate.size - policy.destinations.length,
      };
    }
    return result;
  });
}

function edgeKey(atom) {
  return `${atom.source}|${atom.destination}`;
}

function buildRectanglesBySource(edges) {
  const destinationsBySource = new Map();
  for (const edge of edges) {
    if (!destinationsBySource.has(edge.source)) destinationsBySource.set(edge.source, new Set());
    destinationsBySource.get(edge.source).add(edge.destination);
  }
  const groups = new Map();
  for (const [source, destinations] of destinationsBySource) {
    const sortedDestinations = [...destinations].sort();
    const signature = sortedDestinations.join('|');
    if (!groups.has(signature)) groups.set(signature, { sources: [], destinations: sortedDestinations });
    groups.get(signature).sources.push(source);
  }
  return [...groups.values()].map(group => ({
    sources: group.sources.sort(),
    destinations: group.destinations,
    orientation: 'source',
  }));
}

function buildRectanglesByDestination(edges) {
  const sourcesByDestination = new Map();
  for (const edge of edges) {
    if (!sourcesByDestination.has(edge.destination)) sourcesByDestination.set(edge.destination, new Set());
    sourcesByDestination.get(edge.destination).add(edge.source);
  }
  const groups = new Map();
  for (const [destination, sources] of sourcesByDestination) {
    const sortedSources = [...sources].sort();
    const signature = sortedSources.join('|');
    if (!groups.has(signature)) groups.set(signature, { sources: sortedSources, destinations: [] });
    groups.get(signature).destinations.push(destination);
  }
  return [...groups.values()].map(group => ({
    sources: group.sources,
    destinations: group.destinations.sort(),
    orientation: 'destination',
  }));
}

function rectangleSortKey(rectangle) {
  return [rectangle.destinations[0] || '', String(rectangle.destinations.length).padStart(8, '0'), rectangle.destinations.join(','), rectangle.sources.join(',')].join('|');
}

function chooseRectangles(edges) {
  const bySource = buildRectanglesBySource(edges);
  const byDestination = buildRectanglesByDestination(edges);
  const chosen = byDestination.length < bySource.length ? byDestination : bySource;
  return chosen.sort((a, b) => rectangleSortKey(a).localeCompare(rectangleSortKey(b)));
}

function confidenceForAtoms(atoms) {
  const days = new Set(atoms.flatMap(atom => atom.days || []));
  if (!atoms.some(atom => atom.firstSeen != null)) return 'unknown';
  if (days.size <= 1) return 'low';
  if (days.size >= 7) return 'high';
  return 'medium';
}

function policySortKey(policy) {
  return [
    policy.partitionKey,
    policy.destinations[0] || '',
    String(policy.destinations.length).padStart(8, '0'),
    policy.destinations.join(','),
    policy.sources.join(','),
    policy.serviceKeys.join(','),
  ].join('|');
}

function mergeIdenticalRectangles(policies) {
  const groups = new Map();
  for (const policy of policies) {
    const key = [policy.partitionKey, policy.sources.join(','), policy.destinations.join(',')].join('||');
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(policy);
  }
  return [...groups.values()].map(group => {
    if (group.length === 1) return group[0];
    const base = group[0];
    const serviceDescriptors = [...new Map(
      group.flatMap(policy => policy.serviceDescriptors).map(service => [service.key, service])
    ).values()].sort((a, b) => a.key.localeCompare(b.key));
    const tupleByKey = new Map();
    for (const tuple of group.flatMap(policy => policy.serviceTuples)) {
      const key = `${tuple.proto}|${tuple.port}|${tuple.service}`;
      if (!tupleByKey.has(key)) tupleByKey.set(key, { ...tuple, sessions: 0 });
      tupleByKey.get(key).sessions += Number(tuple.sessions || 0);
    }
    const days = [...new Set(group.flatMap(policy => policy.days || []))].sort();
    const firstSeen = group.map(policy => policy.firstSeen).filter(value => value != null);
    const lastSeen = group.map(policy => policy.lastSeen).filter(value => value != null);
    return {
      ...base,
      serviceKeys: serviceDescriptors.map(service => service.key),
      serviceDescriptors,
      serviceTuples: [...tupleByKey.values()].sort((a, b) => `${a.proto}|${a.port}|${a.service}`.localeCompare(`${b.proto}|${b.port}|${b.service}`)),
      services: serviceDescriptors.map(service => service.label),
      ports: [...new Set(serviceDescriptors.map(service => service.port).filter(port => port != null))].sort((a, b) => a - b),
      protos: [...new Set(serviceDescriptors.map(service => service.protocol))].sort(),
      serviceDesc: serviceDescriptors.map(service => service.label).join(', '),
      analysis: { ...base.analysis, services: serviceDescriptors },
      sessions: group.reduce((sum, policy) => sum + policy.sessions, 0),
      sentBytes: group.reduce((sum, policy) => sum + policy.sentBytes, 0),
      rcvdBytes: group.reduce((sum, policy) => sum + policy.rcvdBytes, 0),
      firstSeen: firstSeen.length ? Math.min(...firstSeen) : null,
      lastSeen: lastSeen.length ? Math.max(...lastSeen) : null,
      days,
      daysObserved: firstSeen.length ? days.length : null,
      confidence: group.every(policy => policy.confidence === group[0].confidence) ? group[0].confidence : 'mixed',
      trace: {
        atomIds: [...new Set(group.flatMap(policy => policy.trace.atomIds))].sort(),
        reason: 'Services fusionnés sur un rectangle source-destination strictement identique',
        orientation: base.trace.orientation,
      },
    };
  });
}

function buildRecommendedPolicies(atoms) {
  const partitions = new Map();
  for (const atom of atoms) {
    if (!partitions.has(atom.partitionKey)) partitions.set(atom.partitionKey, []);
    partitions.get(atom.partitionKey).push(atom);
  }

  const policies = [];
  for (const partitionAtoms of partitions.values()) {
    const services = new Map();
    for (const atom of partitionAtoms) {
      if (!services.has(atom.service.key)) services.set(atom.service.key, []);
      services.get(atom.service.key).push(atom);
    }

    const behaviorGroups = new Map();
    for (const [serviceKey, serviceAtoms] of services) {
      const signature = serviceAtoms.map(edgeKey).sort().join(',');
      if (!behaviorGroups.has(signature)) behaviorGroups.set(signature, { serviceKeys: [], atoms: [] });
      const group = behaviorGroups.get(signature);
      group.serviceKeys.push(serviceKey);
      group.atoms.push(...serviceAtoms);
    }

    for (const group of behaviorGroups.values()) {
      group.serviceKeys.sort();
      const representativeEdges = services.get(group.serviceKeys[0]);
      const serviceAtoms = group.serviceKeys.map(key => services.get(key)[0]);
      const serviceDescriptors = serviceAtoms.map(atom => ({ ...atom.service })).sort((a, b) => a.key.localeCompare(b.key));
      for (const rectangle of chooseRectangles(representativeEdges)) {
        const sourceSet = new Set(rectangle.sources);
        const destinationSet = new Set(rectangle.destinations);
        const supportingAtoms = group.atoms.filter(atom => sourceSet.has(atom.source) && destinationSet.has(atom.destination));
        const base = supportingAtoms[0];
        const observedDays = [...new Set(supportingAtoms.flatMap(atom => atom.days || []))].sort();
        const firstSeenValues = supportingAtoms.map(atom => atom.firstSeen).filter(value => value != null);
        const lastSeenValues = supportingAtoms.map(atom => atom.lastSeen).filter(value => value != null);
        const serviceTuples = serviceDescriptors.map(service => ({
          proto: protocolNumber(service.protocol),
          port: service.port == null ? '' : String(service.port),
          service: service.label,
          icmpType: service.icmpType,
          icmpCode: service.icmpCode,
          sessions: supportingAtoms
            .filter(atom => atom.service.key === service.key)
            .reduce((sum, atom) => sum + atom.count, 0),
        }));
        policies.push({
          id: '',
          name: '',
          profile: 'recommended',
          scope: base.scope,
          partitionKey: base.partitionKey,
          sourceInterface: base.sourceInterface,
          destinationInterface: base.destinationInterface,
          flowSrcintf: base.sourceInterface,
          srcintf: base.sourceInterface,
          dstintf: base.destinationInterface,
          _srcintf: base.sourceInterface,
          _dstintf: base.destinationInterface,
          sources: rectangle.sources,
          destinations: rectangle.destinations,
          serviceKeys: group.serviceKeys,
          serviceDescriptors,
          serviceTuples,
          services: serviceDescriptors.map(service => service.label),
          ports: serviceDescriptors.map(service => service.port).filter(port => port != null),
          protos: [...new Set(serviceDescriptors.map(service => service.protocol))].sort(),
          serviceDesc: serviceDescriptors.map(service => service.label).join(', '),
          srcHosts: rectangle.sources,
          dstHosts: rectangle.destinations,
          srcSubnet: `${rectangle.sources[0]}/32`,
          srcSubnets: rectangle.sources.map(source => `${source}/32`),
          dstTarget: `${rectangle.destinations[0]}/32`,
          dstTargets: rectangle.destinations.map(destination => `${destination}/32`),
          dstType: base.destinationType,
          _use32Src: true,
          _use32Dst: true,
          _srcMode: 'hosts',
          _dstMode: 'hosts',
          _useSrcGroup: rectangle.sources.length > 1,
          _useDstGroup: rectangle.destinations.length > 1,
          _segmentationPlan: { source: 'host', destination: 'host', services: 'grouped' },
          _segmentationEvidence: {
            verified: true,
            observedPairCount: rectangle.sources.length * rectangle.destinations.length,
          },
          _policyEngineV2: { profile: 'recommended', safeExact: true },
          _isMultiDst: rectangle.destinations.length > 1,
          _multiSrcSubnets: rectangle.sources.length > 1
            ? rectangle.sources.map(source => ({ subnet: `${source}/32`, hosts: [source], useSubnet: false, addrFound: false, addrName: '' }))
            : null,
          _multiDstSubnets: rectangle.destinations.length > 1
            ? rectangle.destinations.map(destination => ({ subnet: `${destination}/32`, hosts: [destination], useSubnet: false, addrFound: false, addrName: '' }))
            : null,
          sessions: supportingAtoms.reduce((sum, atom) => sum + atom.count, 0),
          sentBytes: supportingAtoms.reduce((sum, atom) => sum + atom.sentBytes, 0),
          rcvdBytes: supportingAtoms.reduce((sum, atom) => sum + atom.receivedBytes, 0),
          firstSeen: firstSeenValues.length ? Math.min(...firstSeenValues) : null,
          lastSeen: lastSeenValues.length ? Math.max(...lastSeenValues) : null,
          days: observedDays,
          daysObserved: firstSeenValues.length ? observedDays.length : null,
          confidence: confidenceForAtoms(supportingAtoms),
          analysis: { services: serviceDescriptors },
          trace: {
            atomIds: supportingAtoms.map(atom => atom.id).sort(),
            reason: group.serviceKeys.length > 1
              ? `Services aux signatures source-destination identiques; rectangle ${rectangle.orientation} complet`
              : `Rectangle ${rectangle.orientation} complet sans tuple ajouté`,
            orientation: rectangle.orientation,
          },
          action: 'accept',
        });
      }
    }
  }

  return mergeIdenticalRectangles(policies)
    .sort((a, b) => policySortKey(a).localeCompare(policySortKey(b)))
    .map((policy, index) => ({
      ...policy,
      id: `P-${String(index + 1).padStart(5, '0')}`,
      name: `FFV2-${String(index + 1).padStart(5, '0')}`,
    }));
}

function permissionKey(partitionKey, source, destination, serviceKey) {
  return [partitionKey, source, destination, serviceKey].join('||');
}

function evaluatePolicies(atoms, policies) {
  const observed = new Set(atoms.map(atom => permissionKey(atom.partitionKey, atom.source, atom.destination, atom.service.key)));
  const allowed = new Set();
  for (const policy of policies) {
    for (const source of (policy.allowedSources || policy.sources)) {
      for (const destination of (policy.allowedDestinations || policy.destinations)) {
        for (const serviceKey of policy.serviceKeys) {
          allowed.add(permissionKey(policy.partitionKey, source, destination, serviceKey));
        }
      }
    }
  }
  let coveredRequiredTuples = 0;
  for (const tuple of observed) if (allowed.has(tuple)) coveredRequiredTuples++;
  let unexpectedAllowedTuples = 0;
  for (const tuple of allowed) if (!observed.has(tuple)) unexpectedAllowedTuples++;
  const missingRequiredTuples = observed.size - coveredRequiredTuples;
  return {
    observedRequiredTuples: observed.size,
    coveredRequiredTuples,
    missingRequiredTuples,
    allowedTuples: allowed.size,
    unexpectedAllowedTuples,
    coverageRatio: observed.size ? coveredRequiredTuples / observed.size : 1,
    expansionRatio: observed.size ? unexpectedAllowedTuples / observed.size : 0,
  };
}

function evaluatePolicy(observedTupleSet, policy) {
  const allowed = new Set();
  for (const source of (policy.allowedSources || policy.sources)) {
    for (const destination of (policy.allowedDestinations || policy.destinations)) {
      for (const serviceKey of policy.serviceKeys) {
        allowed.add(permissionKey(policy.partitionKey, source, destination, serviceKey));
      }
    }
  }
  let observedTuples = 0;
  for (const tuple of allowed) if (observedTupleSet.has(tuple)) observedTuples++;
  const unexpectedAllowedTuples = allowed.size - observedTuples;
  return {
    observedTuples,
    allowedTuples: allowed.size,
    unexpectedAllowedTuples,
    expansionRatio: observedTuples ? unexpectedAllowedTuples / observedTuples : 0,
  };
}

function buildAffinityViews(policies) {
  const groups = new Map();
  for (const policy of policies) {
    const key = `${policy.partitionKey}||${policy.sources.join('|')}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(policy);
  }
  return [...groups.values()]
    .sort((a, b) => policySortKey(a[0]).localeCompare(policySortKey(b[0])))
    .map((group, index) => {
      const sources = [...new Set(group.flatMap(policy => policy.sources))].sort();
      const destinations = [...new Set(group.flatMap(policy => policy.destinations))].sort();
      const serviceKeys = [...new Set(group.flatMap(policy => policy.serviceKeys))].sort();
      const destinationsByService = new Map(serviceKeys.map(serviceKey => [serviceKey, new Set()]));
      for (const policy of group) {
        for (const serviceKey of policy.serviceKeys) {
          const serviceDestinations = destinationsByService.get(serviceKey);
          for (const destination of policy.destinations) serviceDestinations.add(destination);
        }
      }
      const matrix = {};
      for (const serviceKey of serviceKeys) {
        matrix[serviceKey] = {};
        for (const destination of destinations) {
          matrix[serviceKey][destination] = destinationsByService.get(serviceKey).has(destination);
        }
      }
      const commonServiceKeys = serviceKeys.filter(serviceKey =>
        destinations.every(destination => matrix[serviceKey][destination])
      );
      const commonSet = new Set(commonServiceKeys);
      const residualServiceKeysByDestination = {};
      for (const destination of destinations) {
        const residual = serviceKeys.filter(serviceKey => matrix[serviceKey][destination] && !commonSet.has(serviceKey));
        if (residual.length) residualServiceKeysByDestination[destination] = residual;
      }
      return {
        id: `AV-${String(index + 1).padStart(5, '0')}`,
        policyIds: group.map(policy => policy.id).sort(),
        sources,
        destinations,
        serviceKeys,
        commonServiceKeys,
        residualServiceKeysByDestination,
        matrix,
      };
    });
}

function buildStrictPolicies(atoms) {
  return atoms.map((atom, index) => ({
    id: `P-${String(index + 1).padStart(5, '0')}`,
    name: `FFV2-STRICT-${String(index + 1).padStart(5, '0')}`,
    profile: 'strict',
    scope: atom.scope,
    partitionKey: atom.partitionKey,
    sourceInterface: atom.sourceInterface,
    destinationInterface: atom.destinationInterface,
    flowSrcintf: atom.sourceInterface,
    srcintf: atom.sourceInterface,
    dstintf: atom.destinationInterface,
    _srcintf: atom.sourceInterface,
    _dstintf: atom.destinationInterface,
    sources: [atom.source],
    destinations: [atom.destination],
    serviceKeys: [atom.service.key],
    serviceDescriptors: [{ ...atom.service }],
    serviceTuples: [{
      proto: protocolNumber(atom.service.protocol),
      port: atom.service.port == null ? '' : String(atom.service.port),
      service: atom.service.label,
      icmpType: atom.service.icmpType,
      icmpCode: atom.service.icmpCode,
      sessions: atom.count,
    }],
    services: [atom.service.label],
    ports: atom.service.port == null ? [] : [atom.service.port],
    protos: [atom.service.protocol],
    serviceDesc: atom.service.label,
    srcHosts: [atom.source],
    dstHosts: [atom.destination],
    srcSubnet: `${atom.source}/32`,
    srcSubnets: [`${atom.source}/32`],
    dstTarget: `${atom.destination}/32`,
    dstTargets: [`${atom.destination}/32`],
    dstType: atom.destinationType,
    _use32Src: true,
    _use32Dst: true,
    _srcMode: 'hosts',
    _dstMode: 'hosts',
    _useSrcGroup: false,
    _useDstGroup: false,
    _segmentationPlan: { source: 'host', destination: 'host', services: 'grouped' },
    _segmentationEvidence: { verified: true, observedPairCount: 1 },
    _policyEngineV2: { profile: 'strict', safeExact: true },
    _isMultiDst: false,
    _multiSrcSubnets: null,
    _multiDstSubnets: null,
    sessions: atom.count,
    sentBytes: atom.sentBytes,
    rcvdBytes: atom.receivedBytes,
    firstSeen: atom.firstSeen,
    lastSeen: atom.lastSeen,
    days: atom.days,
    daysObserved: atom.firstSeen != null ? atom.days.length : null,
    confidence: confidenceForAtoms([atom]),
    analysis: { services: [{ ...atom.service }] },
    trace: { atomIds: [atom.id], reason: 'Tuple canonique strict', orientation: 'strict' },
    action: 'accept',
  }));
}

function buildPolicyEngineV2(flows, options = {}) {
  const profile = PROFILE_NAMES.has(options.profile) ? options.profile : 'recommended';
  const inputSummary = summarizeInput(flows);
  const canonicalAtoms = canonicalizeFlows(flows);
  const serviceInventory = buildServiceInventory(canonicalAtoms, options.fortiConfig || {});
  const serviceByKey = new Map(serviceInventory.map(service => [service.key, service]));
  const atoms = canonicalAtoms.map(atom => ({
    ...atom,
    service: { ...atom.service, ...serviceByKey.get(atom.service.key) },
  }));
  const exactPolicies = profile === 'strict' ? buildStrictPolicies(atoms) : buildRecommendedPolicies(atoms);
  const policies = profile === 'synthetic'
    ? applySyntheticAggregation(exactPolicies, options)
    : exactPolicies.map(policy => ({
      ...policy,
      profile,
      _policyEngineV2: {
        ...policy._policyEngineV2,
        profile,
        deploymentBlocked: policy.serviceDescriptors.some(service => service.deploymentBlocked),
      },
    }));
  const observedTupleSet = new Set(atoms.map(atom =>
    permissionKey(atom.partitionKey, atom.source, atom.destination, atom.service.key)
  ));
  for (const policy of policies) {
    policy._policyEngineV2.deploymentBlocked = policy.serviceDescriptors.some(service => service.deploymentBlocked);
    policy.metrics = evaluatePolicy(observedTupleSet, policy);
  }
  const metrics = evaluatePolicies(atoms, policies);
  const affinityViews = buildAffinityViews(policies);
  const blockers = serviceInventory
    .filter(service => service.deploymentBlocked)
    .map(service => service.classification === 'unresolved-port' ? {
      code: 'MISSING_DSTPORT',
      serviceKey: service.key,
      affectedTuples: atoms.filter(atom => atom.service.key === service.key).length,
      message: 'Le port destination observé est absent ou illisible ; aucune permission FortiGate exacte ne peut être calculée.',
    } : {
      code: 'UNRESOLVED_PROTOCOL_SERVICE',
      serviceKey: service.key,
      affectedTuples: atoms.filter(atom => atom.service.key === service.key).length,
      message: 'Le protocole observé ne fournit pas une définition FortiGate assez précise pour une génération automatique.',
    });
  metrics.blockedRequiredTuples = blockers.reduce((sum, blocker) => sum + blocker.affectedTuples, 0);
  metrics.deployableRequiredTuples = metrics.observedRequiredTuples - metrics.blockedRequiredTuples;
  if ((profile === 'recommended' || profile === 'strict')
    && (metrics.missingRequiredTuples !== 0 || metrics.unexpectedAllowedTuples !== 0)) {
    throw new Error('Policy Engine V2 invariant violation: safe profile changed the required tuple set');
  }
  const expertParameters = profile === 'expert' ? {
    groupingStrategy: 'deterministic-safe-rectangles',
    serviceIdentity: 'protocol-destination-port',
    allowImplicitExpansion: false,
    networkAggregation: false,
  } : undefined;
  return { profile, atoms, policies, metrics, serviceInventory, affinityViews, blockers, inputSummary, expertParameters };
}

module.exports = {
  buildPolicyEngineV2,
  canonicalizeFlows,
  evaluatePolicies,
  normalizeProtocol,
};
