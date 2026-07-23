'use strict';

const { portName } = require('./ports');

// ─── RFC1918 ──────────────────────────────────────────────────────────────────

function ip2int(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return NaN;
  return parts.reduce((acc, p) => (acc * 256) + parseInt(p, 10), 0);
}

const RFC1918_RANGES = [
  { start: ip2int('10.0.0.0'),    end: ip2int('10.255.255.255')   },
  { start: ip2int('172.16.0.0'),  end: ip2int('172.31.255.255')   },
  { start: ip2int('192.168.0.0'), end: ip2int('192.168.255.255')  },
];

function isPrivate(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const n = ip2int(ip);
  if (isNaN(n)) return false;
  return RFC1918_RANGES.some(r => n >= r.start && n <= r.end);
}

function ipType(ip) {
  return isPrivate(ip) ? 'private' : 'public';
}

function getSubnet24(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

// Longest-prefix match against knownSubnets (sorted most-specific first).
// Falls back to /24 if no match or no knownSubnets provided.
// knownSubnets = [{ prefix: Number, networkInt: Number, cidr: String }]
function getSubnetForIP(ip, knownSubnets) {
  if (knownSubnets && knownSubnets.length > 0) {
    const n = ip2int(ip);
    if (!isNaN(n)) {
      for (const { prefix, networkInt, cidr } of knownSubnets) {
        const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
        if ((n & mask) >>> 0 === networkInt) return cidr;
      }
    }
  }
  return getSubnet24(ip);
}

// ─── Proto labels ─────────────────────────────────────────────────────────────

const PROTO_MAP = { '1': 'ICMP', '6': 'TCP', '17': 'UDP', '47': 'GRE', '50': 'ESP', '89': 'OSPF' };

function protoName(proto) {
  return PROTO_MAP[String(proto)] || (proto ? `PROTO${proto}` : '');
}

const ALLOW_ACTIONS = new Set([
  'accept', 'allow', 'allowed', 'pass', 'close', 'timeout',
  'client-rst', 'server-rst', 'ip-conn',
]);
const DENY_ACTIONS = new Set([
  'deny', 'denied', 'drop', 'dropped', 'block', 'blocked',
  'reject', 'rejected', 'violation',
]);

// Compatibilité avec les imports déjà présents en mémoire : les nouveaux parsers
// fournissent decision, les anciens flux sont normalisés ici avec le même mode fail-closed.
function flowDecision(flow) {
  if (flow && (flow.decision === 'allow' || flow.decision === 'deny')) return flow.decision;
  const action = String(flow?.action || '').toLowerCase().trim();
  if (ALLOW_ACTIONS.has(action)) return 'allow';
  if (DENY_ACTIONS.has(action)) return 'deny';
  return 'unknown';
}

function flowScope(flow) {
  return {
    devid: String(flow?.devid || ''),
    devname: String(flow?.devname || ''),
    vdom: String(flow?.vdom || ''),
  };
}

function flowScopeKey(flow) {
  const scope = flowScope(flow);
  return `${scope.devid || scope.devname || 'unknown-device'}::${scope.vdom || 'root'}`;
}

// ─── Main analysis ────────────────────────────────────────────────────────────

// Single-pass builder: computes all 4 subnet-group variants + port stats in
// one iteration over flows, avoiding 5 separate passes.
function buildAllSubnetGroupsAndPorts(flows, topN = 25, knownSubnets = []) {
  const all          = {};  // all flows
  const allowed      = {};  // accept only (not deny/drop)
  const allowedByIntf = {}; // accept only, keyed by (srcSubnet|srcintf) — for per-interface policy grouping
  const accept       = {};  // accept only (for matrix)
  const deny         = {};  // deny + drop (for matrix + denied count)

  const tcpMap = new Map();
  const udpMap = new Map();
  const subnetOf = (ip) => getSubnetForIP(ip, knownSubnets);

  // groupKey: explicit key override (e.g. "10.1.6.0/24|vlan850"); defaults to srcSubnet
  function addToGroup(groups, flow, groupKey) {
    if (!isPrivate(flow.srcip)) return;
    const srcSubnet = subnetOf(flow.srcip);
    if (!srcSubnet) return;
    const key = groupKey !== undefined ? groupKey : srcSubnet;
    if (!groups[key]) {
      groups[key] = { subnet: srcSubnet, srcIPs: new Set(), dsts: {}, scope: flowScope(flow) };
    }
    const sg = groups[key];
    sg.srcIPs.add(flow.srcip);
    const dstKey  = isPrivate(flow.dstip) ? subnetOf(flow.dstip) : flow.dstip;
    const dstType = isPrivate(flow.dstip) ? 'private' : 'public';
    if (!dstKey) return;
    if (!sg.dsts[dstKey]) {
      sg.dsts[dstKey] = { key: dstKey, type: dstType, ports: new Set(), protos: new Set(), services: new Set(), serviceTuples: new Map(), policyIds: new Set(), dstIPs: new Set(), srcIPs: new Set(), count: 0, sentBytes: 0, rcvdBytes: 0, noRcvdFlows: 0, noRcvdSrcIPs: new Set(), firstTs: null, lastTs: null, days: new Set() };
    }
    const dst = sg.dsts[dstKey];
    if (flow.dstport)  dst.ports.add(flow.dstport);
    if (flow.proto)    dst.protos.add(protoName(flow.proto));
    if (flow.service)  dst.services.add(flow.service.toUpperCase());
    const tupleKey = `${String(flow.proto || '')}|${String(flow.dstport || '')}|${String(flow.service || '').toUpperCase()}`;
    if (!dst.serviceTuples.has(tupleKey)) {
      dst.serviceTuples.set(tupleKey, {
        proto: String(flow.proto || ''),
        port: String(flow.dstport || ''),
        service: String(flow.service || '').toUpperCase(),
        sessions: 0,
      });
    }
    dst.serviceTuples.get(tupleKey).sessions += flow.count;
    if (flow.policyid) dst.policyIds.add(String(flow.policyid));
    if (flow.srcip)    dst.srcIPs.add(flow.srcip);
    if (flow.dstip)    dst.dstIPs.add(flow.dstip);
    dst.count      += flow.count;
    dst.sentBytes  += flow.sentBytes;
    dst.rcvdBytes  += flow.rcvdBytes;
    if ((flow.rcvdBytes || 0) === 0) { dst.noRcvdFlows += flow.count; if (flow.srcip) dst.noRcvdSrcIPs.add(flow.srcip); }
    // #1: stats temporelles (flux agrégés portent firstTs/lastTs/days depuis le parser)
    if (flow.firstTs != null && (dst.firstTs == null || flow.firstTs < dst.firstTs)) dst.firstTs = flow.firstTs;
    if (flow.lastTs  != null && (dst.lastTs  == null || flow.lastTs  > dst.lastTs))  dst.lastTs  = flow.lastTs;
    if (flow.days) for (const d of flow.days) dst.days.add(d);
  }

  for (const f of flows) {
    const decision = flowDecision(f);
    const isDeny   = decision === 'deny';
    const isAccept = decision === 'allow';

    addToGroup(all, f);
    if (isAccept) {
      addToGroup(allowed, f);
      // Isoler les suggestions par équipement/VDOM et par interface observée.
      const srcSubnetKey = isPrivate(f.srcip) ? subnetOf(f.srcip) : null;
      if (srcSubnetKey) {
        const intfKey = f.srcintf ? `${srcSubnetKey}|${f.srcintf}` : srcSubnetKey;
        addToGroup(allowedByIntf, f, `${flowScopeKey(f)}||${intfKey}`);
      }
    }
    if (isAccept) addToGroup(accept, f);
    if (isDeny)   addToGroup(deny, f);

    // Port stats
    const port = parseInt(f.dstport, 10);
    if (port > 0 && port <= 65535) {
      const pn = String(f.proto);
      if (pn === '17' || pn.toUpperCase() === 'UDP') {
        udpMap.set(port, (udpMap.get(port) || 0) + f.count);
      } else {
        tcpMap.set(port, (tcpMap.get(port) || 0) + f.count);
      }
    }
  }

  function toTopList(map, proto) {
    const entries = [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, topN);
    const total = entries.reduce((s, [, c]) => s + c, 0) || 1;
    return entries.map(([port, count]) => ({
      port,
      name:  portName(port, proto),
      count,
      pct:   Math.round((count / total) * 1000) / 10,
    }));
  }

  return {
    subnetGroups:           all,
    allowedSubnetGroups:    allowed,
    allowedByIntfGroups:    allowedByIntf,
    acceptSubnetGroups:     accept,
    denySubnetGroups:       deny,
    portStats: {
      tcp: toTopList(tcpMap, 'TCP'),
      udp: toTopList(udpMap, 'UDP'),
    },
  };
}

function buildAnalysis(flowInput, knownSubnets = []) {
  const flows = Array.isArray(flowInput) ? flowInput : Array.from(flowInput.values());
  const subnetOf = (ip) => getSubnetForIP(ip, knownSubnets);

  // ── Single pass: all subnet groups + port stats ──
  const { subnetGroups, allowedSubnetGroups, allowedByIntfGroups, acceptSubnetGroups, denySubnetGroups, portStats } =
    buildAllSubnetGroupsAndPorts(flows, 25, knownSubnets);

  // ── Global stats (single pass) ──
  const srcIPs = new Set();
  const dstIPs = new Set();
  let totalSessions  = 0;
  let acceptSessions  = 0;
  let denySessions    = 0;
  let unknownSessions = 0;
  let totalBytes      = 0;
  const scopes = new Map();
  // #1: fenêtre d'observation globale
  let captureStartTs = null;
  let captureEndTs   = null;
  const captureDaySet = new Set();

  for (const f of flows) {
    srcIPs.add(f.srcip);
    dstIPs.add(f.dstip);
    totalSessions += f.count;
    totalBytes    += f.sentBytes + f.rcvdBytes;
    const decision = flowDecision(f);
    if (decision === 'allow') {
      acceptSessions += f.count;
    } else if (decision === 'deny') {
      denySessions += f.count;
    } else {
      unknownSessions += f.count;
    }
    const scopeKey = flowScopeKey(f);
    if (!scopes.has(scopeKey)) scopes.set(scopeKey, { key: scopeKey, ...flowScope(f), sessions: 0 });
    scopes.get(scopeKey).sessions += f.count;
    if (f.firstTs != null && (captureStartTs == null || f.firstTs < captureStartTs)) captureStartTs = f.firstTs;
    if (f.lastTs  != null && (captureEndTs   == null || f.lastTs  > captureEndTs))   captureEndTs   = f.lastTs;
    if (f.days) for (const d of f.days) captureDaySet.add(d);
  }

  const temporalDataAvailable = captureStartTs != null;
  const captureDays = captureDaySet.size;

  const srcIPsArr      = [...srcIPs];
  const dstIPsArr      = [...dstIPs];
  const privateSrcIPs  = srcIPsArr.filter(isPrivate);
  const privateDstIPs  = dstIPsArr.filter(isPrivate);
  const srcSubnetsSet  = new Set(privateSrcIPs.map(ip => subnetOf(ip)).filter(Boolean));

  // ── Denied policy groups count ──
  let deniedPolicyGroups = 0;
  for (const [srcSubnet, sg] of Object.entries(denySubnetGroups)) {
    for (const dstKey of Object.keys(sg.dsts)) {
      if (!allowedSubnetGroups[srcSubnet]?.dsts[dstKey]) deniedPolicyGroups++;
    }
  }

  // ── Serialize Sets → Arrays for JSON transport ──
  const subnets = {};
  for (const [key, sg] of Object.entries(subnetGroups)) {
    subnets[key] = {
      subnet:  sg.subnet,
      srcIPs:  [...sg.srcIPs].sort(),
      dstCount: Object.keys(sg.dsts).length,
      dsts: Object.fromEntries(
        Object.entries(sg.dsts).map(([k, d]) => [k, {
          key:       d.key,
          type:      d.type,
          ports:     [...d.ports].map(Number).sort((a, b) => a - b),
          protos:    [...d.protos],
          services:  [...d.services].sort(),
          count:     d.count,
          sentBytes: d.sentBytes,
          rcvdBytes: d.rcvdBytes,
        }])
      ),
    };
  }

  // ── Flows for table view (add computed fields + geo) ──
  const enrichedFlows = flows.map(f => {
    const pn         = protoName(f.proto);
    const resolvedSvc = f.service || portName(f.dstport, pn) || '';
    const dstPriv    = isPrivate(f.dstip);
    return {
      ...f,
      service:    resolvedSvc,
      protoName:  pn,
      srcType:    ipType(f.srcip),
      dstType:    dstPriv ? 'private' : 'public',
      srcSubnet:  isPrivate(f.srcip) ? subnetOf(f.srcip) : null,
      dstSubnet:  dstPriv ? subnetOf(f.dstip) : null,
      totalBytes: f.sentBytes + f.rcvdBytes,
    };
  });

  // ── Policy suggestions (flux acceptés seulement) ──
  const policies = buildPolicies(allowedByIntfGroups, { captureDays, temporalDataAvailable });

  // ── Subnet → interfaces map (src + dst, tous les flows) ───────────────────
  const subnetIntfMap = {};
  for (const f of flows) {
    if (f.srcintf && isPrivate(f.srcip)) {
      const sub = subnetOf(f.srcip);
      if (sub) {
        if (!subnetIntfMap[sub]) subnetIntfMap[sub] = new Set();
        subnetIntfMap[sub].add(f.srcintf);
      }
    }
    if (f.dstintf && isPrivate(f.dstip)) {
      const sub = subnetOf(f.dstip);
      if (sub) {
        if (!subnetIntfMap[sub]) subnetIntfMap[sub] = new Set();
        subnetIntfMap[sub].add(f.dstintf);
      }
    }
  }
  for (const k of Object.keys(subnetIntfMap)) {
    subnetIntfMap[k] = [...subnetIntfMap[k]].sort();
  }

  // ── Matrices accept vs deny (private→private heatmap) ──
  const matrix     = buildMatrix(acceptSubnetGroups);
  const denyMatrix = buildMatrix(denySubnetGroups);
  matrix.subnetIntfMap     = subnetIntfMap;
  denyMatrix.subnetIntfMap = subnetIntfMap;

  return {
    stats: {
      totalSessions,
      uniqueFlows:   flows.length,
      uniqueSrcIPs:  srcIPs.size,
      uniqueDstIPs:  dstIPs.size,
      privateSrcIPs: privateSrcIPs.length,
      privateDstIPs: privateDstIPs.length,
      srcSubnets:    srcSubnetsSet.size,
      acceptSessions,
      denySessions,
      unknownSessions,
      deniedPolicyGroups,
      totalBytes,
      // #1: fenêtre d'observation globale (null si logs sans timestamp)
      captureStart: captureStartTs,
      captureEnd:   captureEndTs,
      captureDays,
      temporalDataAvailable,
    },
    flows:    enrichedFlows,
    subnets,
    policies,
    portStats,
    matrix,
    denyMatrix,
    scopes: [...scopes.values()].sort((a, b) => b.sessions - a.sessions),
  };
}

// ─── Policy suggestions ───────────────────────────────────────────────────────

// #1: niveau de confiance basé UNIQUEMENT sur des faits observés (jamais fabriqué).
// Seuils transparents (exposés à l'UI) :
//  - 'unknown'      : aucune donnée temporelle dans les logs
//  - 'short-window' : capture ≤ 1 jour → impossible de juger la récurrence
//  - 'high'         : vu ≥ 7 jours distincts OU sur ≥ 50 % des jours de la capture
//  - 'low'          : vu un seul jour
//  - 'medium'       : entre les deux
function computeConfidence(daysObserved, captureDays, temporalDataAvailable) {
  if (!temporalDataAvailable || daysObserved == null) return 'unknown';
  if (captureDays <= 1) return 'short-window';
  if (daysObserved >= 7 || daysObserved / captureDays >= 0.5) return 'high';
  if (daysObserved <= 1) return 'low';
  return 'medium';
}

function buildPolicies(subnetGroups, captureCtx = {}) {
  const { captureDays = 0, temporalDataAvailable = false } = captureCtx;
  const policies = [];
  let id = 1;

  for (const [groupKey, sg] of Object.entries(subnetGroups)) {
    // Clé : "device::vdom||10.1.6.0/24|vlan850". Le préfixe de scope
    // empêche toute fusion silencieuse entre équipements ou VDOM.
    const scopeSep = groupKey.indexOf('||');
    const scopedGroupKey = scopeSep >= 0 ? groupKey.slice(scopeSep + 2) : groupKey;
    const pipeIdx = scopedGroupKey.indexOf('|');
    const srcSubnet   = pipeIdx >= 0 ? scopedGroupKey.slice(0, pipeIdx) : scopedGroupKey;
    const flowSrcintf = pipeIdx >= 0 ? scopedGroupKey.slice(pipeIdx + 1) : null;

    for (const [dstKey, dst] of Object.entries(sg.dsts)) {
      const services  = [...dst.services].sort();
      const ports     = [...dst.ports].map(Number).sort((a, b) => a - b);
      const protos    = [...dst.protos];
      const serviceTuples = [...dst.serviceTuples.values()]
        .sort((a, b) => b.sessions - a.sessions || a.proto.localeCompare(b.proto) || Number(a.port || 0) - Number(b.port || 0));
      const daysObserved = dst.days ? dst.days.size : 0;

      // Human-readable service description
      let serviceDesc;
      if (services.length > 0) {
        serviceDesc = services.join(', ');
      } else if (ports.length > 0) {
        const protoLabel = protos[0] || 'TCP';
        serviceDesc = ports.slice(0, 10).map(p => `${p}/${protoLabel}`).join(', ');
        if (ports.length > 10) serviceDesc += ` +${ports.length - 10} autres`;
      } else {
        serviceDesc = protos.join(', ') || 'ANY';
      }

      policies.push({
        id: id++,
        srcSubnet,
        flowSrcintf,   // interface observed in logs — used by analyzePolicies for srcintf detection
        scope:        sg.scope,
        dstTarget:   dstKey,
        dstType:     dst.type,
        services,
        ports,
        protos,
        serviceTuples,
        serviceDesc,
        policyIds:   [...dst.policyIds].sort((a, b) => Number(a) - Number(b)),
        dstIPs:      dst.type === 'public' ? [dstKey] : [],
        srcHosts:    [...dst.srcIPs].sort(),
        dstHosts:    dst.type === 'private' ? [...dst.dstIPs].sort() : [],
        sessions:      dst.count,
        sentBytes:     dst.sentBytes,
        rcvdBytes:     dst.rcvdBytes,
        noRcvdFlows:   dst.noRcvdFlows,
        noRcvdSrcHosts: [...dst.noRcvdSrcIPs],
        // #1: fenêtre d'observation par policy (null si pas de timestamp dans les logs)
        firstSeen:     dst.firstTs,
        lastSeen:      dst.lastTs,
        days:          dst.days ? [...dst.days].sort() : [],   // jours distincts (pour union lors des fusions)
        daysObserved:  temporalDataAvailable ? daysObserved : null,
        confidence:    computeConfidence(temporalDataAvailable ? daysObserved : null, captureDays, temporalDataAvailable),
        action:        'accept',
        // FortiGate-compatible comment
        name:        `FF-${srcSubnet.replace(/\//g, '_').replace(/\./g, '_')}-to-${dstKey.replace(/\//g, '_').replace(/\./g, '_')}`,
      });
    }
  }

  return policies.sort((a, b) => b.sessions - a.sessions);
}

// ─── Heatmap matrix ───────────────────────────────────────────────────────────

// Tri numérique d'une adresse IP/CIDR (ex: "10.0.2.0/24" < "10.0.10.0/24")
function ipSortKey(cidr) {
  const ip = cidr.split('/')[0];
  return ip.split('.').map(n => parseInt(n, 10).toString().padStart(3, '0')).join('.');
}

function buildMatrix(subnetGroups) {
  // Only private→private for the matrix
  const srcSet = new Set(Object.keys(subnetGroups));
  const dstSet = new Set();

  for (const sg of Object.values(subnetGroups)) {
    for (const [key, dst] of Object.entries(sg.dsts)) {
      if (dst.type === 'private') dstSet.add(key);
    }
  }

  // Liste unifiée : mêmes réseaux au même indice sur les deux axes
  const allSubnets = [...new Set([...srcSet, ...dstSet])].sort((a, b) => ipSortKey(a).localeCompare(ipSortKey(b)));
  const srcSubnets = allSubnets;
  const dstSubnets = allSubnets;

  // Build cell list for efficient Canvas rendering
  const cells = [];
  let maxCount = 0;

  for (let si = 0; si < srcSubnets.length; si++) {
    const src = srcSubnets[si];
    const sg  = subnetGroups[src];
    if (!sg) continue; // réseau dst-only, pas de trafic source
    for (let di = 0; di < dstSubnets.length; di++) {
      const dst = sg.dsts[dstSubnets[di]];
      if (!dst) continue;
      cells.push({
        si, di,
        src,
        dst: dstSubnets[di],
        count:    dst.count,
        services: [...dst.services].slice(0, 5),
        ports:    [...dst.ports].map(Number).sort((a, b) => a - b).slice(0, 5),
      });
      if (dst.count > maxCount) maxCount = dst.count;
    }
  }

  return { srcSubnets, dstSubnets, cells, maxCount };
}

// ─── Consolidation engine ─────────────────────────────────────────────────────
// Algorithme 2 passes :
//  1. grouper par (dstTarget + empreinte service) → fusionner les sources
//  2. grouper par (sources triées + empreinte service) → fusionner les destinations

function serviceFingerprint(p) {
  if (p.services && p.services.length > 0)
    return 'S:' + [...p.services].sort().join(',');
  if (p.ports && p.ports.length > 0) {
    const proto = (p.protos && p.protos[0]) || 'TCP';
    return 'P:' + [...p.ports].sort((a, b) => a - b).map(pt => `${pt}/${proto}`).join(',');
  }
  if (p.protos && p.protos.length > 0)
    return 'T:' + [...p.protos].sort().join(',');
  return 'ANY';
}

function consolidatePolicies(rawPolicies) {
  if (!rawPolicies.length) return [];

  // ── Passe 1 : (dstTarget + fp) → regrouper les srcSubnets ──
  const phase1 = new Map();
  for (const p of rawPolicies) {
    const fp  = serviceFingerprint(p);
    const key = `${p.dstTarget}||${fp}`;
    if (!phase1.has(key)) {
      phase1.set(key, {
        srcs: new Set(), dst: p.dstTarget, dstType: p.dstType,
        fp, services: p.services, ports: p.ports, protos: p.protos,
        serviceDesc: p.serviceDesc, sessions: 0, sentBytes: 0, rcvdBytes: 0, noRcvdFlows: 0, noRcvdSrcHosts: [],
      });
    }
    const e = phase1.get(key);
    e.srcs.add(p.srcSubnet);
    e.sessions      += p.sessions;
    e.sentBytes     += p.sentBytes;
    e.rcvdBytes     += p.rcvdBytes;
    e.noRcvdFlows   += (p.noRcvdFlows || 0);
    for (const h of (p.noRcvdSrcHosts || [])) { if (!e.noRcvdSrcHosts.includes(h)) e.noRcvdSrcHosts.push(h); }
  }

  // ── Passe 2 : (sources triées + fp) → regrouper les dstTargets ──
  const phase2 = new Map();
  for (const e of phase1.values()) {
    const srcsKey = [...e.srcs].sort().join('|');
    const key     = `${srcsKey}||${e.fp}`;
    if (!phase2.has(key)) {
      phase2.set(key, {
        srcSubnets: [...e.srcs].sort(), dstTargets: [], dstTypes: {},
        fp: e.fp, services: e.services, ports: e.ports, protos: e.protos,
        serviceDesc: e.serviceDesc, sessions: 0, sentBytes: 0, rcvdBytes: 0, noRcvdFlows: 0, noRcvdSrcHosts: [],
      });
    }
    const g = phase2.get(key);
    g.dstTargets.push(e.dst);
    g.dstTypes[e.dst] = e.dstType;
    g.sessions      += e.sessions;
    g.sentBytes     += e.sentBytes;
    g.rcvdBytes     += e.rcvdBytes;
    g.noRcvdFlows   += e.noRcvdFlows;
    for (const h of (e.noRcvdSrcHosts || [])) { if (!g.noRcvdSrcHosts.includes(h)) g.noRcvdSrcHosts.push(h); }
  }

  let id = 1;
  return [...phase2.values()]
    .sort((a, b) => b.sessions - a.sessions)
    .map(g => {
      const dstTargets = [...g.dstTargets].sort();
      // dstType global : "mixed" si private+public, sinon le type commun
      const types = [...new Set(dstTargets.map(d => g.dstTypes[d]))];
      const dstTypeSummary = types.length > 1 ? 'mixed' : types[0];
      return {
        id:           id++,
        srcSubnets:   g.srcSubnets,
        dstTargets,
        dstTypes:     g.dstTypes,
        dstTypeSummary,
        services:     g.services,
        ports:        g.ports,
        protos:       g.protos,
        serviceDesc:  g.serviceDesc,
        sessions:       g.sessions,
        sentBytes:      g.sentBytes,
        rcvdBytes:      g.rcvdBytes,
        noRcvdFlows:    g.noRcvdFlows,
        noRcvdSrcHosts: g.noRcvdSrcHosts,
        action:         'accept',
        // Combien de policies brutes sont fusionnées ici
        rawCount:     g.srcSubnets.length * dstTargets.length,
        savedCount:   g.srcSubnets.length * dstTargets.length - 1,
        name:         `FF-CONS-${String(id - 1).padStart(3, '0')}`,
      };
    });
}

module.exports = { isPrivate, ipType, getSubnet24, protoName, flowDecision, buildAnalysis, consolidatePolicies };
