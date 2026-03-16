'use strict';

const { portName } = require('./ports');

let geoip;
try { geoip = require('geoip-lite'); } catch { geoip = null; }

// ─── Geo lookup (cache par IP) ────────────────────────────────────────────────

const geoCache = new Map();
const GEO_CACHE_MAX = 5000;
function geoCacheSet(ip, val) {
  if (geoCache.size >= GEO_CACHE_MAX) {
    // Supprime la première entrée (la plus ancienne)
    geoCache.delete(geoCache.keys().next().value);
  }
  geoCache.set(ip, val);
}

function lookupCountry(ip) {
  if (!geoip || !ip) return '';
  if (geoCache.has(ip)) return geoCache.get(ip);
  const result = geoip.lookup(ip);
  const cc = result?.country || '';
  geoCacheSet(ip, cc);
  return cc;
}

// Emoji flag depuis code ISO-2
function countryFlag(cc) {
  if (!cc || cc.length !== 2) return '';
  return String.fromCodePoint(
    ...cc.toUpperCase().split('').map(c => 0x1F1E0 + c.charCodeAt(0) - 65)
  );
}

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

// ─── Proto labels ─────────────────────────────────────────────────────────────

const PROTO_MAP = { '1': 'ICMP', '6': 'TCP', '17': 'UDP', '47': 'GRE', '50': 'ESP', '89': 'OSPF' };

function protoName(proto) {
  return PROTO_MAP[String(proto)] || (proto ? `PROTO${proto}` : '');
}

// ─── Subnet group builder (reusable for any flow subset) ─────────────────────

function buildSubnetGroups(flows) {
  const subnetGroups = {};
  for (const flow of flows) {
    if (!isPrivate(flow.srcip)) continue;
    const srcSubnet = getSubnet24(flow.srcip);
    if (!srcSubnet) continue;

    if (!subnetGroups[srcSubnet]) {
      subnetGroups[srcSubnet] = { subnet: srcSubnet, srcIPs: new Set(), dsts: {} };
    }
    const sg = subnetGroups[srcSubnet];
    sg.srcIPs.add(flow.srcip);

    const dstKey  = isPrivate(flow.dstip) ? getSubnet24(flow.dstip) : flow.dstip;
    const dstType = isPrivate(flow.dstip) ? 'private' : 'public';
    if (!dstKey) continue;

    if (!sg.dsts[dstKey]) {
      sg.dsts[dstKey] = { key: dstKey, type: dstType, ports: new Set(), protos: new Set(), services: new Set(), policyIds: new Set(), dstIPs: new Set(), srcIPs: new Set(), count: 0, sentBytes: 0, rcvdBytes: 0 };
    }
    const dst = sg.dsts[dstKey];
    if (flow.dstport)  dst.ports.add(flow.dstport);
    if (flow.proto)    dst.protos.add(protoName(flow.proto));
    if (flow.service)  dst.services.add(flow.service.toUpperCase());
    if (flow.policyid) dst.policyIds.add(String(flow.policyid));
    if (flow.srcip)    dst.srcIPs.add(flow.srcip);
    if (flow.dstip)    dst.dstIPs.add(flow.dstip);
    dst.count      += flow.count;
    dst.sentBytes  += flow.sentBytes;
    dst.rcvdBytes  += flow.rcvdBytes;
  }
  return subnetGroups;
}

// ─── Main analysis ────────────────────────────────────────────────────────────

function buildAnalysis(flowMap) {
  const flows = Array.from(flowMap.values());

  // ── Global stats ──
  const srcIPs   = new Set(flows.map(f => f.srcip));
  const dstIPs   = new Set(flows.map(f => f.dstip));
  const totalSessions = flows.reduce((s, f) => s + f.count, 0);
  const acceptSessions = flows.filter(f => f.action === 'accept').reduce((s, f) => s + f.count, 0);
  const denySessions   = flows.filter(f => f.action === 'deny' || f.action === 'drop').reduce((s, f) => s + f.count, 0);

  const privateSrcIPs  = [...srcIPs].filter(isPrivate);
  const privateDstIPs  = [...dstIPs].filter(isPrivate);
  const srcSubnetsSet  = new Set(privateSrcIPs.map(getSubnet24).filter(Boolean));

  // ── Subnet groups ──
  // Subnets tab : tous les flows (pour avoir la vue complète du trafic observé)
  const subnetGroups = buildSubnetGroups(flows);

  // Policies : seulement les flows acceptés (deny/drop = déjà bloqué, inutile de créer une allow)
  const allowedFlows = flows.filter(f => f.action !== 'deny' && f.action !== 'drop');
  const allowedSubnetGroups = buildSubnetGroups(allowedFlows);

  // Compter les groupes src→dst purement refusés (pour info UI)
  const denyOnlyGroups = buildSubnetGroups(flows.filter(f => f.action === 'deny' || f.action === 'drop'));
  let deniedPolicyGroups = 0;
  for (const [srcSubnet, sg] of Object.entries(denyOnlyGroups)) {
    for (const dstKey of Object.keys(sg.dsts)) {
      // "purement refusé" = aucune session acceptée pour ce même src→dst
      if (!allowedSubnetGroups[srcSubnet]?.dsts[dstKey]) deniedPolicyGroups++;
    }
  }

  // Serialize Sets → Arrays for JSON transport
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
    const pn        = protoName(f.proto);
    const resolvedSvc = f.service || portName(f.dstport, pn) || '';
    const dstPriv   = isPrivate(f.dstip);
    const dstCountry = !dstPriv ? lookupCountry(f.dstip) : '';
    return {
      ...f,
      service:    resolvedSvc,
      protoName:  pn,
      srcType:    ipType(f.srcip),
      dstType:    dstPriv ? 'private' : 'public',
      srcSubnet:  isPrivate(f.srcip) ? getSubnet24(f.srcip) : null,
      dstSubnet:  dstPriv ? getSubnet24(f.dstip) : null,
      dstCountry,
      dstFlag:    countryFlag(dstCountry),
      totalBytes: f.sentBytes + f.rcvdBytes,
    };
  });

  // ── Port stats top 25 TCP + UDP ──
  const portStats = buildPortStats(flows);

  // ── Geo enrichment dans subnets (destinations publiques) ──
  for (const sg of Object.values(subnets)) {
    for (const [dstKey, dst] of Object.entries(sg.dsts)) {
      if (dst.type === 'public') {
        const cc = lookupCountry(dstKey);
        dst.country = cc;
        dst.flag    = countryFlag(cc);
      }
    }
  }

  // ── Policy suggestions (flux acceptés seulement) ──
  const policies = buildPolicies(allowedSubnetGroups);

  // ── Matrices accept vs deny (private→private heatmap) ──
  const acceptFlows = flows.filter(f => f.action === 'accept');
  const denyFlows   = flows.filter(f => f.action === 'deny' || f.action === 'drop');
  const matrix      = buildMatrix(buildSubnetGroups(acceptFlows));
  const denyMatrix  = buildMatrix(buildSubnetGroups(denyFlows));

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
      deniedPolicyGroups,
      totalBytes:    flows.reduce((s, f) => s + f.sentBytes + f.rcvdBytes, 0),
    },
    flows:    enrichedFlows,
    subnets,
    policies,
    portStats,
    matrix,
    denyMatrix,
  };
}

// ─── Top ports stats ──────────────────────────────────────────────────────────

function buildPortStats(flows, topN = 25) {
  const tcpMap = new Map(); // port → count
  const udpMap = new Map();

  for (const f of flows) {
    const port = parseInt(f.dstport, 10);
    if (!port || port <= 0 || port > 65535) continue;
    const pn = String(f.proto);
    if (pn === '17' || pn.toUpperCase() === 'UDP') {
      udpMap.set(port, (udpMap.get(port) || 0) + f.count);
    } else {
      tcpMap.set(port, (tcpMap.get(port) || 0) + f.count);
    }
  }

  function toTopList(map, proto) {
    const total = [...map.values()].reduce((s, c) => s + c, 0) || 1;
    return [...map.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, topN)
      .map(([port, count]) => ({
        port,
        name:  portName(port, proto),
        count,
        pct:   Math.round((count / total) * 1000) / 10,
      }));
  }

  return {
    tcp: toTopList(tcpMap, 'TCP'),
    udp: toTopList(udpMap, 'UDP'),
  };
}

// ─── Policy suggestions ───────────────────────────────────────────────────────

function buildPolicies(subnetGroups) {
  const policies = [];
  let id = 1;

  for (const [srcSubnet, sg] of Object.entries(subnetGroups)) {
    for (const [dstKey, dst] of Object.entries(sg.dsts)) {
      const services  = [...dst.services].sort();
      const ports     = [...dst.ports].map(Number).sort((a, b) => a - b);
      const protos    = [...dst.protos];

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
        dstTarget:   dstKey,
        dstType:     dst.type,
        services,
        ports:       ports.slice(0, 20),
        protos,
        serviceDesc,
        policyIds:   [...dst.policyIds].sort((a, b) => Number(a) - Number(b)),
        dstIPs:      dst.type === 'public' ? [dstKey] : [],
        srcHosts:    [...dst.srcIPs].sort(),
        dstHosts:    dst.type === 'private' ? [...dst.dstIPs].sort() : [],
        sessions:    dst.count,
        sentBytes:   dst.sentBytes,
        rcvdBytes:   dst.rcvdBytes,
        action:      'accept',
        // FortiGate-compatible comment
        name:        `FF-${srcSubnet.replace(/\//g, '_').replace(/\./g, '_')}-to-${dstKey.replace(/\//g, '_').replace(/\./g, '_')}`,
      });
    }
  }

  return policies.sort((a, b) => b.sessions - a.sessions);
}

// ─── Heatmap matrix ───────────────────────────────────────────────────────────

function buildMatrix(subnetGroups) {
  // Only private→private for the matrix
  const srcSubnets = Object.keys(subnetGroups).sort();
  const dstSet = new Set();

  for (const sg of Object.values(subnetGroups)) {
    for (const [key, dst] of Object.entries(sg.dsts)) {
      if (dst.type === 'private') dstSet.add(key);
    }
  }
  const dstSubnets = [...dstSet].sort();

  // Build cell list for efficient Canvas rendering
  const cells = [];
  let maxCount = 0;

  for (let si = 0; si < srcSubnets.length; si++) {
    const src = srcSubnets[si];
    const sg  = subnetGroups[src];
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
        serviceDesc: p.serviceDesc, sessions: 0, sentBytes: 0, rcvdBytes: 0,
      });
    }
    const e = phase1.get(key);
    e.srcs.add(p.srcSubnet);
    e.sessions  += p.sessions;
    e.sentBytes += p.sentBytes;
    e.rcvdBytes += p.rcvdBytes;
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
        serviceDesc: e.serviceDesc, sessions: 0, sentBytes: 0, rcvdBytes: 0,
      });
    }
    const g = phase2.get(key);
    g.dstTargets.push(e.dst);
    g.dstTypes[e.dst] = e.dstType;
    g.sessions  += e.sessions;
    g.sentBytes += e.sentBytes;
    g.rcvdBytes += e.rcvdBytes;
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
        sessions:     g.sessions,
        sentBytes:    g.sentBytes,
        rcvdBytes:    g.rcvdBytes,
        action:       'accept',
        // Combien de policies brutes sont fusionnées ici
        rawCount:     g.srcSubnets.length * dstTargets.length,
        savedCount:   g.srcSubnets.length * dstTargets.length - 1,
        name:         `FF-CONS-${String(id - 1).padStart(3, '0')}`,
      };
    });
}

module.exports = { isPrivate, ipType, getSubnet24, protoName, buildAnalysis, consolidatePolicies };
