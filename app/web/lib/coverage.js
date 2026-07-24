'use strict';

// ─── Moteur de couverture conservateur (#3) ──────────────────────────────────
//
// Détermine, pour le trafic observé, s'il est DÉJÀ autorisé / bloqué / nouveau
// par rapport aux policies FortiGate existantes.
//
// PRINCIPE DE SÛRETÉ (impératif) : on n'affirme JAMAIS « déjà autorisé » sans
// preuve. La résolution se fait sur des CIDR/ports CONCRETS (pas des noms),
// en respectant l'ordre first-match FortiGate, action, status et interfaces.
// Toute ambiguïté (objet non résolvable, interface inconnue, FQDN) → « incertain »,
// jamais « autorisé ». Sous-estimer la couverture est sûr ; sur-estimer crée un
// trou de segmentation → interdit.

const { ip2int, int2ip, networkAddress, findPredefinedService, PREDEFINED } = require('./forticonfig');
const { flowDecision } = require('./analyzer');

// name → [{port, proto}]  (réciproque de PREDEFINED, indexé par port)
const PREDEF_BY_NAME = (() => {
  const m = {};
  for (const [port, e] of Object.entries(PREDEFINED)) {
    (m[e.name] = m[e.name] || []).push({ port: parseInt(port, 10), proto: e.proto });
  }
  return m;
})();

function stripQuotes(s) { return String(s == null ? '' : s).replace(/^"|"$/g, ''); }

// CIDR/IP → {s, e} (entiers). null si non convertible (FQDN, geo, invalide).
function cidrToRange(cidr) {
  if (!cidr || typeof cidr !== 'string') return null;
  const m = cidr.match(/^(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?$/);
  if (!m) return null;
  const prefix = m[2] === undefined ? 32 : parseInt(m[2], 10);
  if (prefix < 0 || prefix > 32) return null;
  let net;
  try { net = ip2int(networkAddress(m[1], prefix)); } catch { return null; }
  const size = 2 ** (32 - prefix); // 2^(32-prefix) — Number (évite la troncature 32 bits de >>>)
  return { s: net, e: net + size - 1 };
}

function resolveAddrObj(addr) {
  if (!addr) return null;
  if (addr.startInt !== undefined && addr.endInt !== undefined) return { s: addr.startInt, e: addr.endInt };
  if (addr.cidr) { const r = cidrToRange(addr.cidr); if (r) return r; }
  return null; // fqdn / non résolvable
}

// Résout une liste de noms src/dst en plages concrètes.
// unresolvable=true si au moins un membre ne peut être résolu en IP (FQDN, geo, nom inconnu).
function resolveAddrNames(names, addresses, addressGroups) {
  const ranges = [];
  let hasAll = false, unresolvable = false;
  for (const raw of (names || [])) {
    const name = stripQuotes(raw);
    if (!name) continue;
    if (name.toLowerCase() === 'all') { hasAll = true; continue; }
    if (addresses[name]) {
      const r = resolveAddrObj(addresses[name]);
      if (r) ranges.push(r); else unresolvable = true;
    } else if (addressGroups[name]) {
      const cidrs = addressGroups[name].expandedCidrs || [];
      if (!cidrs.length) unresolvable = true;
      for (const c of cidrs) { const r = cidrToRange(c); if (r) ranges.push(r); else unresolvable = true; }
    } else {
      unresolvable = true; // built-in non géré, geography, VIP, etc.
    }
  }
  return { ranges, hasAll, unresolvable };
}

// Résout une liste de noms de services en ensembles de ports concrets.
function resolveServiceNames(names, customServices) {
  const svc = { allAll: false, allTcp: false, allUdp: false, allIcmp: false, tcp: new Set(), udp: new Set(), icmpAny: false, unresolvable: false };
  for (const raw of (names || [])) {
    const name = stripQuotes(raw);
    if (!name) continue;
    const up = name.toUpperCase();
    if (up === 'ALL') { svc.allAll = true; continue; }
    if (up === 'ALL_TCP') { svc.allTcp = true; continue; }
    if (up === 'ALL_UDP') { svc.allUdp = true; continue; }
    if (up === 'ALL_ICMP' || up === 'ALL_ICMP6') { svc.allIcmp = true; continue; }
    const cs = customServices[name];
    if (cs) {
      for (const p of (cs.tcpPorts || [])) svc.tcp.add(p);
      for (const p of (cs.udpPorts || [])) svc.udp.add(p);
      if (cs.proto === 'ICMP' || cs.proto === 'ICMP6') svc.icmpAny = true;
      continue;
    }
    if (PREDEF_BY_NAME[name]) {
      for (const { port, proto } of PREDEF_BY_NAME[name]) {
        if (proto === 'tcp' || proto === 'both') svc.tcp.add(port);
        if (proto === 'udp' || proto === 'both') svc.udp.add(port);
      }
      continue;
    }
    svc.unresolvable = true; // service inconnu (built-in non listé, custom absent)
  }
  return svc;
}

// Pré-résout toutes les policies existantes ACTIVES, dans l'ordre du fichier (first-match).
function resolveExistingPolicies(fortiConfig) {
  const { existingPolicies = [], addresses = {}, addressGroups = {}, customServices = {}, zones = {} } = fortiConfig || {};
  // Map zone (minuscule) → interfaces membres : une règle sur une zone couvre ses interfaces.
  // Les logs FortiAnalyzer rapportent souvent l'interface/VLAN membre, pas le nom de zone.
  const zoneMembers = {};
  for (const [zn, z] of Object.entries(zones)) {
    zoneMembers[String(zn).toLowerCase()] = (z.members || []).map(m => String(m).toLowerCase());
  }
  const expandIntf = (arr) => {
    const out = new Set();
    for (const raw of (arr || [])) {
      const n = stripQuotes(raw).toLowerCase();
      out.add(n);                                        // garde le nom (zone OU interface)
      if (zoneMembers[n]) zoneMembers[n].forEach(m => out.add(m));  // + interfaces membres si zone
    }
    return [...out];
  };
  return existingPolicies
    .filter(p => String(p.status || 'enable').toLowerCase() !== 'disable')
    .map(p => {
      const src = resolveAddrNames(p.srcaddr, addresses, addressGroups);
      const dst = resolveAddrNames(p.dstaddr, addresses, addressGroups);
      const svc = resolveServiceNames(p.service, customServices);
      return {
        policyid: p.policyid,
        name:     p.name || '',
        action:   String(p.action || 'deny').toLowerCase(),
        src, dst, svc,
        srcintf:  expandIntf(p.srcintf),
        dstintf:  expandIntf(p.dstintf),
        unsupported: (p.unsupportedCoverageFeatures || []).length > 0,
        unsupportedCoverageFeatures: p.unsupportedCoverageFeatures || [],
        // règle « large/permissive » : autorise tout en service, ou source/dest = all
        broad:    svc.allAll || src.hasAll || dst.hasAll,
      };
    });
}

// 'yes' | 'no' | 'maybe'
function ipInResolved(ipInt, resolved) {
  if (resolved.hasAll) return 'yes';
  for (const r of resolved.ranges) if (ipInt >= r.s && ipInt <= r.e) return 'yes';
  return resolved.unresolvable ? 'maybe' : 'no';
}

function svcMatch(proto, port, svc) {
  const isUdp  = proto === '17' || /udp/i.test(String(proto));
  const isIcmp = proto === '1'  || proto === '58' || /icmp/i.test(String(proto));
  if (svc.allAll) return 'yes';
  if (isIcmp) { if (svc.allIcmp || svc.icmpAny) return 'yes'; return svc.unresolvable ? 'maybe' : 'no'; }
  if (isUdp)  { if (svc.allUdp || svc.udp.has(port)) return 'yes'; return svc.unresolvable ? 'maybe' : 'no'; }
  // tcp par défaut
  if (svc.allTcp || svc.tcp.has(port)) return 'yes';
  return svc.unresolvable ? 'maybe' : 'no';
}

function intfMatch(flowIntf, polIntf) {
  if (!polIntf || polIntf.length === 0) return 'yes';   // non spécifié → any
  if (polIntf.includes('any')) return 'yes';
  if (!flowIntf) return 'maybe';                          // pas d'info → on ne peut pas prouver le chemin
  return polIntf.includes(String(flowIntf).toLowerCase()) ? 'yes' : 'no';
}

function combine(states) {
  if (states.includes('no')) return 'no';
  if (states.includes('maybe')) return 'maybe';
  return 'yes';
}

// Classe UN flux : { verdict: 'allowed'|'blocked'|'new'|'uncertain', policyid? }
// Itère dans l'ordre (first-match). À la première règle qui matche définitivement,
// l'action décide. Une règle « maybe » (ambiguë) avant tout match définitif →
// 'uncertain' (on ne peut pas garantir le first-match → jamais 'allowed').
function classifyFlow(flow, resolved) {
  let srcInt, dstInt;
  try { srcInt = ip2int(flow.srcip); dstInt = ip2int(flow.dstip); } catch { return { verdict: 'uncertain' }; }
  const port = parseInt(flow.dstport, 10);
  for (const rp of resolved) {
    const s = ipInResolved(srcInt, rp.src);
    if (s === 'no') continue;
    const d = ipInResolved(dstInt, rp.dst);
    if (d === 'no') continue;
    const v = svcMatch(String(flow.proto), port, rp.svc);
    if (v === 'no') continue;
    const si = intfMatch(flow.srcintf, rp.srcintf);
    if (si === 'no') continue;
    const di = intfMatch(flow.dstintf, rp.dstintf);
    if (di === 'no') continue;
    const c = combine([s, d, v, si, di]);
    if (c === 'yes') {
      if (rp.unsupported) {
        return {
          verdict: 'uncertain',
          policyid: rp.policyid,
          unsupportedCoverageFeatures: rp.unsupportedCoverageFeatures,
        };
      }
      return rp.action === 'accept'
        ? { verdict: 'allowed', policyid: rp.policyid, name: rp.name, broad: rp.broad }
        : { verdict: 'blocked', policyid: rp.policyid, name: rp.name };
    }
    return { verdict: 'uncertain', policyid: rp.policyid }; // match ambigu → first-match indéterminé
  }
  return { verdict: 'new' };
}

// Dérive le verdict d'une paire/policy à partir d'un tally de verdicts de flux.
// 'allowed' UNIQUEMENT si 100% des flux sont prouvés autorisés (jamais sur-déclaré).
function deriveVerdict(t) {
  const total = t.allowed + t.blocked + t.new + t.uncertain;
  if (total === 0) return 'new';
  if (t.allowed === total) return 'allowed';
  if (t.blocked === total) return 'blocked';
  if (t.new === total) return 'new';
  if (t.uncertain === total) return 'uncertain';
  if (t.allowed > 0 || t.blocked > 0) return 'partial';
  return t.uncertain > 0 ? 'uncertain' : 'new';
}

// Construit hostPairCoverage : "srcip|dstip" → { verdict, ruleIds[], blockIds[], counts }
// Agrège tous les flux ACCEPT observés pour la paire (tous services confondus).
// verdict='allowed' ⇒ tous les services de la paire sont couverts → toute policy
// dont les services ⊆ ceux de la paire est forcément couverte (sûr, jamais sur-déclaré).
function buildHostPairCoverage(flows, fortiConfig) {
  const resolved = resolveExistingPolicies(fortiConfig);
  const out = {};
  if (!resolved.length) return { hostPairCoverage: out, hasConfig: false };
  for (const f of (flows || [])) {
    if (flowDecision(f) !== 'allow') continue;
    if (!f.srcip || !f.dstip) continue;
    const key = f.srcip + '|' + f.dstip;
    let e = out[key];
    if (!e) e = out[key] = { t: { allowed: 0, blocked: 0, new: 0, uncertain: 0 }, ruleIds: new Set(), blockIds: new Set(), broad: false };
    const r = classifyFlow(f, resolved);
    e.t[r.verdict] += 1;
    if (r.verdict === 'allowed') { if (r.policyid != null) e.ruleIds.add(r.policyid); if (r.broad) e.broad = true; }
    if (r.verdict === 'blocked' && r.policyid != null) e.blockIds.add(r.policyid);
  }
  // Finaliser (Sets → arrays, verdict dérivé) — JSON-safe pour le transport
  const final = {};
  const dbg = { allowed: 0, allowedBroad: 0, blocked: 0, new: 0, uncertain: 0 };
  for (const [k, e] of Object.entries(out)) {
    const v = deriveVerdict(e.t);
    dbg[v] = (dbg[v] || 0) + 1;
    if (v === 'allowed' && e.broad) dbg.allowedBroad++;
    final[k] = { verdict: v, ruleIds: [...e.ruleIds], blockIds: [...e.blockIds], broad: !!e.broad };
  }
  console.log(`[DBG coverage] policies résolues=${resolved.length} paires=${Object.keys(final).length} verdicts=${JSON.stringify(dbg)}`);
  return { hostPairCoverage: final, hasConfig: true };
}

module.exports = {
  buildHostPairCoverage,
  // exportés pour tests unitaires
  resolveExistingPolicies,
  classifyFlow,
  resolveAddrNames,
  resolveServiceNames,
  cidrToRange,
  deriveVerdict,
};
