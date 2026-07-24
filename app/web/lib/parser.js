'use strict';

const fs       = require('fs');
const path     = require('path');
const readline = require('readline');
const zlib     = require('zlib');
const { Transform } = require('stream');

const configuredDecompressedMb = Number.parseInt(process.env.MAX_DECOMPRESSED_SIZE_MB || '4096', 10);
const MAX_DECOMPRESSED_BYTES = (
  Number.isFinite(configuredDecompressedMb) && configuredDecompressedMb > 0
    ? Math.min(configuredDecompressedMb, 32768)
    : 4096
) * 1024 * 1024;
const configuredZipEntries = Number.parseInt(process.env.MAX_ARCHIVE_ENTRIES || '100', 10);
const MAX_ARCHIVE_ENTRIES = Number.isFinite(configuredZipEntries) && configuredZipEntries > 0
  ? Math.min(configuredZipEntries, 1000)
  : 100;
const configuredDedupeKeys = Number.parseInt(process.env.MAX_SESSION_DEDUPE_KEYS || '2000000', 10);
const MAX_SESSION_DEDUPE_KEYS = Number.isFinite(configuredDedupeKeys) && configuredDedupeKeys > 0
  ? configuredDedupeKeys
  : 2000000;
const configuredXlsxMb = Number.parseInt(process.env.MAX_XLSX_SIZE_MB || '100', 10);
const MAX_XLSX_BYTES = (
  Number.isFinite(configuredXlsxMb) && configuredXlsxMb > 0
    ? Math.min(configuredXlsxMb, 512)
    : 100
) * 1024 * 1024;

function decompressedLimitStream(shared = { bytes: 0 }) {
  return new Transform({
    transform(chunk, _encoding, callback) {
      shared.bytes += chunk.length;
      if (shared.bytes > MAX_DECOMPRESSED_BYTES) {
        const error = new Error(
          `Contenu décompressé trop volumineux (limite ${Math.round(MAX_DECOMPRESSED_BYTES / 1024 / 1024)} Mo)`
        );
        error.code = 'DECOMPRESSED_SIZE_LIMIT';
        callback(error);
        return;
      }
      callback(null, chunk);
    },
  });
}

// ─── Key=Value parser ─────────────────────────────────────────────────────────

function parseKV(line) {
  // R1: regex locale + matchAll — aucun état `lastIndex` partagé entre appels/streams concurrents.
  const re = /(\w+)=("(?:[^"\\]|\\.)*"|[^\s"]\S*)/g;
  const fields = {};
  for (const m of line.matchAll(re)) {
    let val = m[2];
    if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
    fields[m[1]] = val;
  }
  return fields;
}

// ─── CSV parser ───────────────────────────────────────────────────────────────

function parseCSVLine(line, sep) {
  const result = [];
  let cur = '';
  let inQ = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQ && line[i + 1] === '"') { cur += '"'; i++; }
      else inQ = !inQ;
    } else if (ch === sep && !inQ) {
      result.push(cur); cur = '';
    } else {
      cur += ch;
    }
  }
  result.push(cur);
  return result;
}

// FortiAnalyzer CSV headers → internal field names (étendu)
const HEADER_MAP = {
  // Source IP — variantes FortiAnalyzer / FortiGate / export manuel
  srcip: 'srcip', src_ip: 'srcip', source_ip: 'srcip',
  'source ip': 'srcip', 'src ip': 'srcip', sourceip: 'srcip',
  'ip source': 'srcip', 'ip src': 'srcip', source: 'srcip',
  'source address': 'srcip', 'source ip address': 'srcip',
  'adresse source': 'srcip', 'adresse ip source': 'srcip',

  // Destination IP
  dstip: 'dstip', dst_ip: 'dstip', destination_ip: 'dstip',
  'destination ip': 'dstip', 'dst ip': 'dstip', destinationip: 'dstip',
  'ip destination': 'dstip', 'ip dst': 'dstip', destination: 'dstip',
  'destination address': 'dstip', 'destination ip address': 'dstip',
  'adresse destination': 'dstip', 'adresse ip destination': 'dstip',

  // Source port
  srcport: 'srcport', src_port: 'srcport', sourceport: 'srcport',
  'source port': 'srcport', 'src port': 'srcport', 'port source': 'srcport', sport: 'srcport',

  // Destination port
  dstport: 'dstport', dst_port: 'dstport', destinationport: 'dstport',
  'destination port': 'dstport', 'dst port': 'dstport', 'port destination': 'dstport', dport: 'dstport',

  // Protocol
  proto: 'proto', protocol: 'proto', protocole: 'proto', 'ip protocol': 'proto', ip_protocol: 'proto',

  // Action
  action: 'action', verdict: 'action',

  // Service
  service: 'service', 'service name': 'service', servicename: 'service', app: 'service',

  // Interfaces
  srcintf: 'srcintf', src_intf: 'srcintf', srcinterface: 'srcintf',
  'source interface': 'srcintf', 'src interface': 'srcintf', 'interface source': 'srcintf', ingressintf: 'srcintf',
  dstintf: 'dstintf', dst_intf: 'dstintf', dstinterface: 'dstintf',
  'destination interface': 'dstintf', 'dst interface': 'dstintf', 'interface destination': 'dstintf', egressintf: 'dstintf',

  // Policy
  policyid: 'policyid', policy_id: 'policyid', ruleid: 'policyid',
  'policy id': 'policyid',
  policyname: 'policyname', 'policy name': 'policyname', rulename: 'policyname',

  // Bytes
  sentbyte: 'sentbyte', sent_byte: 'sentbyte', sentbytes: 'sentbyte',
  'bytes sent': 'sentbyte', 'sent bytes': 'sentbyte', txbytes: 'sentbyte',
  rcvdbyte: 'rcvdbyte', rcvd_byte: 'rcvdbyte', rcvdbytes: 'rcvdbyte',
  'bytes received': 'rcvdbyte', 'rcvd bytes': 'rcvdbyte', rxbytes: 'rcvdbyte',

  // Date / time
  date: 'date', time: 'time', datetime: 'date', timestamp: 'date',
  eventtime: 'eventtime', itime: 'eventtime',

  // Scope FortiGate / FortiAnalyzer — indispensable en environnement multi-équipements / multi-VDOM
  devname: 'devname', device: 'devname', 'device name': 'devname', hostname: 'devname',
  devid: 'devid', device_id: 'devid', 'device id': 'devid', serial: 'devid',
  vd: 'vd', vdom: 'vd', 'virtual domain': 'vd',

  // Session / volumétrie complémentaire
  sessionid: 'sessionid', session_id: 'sessionid', 'session id': 'sessionid',
  logid: 'logid', log_id: 'logid', 'log id': 'logid',
  poluuid: 'poluuid', policyuuid: 'poluuid', 'policy uuid': 'poluuid',
  duration: 'duration', sentpkt: 'sentpkt', sent_pkts: 'sentpkt', 'packets sent': 'sentpkt',
  rcvdpkt: 'rcvdpkt', rcvd_pkts: 'rcvdpkt', 'packets received': 'rcvdpkt',

  // Contexte de preuve : évite de transformer un trafic local, NATé ou non
  // qualifié en règle firewall forward.
  subtype: 'subtype', sub_type: 'subtype', 'log subtype': 'subtype',
  policytype: 'policytype', policy_type: 'policytype', 'policy type': 'policytype',
  trandisp: 'trandisp', translation: 'trandisp', 'translation disposition': 'trandisp',
  transip: 'transip', translated_ip: 'transip', 'translated ip': 'transip',
  transport: 'transport', translated_port: 'transport', 'translated port': 'transport',
  msg: 'msg', message: 'msg',
};

// Services UDP par défaut (quand le champ proto est absent)
const UDP_SERVICES = new Set([
  'DNS', 'DHCP', 'NTP', 'SNMP', 'SNMPTRAP', 'SYSLOG', 'TFTP',
  'RIP', 'MDNS', 'LLMNR', 'BOOTP', 'RADIUS', 'ISAKMP', 'IKE',
]);

// Ne jamais considérer une action inconnue comme autorisée. Les logs de fin de session
// FortiOS utilisent notamment close/timeout/client-rst/server-rst pour des sessions acceptées.
const ALLOW_ACTIONS = new Set([
  'accept', 'allow', 'allowed', 'pass', 'start', 'close', 'timeout',
  'client-rst', 'server-rst', 'ip-conn',
]);
const DENY_ACTIONS = new Set([
  'deny', 'denied', 'drop', 'dropped', 'block', 'blocked',
  'reject', 'rejected', 'violation',
]);

function normalizeDecision(action, context = {}) {
  const value = String(action || '').toLowerCase().trim();
  if (ALLOW_ACTIONS.has(value)) return 'allow';
  if (DENY_ACTIONS.has(value)) return 'deny';

  // FortiOS journalise certaines tentatives DNS non abouties avec action="dns"
  // et msg="Connection Failed". Ce n'est ni une autorisation ni un refus :
  // garder une classe dédiée empêche de créer une règle à partir d'un échec connu.
  const message = String(context.msg || '').toLowerCase().trim();
  const dstport = String(context.dstport || '').trim();
  const proto = String(context.proto || '').toLowerCase().trim();
  if (value === 'dns' && message === 'connection failed' && dstport === '53' && (proto === '17' || proto === 'udp')) {
    return 'failed';
  }

  return 'unknown';
}

// ─── Format detection ─────────────────────────────────────────────────────────

function countDelimiterOutsideQuotes(line, delimiter) {
  let count = 0;
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '"') {
      if (inQuotes && line[i + 1] === '"') i++;
      else inQuotes = !inQuotes;
    } else if (!inQuotes && line[i] === delimiter) {
      count++;
    }
  }
  return count;
}

function separatorLabel(sep) {
  if (sep === '\t') return 'tabulation';
  if (sep === ';') return 'point-virgule';
  if (sep === '|') return 'barre verticale';
  return 'virgule';
}

function normalizeCsvHeader(value) {
  return String(value ?? '')
    .replace(/^\uFEFF/, '')
    .toLowerCase()
    .trim()
    .replace(/^"|"$/g, '')
    .replace(/\s+/g, ' ');
}

function mapAndValidateCsvHeaders(parts, sep) {
  const rawHeaders = parts.map(normalizeCsvHeader);
  const headers = rawHeaders.map(h => HEADER_MAP[h] || h);
  const required = ['srcip', 'dstip', 'action'];
  const missing = required.filter(h => !headers.includes(h));
  const hasServiceEvidence = ['dstport', 'service', 'proto'].some(h => headers.includes(h));

  if (missing.length || !hasServiceEvidence) {
    const expected = [...missing, ...(!hasServiceEvidence ? ['dstport/service/proto'] : [])];
    const detected = rawHeaders.filter(Boolean).slice(0, 15).join(', ') || 'aucune';
    throw new Error(
      `CSV détecté (séparateur : ${separatorLabel(sep)}), mais colonnes obligatoires introuvables : ${expected.join(', ')}. ` +
      `Colonnes détectées : ${detected}. Exportez au minimum les IP source/destination, l’action et le service ou port/protocole.`
    );
  }

  return headers;
}

function parseDelimitedKvRow(line, sep) {
  const fields = {};
  for (const rawCell of parseCSVLine(line, sep)) {
    const cell = rawCell.trim();
    if (!cell) continue;
    const eq = cell.indexOf('=');
    if (eq <= 0) continue;
    const key = cell.slice(0, eq).trim();
    if (!/^\w+$/.test(key)) continue;
    let value = cell.slice(eq + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    fields[key] = value;
  }
  return fields;
}

function countDelimitedKvCells(line, sep) {
  let count = 0;
  for (const cell of parseCSVLine(line, sep)) {
    if (/^\s*\w+=/.test(cell)) count++;
    if (count >= 3) return count;
  }
  return count;
}

function detectFormat(firstLine) {
  // Les exports FAZ "CSV" peuvent ne pas avoir d’en-tête : chaque ligne est une
  // suite de cellules "clé=valeur". Cette forme doit être reconnue avant le KV
  // classique, sinon sa première valeur absorbe toute la ligne.
  const candidates = ['\t', ',', ';', '|']
    .map(sep => ({ sep, count: countDelimiterOutsideQuotes(firstLine, sep) }))
    .sort((a, b) => b.count - a.count);
  if (candidates[0].count >= 1 && countDelimitedKvCells(firstLine, candidates[0].sep) >= 3) {
    return { format: 'csv-kv', sep: candidates[0].sep };
  }

  // Un vrai log KV FortiAnalyzer contient de nombreux couples key=val sur une ligne.
  const kvCount = (firstLine.match(/\b\w+=\S/g) || []).length;
  if (kvCount >= 3) return { format: 'kv', sep: null };

  // CSV à en-têtes classique.
  if (candidates[0].count >= 1) return { format: 'csv', sep: candidates[0].sep };

  return { format: 'kv', sep: null };
}

// ─── IP validation ───────────────────────────────────────────────────────────

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isValidIPv4(ip) {
  if (!ip) return false;
  const m = IPV4_RE.exec(ip);
  if (!m) return false;
  return +m[1] <= 255 && +m[2] <= 255 && +m[3] <= 255 && +m[4] <= 255;
}

// ─── Flow extraction ──────────────────────────────────────────────────────────

// Timestamp epoch (ms) du flux : eventtime prioritaire, sinon date+time. null si absent.
// On ne fabrique jamais de date — si la source ne fournit rien, ts reste null (#1).
function flowTimestamp(fields) {
  const et = parseInt(fields.eventtime || '', 10);
  if (et) {
    // eventtime FortiOS varie selon la version : secondes / ms / µs / NANOSECONDES (19 chiffres).
    // Normaliser en millisecondes d'après l'ordre de grandeur (sinon Date hors plage → crash rendu).
    if (et >= 1e18) return Math.floor(et / 1e6);   // nanosecondes → ms
    if (et >= 1e15) return Math.floor(et / 1e3);   // microsecondes → ms
    if (et >= 1e12) return et;                      // millisecondes
    return et * 1000;                               // secondes → ms
  }
  const d = (fields.date || '').trim();
  if (d) {
    const t = (fields.time || '').trim();
    const parsed = Date.parse(t ? `${d}T${t}` : d);
    if (!isNaN(parsed)) return parsed;
  }
  return null;
}

// Jour observé (YYYY-MM-DD). On privilégie le champ `date` brut (exact, sans décalage TZ),
// sinon on dérive du ts. null si rien.
function flowDay(fields, ts) {
  const d = (fields.date || '').trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(d)) return d;
  if (ts != null) return new Date(ts).toISOString().slice(0, 10);
  return null;
}

function extractFlow(fields) {
  const service = (fields.service || '').toUpperCase().trim();
  let proto = (fields.proto || '').trim();
  let protoSource = proto ? 'explicit' : 'missing';

  // Normaliser les chaînes protocole → chiffres
  if (/^tcp$/i.test(proto))  proto = '6';
  if (/^udp$/i.test(proto))  proto = '17';
  if (/^icmp$/i.test(proto)) proto = '1';

  // Compatibilité d'analyse : un protocole absent peut être estimé pour
  // l'affichage, mais cette estimation n'est jamais une preuve de déploiement.
  if (!proto && service) {
    proto = UDP_SERVICES.has(service) ? '17' : '6';
    protoSource = 'inferred-service';
  }

  const srcip = (fields.srcip || '').trim();
  const dstip = (fields.dstip || '').trim();
  const unsupportedReason = (srcip.includes(':') || dstip.includes(':')) ? 'ipv6' : null;

  const ts       = flowTimestamp(fields);
  const day      = flowDay(fields, ts);
  const action   = (fields.action || '').toLowerCase().trim();
  const decision = normalizeDecision(action, { ...fields, proto, service });
  const subtype  = String(fields.subtype || '').toLowerCase().trim();
  const policytype = String(fields.policytype || '').toLowerCase().trim();
  const trandisp = String(fields.trandisp || '').toLowerCase().trim();
  const dstport = String(fields.dstport || '').trim();
  const evidenceIssues = [];

  if (decision === 'allow') {
    if (protoSource !== 'explicit') evidenceIssues.push('protocol_inferred');

    const protoNumber = parseInt(proto, 10);
    if (![1, 6, 17].includes(protoNumber)) {
      evidenceIssues.push('unsupported_protocol');
    } else if ((protoNumber === 6 || protoNumber === 17)
      && (!/^\d+$/.test(dstport) || Number(dstport) < 1 || Number(dstport) > 65535)) {
      evidenceIssues.push('invalid_destination_port');
    }

    if ((subtype && subtype !== 'forward') || /local/.test(policytype)) {
      evidenceIssues.push('non_forward_traffic');
    }

    const hasForwardProof = subtype === 'forward'
      || (String(fields.srcintf || '').trim()
        && String(fields.dstintf || '').trim()
        && String(fields.policyid || '').trim());
    if (!hasForwardProof) evidenceIssues.push('forward_context_missing');

    if (trandisp && !['noop', 'none', '0'].includes(trandisp)) {
      evidenceIssues.push('nat_translation');
    }
  }

  return {
    srcip:    isValidIPv4(srcip) ? srcip : '',
    dstip:    isValidIPv4(dstip) ? dstip : '',
    unsupportedReason,
    srcport:  fields.srcport  || '',
    dstport,
    proto,
    protoSource,
    action,
    decision,
    service,
    srcintf:    fields.srcintf    || '',
    dstintf:    fields.dstintf    || '',
    policyid:   fields.policyid   || '',
    policyname: fields.policyname || '',
    devname:    (fields.devname || '').trim(),
    devid:      (fields.devid || '').trim(),
    vdom:       (fields.vd || '').trim(),
    sessionid:  (fields.sessionid || '').trim(),
    logid:      (fields.logid || '').trim(),
    poluuid:    (fields.poluuid || '').trim(),
    subtype,
    policytype,
    trandisp,
    transip:    String(fields.transip || '').trim(),
    transport:  String(fields.transport || '').trim(),
    evidenceIssues,
    deploymentEligible: evidenceIssues.length === 0,
    date:     fields.date     || '',
    time:     fields.time     || '',
    ts,                       // epoch ms ou null (#1)
    day,                      // 'YYYY-MM-DD' ou null (#1)
    sentbyte: parseInt(fields.sentbyte || 0, 10) || 0,
    rcvdbyte: parseInt(fields.rcvdbyte || 0, 10) || 0,
    sentpkt:  parseInt(fields.sentpkt  || 0, 10) || 0,
    rcvdpkt:  parseInt(fields.rcvdpkt  || 0, 10) || 0,
    duration: parseInt(fields.duration || 0, 10) || 0,
  };
}

// ─── Flow aggregation helper ──────────────────────────────────────────────────

function createDedupeState() {
  return {
    sessions: new Map(),
    duplicateRecords: 0,
    sessionRecords: 0,
    saturated: false,
  };
}

function flowSessionKey(flow) {
  if (!flow.sessionid) return '';
  return [
    flow.devid || flow.devname,
    flow.vdom,
    flow.sessionid,
    flow.srcip,
    flow.srcport,
    flow.dstip,
    flow.dstport,
    flow.proto,
    flow.policyid || flow.poluuid,
    flow.srcintf,
    flow.dstintf,
    flow.subtype,
    flow.policytype,
    flow.trandisp,
  ].join('|');
}

const TERMINAL_SESSION_ACTIONS = new Set(['close', 'timeout', 'client-rst', 'server-rst']);

function sessionMetrics(flow) {
  return {
    sentbyte: flow.sentbyte,
    rcvdbyte: flow.rcvdbyte,
    sentpkt: flow.sentpkt,
    rcvdpkt: flow.rcvdpkt,
    duration: flow.duration,
  };
}

function aggregateFlow(flowMap, flow, dedupeState = null) {
  if (!flow.srcip || !flow.dstip) return false;
  // Le scope équipement/VDOM fait partie de l'identité du flux : deux VDOM peuvent
  // légitimement utiliser les mêmes réseaux RFC1918 sans représenter le même contexte.
  // Le libellé de service n'est pas une identité réseau : FortiOS peut ne le
  // renseigner qu'au log terminal. Le tuple protocole/port reste la preuve.
  const key = `${flow.devid || flow.devname}|${flow.vdom}|${flow.srcip}|${flow.dstip}|${flow.dstport}|${flow.proto}|${flow.decision}|${flow.srcintf}|${flow.dstintf}|${flow.policyid}|${flow.subtype}|${flow.policytype}|${flow.trandisp}|${flow.evidenceIssues.join(',')}`;
  if (!flowMap.has(key)) {
    flowMap.set(key, {
      srcip: flow.srcip, dstip: flow.dstip,
      srcport: flow.srcport, dstport: flow.dstport,
      proto: flow.proto, action: flow.action, decision: flow.decision, service: flow.service,
      srcintf: flow.srcintf, dstintf: flow.dstintf, policyid: flow.policyid, policyname: flow.policyname,
      devname: flow.devname, devid: flow.devid, vdom: flow.vdom,
      logid: flow.logid, poluuid: flow.poluuid,
      protoSource: flow.protoSource,
      subtype: flow.subtype, policytype: flow.policytype, trandisp: flow.trandisp,
      transip: flow.transip, transport: flow.transport,
      evidenceIssues: flow.evidenceIssues,
      deploymentEligible: flow.deploymentEligible,
      count: 0, sentBytes: 0, rcvdBytes: 0, sentPackets: 0, rcvdPackets: 0, duration: 0,
      firstTs: null, lastTs: null, days: [],   // #1: stats temporelles (days = tableau, JSON-safe)
    });
  }
  const e = flowMap.get(key);
  if (!e.service && flow.service) e.service = flow.service;

  const sessionKey = dedupeState ? flowSessionKey(flow) : '';
  if (sessionKey && !dedupeState.saturated) {
    dedupeState.sessionRecords++;
    const previous = dedupeState.sessions.get(sessionKey);
    // Un nouvel événement start après une terminaison explicite indique une
    // réutilisation de l'identifiant FortiOS : il s'agit bien d'une autre session.
    const reusedSession = previous
      && flow.action === 'start'
      && previous.terminal;
    if (previous && !reusedSession) {
      dedupeState.duplicateRecords++;
      // Les compteurs FortiOS sont cumulatifs. Ajouter uniquement leur progression
      // neutralise les doublons exacts et conserve la valeur terminale maximale.
      e.sentBytes   += Math.max(0, flow.sentbyte - previous.metrics.sentbyte);
      e.rcvdBytes   += Math.max(0, flow.rcvdbyte - previous.metrics.rcvdbyte);
      e.sentPackets += Math.max(0, flow.sentpkt  - previous.metrics.sentpkt);
      e.rcvdPackets += Math.max(0, flow.rcvdpkt  - previous.metrics.rcvdpkt);
      e.duration     += Math.max(0, flow.duration - previous.metrics.duration);
      previous.metrics.sentbyte = Math.max(previous.metrics.sentbyte, flow.sentbyte);
      previous.metrics.rcvdbyte = Math.max(previous.metrics.rcvdbyte, flow.rcvdbyte);
      previous.metrics.sentpkt  = Math.max(previous.metrics.sentpkt, flow.sentpkt);
      previous.metrics.rcvdpkt  = Math.max(previous.metrics.rcvdpkt, flow.rcvdpkt);
      previous.metrics.duration = Math.max(previous.metrics.duration, flow.duration);
      previous.terminal ||= TERMINAL_SESSION_ACTIONS.has(flow.action);
      if (flow.ts != null) {
        if (e.firstTs == null || flow.ts < e.firstTs) e.firstTs = flow.ts;
        if (e.lastTs  == null || flow.ts > e.lastTs)  e.lastTs  = flow.ts;
      }
      if (flow.day && !e.days.includes(flow.day)) e.days.push(flow.day);
      return true;
    }
    if (dedupeState.sessions.size >= MAX_SESSION_DEDUPE_KEYS && !reusedSession) {
      dedupeState.saturated = true;
      dedupeState.sessions.clear();
    } else {
      dedupeState.sessions.set(sessionKey, {
        metrics: sessionMetrics(flow),
        terminal: TERMINAL_SESSION_ACTIONS.has(flow.action),
      });
    }
  }

  e.count++;
  e.sentBytes   += flow.sentbyte;
  e.rcvdBytes   += flow.rcvdbyte;
  e.sentPackets += flow.sentpkt;
  e.rcvdPackets += flow.rcvdpkt;
  e.duration     += flow.duration;
  // #1: conserver la granularité temporelle perdue auparavant (clé de dédup inchangée).
  if (flow.ts != null) {
    if (e.firstTs == null || flow.ts < e.firstTs) e.firstTs = flow.ts;
    if (e.lastTs  == null || flow.ts > e.lastTs)  e.lastTs  = flow.ts;
  }
  if (flow.day && !e.days.includes(flow.day)) e.days.push(flow.day);  // jours distincts (peu nombreux)
  return true;
}

// ─── Core streaming parser (text streams) ─────────────────────────────────────

async function parseStream(inputStream, onProgress, sharedDedupeState = null) {
  const flowMap = new Map();
  const dedupeState = sharedDedupeState || createDedupeState();
  let lineCount = 0;
  let skipped   = 0;
  const skipReasons = { nonTraffic: 0, invalidFlow: 0, ipv6: 0, archiveEntryError: 0 };
  let format    = null;
  let sep       = null;
  let csvHeaders = null;
  const startTs = Date.now();

  const rl = readline.createInterface({ input: inputStream, crlfDelay: Infinity });

  for await (const rawLine of rl) {
    const line = rawLine.trim();
    if (!line) continue;
    lineCount++;

    if (onProgress && lineCount % 50000 === 0) {
      const elapsed    = (Date.now() - startTs) / 1000;
      const linesPerSec = elapsed > 0 ? Math.round(lineCount / elapsed) : 0;
      onProgress({ lines: lineCount, linesPerSec });
    }

    if (!format) {
      // Directive optionnelle produite par Excel selon la locale : "sep=;".
      const sepDirective = /^sep=(.)$/i.exec(line);
      if (sepDirective) {
        format = 'csv';
        sep = sepDirective[1];
        continue;
      }
      const det = detectFormat(line);
      format = det.format;
      sep    = det.sep;
    }

    let fields;

    if (format === 'kv' || format === 'csv-kv') {
      fields = format === 'csv-kv' ? parseDelimitedKvRow(line, sep) : parseKV(line);
      const t = fields.type;
      if (t && t !== 'traffic') { skipped++; skipReasons.nonTraffic++; continue; }
    } else {
      const parts = parseCSVLine(line, sep);
      if (!csvHeaders) {
        csvHeaders = mapAndValidateCsvHeaders(parts, sep);
        continue;
      }
      fields = {};
      for (let i = 0; i < csvHeaders.length; i++) {
        fields[csvHeaders[i]] = (parts[i] || '').trim().replace(/^"|"$/g, '');
      }
    }

    const flow = extractFlow(fields);
    if (!aggregateFlow(flowMap, flow, dedupeState)) {
      skipped++;
      if (flow.unsupportedReason === 'ipv6') skipReasons.ipv6++;
      else skipReasons.invalidFlow++;
    }
  }

  return {
    flowMap,
    lineCount,
    skipped,
    skipReasons,
    dedupe: {
      duplicateRecords: dedupeState.duplicateRecords,
      sessionRecords: dedupeState.sessionRecords,
      trackedSessions: dedupeState.saturated ? MAX_SESSION_DEDUPE_KEYS : dedupeState.sessions.size,
      saturated: dedupeState.saturated,
    },
  };
}

// ─── XLSX parser ──────────────────────────────────────────────────────────────

async function parseXLSX(filePath, onProgress) {
  let XLSX;
  try { XLSX = require('xlsx'); }
  catch { throw new Error('Module "xlsx" manquant — lancez: npm install'); }

  const workbook = XLSX.readFile(filePath, { dense: true });
  const sheetName = workbook.SheetNames[0];
  if (!sheetName) throw new Error('Fichier XLSX sans feuilles');
  const sheet = workbook.Sheets[sheetName];
  const rows  = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '' });

  if (rows.length < 2) return { flowMap: new Map(), lineCount: 0, skipped: 0 };

  // First row = headers
  const headers = mapAndValidateCsvHeaders(rows[0], ',');

  const flowMap = new Map();
  const dedupeState = createDedupeState();
  let lineCount = 0;
  let skipped   = 0;
  const skipReasons = { nonTraffic: 0, invalidFlow: 0, ipv6: 0, archiveEntryError: 0 };
  const startTs = Date.now();

  for (let r = 1; r < rows.length; r++) {
    lineCount++;
    if (onProgress && lineCount % 50000 === 0) {
      const elapsed     = (Date.now() - startTs) / 1000;
      const linesPerSec = elapsed > 0 ? Math.round(lineCount / elapsed) : 0;
      const pct         = Math.round((r / (rows.length - 1)) * 100);
      onProgress({ lines: lineCount, linesPerSec, pct });
    }

    const parts  = rows[r];
    const fields = {};
    for (let i = 0; i < headers.length; i++) {
      fields[headers[i]] = String(parts[i] ?? '').trim();
    }
    const flow = extractFlow(fields);
    if (!aggregateFlow(flowMap, flow, dedupeState)) {
      skipped++;
      if (flow.unsupportedReason === 'ipv6') skipReasons.ipv6++;
      else skipReasons.invalidFlow++;
    }
  }

  return {
    flowMap,
    lineCount,
    skipped,
    skipReasons,
    dedupe: {
      duplicateRecords: dedupeState.duplicateRecords,
      sessionRecords: dedupeState.sessionRecords,
      trackedSessions: dedupeState.saturated ? MAX_SESSION_DEDUPE_KEYS : dedupeState.sessions.size,
      saturated: dedupeState.saturated,
    },
  };
}

// ─── File entry point (GZ / ZIP / XLSX / plain) ───────────────────────────────

async function parseFile(filePath, onProgress) {
  const ext = path.extname(filePath).toLowerCase();

  // XLSX / XLS
  if (ext === '.xlsx' || ext === '.xls') {
    const size = fs.statSync(filePath).size;
    if (size > MAX_XLSX_BYTES) {
      throw new Error(
        `Classeur Excel trop volumineux pour un chargement mémoire sûr `
        + `(${Math.ceil(size / 1024 / 1024)} Mo, limite ${Math.round(MAX_XLSX_BYTES / 1024 / 1024)} Mo). `
        + 'Exportez les logs en CSV puis compressez-les en .gz.'
      );
    }
    return parseXLSX(filePath, onProgress);
  }

  // Estimate total lines for progress % (only plain + gz)
  let estimatedLines = 0;
  try {
    const stat = fs.statSync(filePath);
    estimatedLines = ext === '.gz'
      ? Math.round(stat.size * 10 / 250)   // ~10x compression, ~250 bytes/line
      : Math.round(stat.size / 250);
  } catch { /* ignore */ }

  // Wrap onProgress to add pct + eta
  let progressCb = onProgress;
  if (onProgress && estimatedLines > 0) {
    const startTs = Date.now();
    progressCb = ({ lines, linesPerSec }) => {
      const pct = Math.min(99, Math.round((lines / estimatedLines) * 100));
      const eta = linesPerSec > 0
        ? Math.round((estimatedLines - lines) / linesPerSec)
        : null;
      onProgress({ lines, linesPerSec, pct, eta });
    };
  }

  let inputStream;

  if (ext === '.gz') {
    inputStream = fs.createReadStream(filePath)
      .pipe(zlib.createGunzip())
      .pipe(decompressedLimitStream());

  } else if (ext === '.zip') {
    let unzipper;
    try { unzipper = require('unzipper'); }
    catch { throw new Error('Module "unzipper" manquant — lancez: npm install'); }

    const directory = await unzipper.Open.file(filePath);
    const entries = directory.files.filter(f => !f.path.startsWith('__MACOSX') && f.type === 'File');
    if (!entries.length) throw new Error('Archive ZIP vide ou format non supporté');
    if (entries.length > MAX_ARCHIVE_ENTRIES) {
      throw new Error(`Archive ZIP trop complexe : ${entries.length} fichiers (limite ${MAX_ARCHIVE_ENTRIES})`);
    }

    // Parse all files in the ZIP and merge results
    const mergedFlowMap = new Map();
    let totalLines = 0;
    let totalSkipped = 0;
    const totalSkipReasons = { nonTraffic: 0, invalidFlow: 0, ipv6: 0, archiveEntryError: 0 };
    // Un même export FAZ peut être découpé en plusieurs fichiers dans le ZIP.
    // L’état doit donc être partagé entre les entrées pour neutraliser une paire
    // start/close même lorsqu’elle traverse cette frontière.
    const archiveDedupeState = createDedupeState();
    const decompressedState = { bytes: 0 };

    for (const entry of entries) {
      try {
        let stream = entry.stream();
        if (entry.path.endsWith('.gz')) stream = stream.pipe(zlib.createGunzip());
        stream = stream.pipe(decompressedLimitStream(decompressedState));
        const { flowMap, lineCount, skipped, skipReasons } = await parseStream(
          stream,
          progressCb,
          archiveDedupeState
        );
        totalLines   += lineCount;
        totalSkipped += skipped;
        if (skipReasons) {
          totalSkipReasons.nonTraffic  += skipReasons.nonTraffic  || 0;
          totalSkipReasons.invalidFlow += skipReasons.invalidFlow || 0;
          totalSkipReasons.ipv6        += skipReasons.ipv6        || 0;
          totalSkipReasons.archiveEntryError += skipReasons.archiveEntryError || 0;
        }
        // Merge into combined flowMap
        for (const [key, flow] of flowMap) {
          if (!mergedFlowMap.has(key)) {
            mergedFlowMap.set(key, { ...flow });
          } else {
            const e = mergedFlowMap.get(key);
            e.count       += flow.count;
            e.sentBytes   += flow.sentBytes;
            e.rcvdBytes   += flow.rcvdBytes;
            e.sentPackets += flow.sentPackets || 0;
            e.rcvdPackets += flow.rcvdPackets || 0;
            e.duration     += flow.duration || 0;
            if (flow.firstTs != null && (e.firstTs == null || flow.firstTs < e.firstTs)) e.firstTs = flow.firstTs;
            if (flow.lastTs  != null && (e.lastTs  == null || flow.lastTs  > e.lastTs))  e.lastTs  = flow.lastTs;
            for (const day of (flow.days || [])) {
              if (!e.days.includes(day)) e.days.push(day);
            }
          }
        }
      } catch (err) {
        if (err?.code === 'DECOMPRESSED_SIZE_LIMIT') throw err;
        // Continuer permet d'afficher les autres entrées, mais l'analyse restera
        // non certifiable : une archive partielle ne doit jamais générer du CLI.
        totalSkipped++;
        totalSkipReasons.archiveEntryError++;
      }
    }

    return {
      flowMap: mergedFlowMap,
      lineCount: totalLines,
      skipped: totalSkipped,
      skipReasons: totalSkipReasons,
      dedupe: {
        duplicateRecords: archiveDedupeState.duplicateRecords,
        sessionRecords: archiveDedupeState.sessionRecords,
        trackedSessions: archiveDedupeState.saturated
          ? MAX_SESSION_DEDUPE_KEYS
          : archiveDedupeState.sessions.size,
        saturated: archiveDedupeState.saturated,
      },
    };

  } else {
    inputStream = fs.createReadStream(filePath);
  }

  return parseStream(inputStream, progressCb);
}

module.exports = { parseFile, parseStream, normalizeDecision };
