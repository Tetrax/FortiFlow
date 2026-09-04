'use strict';

const fs       = require('fs');
const path     = require('path');
const readline = require('readline');
const zlib     = require('zlib');

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
  'ip source': 'srcip', 'ip src': 'srcip',

  // Destination IP
  dstip: 'dstip', dst_ip: 'dstip', destination_ip: 'dstip',
  'destination ip': 'dstip', 'dst ip': 'dstip', destinationip: 'dstip',
  'ip destination': 'dstip', 'ip dst': 'dstip',

  // Source port
  srcport: 'srcport', src_port: 'srcport', sourceport: 'srcport',
  'source port': 'srcport', 'src port': 'srcport', sport: 'srcport',

  // Destination port
  dstport: 'dstport', dst_port: 'dstport', destinationport: 'dstport',
  'destination port': 'dstport', 'dst port': 'dstport', dport: 'dstport',

  // Protocol
  proto: 'proto', protocol: 'proto', 'ip protocol': 'proto', ip_protocol: 'proto',

  // Action
  action: 'action', verdict: 'action',

  // Service
  service: 'service', 'service name': 'service', servicename: 'service', app: 'service',

  // Interfaces
  srcintf: 'srcintf', src_intf: 'srcintf', srcinterface: 'srcintf',
  'source interface': 'srcintf', 'src interface': 'srcintf', ingressintf: 'srcintf',
  dstintf: 'dstintf', dst_intf: 'dstintf', dstinterface: 'dstintf',
  'destination interface': 'dstintf', 'dst interface': 'dstintf', egressintf: 'dstintf',

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
};

// ─── Format detection ─────────────────────────────────────────────────────────

function detectFormat(firstLine) {
  // R2: un vrai log KV FortiAnalyzer contient de nombreux couples key=val (date=, srcip=, …).
  // Exiger ≥3 couples évite qu'une ligne CSV contenant un seul '=' (commentaire, valeur) bascule en KV.
  const kvCount = (firstLine.match(/\b\w+=\S/g) || []).length;
  const tabs    = (firstLine.match(/\t/g) || []).length;
  const commas  = (firstLine.match(/,/g) || []).length;
  if (kvCount >= 3) return { format: 'kv', sep: null };
  if (tabs > 3)     return { format: 'csv', sep: '\t' };
  if (commas > 2)   return { format: 'csv', sep: ',' };
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

const SUPPORTED_PROTOCOLS = new Set(['1', '6', '17', '47', '50', '58', '89']);
const PROTOCOL_ALIASES = new Map([
  ['TCP', '6'],
  ['UDP', '17'],
  ['ICMP', '1'],
]);

function normalizeProtocol(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return { proto: null, skipReason: 'missingProtocol' };
  const alias = PROTOCOL_ALIASES.get(raw.toUpperCase());
  const proto = alias || (/^\d+$/.test(raw) ? String(Number(raw)) : null);
  return proto && SUPPORTED_PROTOCOLS.has(proto)
    ? { proto, skipReason: null }
    : { proto: null, skipReason: 'invalidProtocol' };
}

function extractFlow(fields) {
  const service = (fields.service || '').toUpperCase().trim();
  const protocol = normalizeProtocol(fields.proto);

  // Le nom du service n'est jamais une preuve du protocole observé.
  if (!protocol.proto) return { flow: null, skipReason: protocol.skipReason };

  // NAT/trandisp et une éventuelle direction de log ne pilotent pas le moteur
  // actuel : NAT est une décision de policy et le sens vient de srcintf/dstintf.
  // Ne pas conserver arbitrairement la valeur du premier log agrégé.

  const srcip = (fields.srcip || '').trim();
  const dstip = (fields.dstip || '').trim();

  return { flow: {
    srcip:    isValidIPv4(srcip) ? srcip : '',
    dstip:    isValidIPv4(dstip) ? dstip : '',
    srcport:  String(fields.srcport || '').trim(),
    dstport:  fields.dstport  || '',
    proto: protocol.proto,
    action:   (fields.action  || '').toLowerCase().trim(),
    service,
    srcintf:    fields.srcintf    || '',
    dstintf:    fields.dstintf    || '',
    policyid:   fields.policyid   || '',
    policyname: fields.policyname || '',
    date:     fields.date     || '',
    time:     fields.time     || '',
    sentbyte: parseInt(fields.sentbyte || 0, 10) || 0,
    rcvdbyte: parseInt(fields.rcvdbyte || 0, 10) || 0,
  }, skipReason: null };
}

// ─── Flow aggregation helper ──────────────────────────────────────────────────

function mergeSourcePortEvidence(target, source) {
  const values = Array.isArray(source.srcports)
    ? source.srcports
    : [source.srcport].filter(value => String(value || '').trim());
  const srcportSet = target._srcportSet || new Set(target.srcports || []);
  for (const value of values) srcportSet.add(String(value).trim());
  target._srcportSet = srcportSet;
  target.srcportMissing = target.srcportMissing === true
    || source.srcportMissing === true
    || (!Array.isArray(source.srcports) && !String(source.srcport || '').trim());
}

function compareSourcePortEvidence(a, b) {
  const aIsPort = /^\d{1,5}$/.test(a) && Number(a) <= 65535;
  const bIsPort = /^\d{1,5}$/.test(b) && Number(b) <= 65535;
  if (aIsPort && bIsPort) {
    const numericOrder = Number(a) - Number(b);
    if (numericOrder) return numericOrder;
  } else if (aIsPort !== bIsPort) {
    return aIsPort ? -1 : 1;
  }
  return a < b ? -1 : a > b ? 1 : 0;
}

function finalizeSourcePortEvidence(flowMap) {
  for (const flow of flowMap.values()) {
    const srcportSet = flow._srcportSet || new Set(flow.srcports || []);
    flow.srcports = [...srcportSet].sort(compareSourcePortEvidence);
    flow.srcport = !flow.srcportMissing && flow.srcports.length === 1
      ? flow.srcports[0]
      : '';
    delete flow._srcportSet;
  }
}

function aggregateFlow(flowMap, flow) {
  if (!flow.srcip || !flow.dstip) return false;
  const key = `${flow.srcip}|${flow.dstip}|${flow.dstport}|${flow.proto}|${flow.action}|${flow.service}|${flow.srcintf}|${flow.dstintf}|${flow.policyid}`;
  if (!flowMap.has(key)) {
    flowMap.set(key, {
      srcip: flow.srcip, dstip: flow.dstip,
      srcport: '', srcports: [], srcportMissing: false, dstport: flow.dstport,
      proto: flow.proto, action: flow.action, service: flow.service,
      srcintf: flow.srcintf, dstintf: flow.dstintf, policyid: flow.policyid, policyname: flow.policyname,
      count: 0, sentBytes: 0, rcvdBytes: 0,
    });
  }
  const e = flowMap.get(key);
  mergeSourcePortEvidence(e, flow);
  e.count++;
  e.sentBytes += flow.sentbyte;
  e.rcvdBytes += flow.rcvdbyte;
  return true;
}

// ─── Core streaming parser (text streams) ─────────────────────────────────────

async function parseStream(inputStream, onProgress) {
  const flowMap = new Map();
  let lineCount = 0;
  let skipped   = 0;
  const skipReasons = { nonTraffic: 0, invalidFlow: 0, missingProtocol: 0, invalidProtocol: 0 };
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
      const det = detectFormat(line);
      format = det.format;
      sep    = det.sep;
    }

    let fields;

    if (format === 'kv') {
      fields = parseKV(line);
      const t = fields.type;
      if (t && t !== 'traffic') { skipped++; skipReasons.nonTraffic++; continue; }
    } else {
      const parts = parseCSVLine(line, sep);
      if (!csvHeaders) {
        const raw  = parts.map(h => h.toLowerCase().trim().replace(/^"|"$/g, ''));
        csvHeaders = raw.map(h => HEADER_MAP[h] || h);
        continue;
      }
      fields = {};
      for (let i = 0; i < csvHeaders.length; i++) {
        fields[csvHeaders[i]] = (parts[i] || '').trim().replace(/^"|"$/g, '');
      }
    }

    const extracted = extractFlow(fields);
    if (!extracted.flow) {
      skipped++;
      skipReasons[extracted.skipReason]++;
      continue;
    }
    const flow = extracted.flow;
    if (!aggregateFlow(flowMap, flow)) { skipped++; skipReasons.invalidFlow++; }
  }

  finalizeSourcePortEvidence(flowMap);
  return { flowMap, lineCount, skipped, skipReasons };
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

  const skipReasons = { nonTraffic: 0, invalidFlow: 0, missingProtocol: 0, invalidProtocol: 0 };
  if (rows.length < 2) return { flowMap: new Map(), lineCount: 0, skipped: 0, skipReasons };

  // First row = headers
  const rawHeaders = rows[0].map(h => String(h).toLowerCase().trim());
  const headers    = rawHeaders.map(h => HEADER_MAP[h] || h);

  const flowMap = new Map();
  let lineCount = 0;
  let skipped   = 0;
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
    const extracted = extractFlow(fields);
    if (!extracted.flow) {
      skipped++;
      skipReasons[extracted.skipReason]++;
      continue;
    }
    if (!aggregateFlow(flowMap, extracted.flow)) {
      skipped++;
      skipReasons.invalidFlow++;
    }
  }

  finalizeSourcePortEvidence(flowMap);
  return { flowMap, lineCount, skipped, skipReasons };
}

// ─── File entry point (GZ / ZIP / XLSX / plain) ───────────────────────────────

async function parseFile(filePath, onProgress) {
  const ext = path.extname(filePath).toLowerCase();

  // XLSX / XLS
  if (ext === '.xlsx' || ext === '.xls') {
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
    inputStream = fs.createReadStream(filePath).pipe(zlib.createGunzip());

  } else if (ext === '.zip') {
    let unzipper;
    try { unzipper = require('unzipper'); }
    catch { throw new Error('Module "unzipper" manquant — lancez: npm install'); }

    const directory = await unzipper.Open.file(filePath);
    const entries = directory.files.filter(f => !f.path.startsWith('__MACOSX') && f.type === 'File');
    if (!entries.length) throw new Error('Archive ZIP vide ou format non supporté');

    // Parse all files in the ZIP and merge results
    const mergedFlowMap = new Map();
    let totalLines = 0;
    let totalSkipped = 0;
    const totalSkipReasons = { nonTraffic: 0, invalidFlow: 0, missingProtocol: 0, invalidProtocol: 0 };

    for (const entry of entries) {
      try {
        let stream = entry.stream();
        if (entry.path.endsWith('.gz')) stream = stream.pipe(zlib.createGunzip());
        const { flowMap, lineCount, skipped, skipReasons } = await parseStream(stream, progressCb);
        totalLines   += lineCount;
        totalSkipped += skipped;
        if (skipReasons) {
          totalSkipReasons.nonTraffic   += skipReasons.nonTraffic   || 0;
          totalSkipReasons.invalidFlow  += skipReasons.invalidFlow  || 0;
          totalSkipReasons.missingProtocol += skipReasons.missingProtocol || 0;
          totalSkipReasons.invalidProtocol += skipReasons.invalidProtocol || 0;
        }
        // Merge into combined flowMap
        for (const [key, flow] of flowMap) {
          if (!mergedFlowMap.has(key)) {
            mergedFlowMap.set(key, { ...flow, srcports: [...(flow.srcports || [])] });
          } else {
            const e = mergedFlowMap.get(key);
            mergeSourcePortEvidence(e, flow);
            e.count     += flow.count;
            e.sentBytes += flow.sentBytes;
            e.rcvdBytes += flow.rcvdBytes;
          }
        }
      } catch (err) {
        // Skip corrupted/unreadable entries, continue with remaining files
        totalSkipped++;
      }
    }

    finalizeSourcePortEvidence(mergedFlowMap);
    return { flowMap: mergedFlowMap, lineCount: totalLines, skipped: totalSkipped, skipReasons: totalSkipReasons };

  } else {
    inputStream = fs.createReadStream(filePath);
  }

  return parseStream(inputStream, progressCb);
}

module.exports = { parseFile, parseStream };
