'use strict';

const fs       = require('fs');
const path     = require('path');
const readline = require('readline');
const zlib     = require('zlib');

// ─── Key=Value parser ─────────────────────────────────────────────────────────

const KV_RE = /(\w+)=("(?:[^"\\]|\\.)*"|[^\s"]\S*)/g;

function parseKV(line) {
  const fields = {};
  KV_RE.lastIndex = 0;
  let m;
  while ((m = KV_RE.exec(line)) !== null) {
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
  policyid: 'policyid', policy_id: 'policyid', policyname: 'policyid',
  'policy id': 'policyid', 'policy name': 'policyid', ruleid: 'policyid',

  // Bytes
  sentbyte: 'sentbyte', sent_byte: 'sentbyte', sentbytes: 'sentbyte',
  'bytes sent': 'sentbyte', 'sent bytes': 'sentbyte', txbytes: 'sentbyte',
  rcvdbyte: 'rcvdbyte', rcvd_byte: 'rcvdbyte', rcvdbytes: 'rcvdbyte',
  'bytes received': 'rcvdbyte', 'rcvd bytes': 'rcvdbyte', rxbytes: 'rcvdbyte',

  // Date / time
  date: 'date', time: 'time', datetime: 'date', timestamp: 'date',
};

// Services UDP par défaut (quand le champ proto est absent)
const UDP_SERVICES = new Set([
  'DNS', 'DHCP', 'NTP', 'SNMP', 'SNMPTRAP', 'SYSLOG', 'TFTP',
  'RIP', 'MDNS', 'LLMNR', 'BOOTP', 'RADIUS', 'ISAKMP', 'IKE',
]);

// ─── Format detection ─────────────────────────────────────────────────────────

function detectFormat(firstLine) {
  const hasKV = /\w+=/.test(firstLine);
  if (hasKV) return { format: 'kv', sep: null };
  const tabs   = (firstLine.match(/\t/g) || []).length;
  const commas = (firstLine.match(/,/g) || []).length;
  if (tabs > 3)   return { format: 'csv', sep: '\t' };
  if (commas > 2) return { format: 'csv', sep: ',' };
  return { format: 'kv', sep: null };
}

// ─── Flow extraction ──────────────────────────────────────────────────────────

function extractFlow(fields) {
  const service = (fields.service || '').toUpperCase().trim();
  let proto = (fields.proto || '').trim();

  // Normaliser les chaînes protocole → chiffres
  if (/^tcp$/i.test(proto))  proto = '6';
  if (/^udp$/i.test(proto))  proto = '17';
  if (/^icmp$/i.test(proto)) proto = '1';

  // Proto absent : déduire depuis le service
  if (!proto && service) {
    proto = UDP_SERVICES.has(service) ? '17' : '6';
  }

  return {
    srcip:    fields.srcip    || '',
    dstip:    fields.dstip    || '',
    srcport:  fields.srcport  || '',
    dstport:  fields.dstport  || '',
    proto,
    action:   (fields.action  || '').toLowerCase().trim(),
    service,
    srcintf:  fields.srcintf  || '',
    dstintf:  fields.dstintf  || '',
    policyid: fields.policyid || '',
    date:     fields.date     || '',
    time:     fields.time     || '',
    sentbyte: parseInt(fields.sentbyte || 0, 10) || 0,
    rcvdbyte: parseInt(fields.rcvdbyte || 0, 10) || 0,
  };
}

// ─── Flow aggregation helper ──────────────────────────────────────────────────

function aggregateFlow(flowMap, flow) {
  if (!flow.srcip || !flow.dstip) return false;
  const key = `${flow.srcip}|${flow.dstip}|${flow.dstport}|${flow.proto}|${flow.action}|${flow.service}`;
  if (!flowMap.has(key)) {
    flowMap.set(key, {
      srcip: flow.srcip, dstip: flow.dstip,
      srcport: flow.srcport, dstport: flow.dstport,
      proto: flow.proto, action: flow.action, service: flow.service,
      srcintf: flow.srcintf, dstintf: flow.dstintf, policyid: flow.policyid,
      count: 0, sentBytes: 0, rcvdBytes: 0,
    });
  }
  const e = flowMap.get(key);
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
      if (t && t !== 'traffic') { skipped++; continue; }
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

    const flow = extractFlow(fields);
    if (!aggregateFlow(flowMap, flow)) skipped++;
  }

  return { flowMap, lineCount, skipped };
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
    const flow = extractFlow(fields);
    if (!aggregateFlow(flowMap, flow)) skipped++;
  }

  return { flowMap, lineCount, skipped };
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
    const entry = directory.files.find(f => !f.path.startsWith('__MACOSX') && f.type === 'File');
    if (!entry) throw new Error('Archive ZIP vide ou format non supporté');

    inputStream = entry.stream();
    if (entry.path.endsWith('.gz')) inputStream = inputStream.pipe(zlib.createGunzip());

  } else {
    inputStream = fs.createReadStream(filePath);
  }

  return parseStream(inputStream, progressCb);
}

module.exports = { parseFile, parseStream };
