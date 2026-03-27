'use strict';

const express          = require('express');
const multer           = require('multer');
const path             = require('path');
const fs               = require('fs');
const { WebSocketServer } = require('ws');

const { parseFile }                                      = require('./lib/parser');
const { buildAnalysis, consolidatePolicies }             = require('./lib/analyzer');
const { createSession, getSession, setSessionData, setFortiConfig,
        setSessionError, deleteSession, getStats }       = require('./lib/store');
const { parseFortiConfig, analyzePolicies,
        generateConfig, validateAgainstExisting,
        preflightValidation,
        parseFullRoutingTable, parseOspfRoutingTable, parseBgpNetworkTable,
        sortRoutes, formatExistingPolicies }             = require('./lib/forticonfig');

const app  = express();
const PORT = process.env.PORT || 3737;

// ─── Upload storage ───────────────────────────────────────────────────────────

const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ─── Cleanup orphan uploads on startup + every 30 min ─────────────────────────
function cleanUploads(maxAgeMs = 60 * 60 * 1000) {
  try {
    const cutoff = Date.now() - maxAgeMs;
    for (const f of fs.readdirSync(UPLOAD_DIR)) {
      const fp = path.join(UPLOAD_DIR, f);
      try {
        const stat = fs.statSync(fp);
        if (stat.isFile() && stat.mtimeMs < cutoff) fs.unlinkSync(fp);
      } catch { /* ignore per-file errors */ }
    }
  } catch { /* ignore if dir unreadable */ }
}
cleanUploads(0);  // on startup: remove ALL leftover files
setInterval(() => cleanUploads(), 30 * 60 * 1000);  // periodic: files > 1h

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename:    (_req, file, cb) => {
      const safe = path.basename(file.originalname).replace(/[^a-zA-Z0-9._-]/g, '_');
      cb(null, `${Date.now()}-${safe}`);
    },
  }),
  limits: { fileSize: 400 * 1024 * 1024 },  // 400 MB
});

// ─── Middleware ───────────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '50mb' }));

// Timeout sur les routes non-SSE seulement (5 min)
app.use((req, res, next) => {
  if (!req.path.startsWith('/api/progress')) {
    req.setTimeout(300000);
    res.setTimeout(300000);
  }
  next();
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function requireSession(req, res) {
  const id = req.query.session || req.params.session;
  const s  = getSession(id);
  if (!s)        { res.status(404).json({ error: 'Session introuvable' }); return null; }
  if (!s.data)   { res.status(202).json({ error: 'Parsing en cours…' });   return null; }
  return s;
}

function applyFlowFilters(flows, q) {
  // Single-pass filter: all conditions evaluated in one .filter() call
  if (!q.srcip && !q.dstip && !q.port && !q.proto && !q.action &&
      !q.src_type && !q.dst_type && !q.subnet && !q.srcSubnet && !q.dstTarget) {
    return flows;
  }
  return flows.filter(f => {
    if (q.srcip     && !f.srcip.includes(q.srcip))                                               return false;
    if (q.dstip     && !f.dstip.includes(q.dstip))                                               return false;
    if (q.port      && f.dstport !== q.port && f.srcport !== q.port)                             return false;
    if (q.proto     && f.proto !== q.proto && f.protoName?.toLowerCase() !== q.proto.toLowerCase()) return false;
    if (q.action    && f.action !== q.action)                                                     return false;
    if (q.src_type  && f.srcType !== q.src_type)                                                  return false;
    if (q.dst_type  && f.dstType !== q.dst_type)                                                  return false;
    if (q.subnet    && f.srcSubnet !== q.subnet && f.dstSubnet !== q.subnet)                      return false;
    if (q.srcSubnet && f.srcSubnet !== q.srcSubnet)                                               return false;
    if (q.dstTarget && f.dstSubnet !== q.dstTarget && f.dstip !== q.dstTarget)                   return false;
    return true;
  });
}

// ─── CSV helper ───────────────────────────────────────────────────────────────

function sendCsv(res, filename, rows, columns) {
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  const safeFilename = filename.replace(/["\r\n\\]/g, '_');
  res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
  res.write('\uFEFF'); // BOM for Excel
  res.write(columns.join(',') + '\n');
  for (const row of rows) {
    const line = columns.map(c => {
      let v = row[c];
      if (Array.isArray(v)) v = v.join(';');
      v = String(v ?? '');
      return (v.includes(',') || v.includes(';')) ? `"${v.replace(/"/g, '""')}"` : v;
    });
    res.write(line.join(',') + '\n');
  }
  res.end();
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// GET /api/health — server health & memory monitoring (no session required)
app.get('/api/health', (_req, res) => {
  res.json(getStats());
});

// POST /api/upload — sauvegarde le fichier, démarre le parse en arrière-plan,
//                    retourne immédiatement le sessionId pour le polling SSE.
app.post('/api/upload', upload.single('logfile'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Aucun fichier reçu' });

  const sessionId = createSession();
  const filePath  = req.file.path;
  const filename  = req.file.originalname;

  // Réponse immédiate → le client ouvre /api/progress/:sessionId
  res.json({ sessionId });

  // Parse asynchrone (non-bloquant pour les autres requêtes)
  setImmediate(async () => {
    const session = getSession(sessionId);
    try {
      const onProgress = (info) => {
        if (session) {
          session.progress = info;
          session.emitter.emit('progress', info);
        }
      };

      const { flowMap, lineCount, skipped, skipReasons } = await parseFile(filePath, onProgress);
      const analysis = buildAnalysis(flowMap);
      analysis.meta  = { lineCount, skipped, skipReasons, uniqueFlows: flowMap.size, filename };
      setSessionData(sessionId, analysis);

      session?.emitter.emit('done', { stats: analysis.stats, meta: analysis.meta });
    } catch (err) {
      setSessionError(sessionId, err.message);
      session?.emitter.emit('error', { error: err.message });
    } finally {
      fs.unlink(filePath, () => {});
    }
  });
});

// GET /api/progress/:id — SSE stream de progression du parse
app.get('/api/progress/:id', (req, res) => {
  const session = getSession(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session introuvable' });

  // Si déjà terminé, répondre directement
  if (session.status === 'ready') {
    return res.json({ done: true, stats: session.data.stats, meta: session.data.meta });
  }
  if (session.status === 'error') {
    return res.status(500).json({ error: session.error });
  }

  // SSE
  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection',    'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const send = (data) => {
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  // Envoyer le dernier état connu immédiatement
  if (session.progress.lines > 0) send(session.progress);

  session.emitter.on('progress', send);

  const onDone = (data) => { send({ ...data, done: true }); res.end(); };
  const onErr  = (data) => { send({ ...data, done: true }); res.end(); };

  session.emitter.once('done',  onDone);
  session.emitter.once('error', onErr);

  req.on('close', () => {
    session.emitter.removeListener('progress', send);
    session.emitter.removeListener('done',     onDone);
    session.emitter.removeListener('error',    onErr);
  });
});

// GET /api/flows — paginated, filterable flow list
app.get('/api/flows', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;
  if (!s.data?.flows) return res.status(410).json({ error: 'Flows libérés après chargement de la config FortiGate' });

  const page  = Math.max(1, parseInt(req.query.page  || 1,   10));
  const limit = Math.min(500, parseInt(req.query.limit || 100, 10));
  const sort  = req.query.sort  || 'count';
  const order = req.query.order || 'desc';

  let flows = applyFlowFilters(s.data.flows, req.query);

  // Sort
  flows = flows.slice().sort((a, b) => {
    const va = a[sort] ?? 0;
    const vb = b[sort] ?? 0;
    if (typeof va === 'string') return order === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
    return order === 'asc' ? va - vb : vb - va;
  });

  const total = flows.length;
  const start = (page - 1) * limit;
  let slice = flows.slice(start, start + limit);

  // Enrich with existing policy name if a config has been uploaded
  if (s.policyMap && s.policyMap.size > 0) {
    slice = slice.map(f => {
      if (!f.policyid) return f;
      const pol = s.policyMap.get(String(f.policyid));
      if (!pol) return f;
      return { ...f, coveredByPolicy: { id: pol.policyid, name: pol.name, action: pol.action } };
    });
  }

  res.json({
    data:  slice,
    total,
    page,
    limit,
    pages: Math.ceil(total / limit),
  });
});

// GET /api/subnets — subnet groups with destinations
app.get('/api/subnets', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;
  res.json(s.data.subnets);
});

// GET /api/matrix — heatmap data (?action=accept|deny)
app.get('/api/matrix', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;
  const action = req.query.action || 'accept';
  res.json(action === 'deny' ? s.data.denyMatrix : s.data.matrix);
});

// GET /api/hosts — détail des hôtes d'un subnet (?subnet=192.168.1.0/24)
app.get('/api/hosts', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;
  const subnet = req.query.subnet;
  if (!subnet) return res.status(400).json({ error: 'Paramètre subnet requis' });
  if (!s.data?.flows) return res.status(410).json({ error: 'Flows libérés après chargement de la config FortiGate' });

  const flows = s.data.flows.filter(f => f.srcSubnet === subnet);

  const hosts = {};
  for (const flow of flows) {
    if (!hosts[flow.srcip]) hosts[flow.srcip] = { ip: flow.srcip, dsts: {}, count: 0 };
    const h = hosts[flow.srcip];
    const dstKey = flow.dstSubnet || flow.dstip;
    if (!h.dsts[dstKey]) {
      h.dsts[dstKey] = { key: dstKey, type: flow.dstType, services: new Set(), ports: new Set(), count: 0 };
    }
    const d = h.dsts[dstKey];
    if (flow.service) d.services.add(flow.service);
    if (flow.dstport) d.ports.add(parseInt(flow.dstport, 10));
    d.count  += flow.count;
    h.count  += flow.count;
  }

  const result = Object.values(hosts)
    .sort((a, b) => b.count - a.count)
    .map(h => ({
      ip:    h.ip,
      count: h.count,
      dsts:  Object.values(h.dsts)
        .sort((a, b) => b.count - a.count)
        .map(d => ({ ...d, services: [...d.services].sort(), ports: [...d.ports].sort((a, b) => a - b) })),
    }));

  res.json(result);
});

// GET /api/policies — suggested firewall policies
app.get('/api/policies', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;

  let policies = s.data.policies;
  if (req.query.subnet) {
    policies = policies.filter(p =>
      p.srcSubnet === req.query.subnet || p.dstTarget === req.query.subnet
    );
  }
  if (req.query.dst_type) {
    policies = policies.filter(p => p.dstType === req.query.dst_type);
  }
  res.json(policies);
});

// GET /api/consolidated-policies — policies optimisées (multi-src / multi-dst)
app.get('/api/consolidated-policies', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;

  let raw = s.data.policies;
  if (req.query.dst_type) {
    raw = raw.filter(p => p.dstType === req.query.dst_type);
  }

  const consolidated = consolidatePolicies(raw);

  // Métriques globales de réduction
  const totalRaw  = raw.length;
  const totalCons = consolidated.length;
  const saved     = consolidated.reduce((s, c) => s + c.savedCount, 0);

  res.json({ consolidated, stats: { totalRaw, totalCons, saved } });
});

// GET /api/export/consolidated-policies — CSV FortiGate multi-src/dst
app.get('/api/export/consolidated-policies', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;

  let raw = s.data.policies;
  if (req.query.dst_type) raw = raw.filter(p => p.dstType === req.query.dst_type);

  const consolidated = consolidatePolicies(raw);
  const COLS = ['name','srcSubnets','dstTargets','dstTypeSummary','serviceDesc','ports','protos','sessions','action'];
  sendCsv(res, 'fortiflow_consolidated.csv', consolidated, COLS);
});

// GET /api/ports — top 25 TCP + UDP destination ports
app.get('/api/ports', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;
  res.json(s.data.portStats);
});

// GET /api/stats — summary stats
app.get('/api/stats', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;
  res.json({ stats: s.data.stats, meta: s.data.meta });
});

// GET /api/export/flows — CSV download of (filtered) flows
app.get('/api/export/flows', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;

  if (!s.data?.flows) return res.status(410).json({ error: 'Flows libérés après chargement de la config FortiGate' });
  const flows = applyFlowFilters(s.data.flows, req.query)
    .sort((a, b) => b.count - a.count);

  const COLS = ['srcip','srcSubnet','srcType','dstip','dstSubnet','dstType',
                'srcport','dstport','proto','protoName','action','service',
                'srcintf','dstintf','policyid','count','sentBytes','rcvdBytes','totalBytes'];
  sendCsv(res, 'fortiflow_flows.csv', flows, COLS);
});

// GET /api/export/policies — CSV download of policy suggestions
app.get('/api/export/policies', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;

  let policies = s.data.policies;
  if (req.query.dst_type) policies = policies.filter(p => p.dstType === req.query.dst_type);

  // FortiGate-friendly CSV layout
  const COLS = ['name','srcSubnet','dstTarget','dstType','serviceDesc','ports','protos','sessions','action'];
  sendCsv(res, 'fortiflow_policies.csv', policies, COLS);
});

// GET /api/export/matrix — XLSX heatmap colorisée (?action=accept|deny)
app.get('/api/export/matrix', async (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;
  const action  = req.query.action || 'accept';
  const matData = action === 'deny' ? s.data.denyMatrix : s.data.matrix;
  if (!matData) return res.status(404).json({ error: 'Matrice non disponible' });

  const ExcelJS  = require('exceljs');
  const { srcSubnets, dstSubnets, cells, maxCount, subnetIntfMap = {} } = matData;
  const isDeny   = action === 'deny';

  // ── helpers couleur (échelle log, identique au canvas) ──────────────────────
  const countMap = new Map();
  cells.forEach(c => countMap.set(`${c.si},${c.di}`, c));

  // ── Charte SNS Security ──────────────────────────────────────────────────────
  // Accept : blanc rosé SNS → vert clair (#4a9e72) → vert foncé (#1a5e3a)
  // Deny   : blanc rosé SNS → rouge clair (#c95252) → rouge foncé (#7a1a1a)
  // Headers: fond #15151e (bg1 SNS dark), texte brand rose #f0b4e4
  const SNS_HDR    = 'FF15151E'; // bg1 dark SNS
  const SNS_ROWHDR = 'FF1C1C28'; // bg3 dark SNS
  const SNS_BRAND  = 'FFF0B4E4'; // rose brand SNS
  const SNS_DIAG   = 'FF232333'; // bg4 dark SNS, cellule diagonale
  const SNS_EMPTY  = 'FFF8F4FC'; // blanc très légèrement rosé pour les cellules vides
  const thin = { style: 'thin', color: { argb: 'FF28283A' } };
  const hdrBorder = { top: thin, bottom: thin, left: thin, right: thin };

  function heatArgb(count) {
    if (!count) return SNS_EMPTY;
    const t = maxCount > 0 ? Math.log1p(count) / Math.log1p(maxCount) : 0;
    let r, g, b;
    if (isDeny) {
      // blanc → rose → rouge SNS #c95252 → foncé #7a1a1a
      r = Math.round(255 - t * 133);  // 255 → 122
      g = Math.round(248 - t * 166);  // 248 → 82 → 26
      b = Math.round(248 - t * 166);  // 248 → 82 → 26
    } else {
      // blanc → vert clair → vert SNS #4a9e72 → foncé #1a5e3a
      r = Math.round(248 - t * 222);  // 248 → 26
      g = Math.round(248 - t * 90);   // 248 → 158 → 94
      b = Math.round(248 - t * 134);  // 248 → 114 → 58
    }
    return 'FF' + [r, g, b].map(v => Math.max(0, Math.min(255, v)).toString(16).padStart(2, '0')).join('').toUpperCase();
  }
  function fontArgb(count) {
    if (!count) return 'FFAAAAAA';
    const t = maxCount > 0 ? Math.log1p(count) / Math.log1p(maxCount) : 0;
    return t > 0.5 ? 'FFFFFFFF' : (isDeny ? 'FF7A1A1A' : 'FF1A5E3A');
  }

  const wb  = new ExcelJS.Workbook();

  // ═══════════════════════════════════════════════════════════════════════════
  // Sheet 1 : Heatmap
  // ═══════════════════════════════════════════════════════════════════════════
  const ws1 = wb.addWorksheet('Heatmap', { views: [{ state: 'frozen', xSplit: 1, ySplit: 1 }] });

  // ── helpers label subnet + interface ──────────────────────────────────────
  const SNS_INTF = 'FF7870A0'; // couleur muted SNS pour le nom d'interface
  function subnetShort(s) { return s.replace('.0/24', '.x').replace('/24',''); }
  function intfNames(subnet)  { return (subnetIntfMap[subnet] || []).join(' / '); }
  function richLabel(subnet, boldColor) {
    const name = subnetShort(subnet);
    const intf = intfNames(subnet);
    if (!intf) return { richText: [{ text: name, font: { bold: true, color: { argb: boldColor }, size: 9, name: 'Calibri' } }] };
    return { richText: [
      { text: name + '\n', font: { bold: true,  color: { argb: boldColor }, size: 9, name: 'Calibri' } },
      { text: intf,        font: { bold: false, color: { argb: SNS_INTF },  size: 7, name: 'Calibri', italic: true } },
    ]};
  }

  // En-tête colonnes (row 1)
  ws1.addRow(['From \\ To', ...dstSubnets.map(() => null)]); // placeholder
  const hRow = ws1.getRow(1);
  hRow.height = 90;

  // Cellule coin top-left
  const cornerCell = hRow.getCell(1);
  cornerCell.value     = { richText: [{ text: 'From \\ To', font: { bold: true, color: { argb: SNS_BRAND }, size: 9, name: 'Calibri' } }] };
  cornerCell.fill      = { type: 'pattern', pattern: 'solid', fgColor: { argb: SNS_HDR } };
  cornerCell.border    = hdrBorder;
  cornerCell.alignment = { horizontal: 'center', vertical: 'middle' };

  // En-têtes colonnes (destinations)
  dstSubnets.forEach((dst, di) => {
    const cell = hRow.getCell(di + 2);
    cell.value     = richLabel(dst, 'FFFFFFFF');
    cell.fill      = { type: 'pattern', pattern: 'solid', fgColor: { argb: SNS_HDR } };
    cell.border    = hdrBorder;
    cell.alignment = { horizontal: 'center', vertical: 'bottom', textRotation: 45, wrapText: true };
  });

  // Lignes de données
  for (let si = 0; si < srcSubnets.length; si++) {
    const rowVals = [null, ...Array(dstSubnets.length).fill(null)]; // placeholder col A
    ws1.addRow(rowVals);
    const row = ws1.getRow(si + 2);
    // Hauteur adaptée selon présence d'interface
    row.height = intfNames(srcSubnets[si]) ? 30 : 22;

    // En-tête ligne (col A) avec subnet + interface
    const rh = row.getCell(1);
    rh.value     = richLabel(srcSubnets[si], SNS_BRAND);
    rh.fill      = { type: 'pattern', pattern: 'solid', fgColor: { argb: SNS_ROWHDR } };
    rh.alignment = { horizontal: 'left', vertical: 'middle', wrapText: true };
    rh.border    = hdrBorder;

    // Cellules de données : couleur heatmap + valeur
    for (let di = 0; di < dstSubnets.length; di++) {
      const cell  = row.getCell(di + 2);
      const c     = countMap.get(`${si},${di}`);
      const count = c ? c.count : 0;
      if (si === di) {
        cell.fill  = { type: 'pattern', pattern: 'solid', fgColor: { argb: SNS_DIAG } };
        cell.value = null;
      } else {
        cell.fill  = { type: 'pattern', pattern: 'solid', fgColor: { argb: heatArgb(count) } };
        cell.value = count || null;
        if (count) cell.font = { color: { argb: fontArgb(count) }, size: 8, name: 'Calibri' };
      }
      cell.alignment = { horizontal: 'center', vertical: 'middle' };
      cell.border    = { top: thin, bottom: thin, left: thin, right: thin };
    }
  }

  // Largeurs colonnes
  ws1.getColumn(1).width = 24; // plus large pour subnet + interface
  for (let di = 0; di < dstSubnets.length; di++) ws1.getColumn(di + 2).width = 9;

  // Légende
  const legRow = srcSubnets.length + 3;
  const legend = isDeny
    ? [['■ Fort trafic refusé',   'FF7A1A1A', 'FFFFFFFF'],
       ['■ Faible trafic refusé', 'FFC95252', 'FFFFFFFF'],
       ['■ Aucun trafic',         SNS_EMPTY,  'FFAAAAAA'],
       ['■ Diagonal (même subnet)', SNS_DIAG, SNS_BRAND]]
    : [['■ Fort trafic accepté',   'FF1A5E3A', 'FFFFFFFF'],
       ['■ Faible trafic accepté', 'FF4A9E72', 'FFFFFFFF'],
       ['■ Aucun trafic',          SNS_EMPTY,  'FFAAAAAA'],
       ['■ Diagonal (même subnet)', SNS_DIAG,  SNS_BRAND]];
  legend.forEach(([label, bgArgb, txtArgb], i) => {
    const lr = ws1.getRow(legRow + i);
    const lc = lr.getCell(1);
    lc.value = label;
    lc.fill      = { type: 'pattern', pattern: 'solid', fgColor: { argb: bgArgb } };
    lc.font      = { size: 9, name: 'Calibri', color: { argb: txtArgb } };
    lc.border    = hdrBorder;
    lc.alignment = { vertical: 'middle' };
    lr.height    = 16;
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Sheet 2 : Détails
  // ═══════════════════════════════════════════════════════════════════════════
  const ws2 = wb.addWorksheet('Détails');
  ws2.addRow(['Source', 'Destination', 'Sessions', 'Services', 'Ports']);
  const dHdr = ws2.getRow(1);
  dHdr.height = 20;
  dHdr.eachCell(cell => {
    cell.fill      = { type: 'pattern', pattern: 'solid', fgColor: { argb: SNS_HDR } };
    cell.font      = { bold: true, color: { argb: SNS_BRAND }, size: 10, name: 'Calibri' };
    cell.alignment = { horizontal: 'center', vertical: 'middle' };
    cell.border    = hdrBorder;
  });

  // Lignes alternées : fond légèrement rosé (SNS) + teinte action
  const rowBg = isDeny ? 'FFFFF0F5' : 'FFF0FFF5';
  const altBg = isDeny ? 'FFFFF8FC' : 'FFF8FFFC';
  cells.forEach((c, i) => {
    ws2.addRow([c.src, c.dst, c.count, (c.services || []).join(', '), (c.ports || []).join(', ')]);
    const row = ws2.getRow(i + 2);
    row.height = 16;
    row.eachCell(cell => {
      cell.fill      = { type: 'pattern', pattern: 'solid', fgColor: { argb: i % 2 === 0 ? rowBg : altBg } };
      cell.font      = { size: 9, name: 'Calibri' };
      cell.alignment = { vertical: 'middle' };
      cell.border    = { bottom: { style: 'thin', color: { argb: 'FFE0E0E0' } } };
    });
    ws2.getRow(i + 2).getCell(3).alignment = { horizontal: 'center', vertical: 'middle' };
  });

  ws2.getColumn(1).width = 18;
  ws2.getColumn(2).width = 18;
  ws2.getColumn(3).width = 12;
  ws2.getColumn(4).width = 35;
  ws2.getColumn(5).width = 30;

  // ── Envoi ────────────────────────────────────────────────────────────────
  const label = isDeny ? 'deny' : 'accept';
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', `attachment; filename="fortiflow_matrix_${label}.xlsx"`);
  try {
    await wb.xlsx.write(res);
    res.end();
  } catch (err) {
    if (!res.headersSent) res.status(500).json({ error: err.message });
  }
});

// DELETE /api/session/:session — free memory
app.delete('/api/session/:session', (req, res) => {
  deleteSession(req.params.session);
  res.json({ ok: true });
});

// GET /api/denied-flows — denied/dropped flows grouped by subnet pair
app.get('/api/denied-flows', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;

  if (!s.data?.flows) return res.status(410).json({ error: 'Flows libérés après chargement de la config FortiGate' });
  const denyFlows = s.data.flows.filter(f => f.action === 'deny' || f.action === 'drop');
  // Group by srcSubnet|dstSubnet
  const groups = new Map();
  for (const f of denyFlows) {
    const src = f.srcSubnet || (f.srcip ? f.srcip.split('.').slice(0, 3).join('.') + '.0/24' : 'unknown');
    const dst = f.dstSubnet || f.dstip || 'unknown';
    const dstType = f.dstType || 'private';
    const k = `${src}|${dst}`;
    if (!groups.has(k)) {
      groups.set(k, { srcSubnet: src, dstTarget: dst, dstType, services: new Set(), ports: new Set(), sessions: 0, bytes: 0 });
    }
    const g = groups.get(k);
    g.sessions += f.count || 1;
    g.bytes    += f.totalBytes || 0;
    if (f.service) g.services.add(f.service);
    if (f.dstport) g.ports.add(String(f.dstport));
  }

  const result = [...groups.values()]
    .map(g => ({ ...g, services: [...g.services], ports: [...g.ports] }))
    .sort((a, b) => b.sessions - a.sessions);

  res.json(result);
});

// ─── Deploy routes ────────────────────────────────────────────────────────────

// POST /api/deploy/config-upload — parse a FortiGate .conf and store in session
app.post('/api/deploy/config-upload', upload.single('conffile'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Aucun fichier reçu' });

  const s = requireSession(req, res);
  if (!s) { fs.unlink(req.file.path, () => {}); return; }

  try {
    const text = await fs.promises.readFile(req.file.path, 'utf8');
    const fortiConfig = parseFortiConfig(text);
    s.fortiConfig = fortiConfig;
    setFortiConfig(s.id, fortiConfig);

    // Free raw flows array — no longer needed once we move to deploy stage.
    // Aggregated data (subnets, policies, stats, matrix) is kept.
    if (s.data && s.data.flows) {
      s.data.flows = null;
    }

    // Build a fast policyid → policy lookup (keyed as string for log compatibility)
    const policyMap = new Map();
    for (const pol of fortiConfig.existingPolicies || []) {
      policyMap.set(String(pol.policyid), pol);
    }
    s.policyMap = policyMap;

    res.json({
      addresses:        Object.keys(fortiConfig.addresses).length,
      addrGroups:       Object.keys(fortiConfig.addressGroups || {}).length,
      services:         Object.keys(fortiConfig.customServices).length,
      serviceGroups:    Object.keys(fortiConfig.serviceGroups || {}).length,
      interfaces:       Object.keys(fortiConfig.interfaces).length,
      zones:            Object.keys(fortiConfig.zones).length,
      sdwan:            fortiConfig.sdwanMembers.length > 0,
      vdom:             fortiConfig.hasVdom  || false,
      routes:           (fortiConfig.fullRoutes || fortiConfig.staticRoutes).length,
      bgp:              fortiConfig.hasBgp   || false,
      ospf:             fortiConfig.hasOspf  || false,
      existingPolicies: (fortiConfig.existingPolicies || []).length,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    fs.unlink(req.file.path, () => {});
  }
});

// GET /api/deploy/interfaces — return interfaces, zones, sdwan, WAN candidates
app.get('/api/deploy/interfaces', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;
  if (!s.fortiConfig) return res.status(404).json({ error: 'Aucune config FortiGate chargée' });

  const { interfaces, zones, sdwanMembers, sdwanZoneNames, sdwanEnabled, sdwanIntfName } = s.fortiConfig;
  res.json({
    interfaces: Object.values(interfaces).map(iface => ({ ...iface })),
    zones: Object.values(zones).map(z => ({ name: z.name, members: z.members })),
    sdwanMembers,
    sdwanZoneNames: sdwanZoneNames || [],
    sdwanEnabled: sdwanEnabled || false,
    sdwanIntfName: sdwanIntfName || null,
  });
});

// POST /api/deploy/dynamic-routes — inject live routing table into session
// protocol: 'all' (get router info routing-table all) | 'ospf' | 'bgp'
// 'all' REPLACES the fullRoutes table entirely (ground truth).
// 'ospf'/'bgp' kept for backward compat — inject only matching routes.
app.post('/api/deploy/dynamic-routes', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;
  if (!s.fortiConfig) return res.status(404).json({ error: 'Aucune config FortiGate chargée' });

  const { protocol, cliOutput } = req.body || {};
  if (!cliOutput || !protocol) return res.status(400).json({ error: 'protocol et cliOutput requis' });

  let parsed = [];
  if (protocol === 'all') {
    parsed = parseFullRoutingTable(cliOutput);
    // Replace fullRoutes entirely — real routing table is ground truth
    s.fortiConfig.fullRoutes = parsed;
    sortRoutes(s.fortiConfig.fullRoutes);

    // Re-correction WAN/LAN depuis la vraie table de routage :
    // seule l'interface portant 0.0.0.0/0 est WAN, les autres sont LAN
    const defaultDevices = new Set(
      parsed.filter(r => r.dst === '0.0.0.0/0').map(r => r.device).filter(Boolean)
    );
    if (defaultDevices.size > 0) {
      for (const iface of Object.values(s.fortiConfig.interfaces || {})) {
        if (iface.isTunnel || iface._roleWan) continue;
        if (iface.isSdwan) { iface.isWan = true; continue; }
        iface.isWan = defaultDevices.has(iface.name);
      }
      for (const zone of Object.values(s.fortiConfig.zones || {})) {
        zone.isWan = zone.members.length > 0 &&
          zone.members.some(m => s.fortiConfig.interfaces[m]?.isWan);
      }
    }

    return res.json({ added: parsed.length, total: parsed.length, routes: parsed, replaced: true });
  } else if (protocol === 'ospf') {
    parsed = parseOspfRoutingTable(cliOutput);
  } else if (protocol === 'bgp') {
    parsed = parseBgpNetworkTable(cliOutput);
  } else {
    return res.status(400).json({ error: 'protocol inconnu (all|ospf|bgp)' });
  }

  // ospf/bgp: inject (deduplicate by dst)
  const existing = new Map(s.fortiConfig.fullRoutes.map(r => [r.dst, r]));
  let added = 0;
  for (const r of parsed) {
    if (!existing.has(r.dst)) {
      s.fortiConfig.fullRoutes.push(r);
      existing.set(r.dst, r);
      added++;
    }
  }
  sortRoutes(s.fortiConfig.fullRoutes);
  res.json({ added, total: parsed.length, routes: parsed });
});

// POST /api/deploy/preflight — validate before generating CLI
app.post('/api/deploy/preflight', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;
  if (!s.fortiConfig) return res.status(404).json({ error: 'Aucune config FortiGate chargée' });

  const { selectedPolicies } = req.body || {};
  if (!Array.isArray(selectedPolicies) || selectedPolicies.length === 0) {
    return res.status(400).json({ error: 'selectedPolicies requis' });
  }

  try {
    const result = preflightValidation(selectedPolicies, s.fortiConfig);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/security-profiles — list available security profiles
app.get('/api/security-profiles', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;
  if (!s.fortiConfig) return res.status(404).json({ error: 'Aucune config FortiGate chargée' });
  res.json(s.fortiConfig.securityProfiles || {});
});

// POST /api/deploy/generate — generate FortiGate CLI from selected policies
app.post('/api/deploy/generate', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;
  if (!s.fortiConfig) return res.status(404).json({ error: 'Aucune config FortiGate chargée' });

  const { selectedPolicies, opts } = req.body || {};
  if (!Array.isArray(selectedPolicies) || selectedPolicies.length === 0) {
    return res.status(400).json({ error: 'selectedPolicies requis' });
  }

  try {
    const o = opts || {};

    // Apply user WAN toggles — build a patched config without mutating the session
    let configToUse = s.fortiConfig;
    if (Array.isArray(o.wanOverrides) && o.wanOverrides.length > 0) {
      const patchedInterfaces = { ...s.fortiConfig.interfaces };
      o.wanOverrides.forEach(name => {
        if (patchedInterfaces[name]) {
          patchedInterfaces[name] = { ...patchedInterfaces[name], isWan: true };
        }
      });
      configToUse = { ...s.fortiConfig, interfaces: patchedInterfaces };
    }

    // SD-WAN zone takes priority; if none, preferredWanIntf falls to null (detectWanCandidates handles it)
    const analyzed = analyzePolicies(selectedPolicies, configToUse, o.preferredWanIntf || null);

    // Re-inject per-policy overrides from frontend (action, log, securityProfiles)
    for (let i = 0; i < analyzed.length; i++) {
      const src = selectedPolicies[i] || {};
      if (src.action)           analyzed[i].action           = src.action;
      if (src.log)              analyzed[i].log              = src.log;
      if (src.securityProfiles) analyzed[i].securityProfiles = src.securityProfiles;
    }

    // Inject frontend-merged services (multi-port / range) into each policy's analysis
    for (let i = 0; i < analyzed.length; i++) {
      const merged = selectedPolicies[i]?._mergedServices;
      if (Array.isArray(merged) && merged.length > 0) {
        for (const ms of merged) {
          analyzed[i].analysis.services.push({
            label: ms.name, found: false, name: null, source: null,
            suggestedName: ms.name, isNamed: false,
            proto: ms.proto, ports: ms.ports || null, portRange: ms.portRange || null,
            _isMerged: true,
          });
        }
      }
    }

    const genOpts = {
      natEnabled:        o.nat     || false,
      actionVerb:        o.action  || 'accept',
      logTraffic:        o.log     || 'all',
      serviceGroups:     s.fortiConfig.serviceGroups || {},
      addresses:         s.fortiConfig.addresses || {},
      addressGroups:     s.fortiConfig.addressGroups || {},
      zones:             s.fortiConfig.zones || {},
      securityProfiles:  o.securityProfiles || {},
    };
    const cli = generateConfig(analyzed, genOpts);

    // Validation against existing policies
    const warnings = validateAgainstExisting(analyzed, s.fortiConfig.existingPolicies || []);

    const download = req.query.download === '1';
    if (download) {
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="fortiflow_deploy.conf"');
    } else {
      res.setHeader('Content-Type', 'application/json');
    }

    // Build global resolvedHosts map {ip → name} for all /32 hosts across all policies
    const addresses = s.fortiConfig.addresses || {};
    // Build CIDR→name lookup once (O(1) per host instead of O(n))
    const cidrIndex = new Map();
    for (const [name, a] of Object.entries(addresses)) {
      if (a.cidr) { cidrIndex.set(a.cidr, name); }
    }
    const resolvedHosts = {};
    for (const p of analyzed) {
      for (const h of [...(p.srcHosts || []), ...(p.dstHosts || [])]) {
        if (!resolvedHosts[h]) {
          const found = cidrIndex.get(`${h}/32`) || cidrIndex.get(h);
          if (found) resolvedHosts[h] = found;
        }
      }
    }

    if (download) {
      res.send(cli);
    } else {
      const existingPoliciesCli = formatExistingPolicies(s.fortiConfig?.existingPolicies || []);
      res.json({ cli, analyzed, addrGroups: s.fortiConfig.addressGroups || {}, warnings, resolvedHosts, existingPoliciesCli });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

const https = require('https');

const DOMAIN = process.env.DOMAIN || 'devval.com';
const SSL_KEY  = process.env.SSL_KEY  || `/etc/letsencrypt/live/${DOMAIN}/privkey.pem`;
const SSL_CERT = process.env.SSL_CERT || `/etc/letsencrypt/live/${DOMAIN}/fullchain.pem`;

function attachWss(server) {
  const wss = new WebSocketServer({ noServer: true });
  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url, 'http://x');
    if (url.pathname !== '/ws/progress') { socket.destroy(); return; }
    wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
  });
  wss.on('connection', (ws, req) => {
    const sessionId = new URL(req.url, 'http://x').searchParams.get('session');
    const s = getSession(sessionId);
    if (!s) { ws.close(4004, 'Session introuvable'); return; }
    if (s.status === 'ready') {
      ws.send(JSON.stringify({ done: true, stats: s.data?.stats, meta: s.data?.meta }));
      ws.close(); return;
    }
    if (s.status === 'error') {
      ws.send(JSON.stringify({ done: true, error: s.error }));
      ws.close(); return;
    }
    const onProgress = d => ws.readyState === ws.OPEN && ws.send(JSON.stringify(d));
    const onDone     = d => { if (ws.readyState === ws.OPEN) ws.send(JSON.stringify({ done: true, ...d })); ws.close(); };
    const onError    = d => { if (ws.readyState === ws.OPEN) ws.send(JSON.stringify({ done: true, error: d.error })); ws.close(); };
    s.emitter.on('progress', onProgress);
    s.emitter.once('done',  onDone);
    s.emitter.once('error', onError);
    ws.on('close', () => {
      s.emitter.off('progress', onProgress);
      s.emitter.off('done',     onDone);
      s.emitter.off('error',    onError);
    });
  });
}

if (fs.existsSync(SSL_KEY) && fs.existsSync(SSL_CERT)) {
  const sslOptions = {
    key:  fs.readFileSync(SSL_KEY),
    cert: fs.readFileSync(SSL_CERT),
  };
  const server = https.createServer(sslOptions, app);
  attachWss(server);
  server.listen(PORT, () => {
    console.log(`\n  FortiFlow  →  https://${DOMAIN}:${PORT}\n`);
  });
} else {
  // Fallback HTTP si les certificats ne sont pas encore présents
  const server = app.listen(PORT, () => {
    console.log(`\n  FortiFlow  →  http://localhost:${PORT}  (HTTP — certificats SSL introuvables)\n`);
  });
  attachWss(server);
}
