'use strict';

const express = require('express');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');

const { parseFile }                                      = require('./lib/parser');
const { buildAnalysis, consolidatePolicies }             = require('./lib/analyzer');
const { createSession, getSession, setSessionData,
        setSessionError, deleteSession }                 = require('./lib/store');
const { parseFortiConfig, analyzePolicies,
        generateConfig, detectWanCandidates }            = require('./lib/forticonfig');

const app  = express();
const PORT = process.env.PORT || 3737;

// ─── Upload storage ───────────────────────────────────────────────────────────

const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename:    (_req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
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
  let r = flows;
  if (q.srcip)     r = r.filter(f => f.srcip.includes(q.srcip));
  if (q.dstip)     r = r.filter(f => f.dstip.includes(q.dstip));
  if (q.port)      r = r.filter(f => f.dstport === q.port || f.srcport === q.port);
  if (q.proto)     r = r.filter(f => f.proto === q.proto || f.protoName?.toLowerCase() === q.proto.toLowerCase());
  if (q.action)    r = r.filter(f => f.action === q.action);
  if (q.src_type)  r = r.filter(f => f.srcType === q.src_type);
  if (q.dst_type)  r = r.filter(f => f.dstType === q.dst_type);
  if (q.subnet)    r = r.filter(f => f.srcSubnet === q.subnet || f.dstSubnet === q.subnet);
  // Drill-down filters: exact subnet match + destination target (subnet /24 ou IP publique)
  if (q.srcSubnet) r = r.filter(f => f.srcSubnet === q.srcSubnet);
  if (q.dstTarget) r = r.filter(f => f.dstSubnet === q.dstTarget || f.dstip === q.dstTarget);
  return r;
}

// ─── Routes ───────────────────────────────────────────────────────────────────

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

      const { flowMap, lineCount, skipped } = await parseFile(filePath, onProgress);
      const analysis = buildAnalysis(flowMap);
      analysis.meta  = { lineCount, skipped, filename };
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

  res.json({
    data:  flows.slice(start, start + limit),
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

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="fortiflow_consolidated.csv"');
  res.write('\uFEFF');
  res.write(COLS.join(',') + '\n');

  for (const p of consolidated) {
    const row = COLS.map(c => {
      let v = p[c];
      if (Array.isArray(v)) v = v.join(';');
      v = String(v ?? '');
      return (v.includes(',') || v.includes(';')) ? `"${v.replace(/"/g, '""')}"` : v;
    });
    res.write(row.join(',') + '\n');
  }
  res.end();
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

  const flows = applyFlowFilters(s.data.flows, req.query)
    .sort((a, b) => b.count - a.count);

  const COLS = ['srcip','srcSubnet','srcType','dstip','dstSubnet','dstType',
                'srcport','dstport','proto','protoName','action','service',
                'srcintf','dstintf','policyid','count','sentBytes','rcvdBytes','totalBytes'];

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="fortiflow_flows.csv"');
  res.write('\uFEFF'); // BOM for Excel
  res.write(COLS.join(',') + '\n');

  for (const f of flows) {
    const row = COLS.map(c => {
      const v = String(f[c] ?? '');
      return v.includes(',') ? `"${v.replace(/"/g, '""')}"` : v;
    });
    res.write(row.join(',') + '\n');
  }
  res.end();
});

// GET /api/export/policies — CSV download of policy suggestions
app.get('/api/export/policies', (req, res) => {
  const s = requireSession(req, res);
  if (!s) return;

  let policies = s.data.policies;
  if (req.query.dst_type) policies = policies.filter(p => p.dstType === req.query.dst_type);

  // FortiGate-friendly CSV layout
  const COLS = ['name','srcSubnet','dstTarget','dstType','serviceDesc','ports','protos','sessions','action'];

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="fortiflow_policies.csv"');
  res.write('\uFEFF');
  res.write(COLS.join(',') + '\n');

  for (const p of policies) {
    const row = COLS.map(c => {
      let v = p[c];
      if (Array.isArray(v)) v = v.join(';');
      v = String(v ?? '');
      return (v.includes(',') || v.includes(';')) ? `"${v.replace(/"/g, '""')}"` : v;
    });
    res.write(row.join(',') + '\n');
  }
  res.end();
});

// DELETE /api/session/:session — free memory
app.delete('/api/session/:session', (req, res) => {
  deleteSession(req.params.session);
  res.json({ ok: true });
});

// ─── Deploy routes ────────────────────────────────────────────────────────────

// POST /api/deploy/config-upload — parse a FortiGate .conf and store in session
app.post('/api/deploy/config-upload', upload.single('conffile'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Aucun fichier reçu' });

  const s = requireSession(req, res);
  if (!s) { fs.unlink(req.file.path, () => {}); return; }

  try {
    const text = fs.readFileSync(req.file.path, 'utf8');
    const fortiConfig = parseFortiConfig(text);
    s.fortiConfig = fortiConfig;

    // Build a Set of WAN interface names for quick lookup
    const wanInfo = detectWanCandidates(fortiConfig.interfaces, fortiConfig.zones, fortiConfig.sdwanMembers);
    s.wanNames = new Set(wanInfo.interfaces.map(i => i.name));

    res.json({
      addresses:  Object.keys(fortiConfig.addresses).length,
      addrGroups: Object.keys(fortiConfig.addressGroups || {}).length,
      services:   Object.keys(fortiConfig.customServices).length,
      interfaces: Object.keys(fortiConfig.interfaces).length,
      zones:      Object.keys(fortiConfig.zones).length,
      sdwan:      fortiConfig.sdwanMembers.length > 0,
      vdom:       fortiConfig.hasVdom  || false,
      routes:     (fortiConfig.fullRoutes || fortiConfig.staticRoutes).length,
      bgp:        fortiConfig.hasBgp   || false,
      ospf:       fortiConfig.hasOspf  || false,
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

  const { interfaces, zones, sdwanMembers, sdwanEnabled, sdwanIntfName } = s.fortiConfig;
  const wanNames = s.wanNames || new Set();

  res.json({
    interfaces: Object.values(interfaces).map(iface => ({
      ...iface,
      isWan: wanNames.has(iface.name),
    })),
    zones: Object.values(zones).map(z => ({ name: z.name, members: z.members })),
    sdwanMembers,
    sdwanEnabled: sdwanEnabled || false,
    sdwanIntfName: sdwanIntfName || null,
  });
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
    const analyzed = analyzePolicies(selectedPolicies, s.fortiConfig, o.preferredWanIntf || null);
    const genOpts = {
      natEnabled:  o.nat     || false,
      actionVerb:  o.action  || 'accept',
      logTraffic:  o.log     || 'all',
    };
    const cli = generateConfig(analyzed, genOpts);

    const download = req.query.download === '1';
    if (download) {
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="fortiflow_deploy.conf"');
    } else {
      res.setHeader('Content-Type', 'application/json');
    }

    if (download) {
      res.send(cli);
    } else {
      res.json({ cli, analyzed, addrGroups: s.fortiConfig.addressGroups || {} });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  FortiFlow  →  http://localhost:${PORT}\n`);
});
