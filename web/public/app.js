'use strict';

// ═══════════════════════════════════════════════════════════════
// State
// ═══════════════════════════════════════════════════════════════

const state = {
  session:  null,   // sessionId string
  stats:    null,
  meta:     null,
  view:     'dashboard',
  flows:    { page: 1, filters: {}, sort: 'count', order: 'desc', total: 0 },
  policies: { dst_type: '' },
  matrix:   { action: 'accept' },
  subView:  { analyse: 'flows', polices: 'policies' },
  expertMode: localStorage.getItem('ff-expert') === '1',
};

let _renderTarget = null;
let _viewAbort = null;

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

function escHtml(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

const fmtNum = n => (n ?? 0).toLocaleString('fr-FR');

function fmtBytes(n) {
  n = n || 0;
  if (n < 1024)         return `${n} B`;
  if (n < 1024 ** 2)    return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3)    return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

function actionTag(a) {
  const cls = { accept: 'tag-accept', deny: 'tag-deny', drop: 'tag-drop' }[a] || 'tag-deny';
  return `<span class="tag ${cls}">${a || '–'}</span>`;
}

function protoTag(p) {
  const cls = { TCP: 'tag-tcp', UDP: 'tag-udp', ICMP: 'tag-icmp' }[p] || '';
  return `<span class="tag ${cls}">${p || '–'}</span>`;
}

function typeTag(t) {
  return t === 'private'
    ? `<span class="tag tag-priv">LAN</span>`
    : `<span class="tag tag-pub">WAN</span>`;
}

function el(id) { return document.getElementById(id); }
function qs(sel, ctx = document) { return ctx.querySelector(sel); }

async function api(path) {
  const sep = path.includes('?') ? '&' : '?';
  const r   = await fetch(`${path}${sep}session=${state.session}`);
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.error || r.statusText); }
  return r.json();
}

// ═══════════════════════════════════════════════════════════════
// Upload
// ═══════════════════════════════════════════════════════════════

function showProgress(show, text = '', detail = '') {
  const ov = el('progress-overlay');
  ov.classList.toggle('show', show);
  if (text)   el('progress-text').textContent   = text;
  if (detail) el('progress-detail').textContent = detail;
  const bar = el('progress-bar-fill');
  if (bar && !show) bar.style.width = '0%';
}

function setProgressInfo({ lines = 0, pct, linesPerSec, eta } = {}) {
  const detail   = el('progress-detail');
  const barFill  = el('progress-bar-fill');
  const pctStr   = pct   != null ? ` · ${pct}%`            : '';
  const speedStr = linesPerSec > 0 ? ` · ${fmtNum(linesPerSec)} l/s` : '';
  const etaStr   = eta   != null ? ` · ETA ${eta}s`        : '';
  if (detail) detail.textContent = `${fmtNum(lines)} lignes${pctStr}${speedStr}${etaStr}`;
  if (barFill && pct != null) barFill.style.width = `${Math.min(pct, 99)}%`;
}

async function handleUpload(file) {
  if (!file) return;
  showProgress(true, `Upload de ${file.name}…`, 'Envoi vers le serveur…');

  const fd = new FormData();
  fd.append('logfile', file);

  let sessionId;
  try {
    const r    = await fetch('/api/upload', { method: 'POST', body: fd });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || 'Erreur serveur');
    sessionId = data.sessionId;
  } catch (e) {
    showProgress(false);
    showError(e.message);
    return;
  }

  el('progress-detail').textContent = 'Parse en cours…';

  // Suivi SSE en temps réel
  await new Promise((resolve, reject) => {
    const sse = new EventSource(`/api/progress/${sessionId}`);

    sse.onmessage = (evt) => {
      const d = JSON.parse(evt.data);
      if (d.done) {
        sse.close();
        if (d.error) { reject(new Error(d.error)); return; }
        state.session = sessionId;
        state.stats   = d.stats;
        state.meta    = d.meta;
        // Barre à 100% un instant avant de fermer
        setProgressInfo({ lines: d.meta?.lineCount || 0, pct: 100, linesPerSec: 0 });
        resolve();
      } else {
        setProgressInfo(d);
      }
    };

    sse.onerror = () => { sse.close(); reject(new Error('Connexion SSE perdue')); };
  }).catch(e => { showProgress(false); showError(e.message); return; });

  showProgress(false);
  updateSidebar();
  navigateTo('dashboard');
}

function showError(msg) {
  el(_renderTarget || 'content').innerHTML = `<div class="alert alert-error">⚠ ${escHtml(msg)}</div>`;
}

// ═══════════════════════════════════════════════════════════════
// Sidebar & routing
// ═══════════════════════════════════════════════════════════════

function updateSidebar() {
  if (!state.session) return;
  const s = state.stats;

  el('sidebar-session').style.display = 'block';
  el('session-filename').textContent  = state.meta?.filename || '';
  // Update hidden badges (for backward compat)
  el('badge-flows').textContent           = fmtNum(s?.uniqueFlows);
  el('badge-groups').textContent          = fmtNum(s?.srcSubnets);
  el('badge-policies').textContent        = '…';
  el('badge-consilpolicies').textContent  = '…';
  // Update visible nav badges
  const analyseEl = el('badge-analyse');
  if (analyseEl) analyseEl.textContent = fmtNum(s?.uniqueFlows);
  const policesEl = el('badge-polices');
  if (policesEl) policesEl.textContent = '…';
}

function navigateTo(view) {
  // Backward compat: map old sub-view names to parent tabs
  const subViewMap = {
    flows:          ['analyse', 'flows'],
    matrix:         ['analyse', 'matrix'],
    groups:         ['analyse', 'groups'],
    ports:          ['analyse', 'ports'],
    policies:       ['polices', 'policies'],
    consilpolicies: ['polices', 'consilpolicies'],
    denied:         ['polices', 'denied'],
  };
  if (subViewMap[view]) {
    const [parent, sub] = subViewMap[view];
    state.subView[parent] = sub;
    view = parent;
  }

  state.view = view;

  document.querySelectorAll('.nav-item').forEach(n => {
    n.classList.toggle('active', n.dataset.view === view);
  });

  const titles = {
    dashboard: ['Dashboard',              'Vue globale de l\'activité réseau'],
    analyse:   ['Analyse',                'Exploration du trafic réseau'],
    polices:   ['Policies',               'Règles firewall suggérées et optimisées'],
    deploy:    ['Déploiement FortiGate',   'Générer la config CLI à injecter sur le firewall'],
  };

  const [title, sub] = titles[view] || ['FortiFlow', ''];
  el('view-title').textContent = title;
  el('view-sub').textContent   = sub;
  el('topbar-actions').innerHTML = '';

  if (!state.session && view !== 'dashboard') {
    renderUpload();
    return;
  }

  const renders = { dashboard, analyse, polices, deploy };
  (renders[view] || renderUpload)();
}

// ═══════════════════════════════════════════════════════════════
// View: Upload / Dashboard empty
// ═══════════════════════════════════════════════════════════════

function renderUpload() {
  el(_renderTarget || 'content').innerHTML = `
    <div id="upload-zone">
      <div class="drop-area" id="drop-area">
        <div class="drop-icon">📂</div>
        <div class="drop-title">Déposez votre fichier de log</div>
        <div class="drop-sub">
          Formats supportés : <em>.log</em> · <em>.txt</em> · <em>.csv</em> · <em>.xlsx</em> · <em>.gz</em> · <em>.zip</em><br>
          FortiGate syslog (key=value) et exports FortiAnalyzer (CSV / XLSX)<br>
          Fichiers jusqu'à 300 Mo — parsing streamé côté serveur
        </div>
        <br>
        <button class="upload-btn" id="btn-pick">Choisir un fichier</button>
      </div>
    </div>`;

  el('btn-pick').addEventListener('click', () => el('file-input').click());

  const drop = el('drop-area');
  drop.addEventListener('dragover',  e => { e.preventDefault(); drop.classList.add('dragover'); });
  drop.addEventListener('dragleave', ()=> drop.classList.remove('dragover'));
  drop.addEventListener('drop', e => {
    e.preventDefault();
    drop.classList.remove('dragover');
    handleUpload(e.dataTransfer.files[0]);
  });
}

// ═══════════════════════════════════════════════════════════════
// View: Dashboard
// ═══════════════════════════════════════════════════════════════

async function dashboard() {
  if (!state.session) { renderUpload(); return; }

  const s  = state.stats;
  const m  = state.meta;
  const pct = s.totalSessions ? Math.round(s.acceptSessions / s.totalSessions * 100) : 0;

  el(_renderTarget || 'content').innerHTML = `
    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-value">${fmtNum(s.totalSessions)}</div>
        <div class="stat-label">Sessions totales</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${fmtNum(s.uniqueFlows)}</div>
        <div class="stat-label">Flux uniques</div>
      </div>
      <div class="stat-card">
        <div class="stat-value blue">${fmtNum(s.uniqueSrcIPs)}</div>
        <div class="stat-label">IPs source</div>
      </div>
      <div class="stat-card">
        <div class="stat-value blue">${fmtNum(s.uniqueDstIPs)}</div>
        <div class="stat-label">IPs destination</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${fmtNum(s.srcSubnets)}</div>
        <div class="stat-label">Subnets /24 source</div>
      </div>
      <div class="stat-card">
        <div class="stat-value orange">${fmtNum(s.privateSrcIPs)}</div>
        <div class="stat-label">Hôtes RFC1918</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${pct}%</div>
        <div class="stat-label">Taux d'acceptation</div>
      </div>
      <div class="stat-card">
        <div class="stat-value red">${fmtNum(s.denySessions)}</div>
        <div class="stat-label">Sessions refusées</div>
      </div>
      <div class="stat-card">
        <div class="stat-value blue">${fmtBytes(s.totalBytes)}</div>
        <div class="stat-label">Volume total</div>
      </div>
    </div>

    <div class="section-header" style="margin-top:8px;">
      <div>
        <div class="section-title">Fichier analysé</div>
        <div class="section-sub">${m?.filename || ''} — ${fmtNum(m?.lineCount)} lignes lues · ${fmtNum(m?.skipped)} lignes ignorées</div>
      </div>
      <div style="display:flex;gap:8px;">
        <button class="export-btn primary" onclick="navigateTo('policies')">◎ Voir les policies</button>
        <button class="upload-btn" style="font-size:12px;padding:7px 14px;" onclick="el('file-input').click()">+ Nouveau fichier</button>
      </div>
    </div>

    <div class="stat-grid" style="grid-template-columns:1fr 1fr;">
      <div class="stat-card" style="cursor:pointer;" onclick="navigateTo('flows')">
        <div style="font-size:12px;color:var(--text2);margin-bottom:8px;">Répartition des actions</div>
        <div style="display:flex;gap:16px;align-items:center;">
          <div><div class="stat-value" style="font-size:18px;">${fmtNum(s.acceptSessions)}</div><div class="stat-label" style="color:var(--accent)">ACCEPT</div></div>
          <div><div class="stat-value" style="font-size:18px;color:var(--danger)">${fmtNum(s.denySessions)}</div><div class="stat-label" style="color:var(--danger)">DENY/DROP</div></div>
        </div>
      </div>
      <div class="stat-card" style="cursor:pointer;" onclick="navigateTo('groups')">
        <div style="font-size:12px;color:var(--text2);margin-bottom:8px;">Destinations</div>
        <div style="display:flex;gap:16px;align-items:center;">
          <div><div class="stat-value" style="font-size:18px;">${fmtNum(s.privateDstIPs)}</div><div class="stat-label" style="color:var(--accent2)">LAN (RFC1918)</div></div>
          <div><div class="stat-value" style="font-size:18px;color:var(--accent3)">${fmtNum(s.uniqueDstIPs - s.privateDstIPs)}</div><div class="stat-label" style="color:var(--accent3)">WAN (public)</div></div>
        </div>
      </div>
    </div>`;
}

// ═══════════════════════════════════════════════════════════════
// View: Flows
// ═══════════════════════════════════════════════════════════════

async function flows() {
  if (_viewAbort) _viewAbort.abort();
  _viewAbort = new AbortController();
  const { signal } = _viewAbort;

  el(_renderTarget || 'content').innerHTML = `
    <div class="filter-bar">
      <input class="filter-input" id="f-srcip"   placeholder="Source IP…">
      <input class="filter-input" id="f-dstip"   placeholder="Dest IP…">
      <input class="filter-input" id="f-port"    placeholder="Port…" style="width:80px">
      <select class="filter-select" id="f-proto">
        <option value="">Proto</option>
        <option>TCP</option><option>UDP</option><option>ICMP</option><option>GRE</option>
      </select>
      <select class="filter-select" id="f-action">
        <option value="">Action</option>
        <option>accept</option><option>deny</option><option>drop</option>
      </select>
      <select class="filter-select" id="f-dst-type">
        <option value="">Dest</option>
        <option value="private">LAN</option>
        <option value="public">WAN</option>
      </select>
      <button class="filter-btn" id="btn-apply-filter">Filtrer</button>
      <button class="filter-btn reset" id="btn-reset-filter">Reset</button>
      <span style="margin-left:auto;display:flex;gap:8px;">
        <a class="export-btn" id="btn-export-flows" href="#">⬇ CSV</a>
      </span>
    </div>
    <div id="flows-table-wrap"></div>
    <div class="pagination" id="flows-pagination"></div>`;

  el('btn-apply-filter').addEventListener('click', () => {
    state.flows.filters = {
      srcip:    el('f-srcip').value.trim(),
      dstip:    el('f-dstip').value.trim(),
      port:     el('f-port').value.trim(),
      proto:    el('f-proto').value,
      action:   el('f-action').value,
      dst_type: el('f-dst-type').value,
    };
    state.flows.page = 1;
    loadFlows();
  }, { signal });

  el('btn-reset-filter').addEventListener('click', () => {
    state.flows.filters = {};
    state.flows.page = 1;
    ['f-srcip','f-dstip','f-port','f-proto','f-action','f-dst-type'].forEach(id => {
      const e = el(id);
      if (e.tagName === 'SELECT') e.value = '';
      else e.value = '';
    });
    loadFlows();
  }, { signal });

  el('btn-export-flows').addEventListener('click', e => {
    e.preventDefault();
    const q = buildFlowQuery();
    window.location = `/api/export/flows?${q}&session=${state.session}`;
  }, { signal });

  loadFlows();
}

function buildFlowQuery() {
  const f = state.flows.filters;
  const parts = [];
  Object.entries(f).forEach(([k, v]) => { if (v) parts.push(`${k}=${encodeURIComponent(v)}`); });
  parts.push(`sort=${state.flows.sort}`, `order=${state.flows.order}`);
  return parts.join('&');
}

async function loadFlows() {
  const wrap = el('flows-table-wrap');
  if (!wrap) return;
  wrap.innerHTML = '<div class="empty-state"><div class="progress-spinner" style="margin:0 auto"></div></div>';

  try {
    const q    = buildFlowQuery();
    const page = state.flows.page;
    const data = await api(`/api/flows?${q}&page=${page}&limit=100`);

    state.flows.total = data.total;
    renderFlowsTable(data);
    renderPagination(data);
  } catch (e) {
    wrap.innerHTML = `<div class="alert alert-error">${escHtml(e.message)}</div>`;
  }
}

function renderFlowsTable(data) {
  const COLS = [
    { key: 'srcip',     label: 'Source IP',  mono: true  },
    { key: 'srcSubnet', label: 'Subnet src', mono: true  },
    { key: 'dstip',     label: 'Dest IP',    mono: true  },
    { key: 'dstType',   label: 'Type dst',   render: r => typeTag(r.dstType) },
    { key: 'dstport',   label: 'Port',       mono: true  },
    { key: 'protoName', label: 'Proto',      render: r => protoTag(r.protoName) },
    { key: 'service',   label: 'Service',    mono: true  },
    { key: 'action',    label: 'Action',     render: r => actionTag(r.action) },
    { key: 'count',     label: 'Sessions',   mono: true, render: r => fmtNum(r.count) },
    { key: 'totalBytes',label: 'Octets',     mono: true, render: r => fmtBytes(r.totalBytes) },
  ];

  const sort  = state.flows.sort;
  const order = state.flows.order;

  const head = COLS.map(c => {
    const sortIcon = c.key === sort ? (order === 'asc' ? ' ↑' : ' ↓') : '';
    return `<th class="${c.key === sort ? 'sorted' : ''}" data-col="${c.key}">${c.label}${sortIcon}</th>`;
  }).join('');

  const rows = data.data.map(r => {
    const cells = COLS.map(c => {
      const val = c.render ? c.render(r) : (r[c.key] ?? '–');
      return `<td${c.mono ? ' class="mono"' : ''}>${val}</td>`;
    }).join('');
    return `<tr>${cells}</tr>`;
  }).join('');

  el('flows-table-wrap').innerHTML = `
    <div class="table-wrap">
      <table>
        <thead><tr>${head}</tr></thead>
        <tbody>${rows || '<tr><td colspan="10" class="empty-state">Aucun flux trouvé</td></tr>'}</tbody>
      </table>
    </div>`;

  // Sort click
  el('flows-table-wrap').querySelectorAll('th[data-col]').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.col;
      if (state.flows.sort === col) {
        state.flows.order = state.flows.order === 'desc' ? 'asc' : 'desc';
      } else {
        state.flows.sort  = col;
        state.flows.order = 'desc';
      }
      state.flows.page = 1;
      loadFlows();
    });
  });
}

function renderPagination(data) {
  const pag = el('flows-pagination');
  if (!pag) return;
  const { page, pages, total, limit } = data;
  const start = (page - 1) * limit + 1;
  const end   = Math.min(page * limit, total);

  const btns = [];
  if (page > 1) btns.push(`<button class="page-btn" data-p="${page - 1}">‹ Préc</button>`);
  const from = Math.max(1, page - 2);
  const to   = Math.min(pages, page + 2);
  for (let p = from; p <= to; p++) {
    btns.push(`<button class="page-btn ${p === page ? 'active' : ''}" data-p="${p}">${p}</button>`);
  }
  if (page < pages) btns.push(`<button class="page-btn" data-p="${page + 1}">Suiv ›</button>`);

  pag.innerHTML = `
    <span>${fmtNum(total)} flux — affichage ${fmtNum(start)}–${fmtNum(end)}</span>
    <div class="page-btns">${btns.join('')}</div>`;

  pag.querySelectorAll('.page-btn[data-p]').forEach(btn => {
    btn.addEventListener('click', () => {
      state.flows.page = parseInt(btn.dataset.p, 10);
      loadFlows();
    });
  });
}

// ═══════════════════════════════════════════════════════════════
// View: Matrix (Canvas heatmap)
// ═══════════════════════════════════════════════════════════════

async function matrix() {
  if (_viewAbort) _viewAbort.abort();
  _viewAbort = new AbortController();
  const { signal } = _viewAbort;

  el(_renderTarget || 'content').innerHTML = `
    <div class="section-header">
      <div>
        <div class="section-title">Heatmap LAN → LAN</div>
        <div class="section-sub">Intensité = nombre de sessions entre subnets /24 privés</div>
      </div>
      <div class="matrix-toggle">
        <button class="toggle-btn ${state.matrix.action === 'accept' ? 'active accept' : ''}" data-action="accept">✔ Acceptés</button>
        <button class="toggle-btn ${state.matrix.action === 'deny'   ? 'active deny'   : ''}" data-action="deny">✖ Refusés</button>
      </div>
    </div>
    <div id="matrix-wrap"><canvas id="matrix-canvas"></canvas></div>
    <div class="matrix-legend">
      <span>Faible</span>
      <canvas id="legend-canvas" class="legend-gradient" width="120" height="12"></canvas>
      <span>Élevé</span>
      <span style="margin-left:16px;color:var(--text2);font-size:11px;">Survol = détail · Clic = filtrer les flux</span>
    </div>`;

  // Toggle wiring
  document.querySelectorAll('.toggle-btn[data-action]').forEach(btn => {
    btn.addEventListener('click', async () => {
      state.matrix.action = btn.dataset.action;
      document.querySelectorAll('.toggle-btn[data-action]').forEach(b => {
        b.className = `toggle-btn${b.dataset.action === state.matrix.action ? ' active ' + b.dataset.action : ''}`;
      });
      el('matrix-wrap').innerHTML = '<div class="empty-state"><div class="progress-spinner" style="margin:0 auto"></div></div>';
      try {
        const data = await api(`/api/matrix?action=${state.matrix.action}`);
        el('matrix-wrap').innerHTML = '<canvas id="matrix-canvas"></canvas>';
        renderMatrix(data, state.matrix.action);
      } catch (e) {
        el('matrix-wrap').innerHTML = `<div class="alert alert-error">${escHtml(e.message)}</div>`;
      }
    }, { signal });
  });

  try {
    const data = await api(`/api/matrix?action=${state.matrix.action}`);
    renderMatrix(data, state.matrix.action);
  } catch (e) {
    el('matrix-wrap').innerHTML = `<div class="alert alert-error">${escHtml(e.message)}</div>`;
  }
}

function renderMatrix(data, mode = 'accept') {
  const { srcSubnets, dstSubnets, cells, maxCount } = data;

  if (!srcSubnets.length || !dstSubnets.length) {
    const msg = mode === 'deny'
      ? 'Aucun flux refusé LAN→LAN détecté'
      : 'Aucune communication LAN→LAN détectée';
    el('matrix-wrap').innerHTML = `<div class="empty-state"><div class="empty-icon">⊞</div><div class="empty-msg">${msg}</div></div>`;
    return;
  }

  const CELL  = 32;
  const FONT  = '11px monospace';
  const PAD   = 8;

  // Measure the longest label to set left margin dynamically
  const tmpCanvas = document.createElement('canvas');
  const tmpCtx    = tmpCanvas.getContext('2d');
  tmpCtx.font = FONT;
  const longestSrc = Math.max(...srcSubnets.map(s => tmpCtx.measureText(s.replace('.0/24', '.x')).width));
  const longestDst = Math.max(...dstSubnets.map(s => tmpCtx.measureText(s.replace('.0/24', '.x')).width));

  // Left margin = longest src label + padding
  const LABEL_LEFT = Math.ceil(longestSrc) + 16;
  // Top margin = longest dst label projected at 45° + padding
  const LABEL_TOP  = Math.ceil(longestDst * Math.sin(Math.PI / 4)) + 24;

  const W = LABEL_LEFT + dstSubnets.length * CELL + PAD;
  const H = LABEL_TOP  + srcSubnets.length * CELL + PAD;

  const canvas = el('matrix-canvas');
  canvas.width  = W;
  canvas.height = H;
  const ctx = canvas.getContext('2d');

  // Background
  ctx.fillStyle = '#0e0e1a';
  ctx.fillRect(0, 0, W, H);

  // Legend canvas — vert pour accept, rouge pour deny
  const lc = el('legend-canvas');
  if (lc) {
    const lctx = lc.getContext('2d');
    const grad = lctx.createLinearGradient(0, 0, 120, 0);
    grad.addColorStop(0, '#0e0e1a');
    if (mode === 'deny') {
      grad.addColorStop(0.5, '#550000');
      grad.addColorStop(1,   '#ff1744');
    } else {
      grad.addColorStop(0.5, '#005533');
      grad.addColorStop(1,   '#00e676');
    }
    lctx.fillStyle = grad;
    lctx.fillRect(0, 0, 120, 12);
  }

  // Cell map for hit detection
  const cellMap = new Map();
  cells.forEach(c => cellMap.set(`${c.si},${c.di}`, c));

  // Draw column labels (dst subnets) — rotated -45°, anchored at bottom-left of each column
  ctx.font = FONT;
  ctx.fillStyle = '#9090b0';
  ctx.textAlign = 'left';
  for (let di = 0; di < dstSubnets.length; di++) {
    const x = LABEL_LEFT + di * CELL + CELL / 2;
    const y = LABEL_TOP - 6;
    ctx.save();
    ctx.translate(x, y);
    ctx.rotate(-Math.PI / 4);
    ctx.fillText(dstSubnets[di].replace('.0/24', '.x'), 0, 0);
    ctx.restore();
  }

  // Draw row labels (src subnets) — right-aligned, vertically centred on each row
  ctx.font = FONT;
  ctx.fillStyle = '#9090b0';
  ctx.textAlign = 'right';
  ctx.textBaseline = 'middle';
  for (let si = 0; si < srcSubnets.length; si++) {
    const y = LABEL_TOP + si * CELL + CELL / 2;
    ctx.fillText(srcSubnets[si].replace('.0/24', '.x'), LABEL_LEFT - 8, y);
  }
  ctx.textBaseline = 'alphabetic';

  // Draw cells
  for (let si = 0; si < srcSubnets.length; si++) {
    for (let di = 0; di < dstSubnets.length; di++) {
      const x = LABEL_LEFT + di * CELL;
      const y = LABEL_TOP  + si * CELL;

      // Grid cell background
      ctx.fillStyle = si === di ? '#12122a' : '#0b0b18';
      ctx.fillRect(x + 1, y + 1, CELL - 2, CELL - 2);

      const c = cellMap.get(`${si},${di}`);
      if (c) {
        const t = maxCount > 0 ? Math.log1p(c.count) / Math.log1p(maxCount) : 0;
        // Couleur : vert (accept) ou rouge (deny) sur échelle log
        if (mode === 'deny') {
          const r = Math.round(80 + t * 175);
          ctx.fillStyle = `rgb(${r},${Math.round(t * 23)},${Math.round(t * 20)})`;
        } else {
          const g = Math.round(60 + t * 170);
          const b = Math.round(60 + t * 58);
          ctx.fillStyle = `rgb(0,${g},${b})`;
        }
        ctx.fillRect(x + 1, y + 1, CELL - 2, CELL - 2);

        // Session count inside cell
        const textColor = mode === 'deny'
          ? (t > 0.55 ? '#000' : '#ff5252')
          : (t > 0.55 ? '#000' : '#00e676');
        ctx.fillStyle = textColor;
        ctx.font = '9px monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(c.count > 9999 ? '9k+' : c.count, x + CELL / 2, y + CELL / 2);
        ctx.textBaseline = 'alphabetic';
      }
    }
  }

  // Save the static render into an offscreen canvas for hover redraw
  const offscreen = document.createElement('canvas');
  offscreen.width  = W;
  offscreen.height = H;
  offscreen.getContext('2d').drawImage(canvas, 0, 0);

  // Tooltip on hover — with early-exit if same cell (P7)
  const tooltip = el('matrix-tooltip');
  let _lastHoverCell = { si: -1, di: -1 };

  canvas.addEventListener('mousemove', e => {
    const rect = canvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left) * (canvas.width  / rect.width);
    const my = (e.clientY - rect.top)  * (canvas.height / rect.height);
    const di = Math.floor((mx - LABEL_LEFT) / CELL);
    const si = Math.floor((my - LABEL_TOP)  / CELL);

    // Early-exit: same cell as last frame → skip redraw
    if (si === _lastHoverCell.si && di === _lastHoverCell.di) {
      // Still update tooltip position if visible
      if (tooltip.style.display === 'block') {
        tooltip.style.left = (e.clientX + 16) + 'px';
        tooltip.style.top  = (e.clientY - 10) + 'px';
      }
      return;
    }
    _lastHoverCell = { si, di };

    if (si >= 0 && di >= 0 && si < srcSubnets.length && di < dstSubnets.length) {
      const c = cellMap.get(`${si},${di}`);
      // Restore static image first, then draw highlight on top
      ctx.drawImage(offscreen, 0, 0);
      if (c) {
        // Highlight the hovered cell with a white border overlay
        const hx = LABEL_LEFT + di * CELL;
        const hy = LABEL_TOP  + si * CELL;
        ctx.strokeStyle = 'rgba(255,255,255,0.7)';
        ctx.lineWidth   = 1.5;
        ctx.strokeRect(hx + 1, hy + 1, CELL - 2, CELL - 2);

        const svcStr  = c.services?.length ? c.services.join(', ') : '–';
        const portStr = c.ports?.length    ? c.ports.join(', ')    : '–';
        tooltip.innerHTML = `
          <div><span class="tt-src">${escHtml(c.src)}</span></div>
          <div>→ <span class="tt-dst">${escHtml(c.dst)}</span></div>
          <div>Sessions : <span class="tt-val">${fmtNum(c.count)}</span></div>
          <div>Services : ${escHtml(svcStr)}</div>
          <div>Ports : ${escHtml(portStr)}</div>`;
        tooltip.style.display = 'block';
        tooltip.style.left    = (e.clientX + 16) + 'px';
        tooltip.style.top     = (e.clientY - 10) + 'px';
      } else {
        tooltip.style.display = 'none';
      }
    } else {
      ctx.drawImage(offscreen, 0, 0);
      tooltip.style.display = 'none';
    }
  });

  canvas.addEventListener('mouseleave', () => {
    _lastHoverCell = { si: -1, di: -1 };
    ctx.drawImage(offscreen, 0, 0);
    tooltip.style.display = 'none';
  });

  // Click → filter flows
  canvas.addEventListener('click', e => {
    const rect = canvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left) * (canvas.width  / rect.width);
    const my = (e.clientY - rect.top)  * (canvas.height / rect.height);
    const di = Math.floor((mx - LABEL_LEFT) / CELL);
    const si = Math.floor((my - LABEL_TOP)  / CELL);

    if (si >= 0 && di >= 0 && si < srcSubnets.length && di < dstSubnets.length) {
      const c = cellMap.get(`${si},${di}`);
      if (c) {
        // Navigate to deploy tab with src/dst pre-filtered
        if (deployState.analyzed && deployState.analyzed.length > 0) {
          deployState.searchFilter = `${c.src} ${c.dst}`.replace(/\.0\/24/g, '');
          deployState.page = 1;
          navigateTo('deploy');
        } else {
          // Fallback: navigate to flows if deploy not yet analyzed
          state.flows.filters = { srcip: c.src.replace('.0/24',''), dstip: c.dst.replace('.0/24','') };
          state.flows.page = 1;
          navigateTo('flows');
        }
      }
    }
  });

  canvas.style.cursor = 'crosshair';
}

// ═══════════════════════════════════════════════════════════════
// View: Groups (subnet cards)
// ═══════════════════════════════════════════════════════════════

async function groups() {
  if (_viewAbort) _viewAbort.abort();
  _viewAbort = new AbortController();
  // signal available for future listeners; groups() renders via innerHTML — no direct listeners to attach
  el(_renderTarget || 'content').innerHTML = '<div class="empty-state"><div class="progress-spinner" style="margin:0 auto"></div></div>';

  try {
    const data = await api('/api/subnets');
    renderGroups(data);
  } catch (e) {
    el(_renderTarget || 'content').innerHTML = `<div class="alert alert-error">${escHtml(e.message)}</div>`;
  }
}

function renderGroups(subnets) {
  const entries = Object.entries(subnets).sort((a, b) => {
    const ta = Object.values(a[1].dsts).reduce((s, d) => s + d.count, 0);
    const tb = Object.values(b[1].dsts).reduce((s, d) => s + d.count, 0);
    return tb - ta;
  });

  if (!entries.length) {
    el(_renderTarget || 'content').innerHTML = '<div class="empty-state"><div class="empty-icon">⊕</div><div class="empty-msg">Aucun subnet RFC1918 trouvé</div></div>';
    return;
  }

  const cards = entries.map(([subnet, sg]) => {
    const dsts = Object.values(sg.dsts).sort((a, b) => b.count - a.count);
    const totalSessions = dsts.reduce((s, d) => s + d.count, 0);
    const privDsts = dsts.filter(d => d.type === 'private').length;
    const pubDsts  = dsts.filter(d => d.type === 'public').length;

    const rows = dsts.map(d => {
      const svcTags = d.services.slice(0, 8).map(s => `<span class="svc">${s}</span>`).join('');
      const portStr = d.ports.slice(0, 5).map(p => `${p}`).join(', ');
      const extra   = d.services.length > 8 ? `<span class="svc">+${d.services.length - 8}</span>` : '';
      return `
        <div class="dst-row">
          <div class="dst-info">
            <div class="dst-ip">${typeTag(d.type)} ${d.key}${d.type === 'public' && d.country ? ` <span class="geo-tag">${d.flag || ''} ${d.country}</span>` : ''}</div>
            <div class="dst-services">${svcTags}${extra}${!d.services.length ? `<span style="color:var(--text2);font-size:11px;">ports: ${portStr || '?'}</span>` : ''}</div>
          </div>
          <div class="dst-stats">
            <div class="dst-sessions">${fmtNum(d.count)}</div>
            <div class="dst-bytes">${fmtBytes(d.sentBytes + d.rcvdBytes)}</div>
          </div>
        </div>`;
    }).join('');

    const cardId  = subnet.replace(/[./]/g, '-');
    const subnetB64 = btoa(subnet);  // safe ID for the host panel

    return `
      <div class="subnet-card" id="card-${cardId}">
        <div class="subnet-header" onclick="toggleCard(this)">
          <div>
            <div class="subnet-name">${subnet}</div>
            <div class="subnet-meta">${sg.srcIPs.length} hôte(s) · ${privDsts} dst LAN · ${pubDsts} dst WAN · ${fmtNum(totalSessions)} sessions</div>
          </div>
          <div style="display:flex;align-items:center;gap:8px;">
            <button class="host-btn" onclick="event.stopPropagation();toggleHostPanel('${subnetB64}','${subnet}')">
              🖥 Hôtes <span id="hbadge-${cardId}">(${sg.srcIPs.length})</span>
            </button>
            <span class="subnet-toggle">›</span>
          </div>
        </div>
        <div class="host-panel" id="hp-${cardId}" style="display:none;"></div>
        <div class="subnet-body">${rows}</div>
      </div>`;
  }).join('');

  el(_renderTarget || 'content').innerHTML = cards;
}

function toggleCard(header) {
  header.closest('.subnet-card').classList.toggle('open');
}
window.toggleCard = toggleCard;

async function toggleHostPanel(subnetB64, subnet) {
  const cardId = subnet.replace(/[./]/g, '-');
  const panel  = el(`hp-${cardId}`);
  if (!panel) return;

  if (panel.style.display !== 'none') {
    panel.style.display = 'none';
    return;
  }

  // First open: fetch and render
  if (!panel.dataset.loaded) {
    panel.style.display = 'block';
    panel.innerHTML = '<div class="host-loading"><div class="progress-spinner" style="margin:0 auto 8px"></div>Chargement des hôtes…</div>';
    try {
      const hosts = await api(`/api/hosts?subnet=${encodeURIComponent(subnet)}`);
      panel.innerHTML = renderHostPanel(hosts, subnet);
      panel.dataset.loaded = '1';
    } catch (e) {
      panel.innerHTML = `<div class="alert alert-error" style="margin:8px 16px">Erreur : ${escHtml(e.message)}</div>`;
    }
  } else {
    panel.style.display = 'block';
  }
}
window.toggleHostPanel = toggleHostPanel;

function renderHostPanel(hosts, subnet) {
  if (!hosts.length) return '<div class="host-empty">Aucun hôte trouvé pour ce subnet.</div>';

  const rows = hosts.map(h => {
    const dstRows = h.dsts.slice(0, 8).map(d => {
      const svc = d.services.slice(0, 4).join(', ') || d.ports.slice(0, 4).join(', ') || '–';
      return `<span class="host-dst">${typeTag(d.type)} <span class="mono">${d.key}</span> <em>${svc}</em> · ${fmtNum(d.count)} sess</span>`;
    }).join('');
    const more = h.dsts.length > 8 ? `<span class="host-dst-more">+${h.dsts.length - 8} dest.</span>` : '';

    return `
      <div class="host-row">
        <div class="host-ip-col">
          <span class="host-ip mono">${h.ip}</span>
          <span class="host-sess">${fmtNum(h.count)} sess</span>
        </div>
        <div class="host-dsts-col">${dstRows}${more}</div>
        <div class="host-actions-col">
          <button class="drill-btn" onclick="filterFlowsByHost('${h.ip}')">→ Flux</button>
        </div>
      </div>`;
  }).join('');

  return `
    <div class="host-panel-inner">
      <div class="host-panel-title">Détail des ${hosts.length} hôte(s) — ${subnet}</div>
      ${rows}
    </div>`;
}

function filterFlowsByHost(ip) {
  state.flows.filters = { srcip: ip };
  state.flows.page = 1;
  navigateTo('flows');
}
window.filterFlowsByHost = filterFlowsByHost;

// ═══════════════════════════════════════════════════════════════
// View: Policies
// ═══════════════════════════════════════════════════════════════

async function policies() {
  if (_viewAbort) _viewAbort.abort();
  _viewAbort = new AbortController();
  const { signal } = _viewAbort;

  el(_renderTarget || 'content').innerHTML = `
    <div class="filter-bar">
      <select class="filter-select" id="p-dst-type">
        <option value="">Toutes destinations</option>
        <option value="private">LAN uniquement</option>
        <option value="public">WAN uniquement</option>
      </select>
      <button class="filter-btn" id="btn-apply-policy-filter">Filtrer</button>
      <span style="margin-left:auto;display:flex;gap:8px;">
        <a class="export-btn primary" id="btn-export-policies" href="#">⬇ Export CSV FortiGate</a>
      </span>
    </div>
    <div id="policies-wrap"></div>`;

  el('btn-apply-policy-filter').addEventListener('click', () => {
    state.policies.dst_type = el('p-dst-type').value;
    loadPolicies();
  }, { signal });

  el('btn-export-policies').addEventListener('click', e => {
    e.preventDefault();
    const q = state.policies.dst_type ? `dst_type=${state.policies.dst_type}` : '';
    window.location = `/api/export/policies${q ? '?' + q : ''}${q ? '&' : '?'}session=${state.session}`;
  }, { signal });

  loadPolicies();
}

async function loadPolicies() {
  const wrap = el('policies-wrap');
  if (!wrap) return;
  wrap.innerHTML = '<div class="empty-state"><div class="progress-spinner" style="margin:0 auto"></div></div>';

  try {
    const q    = state.policies.dst_type ? `dst_type=${state.policies.dst_type}` : '';
    const data = await api(`/api/policies${q ? '?' + q : ''}`);
    el('badge-policies').textContent = fmtNum(data.length);
    const policesEl = el('badge-polices');
    if (policesEl) policesEl.textContent = fmtNum(data.length);
    renderPoliciesTable(data);
  } catch (e) {
    wrap.innerHTML = `<div class="alert alert-error">${escHtml(e.message)}</div>`;
  }
}

function renderPoliciesTable(policies) {
  const wrap = el('policies-wrap');
  if (!policies.length) {
    wrap.innerHTML = '<div class="empty-state"><div class="empty-icon">◎</div><div class="empty-msg">Aucune policy trouvée</div></div>';
    return;
  }

  const rows = policies.map((p, i) => {
    const pid    = `pd-${i}`;
    const srcB64 = btoa(p.srcSubnet);
    const dstB64 = btoa(p.dstTarget);
    return `
    <tr id="pr-${i}">
      <td class="mono" style="color:var(--text2)">${i + 1}</td>
      <td class="mono">${typeTag('private')} ${p.srcSubnet}</td>
      <td class="mono">${typeTag(p.dstType)} ${p.dstTarget}</td>
      <td style="max-width:260px;white-space:normal;font-family:var(--mono);font-size:11px;">${escHtml(p.serviceDesc)}</td>
      <td class="mono">${p.sessions > 0 ? fmtNum(p.sessions) : '–'}</td>
      <td class="mono">${fmtBytes(p.sentBytes + p.rcvdBytes)}</td>
      <td>${actionTag(p.action)}</td>
      <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;font-family:var(--mono);font-size:10px;color:var(--text2)">${escHtml(p.name)}</td>
      <td><button class="drill-btn" onclick="togglePolicyDrill(${i},'${srcB64}','${dstB64}')">▾ Hôtes</button></td>
    </tr>
    <tr id="${pid}" class="policy-drill-row" style="display:none;">
      <td colspan="9"><div id="${pid}-content" class="policy-drill-content"></div></td>
    </tr>`;
  }).join('');

  wrap.innerHTML = `
    <div style="margin-bottom:8px;font-size:12px;color:var(--text2)">
      ${policies.length} règles suggérées — ordonnées par volume de sessions
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Source (subnet /24)</th>
            <th>Destination</th>
            <th>Services / Ports</th>
            <th>Sessions</th>
            <th>Volume</th>
            <th>Action</th>
            <th>Nom suggéré</th>
            <th></th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

// ═══════════════════════════════════════════════════════════════
// Policy drill-down (détail IPs individuelles)
// ═══════════════════════════════════════════════════════════════

async function togglePolicyDrill(idx, srcB64, dstB64) {
  const row     = el(`pd-${idx}`);
  const content = el(`pd-${idx}-content`);
  const btn     = document.querySelector(`#pr-${idx} .drill-btn`);
  if (!row || !content) return;

  if (row.style.display !== 'none') {
    row.style.display = 'none';
    if (btn) btn.textContent = '▾ Hôtes';
    return;
  }

  row.style.display = '';
  if (btn) btn.textContent = '▴ Fermer';

  if (content.dataset.loaded) return; // already fetched

  const srcSubnet = atob(srcB64);
  const dstTarget = atob(dstB64);
  content.innerHTML = '<div class="host-loading"><div class="progress-spinner" style="margin:0 auto 8px"></div>Chargement…</div>';

  try {
    const q    = `srcSubnet=${encodeURIComponent(srcSubnet)}&dstTarget=${encodeURIComponent(dstTarget)}&limit=200`;
    const data = await api(`/api/flows?${q}`);
    content.innerHTML = renderPolicyDrillTable(data.data, srcSubnet, dstTarget);
    content.dataset.loaded = '1';
  } catch (e) {
    content.innerHTML = `<div class="alert alert-error">Erreur : ${escHtml(e.message)}</div>`;
  }
}
window.togglePolicyDrill = togglePolicyDrill;

function renderPolicyDrillTable(flows, srcSubnet, dstTarget) {
  if (!flows.length) return `<div class="host-empty">Aucun flux individuel trouvé pour ${escHtml(srcSubnet)} → ${escHtml(dstTarget)}</div>`;

  // Group by srcip → dstip
  const pairs = {};
  for (const f of flows) {
    const key = `${f.srcip}|${f.dstip}`;
    if (!pairs[key]) pairs[key] = { srcip: f.srcip, dstip: f.dstip, services: new Set(), ports: new Set(), count: 0, action: f.action };
    const p = pairs[key];
    if (f.service) p.services.add(f.service);
    if (f.dstport) p.ports.add(f.dstport);
    p.count += f.count;
  }

  const sorted = Object.values(pairs).sort((a, b) => b.count - a.count);

  const rows = sorted.map(p => {
    const svc = [...p.services].slice(0, 4).join(', ') || [...p.ports].slice(0, 4).join(', ') || '–';
    return `<tr>
      <td class="mono">${p.srcip}</td>
      <td class="mono" style="color:var(--text2)">→</td>
      <td class="mono">${p.dstip}</td>
      <td class="mono" style="font-size:11px;">${escHtml(svc)}</td>
      <td>${actionTag(p.action)}</td>
      <td class="mono">${fmtNum(p.count)}</td>
    </tr>`;
  }).join('');

  return `
    <div class="drill-header">${sorted.length} paire(s) src→dst pour <span class="mono">${escHtml(srcSubnet)}</span> → <span class="mono">${escHtml(dstTarget)}</span></div>
    <table class="drill-table">
      <thead><tr><th>Source IP</th><th></th><th>Dest IP</th><th>Services</th><th>Action</th><th>Sessions</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ═══════════════════════════════════════════════════════════════
// View: Top Ports (top 25 TCP + UDP)
// ═══════════════════════════════════════════════════════════════

async function ports() {
  if (_viewAbort) _viewAbort.abort();
  _viewAbort = new AbortController();
  // signal available for future listeners; ports() renders via innerHTML — no direct listeners to attach
  el(_renderTarget || 'content').innerHTML = '<div class="empty-state"><div class="progress-spinner" style="margin:0 auto"></div></div>';
  try {
    const data = await api('/api/ports');
    renderPorts(data);
  } catch (e) {
    el(_renderTarget || 'content').innerHTML = `<div class="alert alert-error">${escHtml(e.message)}</div>`;
  }
}

function renderPorts({ tcp = [], udp = [] }) {
  const maxTcp = tcp[0]?.count || 1;
  const maxUdp = udp[0]?.count || 1;

  function portRows(list, color, max) {
    if (!list.length) return '<div class="empty-state" style="padding:24px">Aucune donnée</div>';
    return list.map((p, i) => {
      const barPct = Math.round((p.count / max) * 100);
      const label  = p.name ? `<span class="port-name">${p.name}</span>` : '';
      return `
        <div class="port-row">
          <div class="port-rank">${i + 1}</div>
          <div class="port-num mono">${p.port}</div>
          <div class="port-label">${label}</div>
          <div class="port-bar-wrap">
            <div class="port-bar-fill" style="width:${barPct}%;background:${color}"></div>
          </div>
          <div class="port-count mono">${fmtNum(p.count)}</div>
          <div class="port-pct">${p.pct}%</div>
        </div>`;
    }).join('');
  }

  el(_renderTarget || 'content').innerHTML = `
    <div class="ports-grid">
      <div class="ports-col">
        <div class="ports-col-header" style="color:var(--accent)">Top 25 TCP — Ports destination</div>
        <div class="ports-list">${portRows(tcp, 'var(--accent)', maxTcp)}</div>
      </div>
      <div class="ports-col">
        <div class="ports-col-header" style="color:var(--accent2)">Top 25 UDP — Ports destination</div>
        <div class="ports-list">${portRows(udp, 'var(--accent2)', maxUdp)}</div>
      </div>
    </div>`;
}

// ═══════════════════════════════════════════════════════════════
// View: Conseils Policies (moteur de consolidation)
// ═══════════════════════════════════════════════════════════════

async function consilpolicies() {
  if (_viewAbort) _viewAbort.abort();
  _viewAbort = new AbortController();
  const { signal } = _viewAbort;

  el(_renderTarget || 'content').innerHTML = `
    <div class="filter-bar">
      <select class="filter-select" id="cp-dst-type">
        <option value="">Toutes destinations</option>
        <option value="private">LAN uniquement</option>
        <option value="public">WAN uniquement</option>
      </select>
      <button class="filter-btn" id="btn-apply-cp">Filtrer</button>
      <span style="margin-left:auto;display:flex;gap:8px;">
        <a class="export-btn primary" id="btn-export-cp" href="#">⬇ Export CSV FortiGate</a>
      </span>
    </div>
    <div id="cp-wrap"></div>`;

  el('btn-apply-cp').addEventListener('click', loadConsilPolicies, { signal });

  el('btn-export-cp').addEventListener('click', e => {
    e.preventDefault();
    const q = el('cp-dst-type').value ? `dst_type=${el('cp-dst-type').value}` : '';
    window.location = `/api/export/consolidated-policies${q ? '?' + q : ''}${q ? '&' : '?'}session=${state.session}`;
  }, { signal });

  loadConsilPolicies();
}

async function loadConsilPolicies() {
  const wrap = el('cp-wrap');
  if (!wrap) return;
  wrap.innerHTML = '<div class="empty-state"><div class="progress-spinner" style="margin:0 auto"></div></div>';

  try {
    const dst_type = el('cp-dst-type')?.value || '';
    const q        = dst_type ? `dst_type=${dst_type}` : '';
    const data     = await api(`/api/consolidated-policies${q ? '?' + q : ''}`);

    el('badge-consilpolicies').textContent = fmtNum(data.stats.totalCons);
    renderConsilPolicies(data);
  } catch (e) {
    wrap.innerHTML = `<div class="alert alert-error">${escHtml(e.message)}</div>`;
  }
}

function renderConsilPolicies({ consolidated, stats }) {
  const wrap = el('cp-wrap');
  if (!consolidated.length) {
    wrap.innerHTML = '<div class="empty-state"><div class="empty-icon">⚡</div><div class="empty-msg">Aucune policy à consolider</div></div>';
    return;
  }

  const pct     = stats.totalRaw > 0 ? Math.round((1 - stats.totalCons / stats.totalRaw) * 100) : 0;
  const gainCls = pct >= 50 ? 'gain-high' : pct >= 20 ? 'gain-mid' : 'gain-low';

  const rows = consolidated.map((p, i) => {
    const pid     = `cp-${i}`;
    const srcB64  = btoa(JSON.stringify(p.srcSubnets));
    const dstB64  = btoa(JSON.stringify(p.dstTargets));

    // Sources cell
    const srcCell = p.srcSubnets.length === 1
      ? `<span class="mono cell-single">${p.srcSubnets[0]}</span>`
      : `<button class="multi-badge" onclick="toggleMultiList('src-${pid}')">
           ${p.srcSubnets.length} subnets ▾
         </button>
         <div class="multi-list" id="src-${pid}" style="display:none;">
           ${p.srcSubnets.map(s => `<div class="multi-item mono">${s}</div>`).join('')}
         </div>`;

    // Destinations cell
    const dstTypes = p.dstTargets.map(d => p.dstTypes[d]);
    const hasPriv  = dstTypes.includes('private');
    const hasPub   = dstTypes.includes('public');
    const dstTypeTag = hasPriv && hasPub
      ? `<span class="tag tag-mixed">LAN+WAN</span>`
      : hasPriv ? typeTag('private') : typeTag('public');

    const dstCell = p.dstTargets.length === 1
      ? `${typeTag(p.dstTypes[p.dstTargets[0]])} <span class="mono cell-single">${p.dstTargets[0]}</span>`
      : `${dstTypeTag}
         <button class="multi-badge" onclick="toggleMultiList('dst-${pid}')">
           ${p.dstTargets.length} destinations ▾
         </button>
         <div class="multi-list" id="dst-${pid}" style="display:none;">
           ${p.dstTargets.map(d => `<div class="multi-item mono">${typeTag(p.dstTypes[d])} ${d}</div>`).join('')}
         </div>`;

    // Savings badge
    const savBadge = p.savedCount > 0
      ? `<span class="savings-badge ${p.savedCount >= 4 ? 'savings-high' : 'savings-mid'}">−${p.savedCount} rule${p.savedCount > 1 ? 's' : ''}</span>`
      : `<span class="savings-badge savings-none">1:1</span>`;

    return `
      <tr id="cpr-${i}">
        <td class="mono" style="color:var(--text2)">${p.id}</td>
        <td class="cp-src-cell">${srcCell}</td>
        <td class="cp-dst-cell">${dstCell}</td>
        <td style="max-width:240px;white-space:normal;font-family:var(--mono);font-size:11px;">${escHtml(p.serviceDesc)}</td>
        <td class="mono">${fmtNum(p.sessions)}</td>
        <td class="mono">${fmtBytes(p.sentBytes + p.rcvdBytes)}</td>
        <td>${savBadge}</td>
        <td><button class="drill-btn" onclick="toggleCpDrill(${i},'${srcB64}','${dstB64}')">▾ Détail</button></td>
      </tr>
      <tr id="${pid}" class="policy-drill-row" style="display:none;">
        <td colspan="8"><div id="${pid}-content" class="policy-drill-content"></div></td>
      </tr>`;
  }).join('');

  wrap.innerHTML = `
    <div class="cons-banner ${gainCls}">
      <div class="cons-banner-main">
        <span class="cons-num">${fmtNum(stats.totalRaw)}</span>
        <span class="cons-arrow">→</span>
        <span class="cons-num accent">${fmtNum(stats.totalCons)}</span>
        <span class="cons-label"> règles consolidées</span>
        <span class="cons-pct">&nbsp;−${pct}%</span>
      </div>
      <div class="cons-banner-sub">
        ${fmtNum(stats.saved)} rules économisées · algorithme 2 passes (src→dst→service)
      </div>
    </div>

    <div style="margin:8px 0;font-size:12px;color:var(--text2)">
      ${consolidated.length} règles optimisées — cliquer ▾ Détail pour voir les IPs sources/destinations individuelles
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Sources</th>
            <th>Destinations</th>
            <th>Services / Ports</th>
            <th>Sessions</th>
            <th>Volume</th>
            <th>Économie</th>
            <th></th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function toggleMultiList(id) {
  const el2 = el(id);
  if (!el2) return;
  el2.style.display = el2.style.display === 'none' ? 'block' : 'none';
}
window.toggleMultiList = toggleMultiList;

async function toggleCpDrill(idx, srcB64, dstB64) {
  const row     = el(`cp-${idx}`);
  const content = el(`cp-${idx}-content`);
  const btn     = document.querySelector(`#cpr-${idx} .drill-btn`);
  if (!row || !content) return;

  if (row.style.display !== 'none') {
    row.style.display = 'none';
    if (btn) btn.textContent = '▾ Détail';
    return;
  }

  row.style.display = '';
  if (btn) btn.textContent = '▴ Fermer';
  if (content.dataset.loaded) return;

  const srcSubnets = JSON.parse(atob(srcB64));
  const dstTargets = JSON.parse(atob(dstB64));
  content.innerHTML = '<div class="host-loading"><div class="progress-spinner" style="margin:0 auto 8px"></div>Chargement…</div>';

  try {
    // Fetch flows for all combinations src×dst
    const allFlows = [];
    for (const src of srcSubnets) {
      for (const dst of dstTargets) {
        const q    = `srcSubnet=${encodeURIComponent(src)}&dstTarget=${encodeURIComponent(dst)}&limit=500`;
        const data = await api(`/api/flows?${q}`);
        allFlows.push(...data.data);
      }
    }
    content.innerHTML = renderCpDrillTable(allFlows, srcSubnets, dstTargets);
    content.dataset.loaded = '1';
  } catch (e) {
    content.innerHTML = `<div class="alert alert-error">Erreur : ${escHtml(e.message)}</div>`;
  }
}
window.toggleCpDrill = toggleCpDrill;

function renderCpDrillTable(flows, srcSubnets, dstTargets) {
  if (!flows.length) {
    return `<div class="host-empty">Aucun flux individuel trouvé pour ces combinaisons src→dst</div>`;
  }

  // Group by srcSubnet → dstTarget → individual hosts
  const groups = {};
  for (const f of flows) {
    const sk = f.srcSubnet || f.srcip;
    const dk = f.dstSubnet || f.dstip;
    const gkey = `${sk}→${dk}`;
    if (!groups[gkey]) groups[gkey] = { src: sk, dst: dk, hosts: {}, count: 0 };
    const g = groups[gkey];
    const hkey = `${f.srcip}|${f.dstip}`;
    if (!g.hosts[hkey]) g.hosts[hkey] = { srcip: f.srcip, dstip: f.dstip, services: new Set(), count: 0, action: f.action };
    const h = g.hosts[hkey];
    if (f.service) h.services.add(f.service);
    h.count += f.count;
    g.count += f.count;
  }

  const groupList = Object.values(groups).sort((a, b) => b.count - a.count);
  const sections  = groupList.map(g => {
    const hostRows = Object.values(g.hosts).sort((a, b) => b.count - a.count).map(h =>
      `<tr>
        <td class="mono" style="padding-left:24px;">${h.srcip}</td>
        <td class="mono" style="color:var(--text2)">→</td>
        <td class="mono">${h.dstip}</td>
        <td class="mono" style="font-size:11px;">${escHtml([...h.services].slice(0,4).join(', ') || '–')}</td>
        <td>${actionTag(h.action)}</td>
        <td class="mono">${fmtNum(h.count)}</td>
      </tr>`
    ).join('');

    return `
      <tr class="drill-group-header">
        <td colspan="6" class="mono" style="padding:6px 10px;color:var(--accent2);font-size:11px;background:var(--bg2);">
          ${escHtml(g.src)} → ${escHtml(g.dst)} &nbsp;·&nbsp; ${fmtNum(g.count)} sess
        </td>
      </tr>
      ${hostRows}`;
  }).join('');

  return `
    <div class="drill-header">${flows.length} flux · ${groupList.length} pair(s) subnet·subnet</div>
    <table class="drill-table">
      <thead><tr><th>Source IP</th><th></th><th>Dest IP</th><th>Services</th><th>Action</th><th>Sessions</th></tr></thead>
      <tbody>${sections}</tbody>
    </table>`;
}

// ═══════════════════════════════════════════════════════════════
// Denied flows view
// ═══════════════════════════════════════════════════════════════

async function denied() {
  if (_viewAbort) _viewAbort.abort();
  _viewAbort = new AbortController();
  const { signal } = _viewAbort;

  el(_renderTarget || 'content').innerHTML = '<div class="empty-state"><div class="progress-spinner"></div></div>';
  try {
    const data = await api('/api/denied-flows');
    el('badge-denied').textContent = data.length;

    if (data.length === 0) {
      el(_renderTarget || 'content').innerHTML = '<div class="empty-state" style="padding:40px"><div style="font-size:16px;margin-bottom:8px">Aucun flux refusé</div><div style="color:var(--text2)">Aucun trafic deny/drop trouvé dans les logs</div></div>';
      return;
    }

    const totalSessions = data.reduce((s, d) => s + d.sessions, 0);

    const rows = data.map((d, i) => {
      const svcTags = d.services.slice(0, 5).map(s => `<span class="tag">${escHtml(s)}</span>`).join('');
      const portTags = d.ports.slice(0, 8).map(p => `<span class="tag port-tag">${escHtml(p)}</span>`).join('');
      const barW = Math.round((d.sessions / data[0].sessions) * 100);
      return `<tr>
        <td><input type="checkbox" class="denied-chk" data-idx="${i}"></td>
        <td class="mono">${escHtml(d.srcSubnet)}</td>
        <td class="mono">${escHtml(d.dstTarget)}</td>
        <td>${typeTag(d.dstType)}</td>
        <td>${svcTags}${portTags}</td>
        <td class="impact-cell"><div class="impact-bar" style="width:${barW}%;background:color-mix(in srgb, var(--danger) 25%, transparent)"></div><span class="impact-val">${fmtNum(d.sessions)}</span></td>
        <td style="font-size:11px;color:var(--text2)">${fmtBytes(d.bytes)}</td>
      </tr>`;
    }).join('');

    el(_renderTarget || 'content').innerHTML = `
      <div style="padding:24px;max-width:1400px">
        <div style="margin-bottom:12px;display:flex;align-items:center;gap:12px">
          <span style="font-size:13px;color:var(--text2)">${data.length} flux refusés · ${fmtNum(totalSessions)} sessions bloquées</span>
          <button class="btn-accent" id="btn-denied-to-deploy" disabled>Envoyer au déploiement</button>
        </div>
        <div style="overflow-x:auto">
          <table>
            <thead><tr>
              <th><input type="checkbox" id="chk-all-denied"></th>
              <th>Source</th><th>Destination</th><th>Type</th>
              <th>Services / Ports</th><th>Sessions</th><th>Volume</th>
            </tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </div>`;

    // Wire select-all
    const chkAll = el('chk-all-denied');
    const deniedSelected = new Set();
    const updateBtn = () => {
      const btn = el('btn-denied-to-deploy');
      btn.disabled = deniedSelected.size === 0;
      btn.textContent = deniedSelected.size > 0
        ? `Envoyer ${deniedSelected.size} flux au déploiement`
        : 'Envoyer au déploiement';
    };

    chkAll.addEventListener('change', e => {
      document.querySelectorAll('.denied-chk').forEach(chk => {
        chk.checked = e.target.checked;
        e.target.checked ? deniedSelected.add(+chk.dataset.idx) : deniedSelected.delete(+chk.dataset.idx);
      });
      updateBtn();
    }, { signal });

    document.querySelectorAll('.denied-chk').forEach(chk => {
      chk.addEventListener('change', e => {
        e.target.checked ? deniedSelected.add(+chk.dataset.idx) : deniedSelected.delete(+chk.dataset.idx);
        updateBtn();
      }, { signal });
    });

    el('btn-denied-to-deploy').addEventListener('click', () => {
      if (deniedSelected.size === 0) return;
      // Convert selected denied flows to policy format and push to deploy
      const selectedDenied = [...deniedSelected].map(i => data[i]).filter(Boolean);
      // Store as pending denied policies for the deploy tab
      deployState._pendingDenied = selectedDenied.map(d => ({
        srcSubnet:   d.srcSubnet,
        dstTarget:   d.dstTarget,
        dstType:     d.dstType,
        sessions:    d.sessions,
        services:    d.services,
        ports:       d.ports,
        protos:      ['TCP'],
        serviceDesc: [...d.services, ...d.ports.map(p => `${p}/TCP`)].join(', '),
        policyIds:   [],
        action:      'deny',
        _fromDenied: true,
      }));
      navigateTo('deploy');
    }, { signal });

  } catch (err) {
    el(_renderTarget || 'content').innerHTML = `<div class="empty-state" style="padding:40px;color:var(--danger)">${escHtml(err.message)}</div>`;
  }
}

// ═══════════════════════════════════════════════════════════════
// Deploy view
// ═══════════════════════════════════════════════════════════════

// Deploy state (persists across nav changes within a session)
const deployState = {
  fortiConfig:   null,
  interfaces:    null,
  analyzed:      null,
  searchFilter:  '',
  selected:      new Set(),
  page:          1,
  pageSize:      100,
  selectedSdwan: null,  // user-selected SD-WAN priority interface
  warnings:      [],
  viewMode:      'flat',           // 'flat' | 'interface-pair' | 'sequence'
  collapsedGroups: new Set(),      // collapsed group keys for interface-pair view
  wizardStep:    1,                // 1: config upload, 2: interfaces, 3: policies
  use32Global:   false,            // global /32 mode (use real hosts instead of /24)
};

// ── F6: Export/Import session ──
function exportSession() {
  const data = {
    version: 1, timestamp: new Date().toISOString(),
    deployState: {
      fortiConfig:   deployState.fortiConfig,
      analyzed:      deployState.analyzed,
      selected:      [...deployState.selected],
      searchFilter:  deployState.searchFilter,
      interfaces:    deployState.interfaces,
      selectedSdwan: deployState.selectedSdwan,
      generatedCli:  deployState.generatedCli,
      addrGroups:    deployState.addrGroups,
      warnings:      deployState.warnings,
      viewMode:      deployState.viewMode,
    },
  };
  const blob = new Blob([JSON.stringify(data)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `fortiflow_session_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function importSession(file) {
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const data = JSON.parse(e.target.result);
      if (data.version !== 1 || !data.deployState) { alert('Fichier de session invalide'); return; }
      const ds = data.deployState;
      deployState.fortiConfig   = ds.fortiConfig;
      deployState.analyzed      = ds.analyzed;
      deployState.selected      = new Set(ds.selected || []);
      deployState.searchFilter  = ds.searchFilter || '';
      deployState.interfaces    = ds.interfaces;
      deployState.selectedSdwan = ds.selectedSdwan;
      deployState.generatedCli  = ds.generatedCli;
      deployState.addrGroups    = ds.addrGroups;
      deployState.warnings      = ds.warnings || [];
      deployState.viewMode      = ds.viewMode || 'flat';
      deploy();
    } catch { alert('Erreur de lecture du fichier'); }
  };
  reader.readAsText(file);
}

// ── F9: Merge diff modal ──
function showMergeDiff(mode) {
  const original = deployState._analyzedOriginal || deployState.analyzed;
  if (!original) return;
  let preview;
  if (mode === 'policy') preview = mergeByPolicyId(original.map(p => ({ ...p })));
  else preview = mergeAnalyzedPolicies(original.map(p => ({ ...p })), mode);

  const beforeCount = original.length;
  const afterCount  = preview.length;
  const mergedGroups = preview.filter(p => (p._mergedCount || 1) > 1);

  const groupRows = mergedGroups.slice(0, 20).map(g => {
    const src = g.srcSubnets ? g.srcSubnets.join(', ') : g.srcSubnet;
    return `<div style="display:flex;gap:8px;align-items:center;padding:4px 0;border-bottom:1px solid var(--border)">
      <span class="mono" style="font-size:11px;min-width:120px">${escHtml(src)}</span>
      <span style="color:var(--text2)">→</span>
      <span class="mono" style="font-size:11px">${escHtml(g.dstTarget)}</span>
      <span class="merge-badge" style="margin-left:auto">×${g._mergedCount}</span>
    </div>`;
  }).join('');

  const modal = document.createElement('div');
  modal.className = 'merge-modal-overlay';
  modal.innerHTML = `
    <div class="merge-modal">
      <div style="font-size:14px;font-weight:600;margin-bottom:12px">Aperçu fusion : ${mode}</div>
      <div style="display:flex;gap:20px;margin-bottom:16px">
        <div class="stat-card" style="flex:1;padding:12px"><div class="stat-value">${beforeCount}</div><div class="stat-label">avant</div></div>
        <div class="stat-card" style="flex:1;padding:12px"><div class="stat-value" style="color:var(--accent)">${afterCount}</div><div class="stat-label">après</div></div>
        <div class="stat-card" style="flex:1;padding:12px"><div class="stat-value" style="color:var(--accent2)">-${beforeCount - afterCount}</div><div class="stat-label">économie</div></div>
      </div>
      ${mergedGroups.length > 0 ? `<div style="font-size:12px;font-weight:600;margin-bottom:8px">${mergedGroups.length} groupes fusionnés :</div>
      <div style="max-height:250px;overflow-y:auto;margin-bottom:16px">${groupRows}${mergedGroups.length > 20 ? `<div style="color:var(--text2);font-size:11px;padding:4px">+${mergedGroups.length - 20} autres…</div>` : ''}</div>` : ''}
      <div style="display:flex;gap:8px;justify-content:flex-end">
        <button class="btn-sm" id="merge-cancel">Annuler</button>
        <button class="btn-accent" id="merge-confirm">Appliquer</button>
      </div>
    </div>`;

  document.body.appendChild(modal);
  modal.querySelector('#merge-cancel').addEventListener('click', () => modal.remove());
  modal.querySelector('#merge-confirm').addEventListener('click', () => { modal.remove(); applyMerge(mode); });
  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
}

// ── Inventaire des objets manquants ──────────────────────────────────────────

function collectMissingObjects() {
  if (!deployState.analyzed) return { addresses: [], hosts: [], services: [], total: 0 };

  const addresses = new Map(); // cidr → { cidr, name, policyCount }
  const hosts     = new Map(); // ip   → { ip, name, policyCount }
  const services  = new Map(); // key  → { key, port, proto, label, name, policyCount }

  for (const p of deployState.analyzed) {
    const a = p.analysis;
    if (!a) continue;

    // Src address manquante (seulement si pas en mode /32)
    if (!p._use32Src && a.srcAddr && !a.srcAddr.found) {
      const cidr = a.srcAddr.cidr;
      if (cidr) {
        if (!addresses.has(cidr)) addresses.set(cidr, { cidr, name: p._srcAddrName || a.srcAddr.suggestedName, policyCount: 0 });
        addresses.get(cidr).policyCount++;
      }
    }
    // Dst address manquante
    if (!p._use32Dst && p.dstType === 'private' && a.dstAddr && !a.dstAddr.found) {
      const cidr = a.dstAddr.cidr;
      if (cidr && cidr !== 'all') {
        if (!addresses.has(cidr)) addresses.set(cidr, { cidr, name: p._dstAddrName || a.dstAddr.suggestedName, policyCount: 0 });
        addresses.get(cidr).policyCount++;
      }
    }
    // Hôtes /32 src
    if (p._use32Src && p.srcHosts?.length > 0) {
      for (const h of p.srcHosts) {
        if (!hosts.has(h)) {
          const suggested = (p._srcHostNames?.[h]) || `FF_HOST_${h.replace(/\./g, '_')}`;
          hosts.set(h, { ip: h, name: suggested, policyCount: 0 });
        }
        hosts.get(h).policyCount++;
      }
    }
    // Hôtes /32 dst
    if (p._use32Dst && p.dstHosts?.length > 0) {
      for (const h of p.dstHosts) {
        if (!hosts.has(h)) {
          const suggested = (p._dstHostNames?.[h]) || `FF_HOST_${h.replace(/\./g, '_')}`;
          hosts.set(h, { ip: h, name: suggested, policyCount: 0 });
        }
        hosts.get(h).policyCount++;
      }
    }
    // Services manquants
    for (const svc of a.services || []) {
      if (!svc.found) {
        const key = `${svc.port}/${svc.proto}`;
        if (!services.has(key)) services.set(key, { key, port: svc.port, proto: svc.proto, label: svc.label, name: svc.suggestedName || `FF_SVC_${svc.port}_${svc.proto}`, policyCount: 0 });
        services.get(key).policyCount++;
      }
    }
  }

  const result = {
    addresses: [...addresses.values()],
    hosts:     [...hosts.values()],
    services:  [...services.values()],
  };
  result.total = result.addresses.length + result.hosts.length + result.services.length;
  return result;
}

function showObjectsModal() {
  const missing = collectMissingObjects();
  if (missing.total === 0) return;

  function section(title, icon, items, inputPrefix) {
    if (!items.length) return '';
    const rows = items.map((item, i) => {
      const label = item.cidr || item.ip || item.label;
      const hint  = item.policyCount > 1 ? `<span style="font-size:10px;color:var(--text2)">${item.policyCount} policies</span>` : '';
      return `<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--border)">
        <span class="mono" style="min-width:160px;font-size:11px">${escHtml(label)}</span>
        ${hint}
        <input class="deploy-name-input obj-modal-input" style="flex:1" data-obj-prefix="${inputPrefix}" data-obj-key="${escHtml(item.cidr || item.ip || item.key)}" value="${escHtml(item.name)}" placeholder="Nom FortiGate…">
      </div>`;
    }).join('');
    return `<div style="margin-bottom:16px">
      <div style="font-size:12px;font-weight:600;margin-bottom:6px">${icon} ${title} <span style="font-size:11px;font-weight:400;color:var(--text2)">(${items.length})</span></div>
      ${rows}
    </div>`;
  }

  const modal = document.createElement('div');
  modal.className = 'merge-modal-overlay';
  modal.innerHTML = `
    <div class="merge-modal" style="max-width:560px;width:90vw">
      <div style="font-size:14px;font-weight:600;margin-bottom:4px">Objets à créer <span style="font-weight:400;color:var(--text2);font-size:12px">(${missing.total})</span></div>
      <div style="font-size:11px;color:var(--text2);margin-bottom:14px">Nommez les objets manquants — ils seront appliqués à toutes les policies concernées.</div>
      <div id="obj-modal-body" style="max-height:55vh;overflow-y:auto;padding-right:4px">
        ${section('Adresses subnets', '🔖', missing.addresses, 'addr')}
        ${section('Hôtes /32', '📍', missing.hosts, 'host')}
        ${section('Services', '⚙', missing.services, 'svc')}
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px;border-top:1px solid var(--border);padding-top:12px">
        <button class="btn-sm" id="obj-modal-cancel">Annuler</button>
        <button class="btn-accent" id="obj-modal-apply">✓ Appliquer à toutes les policies</button>
      </div>
    </div>`;

  document.body.appendChild(modal);
  modal.querySelector('#obj-modal-cancel').addEventListener('click', () => modal.remove());
  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  modal.querySelector('#obj-modal-apply').addEventListener('click', () => {
    const addrMap = {}, hostsMap = {}, svcMap = {};
    modal.querySelectorAll('.obj-modal-input').forEach(inp => {
      const prefix = inp.dataset.objPrefix;
      const key    = inp.dataset.objKey;
      const val    = inp.value.trim();
      if (!val) return;
      if (prefix === 'addr') addrMap[key] = val;
      else if (prefix === 'host') hostsMap[key] = val;
      else if (prefix === 'svc')  svcMap[key]  = val;
    });
    modal.remove();
    applyObjectNames(addrMap, hostsMap, svcMap);
  });
}

function applyObjectNames(addrMap, hostsMap, svcMap) {
  for (const p of deployState.analyzed) {
    const a = p.analysis;
    if (!a) continue;
    // Src address
    const srcCidr = a.srcAddr?.cidr;
    if (srcCidr && addrMap[srcCidr]) p._srcAddrName = addrMap[srcCidr];
    // Dst address
    const dstCidr = a.dstAddr?.cidr;
    if (dstCidr && dstCidr !== 'all' && addrMap[dstCidr]) p._dstAddrName = addrMap[dstCidr];
    // Host names (stored per-policy for CLI generation)
    if (p._use32Src && p.srcHosts?.length > 0) {
      p._srcHostNames = p._srcHostNames || {};
      for (const h of p.srcHosts) if (hostsMap[h]) p._srcHostNames[h] = hostsMap[h];
    }
    if (p._use32Dst && p.dstHosts?.length > 0) {
      p._dstHostNames = p._dstHostNames || {};
      for (const h of p.dstHosts) if (hostsMap[h]) p._dstHostNames[h] = hostsMap[h];
    }
    // Services
    for (const svc of a.services || []) {
      if (!svc.found) {
        const key = `${svc.port}/${svc.proto}`;
        if (svcMap[key]) svc.suggestedName = svcMap[key];
      }
    }
  }
  renderDeployPolicies(filterDeployPolicies(), false);
}

// ═══════════════════════════════════════════════════════════════
// View: Analyse (wrapper — sub-tabs: Flux, Matrice, Groupes, Ports)
// ═══════════════════════════════════════════════════════════════

async function analyse() {
  const sub = state.subView.analyse;
  const pills = [
    { key: 'flows',  label: 'Flux',    icon: '≡' },
    { key: 'matrix', label: 'Matrice', icon: '⊞' },
    { key: 'groups', label: 'Groupes', icon: '⊕' },
    { key: 'ports',  label: 'Ports',   icon: '◫' },
  ];
  const pillsHtml = pills.map(p =>
    `<button class="sub-pill ${p.key === sub ? 'active' : ''}" data-sub="${p.key}">${p.icon} ${p.label}</button>`
  ).join('');

  el(_renderTarget || 'content').innerHTML = `
    <div class="sub-pill-bar">${pillsHtml}</div>
    <div id="sub-content"></div>`;

  // Wire pill clicks
  document.querySelectorAll('.sub-pill').forEach(btn => {
    btn.addEventListener('click', () => {
      state.subView.analyse = btn.dataset.sub;
      analyse();
    });
  });

  // Render sub-view into #sub-content
  _renderTarget = 'sub-content';
  const subViews = { flows, matrix, groups, ports };
  await (subViews[sub] || flows)();
  _renderTarget = null;
}

// ═══════════════════════════════════════════════════════════════
// View: Polices (wrapper — sub-tabs: Policies, Conseils, Refusés)
// ═══════════════════════════════════════════════════════════════

async function polices() {
  const sub = state.subView.polices;
  const pills = [
    { key: 'policies',       label: 'Policies',  icon: '◎' },
    { key: 'consilpolicies', label: 'Conseils',   icon: '⚡' },
    { key: 'denied',         label: 'Refusés',   icon: '⊘' },
  ];
  const pillsHtml = pills.map(p =>
    `<button class="sub-pill ${p.key === sub ? 'active' : ''}" data-sub="${p.key}">${p.icon} ${p.label}</button>`
  ).join('');

  el(_renderTarget || 'content').innerHTML = `
    <div class="sub-pill-bar">${pillsHtml}</div>
    <div id="sub-content"></div>`;

  document.querySelectorAll('.sub-pill').forEach(btn => {
    btn.addEventListener('click', () => {
      state.subView.polices = btn.dataset.sub;
      polices();
    });
  });

  _renderTarget = 'sub-content';
  const subViews = { policies, consilpolicies, denied };
  await (subViews[sub] || policies)();
  _renderTarget = null;
}

// ═══════════════════════════════════════════════════════════════
// View: Deploy
// ═══════════════════════════════════════════════════════════════

// ── F8: Predefined tags ──
const POLICY_TAGS = ['critique', 'temporaire', 'a valider', 'segmentation'];

async function deploy() {
  // Reset delegation flag — deploy() replaces the entire DOM tree
  resetDeployTableWiring();

  // Auto-advance wizard based on state
  if (deployState.fortiConfig && deployState.wizardStep < 2) deployState.wizardStep = 2;
  if (deployState.analyzed && deployState.wizardStep < 3) deployState.wizardStep = 3;
  const ws = deployState.wizardStep;

  el(_renderTarget || 'content').innerHTML = `
    <div class="deploy-wrap">
      <!-- Wizard progress -->
      <div class="wizard-progress">
        <div class="wizard-step-indicator ${ws >= 1 ? 'active' : ''} ${ws > 1 ? 'done' : ''}" data-step="1">
          <span class="wizard-num">1</span> Config
        </div>
        <div class="wizard-connector ${ws > 1 ? 'done' : ''}"></div>
        <div class="wizard-step-indicator ${ws >= 2 ? 'active' : ''} ${ws > 2 ? 'done' : ''}" data-step="2">
          <span class="wizard-num">2</span> Interfaces
        </div>
        <div class="wizard-connector ${ws > 2 ? 'done' : ''}"></div>
        <div class="wizard-step-indicator ${ws >= 3 ? 'active' : ''}" data-step="3">
          <span class="wizard-num">3</span> Policies
        </div>
      </div>

      <!-- Step 1: import .conf -->
      <div class="deploy-step" id="deploy-step1" ${ws !== 1 ? 'style="display:none"' : ''}>
        <div class="deploy-step-header">
          <span class="deploy-step-num">1</span>
          Importer la config FortiGate
        </div>
        <div class="deploy-step-body">
          ${deployState.fortiConfig
            ? `<div class="deploy-conf-summary" id="deploy-conf-summary">
                 ${renderConfSummary(deployState.fortiConfig)}
               </div>`
            : `<label class="deploy-dropzone" id="deploy-dropzone">
                 <input type="file" id="deploy-file-input" accept=".conf,.txt" style="display:none">
                 <div class="deploy-drop-icon">⊙</div>
                 <div class="deploy-drop-text">Déposez votre config FortiGate (.conf)</div>
                 <div class="deploy-drop-sub">ou cliquez pour choisir un fichier</div>
               </label>`
          }
        </div>
        ${deployState.fortiConfig ? `<div class="wizard-nav"><span></span><button class="btn-accent wizard-next" data-to="2">Suivant →</button></div>` : ''}
      </div>

      <!-- Step 2: interfaces -->
      <div class="deploy-step" id="deploy-step2" ${ws !== 2 ? 'style="display:none"' : ''}>
        <div class="deploy-step-header" id="deploy-iface-toggle" style="cursor:pointer">
          <span class="deploy-step-num">2</span>
          Interfaces &amp; Zones
          <span id="deploy-iface-arrow" style="margin-left:auto;font-size:11px">▾</span>
        </div>
        <div class="deploy-step-body" id="deploy-iface-body">
          ${deployState.interfaces ? renderInterfaces(deployState.interfaces) : ''}
        </div>
        <div class="wizard-nav">
          <button class="btn-sm wizard-prev" data-to="1">← Précédent</button>
          <button class="btn-accent wizard-next" data-to="3">Suivant →</button>
        </div>
      </div>

      <!-- Step 3: policy table -->
      <div class="deploy-step" id="deploy-step3" ${ws !== 3 ? 'style="display:none"' : ''}>
        <div class="deploy-step-header">
          <span class="deploy-step-num">3</span>
          Policies à générer
          <div style="margin-left:auto;display:flex;gap:12px;align-items:center;font-size:12px;font-weight:400">
            <label class="deploy-toggle-label">
              NAT <input type="checkbox" id="opt-nat"> <span class="deploy-toggle-knob"></span>
              <span style="color:var(--text2);font-weight:400;font-size:11px">(WAN uniquement)</span>
            </label>
            <select id="opt-action" class="deploy-select">
              <option value="accept">accept</option>
              <option value="deny">deny</option>
            </select>
            <select id="opt-log" class="deploy-select">
              <option value="all">log all</option>
              <option value="utm">log utm</option>
              <option value="disable">log disable</option>
            </select>
            <button class="btn-accent" id="btn-analyze">Analyser les policies</button>
          </div>
        </div>
        <div class="deploy-merge-bar" id="deploy-merge-bar" style="display:none">
          <span id="deploy-merge-info" style="font-size:11px;color:var(--text2)"></span>
          <div class="dropdown-wrap">
            <button class="btn-sm dropdown-trigger">⚡ Fusion ▾</button>
            <div class="dropdown-menu">
              <div class="dropdown-item" data-merge="internet">Fusionner Internet</div>
              <div class="dropdown-item" data-merge="lan">Fusionner LAN</div>
              <div class="dropdown-item" data-merge="all">Tout fusionner</div>
              <div class="dropdown-item" data-merge="policy">Par Policy ID</div>
              <div class="dropdown-sep"></div>
              <div class="dropdown-item" data-merge="reset">↺ Réinitialiser</div>
            </div>
          </div>
          <div class="dropdown-wrap">
            <button class="btn-sm dropdown-trigger">☰ Vue ▾</button>
            <div class="dropdown-menu">
              <div class="dropdown-item ${deployState.viewMode === 'flat' ? 'active' : ''}" data-view-mode="flat">☰ Liste classique</div>
              <div class="dropdown-item ${deployState.viewMode === 'interface-pair' ? 'active' : ''}" data-view-mode="interface-pair">⇄ Par interfaces</div>
              <div class="dropdown-item ${deployState.viewMode === 'sequence' ? 'active' : ''}" data-view-mode="sequence">⊞ Séquences</div>
            </div>
          </div>
          <button class="btn-sm ${deployState.use32Global ? 'btn-active' : ''}" id="btn-32-global" title="Basculer toutes les policies : /24 subnets ↔ /32 hôtes réels">${deployState.use32Global ? '/32 ✓' : '/24'} ↔ /32</button>
          <button class="btn-sm btn-warn" id="btn-missing-objects" style="display:none" title="Nommer les objets manquants avant de générer le CLI">⚠ …</button>
          <span style="margin-left:auto"></span>
          <input type="text" id="deploy-search" class="deploy-search-input" placeholder="Rechercher (IP, subnet, service, policy...)" value="${escHtml(deployState.searchFilter || '')}" title="Filtrer les policies par texte libre">
        </div>
        <div class="deploy-step-body" id="deploy-policy-body">
          <div class="empty-state" style="padding:24px">Cliquez sur <strong>Analyser les policies</strong> pour commencer</div>
        </div>
        <div class="deploy-step-footer" id="deploy-step3-footer" style="display:none">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
            <button class="btn-accent" id="btn-generate">⬇ Générer config FortiGate</button>
            <span id="deploy-gen-info" style="font-size:11px;color:var(--text2)"></span>
            <span style="margin-left:auto;display:flex;gap:6px">
              <button class="btn-sm" id="btn-export-session" title="Sauvegarder la session de travail">💾 Sauvegarder</button>
              <label class="btn-sm" style="cursor:pointer" title="Charger une session sauvegardée">📂 Charger<input type="file" id="btn-import-session" accept=".json" style="display:none"></label>
            </span>
          </div>
          <div id="deploy-cli-wrap" style="display:none;margin-top:12px">
            <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
              <span style="font-size:12px;font-weight:600">Aperçu CLI</span>
              <button class="btn-sm" id="btn-copy-cli">📋 Copier</button>
              <button class="btn-sm" id="btn-download-cli">⬇ Télécharger</button>
              <button class="btn-sm" id="btn-cli-toggle" style="margin-left:auto">▾ Réduire</button>
            </div>
            <pre id="deploy-cli-pre" class="deploy-cli-pre"></pre>
          </div>
        </div>
      </div>
    </div>`;

  // File input wiring
  const fileInput = el('deploy-file-input');
  if (fileInput) {
    fileInput.addEventListener('change', e => uploadConf(e.target.files[0]));
    el('deploy-dropzone')?.addEventListener('dragover', e => { e.preventDefault(); e.currentTarget.classList.add('dragover'); });
    el('deploy-dropzone')?.addEventListener('dragleave', e => e.currentTarget.classList.remove('dragover'));
    el('deploy-dropzone')?.addEventListener('drop', e => {
      e.preventDefault();
      e.currentTarget.classList.remove('dragover');
      const f = e.dataTransfer.files[0];
      if (f) uploadConf(f);
    });
  }

  // Interfaces toggle
  el('deploy-iface-toggle')?.addEventListener('click', () => {
    const body  = el('deploy-iface-body');
    const arrow = el('deploy-iface-arrow');
    const open  = body.style.display !== 'none';
    body.style.display  = open ? 'none' : '';
    arrow.textContent   = open ? '▸' : '▾';
  });

  // WAN/LAN toggle per interface (délégation)
  el('deploy-iface-body')?.addEventListener('click', e => {
    const btn = e.target.closest('[data-iface-idx]');
    if (!btn) return;
    const idx   = +btn.dataset.ifaceIdx;
    const iface = deployState.interfaces?.interfaces?.[idx];
    if (!iface) return;
    iface.isWan = !iface.isWan;
    // Re-render interfaces panel
    el('deploy-iface-body').innerHTML = renderInterfaces(deployState.interfaces);
  });

  // SD-WAN priority radio (délégation)
  el('deploy-iface-body')?.addEventListener('change', e => {
    if (e.target.name === 'sdwan-priority') {
      deployState.selectedSdwan = e.target.value;
    }
  });

  // Reload conf
  el('btn-reload-conf')?.addEventListener('click', () => {
    deployState.fortiConfig = null;
    deployState.interfaces  = null;
    deployState.analyzed    = null;
    deployState.selected    = new Set();
    deploy();
  });

  // Analyze
  el('btn-analyze')?.addEventListener('click', analyzeDeployPolicies);

  // Global NAT toggle → apply only to WAN rows (wired here since opt-nat is stable in deploy DOM)
  el('opt-nat')?.addEventListener('change', e => {
    document.querySelectorAll('.deploy-nat-chk').forEach(chk => {
      const p = deployState.analyzed?.[+chk.dataset.idx];
      if (p?._isWan) { chk.checked = e.target.checked; p._nat = e.target.checked; }
    });
  });

  // Dropdown toggle + close-on-outside
  el('deploy-merge-bar')?.addEventListener('click', e => {
    const trigger = e.target.closest('.dropdown-trigger');
    if (trigger) {
      const wrap = trigger.closest('.dropdown-wrap');
      const wasOpen = wrap.classList.contains('open');
      document.querySelectorAll('.dropdown-wrap.open').forEach(w => w.classList.remove('open'));
      if (!wasOpen) wrap.classList.add('open');
      e.stopPropagation();
      return;
    }

    // Merge action from dropdown
    const mergeItem = e.target.closest('[data-merge]');
    if (mergeItem) {
      const mode = mergeItem.dataset.merge;
      document.querySelectorAll('.dropdown-wrap.open').forEach(w => w.classList.remove('open'));
      if (mode === 'reset') applyMerge(mode);
      else if (mode) showMergeDiff(mode);
      return;
    }

    // View mode from dropdown
    const viewItem = e.target.closest('[data-view-mode]');
    if (viewItem) {
      deployState.viewMode = viewItem.dataset.viewMode;
      deployState.collapsedGroups = new Set();
      document.querySelectorAll('.dropdown-wrap.open').forEach(w => w.classList.remove('open'));
      if (deployState.analyzed) renderDeployPolicies(filterDeployPolicies(), true);
      return;
    }
  });

  // Close dropdowns on outside click
  document.addEventListener('click', () => {
    document.querySelectorAll('.dropdown-wrap.open').forEach(w => w.classList.remove('open'));
  });

  // Wizard nav buttons
  document.querySelectorAll('.wizard-next, .wizard-prev').forEach(btn => {
    btn.addEventListener('click', () => {
      deployState.wizardStep = +btn.dataset.to;
      deploy();
    });
  });

  // Wizard step indicators (click to jump)
  document.querySelectorAll('.wizard-step-indicator').forEach(ind => {
    ind.addEventListener('click', () => {
      const step = +ind.dataset.step;
      // Only allow jumping to completed steps or current
      if (step === 1 || (step === 2 && deployState.fortiConfig) || (step === 3 && deployState.fortiConfig)) {
        deployState.wizardStep = step;
        deploy();
      }
    });
  });

  // Search bar
  el('deploy-search')?.addEventListener('input', e => {
    deployState.searchFilter = e.target.value;
    deployState.page = 1;
    if (deployState.analyzed) renderDeployPolicies(filterDeployPolicies(), true);
  });

  // Generate
  el('btn-generate')?.addEventListener('click', generateDeployConf);

  // Export/Import session
  el('btn-export-session')?.addEventListener('click', exportSession);
  el('btn-import-session')?.addEventListener('change', e => {
    const f = e.target.files[0];
    if (f) importSession(f);
  });

  // Missing objects modal (wired once — button persists in DOM)
  el('btn-missing-objects')?.addEventListener('click', showObjectsModal);

  // Global /32 toggle (wired once — button persists in DOM)
  el('btn-32-global')?.addEventListener('click', () => {
    deployState.use32Global = !deployState.use32Global;
    if (deployState.analyzed) {
      for (const p of deployState.analyzed) {
        if ((p.srcHosts || []).length > 1) p._use32Src = deployState.use32Global;
        if ((p.dstHosts || []).length > 1) p._use32Dst = deployState.use32Global;
      }
    }
    // Update button appearance
    const btn = el('btn-32-global');
    if (btn) {
      btn.textContent = deployState.use32Global ? '/32 ✓ ↔ /24' : '/24 ↔ /32';
      btn.classList.toggle('btn-active', deployState.use32Global);
    }
    renderDeployPolicies(filterDeployPolicies(), false);
  });

  // Restore analyzed policies if already present (tab switch preservation)
  if (deployState.analyzed && deployState.analyzed.length > 0) {
    el('deploy-merge-bar').style.display = '';
    renderDeployPolicies(filterDeployPolicies(), false);
    // Restore CLI preview if generated
    if (deployState.generatedCli) {
      const wrap = el('deploy-cli-wrap');
      const pre  = el('deploy-cli-pre');
      if (pre)  pre.textContent = deployState.generatedCli;
      if (wrap) wrap.style.display = '';
    }
  }
}

function renderConfSummary(cfg) {
  return `<div class="conf-summary-grid">
    <div class="conf-stat"><span class="conf-stat-val">${cfg.addresses}</span><span class="conf-stat-lbl">adresses</span></div>
    ${cfg.addrGroups > 0 ? `<div class="conf-stat"><span class="conf-stat-val">${cfg.addrGroups}</span><span class="conf-stat-lbl">groupes addr</span></div>` : ''}
    <div class="conf-stat"><span class="conf-stat-val">${cfg.services}</span><span class="conf-stat-lbl">services custom</span></div>
    ${cfg.serviceGroups > 0 ? `<div class="conf-stat"><span class="conf-stat-val">${cfg.serviceGroups}</span><span class="conf-stat-lbl">groupes svc</span></div>` : ''}
    ${cfg.existingPolicies > 0 ? `<div class="conf-stat"><span class="conf-stat-val">${cfg.existingPolicies}</span><span class="conf-stat-lbl">policies</span></div>` : ''}
    <div class="conf-stat"><span class="conf-stat-val">${cfg.interfaces}</span><span class="conf-stat-lbl">interfaces</span></div>
    <div class="conf-stat"><span class="conf-stat-val">${cfg.zones}</span><span class="conf-stat-lbl">zones</span></div>
    ${cfg.routes > 0 ? `<div class="conf-stat" title="Routes (statiques + connected) pour l'auto-détection"><span class="conf-stat-val">${cfg.routes}</span><span class="conf-stat-lbl">routes</span></div>` : ''}
    ${cfg.sdwan ? '<div class="conf-stat"><span class="conf-stat-val">⚡</span><span class="conf-stat-lbl">SD-WAN actif</span></div>' : ''}
    <div class="conf-stat ${cfg.bgp ? '' : 'conf-stat-off'}" title="${cfg.bgp ? 'Voisins BGP utilisés comme routes hôtes /32' : 'Pas de BGP détecté'}"><span class="conf-stat-val">${cfg.bgp ? 'ON' : 'OFF'}</span><span class="conf-stat-lbl">BGP</span></div>
    <div class="conf-stat ${cfg.ospf ? '' : 'conf-stat-off'}" title="${cfg.ospf ? 'OSPF actif' : 'Pas d\'OSPF détecté'}"><span class="conf-stat-val">${cfg.ospf ? 'ON' : 'OFF'}</span><span class="conf-stat-lbl">OSPF</span></div>
    <div class="conf-stat ${cfg.vdom ? 'conf-stat-warn' : 'conf-stat-off'}" title="${cfg.vdom ? 'Configs multi-VDOM : seul le premier VDOM est parsé' : 'Pas de multi-VDOM détecté'}"><span class="conf-stat-val">${cfg.vdom ? 'ON' : 'OFF'}</span><span class="conf-stat-lbl">VDOM</span></div>
    <button class="btn-sm" id="btn-reload-conf" style="margin-left:auto;align-self:center">↺ Recharger</button>
  </div>`;
}

function renderInterfaces({ interfaces, zones, sdwanMembers, sdwanZoneNames, sdwanEnabled, sdwanIntfName }) {
  const ifaceRows = interfaces.map((iface, idx) => `
    <tr>
      <td class="mono">${escHtml(iface.name)}</td>
      <td class="mono" style="color:var(--text2)">${escHtml(iface.cidr || iface.rawIp || '–')}</td>
      <td>
        <button class="deploy-itype-toggle ${iface.isWan ? 'wan' : 'lan'}" data-iface-idx="${idx}" title="Cliquer pour basculer">
          ${iface.isWan ? 'WAN' : 'LAN'} ⇄
        </button>
      </td>
      <td style="color:var(--text2);font-size:11px">${escHtml(iface.alias || '')}</td>
    </tr>`).join('');

  const zoneRows = zones.map(z => `
    <tr>
      <td class="mono">${escHtml(z.name)}</td>
      <td class="mono" style="color:var(--text2)">${z.members.map(escHtml).join(', ')}</td>
      <td colspan="2"></td>
    </tr>`).join('');

  // SD-WAN section: show SDWAN zones as selectable options (zone name goes into dstintf)
  let sdwanSection = '';
  if (sdwanEnabled) {
    // Use sdwanZoneNames if available, fallback to sdwanIntfName
    const zoneOptions = sdwanZoneNames && sdwanZoneNames.length > 0
      ? sdwanZoneNames
      : [sdwanIntfName || 'virtual-wan-link'];
    const currentSel = deployState.selectedSdwan || zoneOptions[0];
    const options = zoneOptions.map(z => ({ value: z, label: z }));
    const radios = options.map(o => `
      <label style="display:flex;align-items:center;gap:6px;cursor:pointer;white-space:nowrap">
        <input type="radio" name="sdwan-priority" value="${escHtml(o.value)}" ${currentSel === o.value ? 'checked' : ''}>
        <span class="mono" style="font-size:12px">${escHtml(o.label)}</span>
      </label>`).join('');
    sdwanSection = `
      <div class="deploy-sdwan-panel">
        <div style="font-size:11px;font-weight:600;color:var(--accent2);margin-bottom:6px">
          ⚡ SD-WAN — Interface de sortie pour les policies WAN
        </div>
        <div style="font-size:11px;color:var(--text2);margin-bottom:8px">
          Sélectionnez l'interface à utiliser comme dstintf pour les règles Internet :
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:10px">
          ${radios}
        </div>
      </div>`;
  } else if (sdwanMembers.length > 0) {
    sdwanSection = `<div style="color:var(--accent2);font-size:11px;margin-top:8px">SD-WAN: ${sdwanMembers.map(escHtml).join(', ')}</div>`;
  }

  return `
    <div style="font-size:11px;color:var(--text2);margin-bottom:8px">Cliquez sur WAN ⇄ / LAN ⇄ pour corriger la classification</div>
    <table class="deploy-iface-table">
      <thead><tr><th>Interface</th><th>IP/CIDR</th><th>Type</th><th>Alias</th></tr></thead>
      <tbody>${ifaceRows}${zoneRows}</tbody>
    </table>
    ${sdwanSection}`;
}

async function uploadConf(file) {
  if (!file) return;
  const form = new FormData();
  form.append('conffile', file);
  form.append('session', state.session);

  try {
    const r = await fetch(`/api/deploy/config-upload?session=${state.session}`, { method: 'POST', body: form });
    if (!r.ok) {
      const text = await r.text();
      const msg  = (() => { try { return JSON.parse(text).error; } catch { return `HTTP ${r.status}`; } })();
      alert('Erreur upload : ' + msg);
      return;
    }
    deployState.fortiConfig = await r.json();

    // Load interfaces
    const ir = await fetch(`/api/deploy/interfaces?session=${state.session}`);
    if (ir.ok) {
      deployState.interfaces = await ir.json();
      // Auto-select first SDWAN zone as default
      if (deployState.interfaces?.sdwanEnabled) {
        const zones = deployState.interfaces.sdwanZoneNames;
        deployState.selectedSdwan = (zones && zones.length > 0)
          ? zones[0]
          : (deployState.interfaces.sdwanIntfName || null);
      } else {
        deployState.selectedSdwan = null;
      }
    }

    deploy(); // re-render
  } catch (err) {
    alert('Erreur : ' + err.message);
  }
}

// ─── Merge logic ──────────────────────────────────────────────────────────────

function mergeAnalyzedPolicies(policies, mode) {
  // mode: 'internet' | 'lan' | 'all'
  // 'internet' = show & merge ONLY internet policies (filter out LAN completely)
  // 'lan'      = show & merge ONLY LAN policies (filter out internet completely)
  // 'all'      = show & merge everything
  const merged   = [];
  const internet = mode === 'internet' || mode === 'all';
  const lan      = mode === 'lan'      || mode === 'all';

  // Collect policies to merge by key
  const internetGroups = new Map(); // key = srcSubnet
  const lanGroups      = new Map(); // key = srcSubnet|dstTarget

  for (const p of policies) {
    const isPublic = p.dstType === 'public' || p.dstTarget === 'all';
    if (isPublic && internet) {
      const k = p.srcSubnet;
      if (!internetGroups.has(k)) internetGroups.set(k, []);
      internetGroups.get(k).push(p);
    } else if (!isPublic && lan) {
      const k = `${p.srcSubnet}|${p.dstTarget}`;
      if (!lanGroups.has(k)) lanGroups.set(k, []);
      lanGroups.get(k).push(p);
    }
    // else: filtered out (not shown)
  }

  // Build merged internet policies (one per srcSubnet → dst=all)
  for (const [srcSubnet, group] of internetGroups) {
    const base = group[0];
    const allServices   = mergeServices(group);
    const totalSessions = group.reduce((s, p) => s + (p.sessions || 0), 0);
    const allPolicyIds  = [...new Set(group.flatMap(p => p.policyIds || []))].sort((a, b) => Number(a) - Number(b));
    merged.push({
      ...base,
      dstTarget:    'all',
      dstType:      'public',
      sessions:     totalSessions,
      serviceDesc:  allServices.map(s => s.label).join(', '),
      policyIds:    allPolicyIds,
      _mergedCount: group.length,
      _srcAddrName: base._srcAddrName || suggestAddrNameFE(srcSubnet),
      _dstAddrName: 'all',
      _policyName:  `FF_${escSlug(srcSubnet)}_to_INTERNET`,
      analysis: {
        ...base.analysis,
        dstAddr:   { found: true, name: 'all', cidr: 'all' },
        services:  allServices,
        needsWork: !base.analysis?.srcAddr?.found || allServices.some(s => !s.found),
      },
    });
  }

  // Build merged LAN policies (one per srcSubnet+dstTarget → merged services)
  for (const [key, group] of lanGroups) {
    const base = group[0];
    const allServices   = mergeServices(group);
    const totalSessions = group.reduce((s, p) => s + (p.sessions || 0), 0);
    const allPolicyIds  = [...new Set(group.flatMap(p => p.policyIds || []))].sort((a, b) => Number(a) - Number(b));
    merged.push({
      ...base,
      sessions:     totalSessions,
      serviceDesc:  allServices.map(s => s.label).join(', '),
      policyIds:    allPolicyIds,
      _mergedCount: group.length,
      analysis: {
        ...base.analysis,
        services:  allServices,
        needsWork: !(base.analysis?.srcAddr?.found) || !(base.analysis?.dstAddr?.found) || allServices.some(s => !s.found),
      },
    });
  }

  return merged;
}

function mergeServices(group) {
  const seen = new Map(); // label → service item
  for (const p of group) {
    for (const svc of (p.analysis?.services || [])) {
      if (!seen.has(svc.label)) seen.set(svc.label, svc);
    }
  }
  return [...seen.values()];
}

// Filtre les policies analysées selon le texte de recherche
function filterDeployPolicies() {
  const q = (deployState.searchFilter || '').toLowerCase().trim();
  if (!q || !deployState.analyzed) return deployState.analyzed || [];
  const terms = q.split(/\s+/);
  return deployState.analyzed.filter(p => {
    const haystack = [
      p.srcSubnet, ...(p.srcSubnets || []),
      p.dstTarget, p._srcAddrName, p._dstAddrName,
      p._srcintf, p._dstintf, p._policyName,
      ...(p.policyIds || []).map(String),
      p.serviceDesc || '',
      ...(p.analysis?.services || []).map(s => s.label || s.name || ''),
      ...(p._dstIPs || []),
      ...(p._tags || []),
    ].join(' ').toLowerCase();
    return terms.every(t => haystack.includes(t));
  });
}

// Cellule dstTarget avec bouton détails pour les targets fusionnés (all + liste IPs)
function dstTargetCell(p, idx) {
  const label = p.dstTarget === 'all' ? 'all (internet)' : p.dstTarget;
  const ips   = p._dstIPs;

  // Badge hôtes /32 pour destinations privées
  const dstHosts = p.dstHosts || [];
  const use32Dst = p._use32Dst || false;
  let dstHostsHtml = '';
  if (p.dstType === 'private' && dstHosts.length > 1) {
    const rows = dstHosts.slice(0, 50).map(h => `<div class="mono" style="font-size:10px;color:var(--text2)">${escHtml(h)}</div>`).join('');
    const moreH = dstHosts.length > 50 ? `<div style="font-size:10px;color:var(--text2)">+${dstHosts.length - 50} autres…</div>` : '';
    dstHostsHtml = `<button class="btn-sm dst-hosts-badge ${use32Dst ? 'hosts-active' : ''}" data-idx="${idx}" style="font-size:9px;padding:1px 5px;margin-left:4px">${dstHosts.length} hôtes${use32Dst ? ' /32 ✓' : ' ▾'}</button>
    <div class="hosts-detail" id="dst-hosts-${idx}" style="display:none;margin-top:4px;max-height:130px;overflow-y:auto;background:var(--bg0);border:1px solid var(--border);border-radius:4px;padding:4px 8px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;padding-bottom:4px;border-bottom:1px solid var(--border)">
        <span style="font-size:10px;font-weight:600">${dstHosts.length} hôtes</span>
        <button class="btn-sm btn-use32" data-idx="${idx}" data-type="dst" style="font-size:9px">${use32Dst ? '↩ /24' : '⇒ /32'}</button>
      </div>
      ${rows}${moreH}
    </div>`;
  }

  if (!ips || ips.length === 0) return `<span class="mono">${escHtml(label)}</span>${dstHostsHtml}`;
  const ipRows = ips.slice(0, 50).map(ip => `<div class="mono" style="font-size:10px;color:var(--text2)">${escHtml(ip)}</div>`).join('');
  const more   = ips.length > 50 ? `<div style="color:var(--text2);font-size:10px">+${ips.length - 50} autres…</div>` : '';
  return `<span class="mono">${escHtml(label)}</span>
    <button class="btn-sm deploy-dst-detail-btn" data-idx="${idx}" style="font-size:9px;padding:1px 5px;margin-left:4px">▸ ${ips.length} IPs</button>
    <div class="deploy-dst-detail" id="dst-detail-${idx}" style="display:none;margin-top:4px;max-height:150px;overflow-y:auto;background:var(--bg0);border:1px solid var(--border);border-radius:4px;padding:4px 8px">
      ${ipRows}${more}
    </div>${dstHostsHtml}`;
}

// Clé de service normalisée pour comparer les ensembles de services entre policies
function serviceSetKey(p) {
  return (p.analysis?.services || [])
    .map(s => `${s.port}/${s.proto}`)
    .sort()
    .join(',');
}

// ── View mode grouping functions ──

function groupByInterfacePair(policies) {
  const groups = new Map();
  for (const p of policies) {
    const src = p._srcintf || '?';
    const dst = p._dstintf || '?';
    const key = `${src} → ${dst}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(p);
  }
  return groups;
}

function buildSequenceAggregated(policies) {
  const groups = new Map();
  for (const p of policies) {
    const srcKey = p.srcSubnets ? p.srcSubnets.slice().sort().join('|') : (p.srcSubnet || '');
    const dstKey = p.dstTarget || '';
    const svcKey = serviceSetKey(p);
    const key = `${srcKey}||${dstKey}||${svcKey}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(p);
  }
  const result = [];
  for (const [, members] of groups) {
    if (members.length === 1) {
      result.push(members[0]);
      continue;
    }
    // Aggregate: merge interfaces, sum sessions
    const srcintfs = [...new Set(members.map(m => m._srcintf).filter(Boolean))];
    const dstintfs = [...new Set(members.map(m => m._dstintf).filter(Boolean))];
    const totalSessions = members.reduce((s, m) => s + (m.sessions || 0), 0);
    const memberIndices = members.map(m => deployState.analyzed.indexOf(m));
    const agg = {
      ...members[0],
      _srcintfList: srcintfs,
      _dstintfList: dstintfs,
      _srcintf: srcintfs.join(', ') || '?',
      _dstintf: dstintfs.join(', ') || '?',
      sessions: totalSessions,
      srcHosts: [...new Set(members.flatMap(m => m.srcHosts || []))].sort(),
      dstHosts: [...new Set(members.flatMap(m => m.dstHosts || []))].sort(),
      _sequenceCount: members.length,
      _sequenceMembers: memberIndices,
      _isAggregated: true,
    };
    result.push(agg);
  }
  return result;
}

// Regroupe les policies ayant le même policyId, en sous-groupant par ensemble de services.
// Entries avec les mêmes services → fusionnées en une règle multi-src.
// Entries avec des services différents → règles séparées.
function mergeByPolicyId(policies) {
  const groups    = new Map(); // firstPolicyId → [policies]
  const ungrouped = [];

  for (const p of policies) {
    const ids = p.policyIds || [];
    if (ids.length === 0) { ungrouped.push({ ...p }); continue; }
    const key = ids[0];
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(p);
  }

  const merged = [...ungrouped];

  for (const [policyId, group] of groups) {
    if (group.length === 1) { merged.push({ ...group[0] }); continue; }

    // Sous-grouper par ensemble de services identiques
    const svcSubGroups = new Map(); // serviceSetKey → [policies]
    for (const p of group) {
      const sk = serviceSetKey(p);
      if (!svcSubGroups.has(sk)) svcSubGroups.set(sk, []);
      svcSubGroups.get(sk).push(p);
    }

    for (const [, subGroup] of svcSubGroups) {
      if (subGroup.length === 1) {
        // Service unique à ce subnet → garder tel quel
        merged.push({ ...subGroup[0] });
        continue;
      }

      // Même ensemble de services → fusionner en multi-src
      const base          = subGroup[0];
      const allServices   = mergeServices(subGroup);
      const totalSessions = subGroup.reduce((s, p) => s + (p.sessions || 0), 0);
      const srcSubnets    = [...new Set(subGroup.map(p => p.srcSubnet).filter(Boolean))].sort();
      const allPolicyIds  = [...new Set(subGroup.flatMap(p => p.policyIds || []))].sort((a, b) => Number(a) - Number(b));
      const isWan         = subGroup.some(p => p._isWan || p.dstType === 'public');
      const dstTarget     = isWan ? 'all' : base.dstTarget;
      const allDstIPs     = [...new Set(subGroup.flatMap(p => p.dstIPs || (p.dstType === 'public' ? [p.dstTarget] : [])).filter(t => t && t !== 'all'))];
      const allSrcHosts   = [...new Set(subGroup.flatMap(p => p.srcHosts || []))].sort();
      const allDstHosts   = [...new Set(subGroup.flatMap(p => p.dstHosts || []))].sort();
      const multiSrc      = srcSubnets.length > 1;

      // Chercher un groupe d'adresses existant contenant ces subnets
      let existingGrp = null;
      if (multiSrc && deployState.addrGroups) {
        const addrGroups = deployState.addrGroups;
        // Build a reverse lookup: cidr → address name
        // We need the analyzed srcAddr names for each subnet
        const subnetAddrNames = subGroup.map(p => p.analysis?.srcAddr?.found ? p.analysis.srcAddr.name : null);
        const allFound = subnetAddrNames.every(Boolean);
        if (allFound) {
          const memberNames = new Set(subnetAddrNames);
          for (const [grpName, grp] of Object.entries(addrGroups)) {
            const grpMembers = new Set(grp.members);
            if (grpMembers.size === memberNames.size && [...memberNames].every(m => grpMembers.has(m))) {
              existingGrp = grpName;
              break;
            }
          }
        }
      }

      merged.push({
        ...base,
        srcSubnet:    srcSubnets[0],
        srcSubnets,
        dstTarget,
        dstType:      isWan ? 'public' : base.dstType,
        sessions:     totalSessions,
        serviceDesc:  allServices.map(s => s.label).join(', '),
        policyIds:    allPolicyIds,
        dstIPs:       allDstIPs,
        _dstIPs:      allDstIPs,
        srcHosts:     allSrcHosts,
        dstHosts:     allDstHosts,
        _mergedCount: subGroup.length,
        _isWan:       isWan,
        _nat:         isWan,
        _srcAddrName: existingGrp || (multiSrc ? `FF_POLICY_${policyId}_SRC` : (base._srcAddrName || suggestAddrNameFE(srcSubnets[0]))),
        _srcAddrGrpFound: !!existingGrp,
        _dstAddrName: isWan ? 'all' : base._dstAddrName,
        _policyName:  `FF_POLICY_${policyId}`,
        srcAddrNames: existingGrp ? null : (multiSrc ? srcSubnets.map(s => `FF_${escSlug(s)}`) : null),
        analysis: {
          ...base.analysis,
          services:  allServices,
          needsWork: allServices.some(s => !s.found),
        },
      });
    }
  }

  return merged;
}

function applyMerge(mode) {
  if (!deployState.analyzed) return;
  if (mode === 'reset') {
    // Preserve manual edits (addr names, intfs, NAT) through the reset
    const edits = new Map();
    for (const p of deployState.analyzed) {
      edits.set(`${p.srcSubnet}|${p.dstTarget}`, {
        _srcAddrName: p._srcAddrName,
        _dstAddrName: p._dstAddrName,
        _srcintf:     p._srcintf,
        _dstintf:     p._dstintf,
        _nat:         p._nat,
        _policyName:  p._policyName,
      });
    }
    deployState.analyzed = deployState._analyzedOriginal
      ? deployState._analyzedOriginal.map(p => {
          const edit = edits.get(`${p.srcSubnet}|${p.dstTarget}`);
          return edit ? { ...p, ...edit } : { ...p };
        })
      : deployState.analyzed;
    deployState._analyzedOriginal = null;
  } else {
    // Save original on first merge
    if (!deployState._analyzedOriginal) {
      deployState._analyzedOriginal = deployState.analyzed.map(p => ({ ...p }));
    }
    // Always merge from original
    if (mode === 'policy') {
      deployState.analyzed = mergeByPolicyId(deployState._analyzedOriginal);
    } else {
      deployState.analyzed = mergeAnalyzedPolicies(deployState._analyzedOriginal, mode);
    }
  }

  // Reset selection to all
  deployState.selected = new Set(deployState.analyzed.map((_, i) => i));
  renderDeployPolicies(filterDeployPolicies());

  const info = el('deploy-merge-info');
  if (info) {
    const orig = deployState._analyzedOriginal?.length || deployState.analyzed.length;
    const cur  = deployState.analyzed.length;
    info.textContent = mode === 'reset'
      ? `${cur} policies (original)`
      : `${cur} policies (économie : ${orig - cur})`;
  }
}

// ─── Policy analysis ──────────────────────────────────────────────────────────

async function analyzeDeployPolicies() {
  // Show loading state
  const body = el('deploy-policy-body');
  const btn  = el('btn-analyze');
  if (btn) { btn.disabled = true; btn.textContent = 'Analyse en cours…'; }
  if (body) body.innerHTML = `
    <div class="deploy-loading">
      <div class="deploy-loading-bar"><div class="deploy-loading-fill" id="deploy-loading-fill"></div></div>
      <div class="deploy-loading-text" id="deploy-loading-text">Récupération des policies…</div>
    </div>`;

  const setLoadingText = (t) => { const el2 = el('deploy-loading-text'); if (el2) el2.textContent = t; };
  const setLoadingPct  = (p) => { const el2 = el('deploy-loading-fill'); if (el2) el2.style.width = `${p}%`; };

  let rawPolicies;
  try {
    rawPolicies = await api('/api/policies');
    // Append pending denied flows if any
    if (deployState._pendingDenied && deployState._pendingDenied.length > 0) {
      rawPolicies = rawPolicies.concat(deployState._pendingDenied);
      deployState._pendingDenied = null;
    }
    setLoadingText(`${rawPolicies.length} policies récupérées — analyse en cours…`);
    setLoadingPct(30);
  } catch (err) { resetAnalyzeBtn(); alert(err.message); return; }
  if (!rawPolicies) { resetAnalyzeBtn(); return; }

  // Ask server to analyze (addr + service matching against the loaded .conf)
  let analyzed;
  try {
    setLoadingPct(50);
    // Determine preferred WAN interface (SD-WAN selection or auto)
    const ifData = deployState.interfaces;
    const preferredWanIntf = deployState.selectedSdwan
      || (ifData?.sdwanEnabled ? (ifData?.sdwanIntfName || null) : null);

    const r = await fetch(`/api/deploy/generate?session=${state.session}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ selectedPolicies: rawPolicies, opts: { preferredWanIntf } }),
    });
    setLoadingPct(80);
    if (!r.ok) {
      const text = await r.text();
      const msg  = (() => { try { return JSON.parse(text).error; } catch { return `HTTP ${r.status}`; } })();
      resetAnalyzeBtn(); alert('Erreur analyse : ' + msg); return;
    }
    const respData = await r.json();
    analyzed = respData.analyzed;
    deployState.addrGroups = respData.addrGroups || {};
    deployState.warnings   = respData.warnings  || [];
    setLoadingPct(95);
    setLoadingText('Enrichissement des données…');
  } catch (err) { resetAnalyzeBtn(); alert(err.message); return; }

  const ifaces = deployState.interfaces?.interfaces || [];
  const zones  = deployState.interfaces?.zones || [];
  // Interface → zone lookup pour afficher la zone au lieu de l'interface
  const _ifToZone = {};
  for (const z of zones) { for (const m of z.members) _ifToZone[m] = z.name; }
  const resolveZone = (ifName) => _ifToZone[ifName] || ifName || '';

  // Enrich with frontend display fields
  analyzed = analyzed.map(p => {
    const isWan = p.dstType === 'public' || p.dstTarget === 'all';
    const rawSrcIntf = p.analysis?.srcZone || p.analysis?.srcIface || ifaces.find(i => i.name === p.srcintf)?.name || '';
    const rawDstIntf = p.analysis?.dstZone || p.analysis?.dstIface || ifaces.find(i => i.name === p.dstintf)?.name || '';
    return {
      ...p,
      srcAddrExists: p.analysis?.srcAddr?.found ?? false,
      dstAddrExists: p.analysis?.dstAddr?.found ?? false,
      _srcintf:          resolveZone(rawSrcIntf),
      _srcIfaceSource:   p.analysis?.srcIfaceSource || 'auto',
      _dstintf:          resolveZone(rawDstIntf),
      _dstIfaceSource:   p.analysis?.dstIfaceSource || 'auto',
      _srcAddrName:  p.analysis?.srcAddr?.name || suggestAddrNameFE(p.srcSubnet),
      _dstAddrName:  p.analysis?.dstAddr?.name || suggestAddrNameFE(p.dstTarget),
      _policyName:   `FF_${escSlug(p.srcSubnet)}_to_${escSlug(p.dstTarget)}`,
      _nat:          isWan,   // NAT on par défaut pour WAN uniquement
      _isWan:        isWan,
      _checked:      true,
    };
  });

  // Tri par srcSubnet pour faciliter la lecture
  analyzed.sort((a, b) => (a.srcSubnet || '').localeCompare(b.srcSubnet || ''));

  deployState.analyzed          = analyzed;
  deployState._analyzedOriginal = null;
  deployState.generatedCli      = null;
  deployState.selected          = new Set(analyzed.map((_, i) => i));

  const bar = el('deploy-merge-bar');
  if (bar) bar.style.display = '';
  const info = el('deploy-merge-info');

  // Récupérer le nombre de flux refusés exclus
  let deniedNote = '';
  try {
    const sr = await fetch(`/api/stats?session=${state.session}`);
    if (sr.ok) {
      const { stats } = await sr.json();
      if (stats?.deniedPolicyGroups > 0) {
        deniedNote = ` · <span class="deploy-denied-note" title="Ces flux étaient déjà refusés dans les logs — pas besoin de créer des règles allow">🚫 ${stats.deniedPolicyGroups} flux refusés exclus</span>`;
      }
    }
  } catch { /* non-bloquant */ }

  if (info) info.innerHTML = `${analyzed.length} policies${deniedNote} · `;

  deployState.wizardStep = 3;
  // Update wizard progress indicators
  document.querySelectorAll('.wizard-step-indicator').forEach(ind => {
    const s = +ind.dataset.step;
    ind.classList.toggle('active', s <= 3);
    ind.classList.toggle('done', s < 3);
  });
  document.querySelectorAll('.wizard-connector').forEach((c, i) => c.classList.toggle('done', i < 2));

  resetAnalyzeBtn();
  renderDeployPolicies(analyzed);
}

function resetAnalyzeBtn() {
  const btn = el('btn-analyze');
  if (btn) { btn.disabled = false; btn.textContent = 'Analyser les policies'; }
}

function suggestAddrNameFE(cidr) {
  if (!cidr) return '';
  return 'FF_' + cidr.replace(/[./]/g, '_');
}

function escSlug(s) {
  return (s || '').replace(/[./]/g, '_').replace(/[^a-zA-Z0-9_]/g, '');
}

// Build an address cell: green text if 1 match, green select if multiple, red input if none
function addrCell(addrAnalysis, currentName, idx, field) {
  if (!addrAnalysis?.found) {
    return `<input class="deploy-name-input" data-idx="${idx}" data-field="${field}" value="${escHtml(currentName)}" placeholder="FF_...">`;
  }
  const matches = addrAnalysis.allMatches || [{ name: addrAnalysis.name }];
  if (matches.length === 1) {
    return `<span class="match-ok">✓ ${escHtml(matches[0].name)}</span>`;
  }
  // Multiple matches → select
  const opts = matches.map(m =>
    `<option value="${escHtml(m.name)}" ${m.name === currentName ? 'selected' : ''}>${escHtml(m.name)}</option>`
  ).join('');
  return `<select class="deploy-name-sel match-ok-sel" data-idx="${idx}" data-field="${field}" title="${matches.length} objets correspondent">
    ${opts}
  </select>`;
}

// Build a service match cell: green text if 1 match, green select if multiple
function svcMatchCell(svc, idx) {
  const matches  = svc.allMatches || [{ name: svc.name, source: svc.source }];
  const portPart = svc.portHint ? `\nPorts: ${svc.portHint}` : '';
  const tip1     = `${matches[0].source || ''}${portPart}`;
  if (matches.length === 1) {
    return `<span class="match-ok" data-tip="${escHtml(tip1)}">✓ ${escHtml(matches[0].name)}</span>`;
  }
  const field = `svc_${svc.port}_${svc.proto}`;
  const opts = matches.map(m =>
    `<option value="${escHtml(m.name)}">${escHtml(m.name)} (${escHtml(m.source)})</option>`
  ).join('');
  return `<select class="deploy-name-sel match-ok-sel" data-idx="${idx}" data-field="${field}" title="${escHtml(`${matches.length} services correspondent${portPart}`)}">
    ${opts}
  </select>`;
}

// Cellule affichant les policy ID(s) FortiGate dans lesquelles le trafic a été observé
function policyIdsCell(p) {
  const ids = p.policyIds || [];
  if (ids.length === 0) return '<span style="color:var(--text2);font-size:11px">–</span>';
  const tip  = ids.length > 3 ? `Policy IDs: ${ids.join(', ')}` : '';
  const shown = ids.slice(0, 3);
  const more  = ids.length > 3 ? ` <span style="color:var(--text2)">+${ids.length - 3}</span>` : '';
  return shown.map(id => `<span class="policy-id-badge" ${tip ? `data-tip="${escHtml(tip)}"` : ''}>${escHtml(id)}</span>`).join(' ') + more;
}

function countMissingObjects(analyzed) {
  const addrs = new Set(), svcs = new Set();
  for (const p of analyzed) {
    if (!p.analysis?.srcAddr?.found && p.analysis?.srcAddr?.cidr) addrs.add(p.analysis.srcAddr.cidr);
    if (!p.analysis?.dstAddr?.found && p.analysis?.dstAddr?.cidr && p.analysis?.dstAddr?.cidr !== 'all') addrs.add(p.analysis.dstAddr.cidr);
    for (const svc of p.analysis?.services || []) {
      if (!svc.found) svcs.add(svc.port ? `${svc.port}/${svc.proto}` : svc.label || svc.name);
    }
  }
  return { addrs: addrs.size, svcs: svcs.size };
}

// ── F7: Event delegation on the deploy table ──────────────────────────────────
// Called once after the deploy-policy-body container exists.
// Installs delegated listeners on the stable container — avoids re-attaching
// hundreds of listeners on every render.

let _deployTableWired = false;
let _dragSrcIdx       = null;

function wireDeployTable() {
  const container = el('deploy-policy-body');
  if (!container || _deployTableWired) return;
  _deployTableWired = true;

  // ── change: .deploy-chk ──
  container.addEventListener('change', e => {
    const chk = e.target.closest('.deploy-chk');
    if (!chk) return;
    if (chk.dataset.seqMembers) {
      const members = chk.dataset.seqMembers.split(',').map(Number);
      members.forEach(i => {
        chk.checked ? deployState.selected.add(i) : deployState.selected.delete(i);
      });
    } else {
      const i = +chk.dataset.idx;
      chk.checked ? deployState.selected.add(i) : deployState.selected.delete(i);
    }
  });

  // ── change: .deploy-nat-chk ──
  container.addEventListener('change', e => {
    if (!e.target.matches('.deploy-nat-chk')) return;
    deployState.analyzed[+e.target.dataset.idx]._nat = e.target.checked;
  });

  // ── change: .deploy-iface-sel ──
  container.addEventListener('change', e => {
    if (!e.target.matches('.deploy-iface-sel')) return;
    const { idx, field } = e.target.dataset;
    deployState.analyzed[+idx][field] = e.target.value;
  });

  // ── change: .deploy-name-sel ──
  container.addEventListener('change', e => {
    if (!e.target.matches('.deploy-name-sel')) return;
    const { idx, field } = e.target.dataset;
    deployState.analyzed[+idx][field] = e.target.value;
  });

  // ── change: .tag-select ──
  container.addEventListener('change', e => {
    if (!e.target.matches('.tag-select')) return;
    const idx = +e.target.dataset.idx;
    const p = deployState.analyzed[idx];
    if (!p) return;
    let val = e.target.value;
    if (val === '__custom') {
      val = prompt('Nom du tag :');
      if (!val) { e.target.value = ''; return; }
    }
    if (!val) return;
    if (!p._tags) p._tags = [];
    if (!p._tags.includes(val)) p._tags.push(val);
    renderDeployPolicies(filterDeployPolicies(), false);
  });

  // ── input: .deploy-name-input ──
  container.addEventListener('input', e => {
    if (!e.target.matches('.deploy-name-input')) return;
    const { idx, field } = e.target.dataset;
    if (!field) return;
    if (field.startsWith('svc_')) {
      const parts = field.split('_'); // svc_PORT_PROTO
      const policy = deployState.analyzed[+idx];
      const svc = (policy?.services || []).find(s => String(s.port) === parts[1] && s.proto === parts[2]);
      if (svc) svc.suggestedName = e.target.value;
    } else {
      if (deployState.analyzed[+idx]) deployState.analyzed[+idx][field] = e.target.value;
    }
  });

  // ── click: .btn-use32 ──
  container.addEventListener('click', e => {
    const btn = e.target.closest('.btn-use32');
    if (!btn) return;
    e.stopPropagation();
    const idx  = +btn.dataset.idx;
    const type = btn.dataset.type; // 'src' | 'dst'
    const p    = deployState.analyzed[idx];
    if (!p) return;
    if (type === 'src') p._use32Src = !p._use32Src;
    else                p._use32Dst = !p._use32Dst;
    renderDeployPolicies(filterDeployPolicies(), false);
  });

  // ── click: .src-hosts-badge and .dst-hosts-badge ──
  container.addEventListener('click', e => {
    const srcBadge = e.target.closest('.src-hosts-badge');
    if (srcBadge) {
      const idx    = srcBadge.dataset.idx;
      const detail = document.getElementById(`src-hosts-${idx}`);
      if (detail) detail.style.display = detail.style.display === 'none' ? '' : 'none';
      return;
    }
    const dstBadge = e.target.closest('.dst-hosts-badge');
    if (dstBadge) {
      const idx    = dstBadge.dataset.idx;
      const detail = document.getElementById(`dst-hosts-${idx}`);
      if (detail) detail.style.display = detail.style.display === 'none' ? '' : 'none';
    }
  });

  // ── click: .deploy-dst-detail-btn ──
  container.addEventListener('click', e => {
    const btn = e.target.closest('.deploy-dst-detail-btn');
    if (!btn) return;
    const idx    = btn.dataset.idx;
    const detail = document.getElementById(`dst-detail-${idx}`);
    if (!detail) return;
    const open = detail.style.display !== 'none';
    detail.style.display = open ? 'none' : '';
    const ips = (deployState.analyzed[+idx]?._dstIPs || []).length;
    btn.textContent = open ? `▸ ${ips} IPs` : '▾ fermer';
  });

  // ── click: .policy-tag (tag-remove) ──
  container.addEventListener('click', e => {
    const tag = e.target.closest('.policy-tag');
    if (!tag) return;
    const idx     = +tag.dataset.idx;
    const tagName = tag.dataset.tag;
    const p       = deployState.analyzed[idx];
    if (p?._tags) p._tags = p._tags.filter(t => t !== tagName);
    renderDeployPolicies(filterDeployPolicies(), false);
  });

  // ── click: .intf-pair-header (collapse/expand groups) ──
  container.addEventListener('click', e => {
    const header = e.target.closest('.intf-pair-header');
    if (!header) return;
    const pair = header.dataset.pair;
    if (deployState.collapsedGroups.has(pair)) {
      deployState.collapsedGroups.delete(pair);
    } else {
      deployState.collapsedGroups.add(pair);
    }
    renderDeployPolicies(filterDeployPolicies(), false);
  });

  // ── Drag & drop reorder (delegated on container) ──
  container.addEventListener('dragstart', e => {
    const handle = e.target.closest('.drag-handle');
    if (!handle) return;
    _dragSrcIdx = +handle.dataset.idx;
    handle.closest('tr')?.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
  });
  container.addEventListener('dragend', e => {
    const handle = e.target.closest('.drag-handle');
    if (handle) handle.closest('tr')?.classList.remove('dragging');
  });
  container.addEventListener('dragover', e => {
    const row = e.target.closest('.deploy-policy-row');
    if (!row) return;
    e.preventDefault();
    row.classList.add('drag-over');
  });
  container.addEventListener('dragleave', e => {
    const row = e.target.closest('.deploy-policy-row');
    if (row) row.classList.remove('drag-over');
  });
  container.addEventListener('drop', e => {
    const row = e.target.closest('.deploy-policy-row');
    if (!row) return;
    e.preventDefault();
    row.classList.remove('drag-over');
    const targetIdx = +row.dataset.idx;
    if (_dragSrcIdx === null || _dragSrcIdx === targetIdx) return;
    const arr    = deployState.analyzed;
    const srcPos = arr.findIndex((_, i) => i === _dragSrcIdx);
    const tgtPos = arr.findIndex((_, i) => i === targetIdx);
    if (srcPos < 0 || tgtPos < 0) return;
    const [moved] = arr.splice(srcPos, 1);
    arr.splice(tgtPos, 0, moved);
    deployState.selected = new Set(arr.map((_, i) => i));
    renderDeployPolicies(filterDeployPolicies(), false);
  });
}

// Reset delegation flag when the deploy view is re-rendered from scratch
// (deploy() replaces the whole DOM, so we must re-wire)
function resetDeployTableWiring() {
  _deployTableWired = false;
  _dragSrcIdx       = null;
}

function renderDeployPolicies(analyzed, resetPage = true) {
  if (resetPage) deployState.page = 1;

  // In sequence mode, aggregate before pagination
  const viewMode = deployState.viewMode || 'flat';
  const displayList = viewMode === 'sequence' ? buildSequenceAggregated(analyzed) : analyzed;

  const total     = displayList.length;
  const pageSize  = deployState.pageSize;
  const pages     = Math.ceil(total / pageSize);
  const page      = Math.min(deployState.page, pages || 1);
  const start     = (page - 1) * pageSize;
  const pageSlice = displayList.slice(start, start + pageSize);

  const ifaces   = (deployState.interfaces?.interfaces || []).map(i => i.name);
  const zones    = (deployState.interfaces?.zones || []);
  const zoneNames = zones.map(z => z.name);
  // Build interface→zone lookup
  const ifaceToZone = {};
  for (const z of zones) { for (const m of z.members) ifaceToZone[m] = z.name; }
  // Dropdown: zones first, then interfaces not in any zone
  const ifaceNotInZone = ifaces.filter(n => !ifaceToZone[n]);
  const allIfOpts = [
    ...zoneNames.map(n => `<option value="${escHtml(n)}">${escHtml(n)} (zone)</option>`),
    ...ifaceNotInZone.map(n => `<option value="${escHtml(n)}">${escHtml(n)}</option>`),
  ].join('');

  // rows use the real index in deployState.analyzed (not filtered position)
  // so that data-idx always references the correct policy in the full array
  const maxSessions = displayList.reduce((m, pp) => Math.max(m, pp.sessions || 0), 1);

  function buildRow(p) {
    const isAgg = p._isAggregated;
    const idx = isAgg ? (p._sequenceMembers?.[0] ?? -1) : deployState.analyzed.indexOf(p);

    // Checkbox: for aggregated rows, use a special data-seq-members attribute
    const chkChecked = isAgg
      ? p._sequenceMembers.every(i => deployState.selected.has(i))
      : deployState.selected.has(idx);
    const chkAttr = isAgg
      ? `class="deploy-chk deploy-chk-seq" data-seq-members="${p._sequenceMembers.join(',')}" ${chkChecked ? 'checked' : ''}`
      : `class="deploy-chk" data-idx="${idx}" ${chkChecked ? 'checked' : ''}`;

    // Pour les policies multi-src : afficher le groupe d'adresses (existant ou à créer)
    let srcAddrCell;
    if (p.srcSubnets && p.srcSubnets.length > 1) {
      if (p._srcAddrGrpFound) {
        srcAddrCell = `<span class="match-ok" title="Groupe existant contenant les ${p.srcSubnets.length} subnets">✓ ${escHtml(p._srcAddrName)}</span>`;
      } else {
        srcAddrCell = `<span style="display:inline-flex;align-items:center;gap:4px">
          <span class="match-miss" title="Aucun groupe existant — à créer">grp</span>
          <input class="deploy-name-input" data-idx="${idx}" data-field="_srcAddrName" value="${escHtml(p._srcAddrName)}" placeholder="FF_GRP_..." title="Nom du groupe d'adresses à créer (${p.srcSubnets.length} membres)">
        </span>`;
      }
    } else {
      srcAddrCell = addrCell(p.analysis?.srcAddr, p._srcAddrName, idx, '_srcAddrName');
    }
    const dstAddrCell = addrCell(p.analysis?.dstAddr, p._dstAddrName, idx, '_dstAddrName');

    const svcList = p.analysis?.services || [];
    const svcCells = svcList.map(svc => {
      if (svc.found) return svcMatchCell(svc, idx);
      const tip = svc.portHint ? `${svc.label}\nPorts: ${svc.portHint}` : svc.label;
      return `<span data-tip="${escHtml(tip)}" style="display:inline-flex;align-items:center;gap:2px"><span class="match-miss">✗</span><input class="deploy-name-input sm" data-idx="${idx}" data-field="svc_${svc.port}_${svc.proto}" value="${escHtml(svc.suggestedName || '')}" placeholder="FF_SVC_..."></span>`;
    }).join(' ');

    // Interface cells: read-only for aggregated policies, dropdown otherwise
    let srcSel, dstSel, sameIntfWarn = '';
    if (isAgg) {
      const srcList = (p._srcintfList || []).join(', ') || '?';
      const dstList = (p._dstintfList || []).join(', ') || '?';
      srcSel = `<span class="mono seq-intf" title="${escHtml(srcList)}">${escHtml(srcList)}</span>`;
      dstSel = `<span class="mono seq-intf" title="${escHtml(dstList)}">${escHtml(dstList)}</span>`;
    } else {
      const srcLabels = { route: '🛣 route', sdwan: '⚡ sdwan', subnet: '🔗 subnet', 'wan-candidate': '📡 wan', auto: '' };
      const srcSrcBadge = p._srcIfaceSource && p._srcIfaceSource !== 'auto' && p._srcintf
        ? `<span class="intf-src-badge ${p._srcIfaceSource}" title="Détecté via : ${srcLabels[p._srcIfaceSource] || p._srcIfaceSource}">${srcLabels[p._srcIfaceSource]}</span>`
        : '';
      srcSel = `<span style="display:inline-flex;align-items:center;gap:4px">${srcSrcBadge}<select class="deploy-iface-sel" data-idx="${idx}" data-field="_srcintf">
        <option value="">— auto —</option>${allIfOpts}
      </select></span>`;
      const dstSrcBadge = p._dstIfaceSource && p._dstIfaceSource !== 'auto' && p._dstintf
        ? `<span class="intf-src-badge ${p._dstIfaceSource}" title="Détecté via : ${srcLabels[p._dstIfaceSource] || p._dstIfaceSource}">${srcLabels[p._dstIfaceSource]}</span>`
        : '';
      dstSel = `<span style="display:inline-flex;align-items:center;gap:4px">${dstSrcBadge}<select class="deploy-iface-sel" data-idx="${idx}" data-field="_dstintf">
        <option value="">— auto —</option>${allIfOpts}
      </select></span>`;
      sameIntfWarn = (p._srcintf && p._dstintf && p._srcintf === p._dstintf)
        ? `<span class="intf-warn" title="⚠ srcintf = dstintf : policy possiblement invalide">⚠</span>` : '';
    }

    const dirBadge = p._isWan
      ? `<span class="dir-badge wan" title="Vers internet">WAN</span>`
      : `<span class="dir-badge lan" title="Trafic interne">LAN</span>`;
    const natChk = `<input type="checkbox" class="deploy-nat-chk" data-idx="${idx}" ${p._nat ? 'checked' : ''} title="NAT pour cette policy">`;

    // Impact / sessions
    const barW = Math.round(((p.sessions || 0) / maxSessions) * 100);

    // Warnings (conflict with existing policies)
    const rowWarnings = (deployState.warnings || []).filter(w => w.generatedIdx === idx);
    const warnBadge = rowWarnings.length > 0
      ? `<span class="conflict-warn" title="${escHtml(rowWarnings.map(w => w.detail).join('\n'))}">${rowWarnings[0].type === 'duplicate' ? '⚠ doublon' : '⚠ conflit'}</span>`
      : '';

    const seqBadge = isAgg ? ` <span class="seq-badge" title="${p._sequenceCount} policies agrégées en 1 séquence">×${p._sequenceCount} seq</span>` : '';
    // Badge hôtes /32 pour source
    const srcHosts = p.srcHosts || [];
    const use32Src = p._use32Src || false;
    let srcHostsHtml = '';
    if (srcHosts.length > 1) {
      const rows = srcHosts.slice(0, 50).map(h => `<div class="mono" style="font-size:10px;color:var(--text2)">${escHtml(h)}</div>`).join('');
      const moreH = srcHosts.length > 50 ? `<div style="font-size:10px;color:var(--text2)">+${srcHosts.length - 50} autres…</div>` : '';
      srcHostsHtml = `<button class="btn-sm src-hosts-badge ${use32Src ? 'hosts-active' : ''}" data-idx="${idx}" style="font-size:9px;padding:1px 5px;margin-top:2px">${srcHosts.length} hôtes${use32Src ? ' /32 ✓' : ' ▾'}</button>
      <div class="hosts-detail" id="src-hosts-${idx}" style="display:none;margin-top:4px;max-height:130px;overflow-y:auto;background:var(--bg0);border:1px solid var(--border);border-radius:4px;padding:4px 8px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;padding-bottom:4px;border-bottom:1px solid var(--border)">
          <span style="font-size:10px;font-weight:600">${srcHosts.length} hôtes réels</span>
          <button class="btn-sm btn-use32" data-idx="${idx}" data-type="src" style="font-size:9px">${use32Src ? '↩ /24' : '⇒ /32'}</button>
        </div>
        ${rows}${moreH}
      </div>`;
    }
    const srcSubnetCell = p.srcSubnets && p.srcSubnets.length > 1
      ? `<div>${p.srcSubnets.map(s => `<span class="mono" style="display:block;font-size:11px">${escHtml(s)}</span>`).join('')}</div>${srcHostsHtml}`
      : `<div><span class="mono">${escHtml(p.srcSubnet)}${p._mergedCount > 1 ? ` <span class="merge-badge" title="${p._mergedCount} policies fusionnées">×${p._mergedCount}</span>` : ''}</span></div>${srcHostsHtml}`;

    // Tags
    const tags = p._tags || [];
    const tagBadges = tags.map(t => `<span class="policy-tag" data-idx="${idx}" data-tag="${escHtml(t)}">${escHtml(t)} ✕</span>`).join('');
    const tagOpts = POLICY_TAGS.filter(t => !tags.includes(t)).map(t => `<option value="${escHtml(t)}">${escHtml(t)}</option>`).join('');
    const tagCell = `<td class="tag-cell">${tagBadges}<select class="tag-select" data-idx="${idx}"><option value="">+</option>${tagOpts}<option value="__custom">autre…</option></select></td>`;

    return `
      <tr class="deploy-policy-row ${isAgg ? 'seq-row' : ''}" data-idx="${idx}" ${isAgg ? `data-seq-members="${p._sequenceMembers.join(',')}"` : ''}>
        <td class="${isAgg ? '' : 'drag-handle'}" ${isAgg ? '' : `draggable="true" data-idx="${idx}"`} data-expert>${isAgg ? '' : '⠿'}</td>
        <td><input type="checkbox" ${chkAttr}></td>
        <td>${dirBadge}</td>
        <td style="text-align:center" data-expert>${natChk}</td>
        <td data-expert>${policyIdsCell(p)}</td>
        <td>${warnBadge}${seqBadge}${srcSubnetCell}</td>
        <td>${srcAddrCell}</td>
        <td>${srcSel}</td>
        <td>${dstTargetCell(p, idx)}</td>
        <td>${dstAddrCell}</td>
        <td>${dstSel}${sameIntfWarn}</td>
        <td>${svcCells || '<span style="color:var(--text2)">–</span>'}</td>
        <td class="impact-cell" data-expert><div class="impact-bar" style="width:${barW}%"></div><span class="impact-val">${fmtNum(p.sessions || 0)}</span></td>
        ${tagCell.replace('<td class="tag-cell">', '<td class="tag-cell" data-expert>')}
      </tr>`;
  }

  // Build rows — for interface-pair mode, insert group headers
  let rows;
  if (viewMode === 'interface-pair') {
    const groups = groupByInterfacePair(pageSlice);
    const parts = [];
    for (const [pair, members] of groups) {
      const collapsed = deployState.collapsedGroups.has(pair);
      parts.push(`<tr class="intf-pair-header ${collapsed ? 'collapsed' : ''}" data-pair="${escHtml(pair)}">
        <td colspan="14"><div class="intf-pair-header-inner">
          <span class="intf-pair-toggle">${collapsed ? '▸' : '▾'}</span>
          <span class="intf-pair-name">${escHtml(pair)}</span>
          <span class="intf-pair-count">${members.length} policy(s)</span>
        </div></td>
      </tr>`);
      if (!collapsed) {
        for (const p of members) parts.push(buildRow(p));
      }
    }
    rows = parts.join('');
  } else {
    rows = pageSlice.map(p => buildRow(p)).join('');
  }

  const selCount = [...deployState.selected].filter(i => i >= 0 && i < deployState.analyzed.length).length;
  const hasMerge = analyzed.some(p => p._mergedCount > 1);

  const paginationBar = pages > 1 ? `
    <div class="deploy-pagination">
      <button class="deploy-pg-btn pg-first" ${page === 1 ? 'disabled' : ''}>«</button>
      <button class="deploy-pg-btn pg-prev"  ${page === 1 ? 'disabled' : ''}>‹</button>
      <span class="deploy-pg-info">Page <strong>${page}</strong> / ${pages} &nbsp;·&nbsp; ${start + 1}–${Math.min(start + pageSize, total)} sur ${total}</span>
      <button class="deploy-pg-btn pg-next"  ${page === pages ? 'disabled' : ''}>›</button>
      <button class="deploy-pg-btn pg-last"  ${page === pages ? 'disabled' : ''}>»</button>
    </div>` : '';

  const { addrs: missingAddrs, svcs: missingSvcs } = countMissingObjects(analyzed);
  const missingNote = (missingAddrs + missingSvcs) > 0
    ? ` · <span style="color:var(--accent2)">+${missingAddrs} adresse${missingAddrs > 1 ? 's' : ''} · +${missingSvcs} service${missingSvcs > 1 ? 's' : ''} à créer</span>`
    : ' · <span style="color:var(--ok)">✓ tous les objets existent</span>';

  const body = el('deploy-policy-body');
  body.innerHTML = `
    <div style="margin-bottom:8px;font-size:12px;color:var(--text2);display:flex;align-items:center;gap:12px">
      <span>${total} policy(s) · <strong>${selCount}</strong> sélectionnées${hasMerge ? ' · <span style="color:var(--accent2)">⚡ fusion active</span>' : ''}${missingNote}${
        (deployState.warnings || []).length > 0
          ? ` · <span style="color:var(--warn)">⚠ ${deployState.warnings.length} conflit${deployState.warnings.length > 1 ? 's' : ''}</span>`
          : ''
      }</span>
    </div>
    ${paginationBar}
    <div style="overflow-x:auto">
      <table class="deploy-policy-table">
        <thead><tr>
          <th style="width:20px" data-expert></th>
          <th><input type="checkbox" id="chk-all-deploy"></th>
          <th>Dir.</th><th data-expert>NAT</th>
          <th data-expert title="Policy(s) FortiGate dans lesquelles ce trafic a été observé">Policy</th>
          <th>Src Subnet</th><th>Src addr</th><th>Src intf*</th>
          <th>Dst Target</th><th>Dst addr</th><th>Dst intf*</th>
          <th>Services</th>
          <th data-expert title="Sessions observées dans les logs">Sessions</th>
          <th data-expert>Tags</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    ${paginationBar}
    <div style="font-size:11px;color:var(--text2);margin-top:6px">* détectée automatiquement — overridable</div>`;

  el('deploy-step3-footer').style.display = '';

  // Wire pagination buttons (both top and bottom bars) — re-wired each render
  // because page/pages values change and the buttons are recreated
  const goPage = (p) => {
    deployState.page = p;
    renderDeployPolicies(filterDeployPolicies(), false);
  };
  document.querySelectorAll('.pg-first').forEach(b => b.addEventListener('click', () => goPage(1)));
  document.querySelectorAll('.pg-prev') .forEach(b => b.addEventListener('click', () => goPage(Math.max(1, page - 1))));
  document.querySelectorAll('.pg-next') .forEach(b => b.addEventListener('click', () => goPage(Math.min(pages, page + 1))));
  document.querySelectorAll('.pg-last') .forEach(b => b.addEventListener('click', () => goPage(pages)));

  // Update missing objects button
  const missingBtn = el('btn-missing-objects');
  if (missingBtn) {
    const missing = collectMissingObjects();
    missingBtn.style.display = missing.total > 0 ? '' : 'none';
    missingBtn.textContent = `⚠ ${missing.total} objet${missing.total > 1 ? 's' : ''} manquant${missing.total > 1 ? 's' : ''}`;
  }

  // Wire select-all (current page only) — re-wired each render (pageIdxs change)
  const chkAll = el('chk-all-deploy');
  if (chkAll) {
    const pageIdxs = [];
    for (const p of pageSlice) {
      if (p._isAggregated && p._sequenceMembers) {
        pageIdxs.push(...p._sequenceMembers);
      } else {
        pageIdxs.push(deployState.analyzed.indexOf(p));
      }
    }
    chkAll.checked = pageIdxs.every(i => deployState.selected.has(i));
    chkAll.indeterminate = !chkAll.checked && pageIdxs.some(i => deployState.selected.has(i));
    chkAll.addEventListener('change', e => {
      pageIdxs.forEach(i => {
        e.target.checked ? deployState.selected.add(i) : deployState.selected.delete(i);
      });
      document.querySelectorAll('.deploy-chk').forEach(chk => { chk.checked = e.target.checked; });
    });
  }

  // Pre-select auto-detected values for interface selects — must happen after innerHTML set
  body.querySelectorAll('.deploy-iface-sel').forEach(sel => {
    const { idx, field } = sel.dataset;
    const auto = deployState.analyzed[+idx]?.[field];
    if (auto) sel.value = auto;
  });

  // Wire event delegation on deploy-policy-body (idempotent — only installed once)
  wireDeployTable();
}

async function generateDeployConf() {
  if (!deployState.analyzed) return;

  let selectedPolicies;
  if (deployState.viewMode === 'sequence') {
    // In sequence mode, aggregate selected policies before sending
    const selected = deployState.analyzed.filter((_, i) => deployState.selected.has(i));
    const aggregated = buildSequenceAggregated(selected);
    selectedPolicies = aggregated.map(p => ({
      ...p,
      srcintf:      p._isAggregated ? (p._srcintfList || []) : (p._srcintf || p.srcintf || ''),
      dstintf:      p._isAggregated ? (p._dstintfList || []) : (p._dstintf || p.dstintf || ''),
      srcAddrName:  p._srcAddrName,
      dstAddrName:  p._dstAddrName,
      policyName:   p._policyName,
      nat:          p._nat ?? p._isWan,
      srcAddrNames: p.srcAddrNames || null,
      tags:         p._tags || [],
    }));
  } else {
    selectedPolicies = deployState.analyzed
      .filter((_, i) => deployState.selected.has(i))
      .map(p => ({
        ...p,
        srcintf:      p._srcintf || p.srcintf || '',
        dstintf:      p._dstintf || p.dstintf || '',
        srcAddrName:  p._srcAddrName,
        dstAddrName:  p._dstAddrName,
        policyName:   p._policyName,
        nat:          p._nat ?? p._isWan,
        srcAddrNames: p.srcAddrNames || null,
        tags:         p._tags || [],
      }));
  }

  if (!selectedPolicies.length) { alert('Sélectionnez au moins une policy'); return; }

  const opts = {
    nat:    el('opt-nat')?.checked || false,
    action: el('opt-action')?.value || 'accept',
    log:    el('opt-log')?.value   || 'all',
  };

  const btn = el('btn-generate');
  if (btn) { btn.disabled = true; btn.textContent = 'Génération…'; }

  try {
    // Fetch JSON (not download) to get CLI text for inline preview
    const r = await fetch(`/api/deploy/generate?session=${state.session}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ selectedPolicies, opts }),
    });
    if (!r.ok) { const e = await r.json(); alert(e.error || 'Erreur génération'); return; }
    const { cli } = await r.json();

    deployState.generatedCli = cli;

    // Show inline preview
    const wrap = el('deploy-cli-wrap');
    const pre  = el('deploy-cli-pre');
    const info = el('deploy-gen-info');
    if (pre)  pre.textContent = cli;
    if (wrap) wrap.style.display = '';
    if (info) info.textContent = `${selectedPolicies.length} policies · ${cli.split('\n').length} lignes`;

    // Wire copy + download buttons (idempotent — replace each time)
    el('btn-copy-cli')?.addEventListener('click', () => {
      navigator.clipboard.writeText(deployState.generatedCli || '').then(() => {
        const b = el('btn-copy-cli');
        if (b) { const old = b.textContent; b.textContent = '✓ Copié !'; setTimeout(() => { b.textContent = old; }, 1800); }
      });
    });
    el('btn-download-cli')?.addEventListener('click', () => {
      const blob = new Blob([deployState.generatedCli || ''], { type: 'text/plain' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href = url; a.download = 'fortiflow_deploy.conf'; a.click();
      URL.revokeObjectURL(url);
    });
    el('btn-cli-toggle')?.addEventListener('click', () => {
      const p2 = el('deploy-cli-pre');
      const b  = el('btn-cli-toggle');
      if (!p2 || !b) return;
      const collapsed = p2.style.display === 'none';
      p2.style.display = collapsed ? '' : 'none';
      b.textContent = collapsed ? '▾ Réduire' : '▸ Développer';
    });

    // Scroll to preview
    wrap?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (err) {
    alert('Erreur : ' + err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '⬇ Générer config FortiGate'; }
  }
}

// ═══════════════════════════════════════════════════════════════
// Init & event wiring
// ═══════════════════════════════════════════════════════════════

document.querySelectorAll('.nav-item[data-view]').forEach(item => {
  item.addEventListener('click', () => navigateTo(item.dataset.view));
});

el('file-input').addEventListener('change', e => {
  handleUpload(e.target.files[0]);
  e.target.value = '';
});

el('btn-clear-session')?.addEventListener('click', () => {
  if (state.session) {
    fetch(`/api/session/${state.session}`, { method: 'DELETE' }).catch(() => {});
  }
  state.session = null;
  state.stats   = null;
  state.meta    = null;
  el('sidebar-session').style.display = 'none';
  ['badge-flows','badge-groups','badge-policies','badge-analyse','badge-polices'].forEach(id => { const b = el(id); if (b) b.textContent = '–'; });
  navigateTo('dashboard');
});

// Expert mode toggle
document.body.classList.toggle('simple-mode', !state.expertMode);
const expertToggle = el('expert-mode-toggle');
if (expertToggle) {
  expertToggle.checked = state.expertMode;
  expertToggle.addEventListener('change', e => {
    state.expertMode = e.target.checked;
    localStorage.setItem('ff-expert', e.target.checked ? '1' : '0');
    document.body.classList.toggle('simple-mode', !state.expertMode);
  });
}

// Start
navigateTo('dashboard');
