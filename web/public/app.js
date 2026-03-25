'use strict';

// ─── Theme ────────────────────────────────────────────────────────────────────
if (localStorage.theme === 'light') document.documentElement.dataset.theme = 'light';
document.addEventListener('click', e => {
  const btn = e.target.closest('#btn-theme');
  if (!btn) return;
  const isLight = document.documentElement.dataset.theme === 'light';
  document.documentElement.dataset.theme = isLight ? '' : 'light';
  localStorage.theme = isLight ? '' : 'light';
  btn.textContent = isLight ? '🌙' : '☀️';
});

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

function badgeHtml(type) {
  const labels = { config: 'CONFIG', predefined: 'PREDEF', auto: 'AUTO', route: 'ROUTE', sdwan: 'SDWAN', subnet: 'SUBNET' };
  return `<span class="badge-${type}">${labels[type] || type.toUpperCase()}</span>`;
}

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

  // Suivi WebSocket en temps réel
  const ok = await new Promise((resolve, reject) => {
    const wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${wsProto}//${location.host}/ws/progress?session=${sessionId}`);

    ws.onmessage = (evt) => {
      const d = JSON.parse(evt.data);
      if (d.done) {
        ws.close();
        if (d.error) { reject(new Error(d.error)); return; }
        state.session = sessionId;
        state.stats   = d.stats;
        state.meta    = d.meta;
        setProgressInfo({ lines: d.meta?.lineCount || 0, pct: 100, linesPerSec: 0 });
        resolve();
      } else {
        setProgressInfo(d);
      }
    };

    ws.onerror = () => { ws.close(); reject(new Error('Connexion WS perdue')); };
  }).then(() => true).catch(e => { showProgress(false); showError(e.message); return false; });

  if (!ok) return;

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
        <div class="section-sub">${m?.filename || ''} — ${fmtNum(m?.lineCount)} lignes lues · ${fmtNum(m?.uniqueFlows || 0)} flux uniques · ${fmtNum(m?.skipped || 0)} ignorées${m?.skipReasons ? ` (${fmtNum(m.skipReasons.nonTraffic || 0)} non-traffic, ${fmtNum(m.skipReasons.invalidFlow || 0)} invalides)` : ''}</div>
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
    { key: 'srcSubnet', label: 'Subnet src', mono: true},
    { key: 'dstip',     label: 'Dest IP',    mono: true  },
    { key: 'dstType',   label: 'Type dst',   render: r => typeTag(r.dstType) },
    { key: 'dstport',   label: 'Port',       mono: true  },
    { key: 'protoName', label: 'Proto',      render: r => protoTag(r.protoName) },
    { key: 'service',   label: 'Service',    mono: true},
    { key: 'action',    label: 'Action',     render: r => actionTag(r.action) },
    { key: 'count',     label: 'Sessions',   mono: true, render: r => fmtNum(r.count) },
    { key: 'totalBytes',label: 'Octets',     mono: true, render: r => fmtBytes(r.totalBytes) },
    { key: 'coveredByPolicy', label: 'Politique', render: r => {
      if (!r.coveredByPolicy) return '<span style="color:var(--text2)">–</span>';
      const p = r.coveredByPolicy;
      const tip = `Policy #${p.id}${p.name ? ' · ' + p.name : ''} (${p.action})`;
      const cls = p.action === 'deny' ? 'tag-deny' : 'tag-accept';
      return `<span class="${cls}" title="${escHtml(tip)}" style="font-size:11px;cursor:default">#${p.id}${p.name ? ' ' + escHtml(p.name) : ''}</span>`;
    }},
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
      const cls = c.mono ? ' class="mono"' : '';

      return `<td${cls}>${val}</td>`;
    }).join('');
    return `<tr>${cells}</tr>`;
  }).join('');

  el('flows-table-wrap').innerHTML = `
    <div class="table-wrap">
      <table>
        <thead><tr>${head}</tr></thead>
        <tbody>${rows || '<tr><td colspan="11" class="empty-state">Aucun flux trouvé</td></tr>'}</tbody>
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
        renderMatrix(data, state.matrix.action, signal);
      } catch (e) {
        el('matrix-wrap').innerHTML = `<div class="alert alert-error">${escHtml(e.message)}</div>`;
      }
    }, { signal });
  });

  try {
    const data = await api(`/api/matrix?action=${state.matrix.action}`);
    renderMatrix(data, state.matrix.action, signal);
  } catch (e) {
    el('matrix-wrap').innerHTML = `<div class="alert alert-error">${escHtml(e.message)}</div>`;
  }
}

function renderMatrix(data, mode = 'accept', signal) {
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
  }, signal ? { signal } : undefined);

  canvas.addEventListener('mouseleave', () => {
    _lastHoverCell = { si: -1, di: -1 };
    ctx.drawImage(offscreen, 0, 0);
    tooltip.style.display = 'none';
  }, signal ? { signal } : undefined);

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
  }, signal ? { signal } : undefined);

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
            <div class="dst-ip">${typeTag(d.type)} ${d.key}${d.type === 'public' && d.country ? ` <span class="geo-tag">${escHtml(d.flag || '')} ${escHtml(d.country)}</span>` : ''}</div>
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

  // First open: fetch and render (guard against concurrent fetches)
  if (!panel.dataset.loaded && !panel.dataset.loading) {
    panel.dataset.loading = '1';
    panel.style.display = 'block';
    panel.innerHTML = '<div class="host-loading"><div class="progress-spinner" style="margin:0 auto 8px"></div>Chargement des hôtes…</div>';
    try {
      const hosts = await api(`/api/hosts?subnet=${encodeURIComponent(subnet)}`);
      panel.innerHTML = renderHostPanel(hosts, subnet);
      panel.dataset.loaded = '1';
    } catch (e) {
      panel.innerHTML = `<div class="alert alert-error" style="margin:8px 16px">Erreur : ${escHtml(e.message)}</div>`;
    } finally { delete panel.dataset.loading; }
  } else if (panel.dataset.loaded) {
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
  wizardStep:    1,                // 1: config upload, 2: routes, 3: interfaces, 4: policies
  use32Global:   false,            // global /32 mode (use real hosts instead of /24)
};

// Collapsed state for interface category groups (persists across re-renders)
const ifaceGroupCollapsed = { lan: false, wan: false, vpn: false };

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
  if (mode === 'policy')        preview = mergeByPolicyId(original.map(p => ({ ...p })));
  else if (mode === 'service')  preview = mergeByService(original.map(p => ({ ...p })));
  else preview = mergeAnalyzedPolicies(original.map(p => ({ ...p })), mode);

  const beforeCount = original.length;
  const afterCount  = preview.length;
  const mergedGroups = preview.filter(p => (p._mergedCount || 1) > 1);

  const groupRows = mergedGroups.slice(0, 20).map((g, gi) => {
    const src = g.srcSubnets ? g.srcSubnets.join(', ') : g.srcSubnet;
    const svcs = (g.analysis?.services || []).map(s => s.label || s.name).join(', ');
    // Show original policies that were merged
    const origPolicies = (g._mergedFrom || []).slice(0, 10);
    const origRows = origPolicies.map(op => `
      <div class="merge-diff-row">
        <span class="merge-diff-label">src</span><span class="merge-diff-val">${escHtml(op.srcSubnet || '')}</span>
        <span class="merge-diff-arrow">→</span>
        <span class="merge-diff-label">dst</span><span class="merge-diff-val">${escHtml(op.dstTarget || '')}</span>
        <span class="merge-diff-arrow">·</span>
        <span class="merge-diff-val">${escHtml((op.analysis?.services || []).map(s => s.label || s.name).join(', ') || '—')}</span>
      </div>`).join('');
    const hasOrig = origPolicies.length > 0;
    return `<div style="padding:6px 0;border-bottom:1px solid var(--border)">
      <div style="display:flex;gap:8px;align-items:center">
        <span class="mono" style="font-size:11px;min-width:120px">${escHtml(src)}</span>
        <span style="color:var(--text2)">→</span>
        <span class="mono" style="font-size:11px">${escHtml(g.dstTarget)}</span>
        <span style="color:var(--text2);font-size:10px;margin-left:4px">[${escHtml(svcs || '—')}]</span>
        <span class="merge-badge" style="margin-left:auto">×${g._mergedCount}</span>
      </div>
      ${hasOrig ? `<details style="margin-top:4px"><summary class="merge-diff-toggle">Voir les ${origPolicies.length} policies sources</summary><div class="merge-diff-details">${origRows}</div></details>` : ''}
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
  const hosts     = new Map(); // ip   → { ip, name, policyCount, found }
  const services  = new Map(); // key  → { key, port, proto, label, name, policyCount }

  for (const p of deployState.analyzed) {
    const a = p.analysis;
    if (!a) continue;

    const srcFoundHosts = new Set(p._srcHostsFound || []);
    const dstFoundHosts = new Set(p._dstHostsFound || []);

    // Src address manquante
    if (a.srcAddr && !a.srcAddr.found) {
      const cidr = a.srcAddr.cidr;
      if (cidr) {
        if (!addresses.has(cidr)) addresses.set(cidr, { cidr, name: p._srcAddrName || a.srcAddr.suggestedName, policyCount: 0 });
        addresses.get(cidr).policyCount++;
      }
    }
    // Dst address manquante
    if (p.dstType === 'private' && a.dstAddr && !a.dstAddr.found) {
      const cidr = a.dstAddr.cidr;
      if (cidr && cidr !== 'all') {
        if (!addresses.has(cidr)) addresses.set(cidr, { cidr, name: p._dstAddrName || a.dstAddr.suggestedName, policyCount: 0 });
        addresses.get(cidr).policyCount++;
      }
    }
    // Multi-dst : collecter les subnets manquants
    if (p._isMultiDst && p._multiDstSubnets?.length) {
      for (const s of p._multiDstSubnets) {
        if (!s.addrFound) {
          const cidr = s.subnet;
          if (cidr && cidr !== 'all') {
            if (!addresses.has(cidr)) addresses.set(cidr, { cidr, name: s.addrName, policyCount: 0 });
            addresses.get(cidr).policyCount++;
          }
        }
      }
    }
    // Multi-src : collecter les subnets manquants
    if (p._multiSrcSubnets?.length) {
      for (const s of p._multiSrcSubnets) {
        if (!s.addrFound) {
          const cidr = s.subnet;
          if (cidr) {
            if (!addresses.has(cidr)) addresses.set(cidr, { cidr, name: s.addrName, policyCount: 0 });
            addresses.get(cidr).policyCount++;
          }
        }
      }
    }
    // Hôtes /32 src — TOUS les hôtes non trouvés dans la config
    if (p.srcHosts?.length > 0) {
      for (const h of p.srcHosts) {
        if (srcFoundHosts.has(h)) continue; // existe dans la config — ne pas lister
        if (!hosts.has(h)) {
          const suggested = (p._srcHostNames?.[h]) || `FF_HOST_${h.replace(/\./g, '_')}`;
          hosts.set(h, { ip: h, name: suggested, policyCount: 0 });
        }
        hosts.get(h).policyCount++;
      }
    }
    // Hôtes /32 dst — TOUS les hôtes non trouvés dans la config
    if (p.dstHosts?.length > 0) {
      for (const h of p.dstHosts) {
        if (dstFoundHosts.has(h)) continue; // existe dans la config
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
        const key = svc.isNamed ? `label:${svc.label}` : `${svc.port}/${svc.proto}`;
        const defaultName = svc.isNamed ? (svc.suggestedName || svc.label) : (svc.suggestedName || `FF_SVC_${svc.port}_${svc.proto}`);
        if (!services.has(key)) services.set(key, { key, port: svc.port, proto: svc.proto, label: svc.label, name: defaultName, policyCount: 0 });
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
    // Multi-dst : propager les noms aux subnets individuels
    if (p._isMultiDst && p._multiDstSubnets?.length) {
      for (const s of p._multiDstSubnets) {
        if (addrMap[s.subnet]) s.addrName = addrMap[s.subnet];
      }
    }
    // Multi-src : propager les noms aux subnets individuels
    if (p._multiSrcSubnets?.length) {
      for (const s of p._multiSrcSubnets) {
        if (addrMap[s.subnet]) s.addrName = addrMap[s.subnet];
      }
    }
    // Host names — propager à TOUTES les policies (pas seulement mode /32)
    if (p.srcHosts?.length > 0) {
      p._srcHostNames = p._srcHostNames || {};
      for (const h of p.srcHosts) if (hostsMap[h]) p._srcHostNames[h] = hostsMap[h];
    }
    if (p.dstHosts?.length > 0) {
      p._dstHostNames = p._dstHostNames || {};
      for (const h of p.dstHosts) if (hostsMap[h]) p._dstHostNames[h] = hostsMap[h];
    }
    // Services
    for (const svc of a.services || []) {
      if (!svc.found) {
        const key = svc.isNamed ? `label:${svc.label}` : `${svc.port}/${svc.proto}`;
        if (svcMap[key]) svc.suggestedName = svcMap[key];
      }
    }
  }
  renderDeployPolicies(filterDeployPolicies(), false);
}

// ── Policy Drawer (side panel) ───────────────────────────────────────────────

let _drawerMounted = false;
let _drawerIdx = null;
let _drawerHistory = [];
const DRAWER_HISTORY_MAX = 10;

function _snapDrawer(p) {
  if (!p) return;
  const snap = {};
  const keys = ['_srcAddrName','_dstAddrName','_policyName','_srcMode','_dstMode',
    '_use32Src','_use32Dst','_srcHostNames','_dstHostNames','_useSrcGroup','_useDstGroup',
    '_srcintf','_dstintf','_nat','_mergeMode','_mergedSvcName','_mergeRange'];
  for (const k of keys) {
    if (!(k in p)) continue;
    const v = p[k];
    snap[k] = (v && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Set) && !(v instanceof Map))
      ? { ...v } : v;
  }
  snap._selectedSvcKeys   = p._selectedSvcKeys   ? new Set(p._selectedSvcKeys)  : undefined;
  snap._analysisServices  = JSON.parse(JSON.stringify(p.analysis?.services || []));
  snap._multiSrcSubnets   = p._multiSrcSubnets   ? JSON.parse(JSON.stringify(p._multiSrcSubnets)) : undefined;
  snap._multiDstSubnets   = p._multiDstSubnets   ? JSON.parse(JSON.stringify(p._multiDstSubnets)) : undefined;
  snap._excludedSrcHosts  = p._excludedSrcHosts  ? new Set(p._excludedSrcHosts) : undefined;
  snap._excludedDstHosts  = p._excludedDstHosts  ? new Set(p._excludedDstHosts) : undefined;
  if (_drawerHistory.length >= DRAWER_HISTORY_MAX) _drawerHistory.shift();
  _drawerHistory.push({ idx: _drawerIdx, snap });
}

function mountDrawer() {
  if (_drawerMounted) return;
  _drawerMounted = true;
  const overlay = document.createElement('div');
  overlay.className = 'policy-drawer-overlay';
  overlay.id = 'drawer-overlay';
  const drawer = document.createElement('div');
  drawer.className = 'policy-drawer';
  drawer.id = 'policy-drawer';
  drawer.innerHTML = `<div class="drawer-header">
    <h3 id="drawer-title">Policy</h3>
    <button class="drawer-close" id="drawer-close">&times;</button>
  </div>
  <div class="drawer-body" id="drawer-body"></div>`;
  document.body.appendChild(overlay);
  document.body.appendChild(drawer);
  overlay.addEventListener('click', closeDrawer);
  drawer.querySelector('#drawer-close').addEventListener('click', closeDrawer);

  // Undo hint span (inserted between title and close button)
  const undoHint = document.createElement('span');
  undoHint.id = 'drawer-undo-hint';
  undoHint.textContent = 'Ctrl+Z';
  undoHint.style.cssText = 'font-size:10px;color:var(--text3);display:none;margin-right:8px;';
  drawer.querySelector('.drawer-header').insertBefore(undoHint, drawer.querySelector('#drawer-close'));

  // Ctrl+Z undo handler (once)
  if (!window._undoWired) {
    window._undoWired = true;
    document.addEventListener('keydown', e => {
      if (!e.ctrlKey || e.key !== 'z' || _drawerIdx === null) return;
      e.preventDefault();
      const last = _drawerHistory.pop();
      if (!last) return;
      const p = deployState.analyzed[last.idx];
      const { _analysisServices, _selectedSvcKeys, _multiSrcSubnets, _multiDstSubnets, _excludedSrcHosts, _excludedDstHosts, ...rest } = last.snap;
      Object.assign(p, rest);
      if (_analysisServices  !== undefined) p.analysis.services   = _analysisServices;
      if (_selectedSvcKeys   !== undefined) p._selectedSvcKeys    = _selectedSvcKeys;
      if (_multiSrcSubnets   !== undefined) p._multiSrcSubnets    = _multiSrcSubnets;
      if (_multiDstSubnets   !== undefined) p._multiDstSubnets    = _multiDstSubnets;
      if (_excludedSrcHosts  !== undefined) p._excludedSrcHosts   = _excludedSrcHosts;
      if (_excludedDstHosts  !== undefined) p._excludedDstHosts   = _excludedDstHosts;
      populateDrawer(last.idx);
      syncRowStatus(last.idx);
      renderDeployPolicies(filterDeployPolicies(), false);
      const hint = document.getElementById('drawer-undo-hint');
      if (hint) hint.style.display = _drawerHistory.length ? '' : 'none';
    });
  }

  // Delegated events inside drawer
  drawer.addEventListener('input', e => {
    const p = _drawerIdx !== null ? deployState.analyzed[_drawerIdx] : null;
    if (!p) return;
    _snapDrawer(p);
    const hint = document.getElementById('drawer-undo-hint');
    if (hint) hint.style.display = '';
    if (e.target.matches('.drawer-src-name'))  { p._srcAddrName = e.target.value; syncInlineCell(_drawerIdx, '_srcAddrName', e.target.value); }
    if (e.target.matches('.drawer-dst-name'))  { p._dstAddrName = e.target.value; syncInlineCell(_drawerIdx, '_dstAddrName', e.target.value); }
    if (e.target.matches('.drawer-policy-name')) p._policyName = e.target.value;
    if (e.target.matches('.drawer-host-input')) {
      const host = e.target.dataset.host;
      const type = e.target.dataset.type;
      if (type === 'src') { if (!p._srcHostNames) p._srcHostNames = {}; p._srcHostNames[host] = e.target.value; }
      else { if (!p._dstHostNames) p._dstHostNames = {}; p._dstHostNames[host] = e.target.value; }
    }
    if (e.target.matches('.svc-merge-name')) { p._mergedSvcName = e.target.value; return; }
    if (e.target.matches('.svc-merge-range')) { p._mergeRange = e.target.value; return; }
    if (e.target.matches('.drawer-svc-name')) {
      const svcKey = e.target.dataset.svcKey;
      const svc = (p.analysis?.services || []).find(s => {
        const _m = s.label?.match(/^(TCP|UDP)\/(\d+)$/i);
        const k = _m ? `${parseInt(_m[2],10)}/${_m[1].toUpperCase()}` : (s.isNamed ? `label:${s.label}` : `${s.port}/${s.proto}`);
        return k === svcKey;
      });
      if (svc) svc.suggestedName = e.target.value;
    }
    if (e.target.matches('.drawer-multidst-name')) {
      const si = +e.target.dataset.si;
      if (p._multiDstSubnets?.[si]) p._multiDstSubnets[si].addrName = e.target.value;
    }
    if (e.target.matches('.drawer-multisrc-name')) {
      const si = +e.target.dataset.si;
      if (p._multiSrcSubnets?.[si]) {
        p._multiSrcSubnets[si].addrName = e.target.value;
        // Also update srcAddrNames array for CLI generation
        if (p.srcAddrNames && p.srcAddrNames[si] !== undefined) p.srcAddrNames[si] = e.target.value;
      }
    }
    if (e.target.matches('.drawer-grp-name')) {
      p._dstAddrName = e.target.value;
    }
    if (e.target.matches('.drawer-src-grp-name')) {
      p._srcAddrName = e.target.value;
    }
    syncRowStatus(_drawerIdx);
  });
  drawer.addEventListener('click', e => {
    const p = _drawerIdx !== null ? deployState.analyzed[_drawerIdx] : null;
    if (!p) return;
    const _snapAndShow = () => {
      _snapDrawer(p);
      const hint = document.getElementById('drawer-undo-hint');
      if (hint) hint.style.display = '';
    };
    // Select-all services toggle
    if (e.target.matches('.svc-sel-all')) {
      _snapAndShow();
      const _svcList = p.analysis?.services || [];
      const _getSvcPP = s => { const m = s.label?.match(/^(TCP|UDP)\/(\d+)$/i); return m ? { port: parseInt(m[2],10), proto: m[1].toUpperCase() } : { port: s.port, proto: (s.proto||'').toUpperCase() }; };
      const _selectable = _svcList.filter(s => { if (s.found) return false; const m = s.label?.match(/^(TCP|UDP)\/(\d+)$/i); return m || (!s.isNamed && s.port); });
      if (!p._selectedSvcKeys) p._selectedSvcKeys = new Set();
      const _allKeys = _selectable.map(s => { const {port, proto} = _getSvcPP(s); return `${port}/${proto}`; });
      const _allSel = _allKeys.every(k => p._selectedSvcKeys.has(k));
      if (_allSel) _allKeys.forEach(k => p._selectedSvcKeys.delete(k));
      else _allKeys.forEach(k => p._selectedSvcKeys.add(k));
      populateDrawer(_drawerIdx);
      return;
    }
    // Service selection toggle
    const svcRow = e.target.closest('.svc-selectable');
    const svcChk = e.target.matches('.svc-sel-chk') ? e.target : null;
    if (svcRow && (!e.target.matches('.drawer-svc-name'))) {
      _snapAndShow();
      const key = svcRow.dataset.svcKey;
      if (!p._selectedSvcKeys) p._selectedSvcKeys = new Set();
      if (p._selectedSvcKeys.has(key)) p._selectedSvcKeys.delete(key);
      else p._selectedSvcKeys.add(key);
      populateDrawer(_drawerIdx);
      return;
    }
    // Merge mode toggle (list vs range)
    const mergeTypeBtn = e.target.closest('.svc-merge-type');
    if (mergeTypeBtn) {
      _snapAndShow();
      p._mergeMode = mergeTypeBtn.dataset.mode;
      populateDrawer(_drawerIdx);
      return;
    }
    // Do merge
    if (e.target.closest('.svc-do-merge')) {
      _snapAndShow();
      const nameInput = document.querySelector('.svc-merge-name');
      const rangeInput = document.querySelector('.svc-merge-range');
      const mergedName = (nameInput?.value.trim()) || null;
      const mode = p._mergeMode || 'list';
      const _gpp = s => { const m = s.label?.match(/^(TCP|UDP)\/(\d+)$/i); return m ? { port: parseInt(m[2],10), proto: m[1].toUpperCase() } : { port: s.port, proto: (s.proto||'').toUpperCase() }; };
      const selSvcs = (p.analysis?.services || []).filter(s => { const {port,proto} = _gpp(s); return p._selectedSvcKeys?.has(`${port}/${proto}`); });
      if (selSvcs.length < 2) return;
      const proto = _gpp(selSvcs[0]).proto;
      const ports = selSvcs.map(s => _gpp(s).port).sort((a, b) => a - b);
      const portRange = mode === 'range' ? (rangeInput?.value.trim() || `${ports[0]}-${ports[ports.length-1]}`) : null;
      const svcName = mergedName || `FF_SVC_${proto.toUpperCase()}_MULTI`;
      // Remove individual entries, add merged
      const remaining = (p.analysis.services).filter(s => { const {port,proto} = _gpp(s); return !p._selectedSvcKeys?.has(`${port}/${proto}`); });
      remaining.push({
        label: svcName,
        found: false,
        name: null,
        source: null,
        suggestedName: svcName,
        isNamed: false,
        proto,
        ports: portRange ? null : ports,
        portRange: portRange || null,
        port: portRange ? null : ports[0],
        portHint: portRange ? `${proto.toUpperCase()}: ${portRange}` : `${proto.toUpperCase()}: ${ports.join(', ')}`,
        _isMerged: true,
      });
      p.analysis.services = remaining;
      p._selectedSvcKeys = new Set();
      delete p._mergedSvcName;
      delete p._mergeMode;
      delete p._mergeRange;
      populateDrawer(_drawerIdx);
      syncRowStatus(_drawerIdx);
      renderDeployPolicies(filterDeployPolicies(), false);
      return;
    }
    const modeBtn = e.target.closest('.drawer-mode-btn');
    if (modeBtn) {
      _snapAndShow();
      const type = modeBtn.dataset.type;
      const mode = modeBtn.dataset.mode;
      if (type === 'src') { p._srcMode = mode; p._use32Src = mode === 'hosts'; }
      else { p._dstMode = mode; p._use32Dst = mode === 'hosts'; }
      populateDrawer(_drawerIdx);
      renderDeployPolicies(filterDeployPolicies(), false);
      return;
    }
    const grpBtn = e.target.closest('.drawer-grp-toggle');
    if (grpBtn) {
      _snapAndShow();
      const type = grpBtn.dataset.type;
      if (type === 'src') p._useSrcGroup = !p._useSrcGroup;
      else p._useDstGroup = !p._useDstGroup;
      populateDrawer(_drawerIdx);
      renderDeployPolicies(filterDeployPolicies(), false);
      return;
    }
    const mdBtn = e.target.closest('.drawer-multidst-mode');
    if (mdBtn) {
      e.stopPropagation();
      _snapAndShow();
      const si = +mdBtn.dataset.si;
      if (p._multiDstSubnets?.[si]) {
        const cur = p._multiDstSubnets[si].useSubnet;
        p._multiDstSubnets[si].useSubnet = (cur === false) ? true : false;
        populateDrawer(_drawerIdx);
      }
      return;
    }
    const msBtn = e.target.closest('.drawer-multisrc-mode');
    if (msBtn) {
      e.stopPropagation();
      _snapAndShow();
      const si = +msBtn.dataset.si;
      if (p._multiSrcSubnets?.[si]) {
        const cur = p._multiSrcSubnets[si].useSubnet;
        p._multiSrcSubnets[si].useSubnet = (cur === false) ? true : false;
        populateDrawer(_drawerIdx);
      }
      return;
    }
    // Delete item (service, subnet, host)
    const delBtn = e.target.closest('.btn-del-item');
    if (delBtn) {
      e.stopPropagation();
      _snapAndShow();
      const dt = delBtn.dataset.delType;
      if (dt === 'svc') {
        const k = delBtn.dataset.svcKey;
        p.analysis.services = (p.analysis.services || []).filter(s => {
          const _m = s.label?.match(/^(TCP|UDP)\/(\d+)$/i);
          const sk = _m ? `${parseInt(_m[2],10)}/${_m[1].toUpperCase()}` : (s.isNamed ? `label:${s.label}` : `${s.port}/${s.proto}`);
          return sk !== k && s.label !== k;
        });
      } else if (dt === 'src-subnet') {
        const si = +delBtn.dataset.si;
        p._multiSrcSubnets = (p._multiSrcSubnets || []).filter((_, i) => i !== si);
      } else if (dt === 'dst-subnet') {
        const si = +delBtn.dataset.si;
        p._multiDstSubnets = (p._multiDstSubnets || []).filter((_, i) => i !== si);
      } else if (dt === 'src-host') {
        if (!p._excludedSrcHosts) p._excludedSrcHosts = new Set();
        p._excludedSrcHosts.add(delBtn.dataset.host);
      } else if (dt === 'dst-host') {
        if (!p._excludedDstHosts) p._excludedDstHosts = new Set();
        p._excludedDstHosts.add(delBtn.dataset.host);
      }
      populateDrawer(_drawerIdx);
      syncRowStatus(_drawerIdx);
      renderDeployPolicies(filterDeployPolicies(), false);
      return;
    }
    // Propagation banner buttons
    if (e.target.closest('.svc-prop-yes')) {
      const pp = p._propagatePending;
      if (pp) {
        for (const op of (deployState.analyzed || [])) {
          if (op === p) continue;
          const match = (op.analysis?.services || []).find(s => {
            if (!s.found) {
              if (pp.label) return s.label === pp.label;
              const sm = s.label?.match(/^(TCP|UDP)\/(\d+)$/i);
              const sp = sm ? parseInt(sm[2], 10) : s.port;
              const spr = sm ? sm[1].toUpperCase() : (s.proto || '').toUpperCase();
              return sp === pp.port && spr === pp.proto;
            }
            return false;
          });
          if (match) {
            match.suggestedName = pp.newName;
            const oi = deployState.analyzed.indexOf(op);
            syncRowStatus(oi);
          }
        }
        delete p._propagatePending;
        renderDeployPolicies(filterDeployPolicies(), false);
        populateDrawer(_drawerIdx);
      }
      return;
    }
    if (e.target.closest('.svc-prop-no')) {
      delete p._propagatePending;
      populateDrawer(_drawerIdx);
      return;
    }
  });
  drawer.addEventListener('change', e => {
    const p = _drawerIdx !== null ? deployState.analyzed[_drawerIdx] : null;
    if (!p) return;
    _snapDrawer(p);
    const hint = document.getElementById('drawer-undo-hint');
    if (hint) hint.style.display = '';
    if (e.target.matches('.drawer-srcintf')) { p._srcintf = e.target.value || undefined; renderDeployPolicies(filterDeployPolicies(), false); }
    if (e.target.matches('.drawer-dstintf')) { p._dstintf = e.target.value || undefined; renderDeployPolicies(filterDeployPolicies(), false); }
    if (e.target.matches('.drawer-nat')) { p._nat = e.target.checked; }
    syncRowStatus(_drawerIdx);
  });
  // Propagation check on service name blur
  drawer.addEventListener('focusout', e => {
    if (!e.target.matches('.drawer-svc-name')) return;
    const p = _drawerIdx !== null ? deployState.analyzed[_drawerIdx] : null;
    if (!p) return;
    const svcKey = e.target.dataset.svcKey;
    const newName = e.target.value.trim();
    if (!newName) return;
    const svc = (p.analysis?.services || []).find(s => {
      const _m = s.label?.match(/^(TCP|UDP)\/(\d+)$/i);
      const k = _m ? `${parseInt(_m[2],10)}/${_m[1].toUpperCase()}` : (s.isNamed ? `label:${s.label}` : `${s.port}/${s.proto}`);
      return k === svcKey;
    });
    if (!svc) return;
    const _sm = svc.label?.match(/^(TCP|UDP)\/(\d+)$/i);
    const targetPort  = _sm ? parseInt(_sm[2], 10) : svc.port;
    const targetProto = _sm ? _sm[1].toUpperCase() : (svc.proto || '').toUpperCase();
    const targetLabel = (!targetPort || !targetProto) ? svc.label : null; // fallback: match par label
    if (!targetPort && !targetLabel) return;
    let count = 0;
    for (let i = 0; i < (deployState.analyzed || []).length; i++) {
      if (i === _drawerIdx) continue;
      const match = (deployState.analyzed[i].analysis?.services || []).find(s => {
        if (!s.found) {
          if (targetLabel) return s.label === targetLabel;
          const sm2 = s.label?.match(/^(TCP|UDP)\/(\d+)$/i);
          const sp = sm2 ? parseInt(sm2[2], 10) : s.port;
          const spr = sm2 ? sm2[1].toUpperCase() : (s.proto || '').toUpperCase();
          return sp === targetPort && spr === targetProto;
        }
        return false;
      });
      if (match) count++;
    }
    if (count > 0) {
      p._propagatePending = { svcKey, newName, port: targetPort, proto: targetProto, label: targetLabel, portHint: svc.portHint || null, count };
      populateDrawer(_drawerIdx);
    }
  });
}

function openDrawer(idx) {
  mountDrawer();
  _drawerIdx = idx;
  _drawerHistory = [];
  populateDrawer(idx);
  document.getElementById('drawer-overlay').classList.add('open');
  document.getElementById('policy-drawer').classList.add('open');
  // Mark row
  document.querySelectorAll('.deploy-policy-row.selected-row').forEach(r => r.classList.remove('selected-row'));
  document.querySelector(`.deploy-policy-row[data-idx="${idx}"]`)?.classList.add('selected-row');
}

function closeDrawer() {
  document.getElementById('drawer-overlay')?.classList.remove('open');
  document.getElementById('policy-drawer')?.classList.remove('open');
  document.querySelectorAll('.deploy-policy-row.selected-row').forEach(r => r.classList.remove('selected-row'));
  _drawerIdx = null;
}

function syncInlineCell(idx, field, value) {
  const cell = document.querySelector(`.inline-editable[data-idx="${idx}"][data-field="${field}"]`);
  if (cell) cell.textContent = value || '—';
  syncRowStatus(idx);
}

function populateDrawer(idx) {
  const p = deployState.analyzed[idx];
  if (!p) return;
  const a = p.analysis || {};
  const title = document.getElementById('drawer-title');
  title.textContent = `Policy ${p._policyName || (p.policyIds || [])[0] || idx}`;

  const ifOpts = (deployState.ifaceOpts || []).map(o =>
    `<option value="${escHtml(o.value)}" ${(o.value === (p._srcintf || '')) ? 'selected' : ''}>${escHtml(o.label)}</option>`
  ).join('');
  const ifOptsDst = (deployState.ifaceOpts || []).map(o =>
    `<option value="${escHtml(o.value)}" ${(o.value === (p._dstintf || '')) ? 'selected' : ''}>${escHtml(o.label)}</option>`
  ).join('');
  const pid0 = (p.policyIds || [])[0] || idx;
  const suggestedSrcGrp = `FF_POLICY_${pid0}_SRC`;
  const suggestedDstGrp = `GRP_${pid0}_DST`;

  const srcMode = p._srcMode || (p._use32Src ? 'hosts' : 'subnet');
  const dstMode = p._dstMode || (p._use32Dst ? 'hosts' : 'subnet');
  const srcHosts = p.srcHosts || [];
  const dstHosts = p.dstHosts || [];

  const srcAddrName = p._srcAddrName || a.srcAddr?.name || '';
  const srcFound = a.srcAddr?.found;
  // inputVal: montre la valeur seulement si différente de la suggestion auto (sinon champ vide + placeholder)
  const inputVal = (stored, auto) => (stored && stored !== auto) ? stored : '';

  // Source section — depends on multi-src or single
  let srcSection = '';
  if (p._multiSrcSubnets?.length) {
    // ── Multi-src : several source subnets ──
    const srcSubs = p._multiSrcSubnets;
    const srcSubRows = srcSubs.map((s, si) => {
      const isSubnet = s.useSubnet !== false;
      const statusIcon = s.addrFound ? `<span style="color:var(--success)">&#10003;</span>` : `<span style="color:var(--warn)">+</span>`;
      const nameInput = `<input class="drawer-input drawer-multisrc-name" data-si="${si}" value="${escHtml(inputVal(s.addrName, suggestAddrNameFE(s.subnet)))}" placeholder="${escHtml(s.addrName)}" style="flex:1;font-size:10px">`;
      let hostsHtml = '';
      if (!isSubnet && s.hosts?.length > 0) {
        const visibleSrcHosts = s.hosts.filter(h => !p._excludedSrcHosts?.has(h));
        hostsHtml = `<div style="padding-left:16px;margin-top:2px;margin-bottom:6px">${visibleSrcHosts.slice(0, 50).map(h => {
          const foundSet = new Set(p._srcHostsFound || []);
          const hostName = (p._srcHostNames || {})[h] || `FF_HOST_${h.replace(/\./g,'_')}`;
          const hostFound = foundSet.has(h);
          return `<div class="drawer-host-row">
            <span class="drawer-host-ip">${escHtml(h)}</span>
            ${hostFound
              ? `<span style="color:var(--success);font-size:10px" title="${escHtml(h)}/32">&#10003; ${escHtml(hostName)}</span>`
              : `<input class="drawer-host-input" data-type="src" data-host="${escHtml(h)}" value="${escHtml(inputVal(p._srcHostNames?.[h], `FF_HOST_${h.replace(/\./g,'_')}`))}" placeholder="${escHtml(hostName)}">`}
            <button class="btn-del-item" data-del-type="src-host" data-host="${escHtml(h)}" title="Retirer cet hôte">✕</button>
          </div>`;
        }).join('')}${visibleSrcHosts.length > 50 ? `<div style="font-size:10px;color:var(--text2)">+${visibleSrcHosts.length - 50} autres…</div>` : ''}</div>`;
      }
      return `<div class="drawer-multisrc-row" style="display:flex;align-items:center;gap:6px;padding:3px 0">
        <span class="drawer-multisrc-subnet" style="font-family:var(--mono);font-size:11px;min-width:120px">${escHtml(s.subnet)}</span>
        <button class="btn-sm drawer-multisrc-mode" data-si="${si}" style="font-size:9px;padding:2px 8px">${isSubnet ? '/24' : `/32 (${s.hosts?.length || 0}h)`}</button>
        ${isSubnet ? statusIcon : ''}
        ${isSubnet ? (s.addrFound ? `<span style="color:var(--success);font-size:10px" title="${escHtml(s.subnet)}">${escHtml(s.addrName)}</span>` : nameInput) : ''}
        <button class="btn-del-item" data-del-type="src-subnet" data-si="${si}" title="Retirer ce subnet">✕</button>
      </div>${hostsHtml}`;
    }).join('');
    srcSection = `<div class="drawer-section">
      <div class="drawer-section-title">Sources (${srcSubs.length} subnets)</div>
      ${srcSubRows}
      <div class="drawer-toggle-row" style="margin-top:8px">
        <button class="drawer-toggle-btn drawer-grp-toggle ${p._useSrcGroup ? 'active' : ''}" data-type="src">Grouper (addrgrp)</button>
        ${p._useSrcGroup ? (p._srcAddrGrpFound
          ? `<span style="color:var(--success);font-size:11px" title="${escHtml(srcSubs.map(s => s.subnet).join(', '))}">&#10003; ${escHtml(p._srcAddrName)}</span>`
          : `<input class="drawer-input drawer-src-grp-name" value="${escHtml(p._srcAddrName || '')}" placeholder="${escHtml(suggestedSrcGrp)}" style="width:160px">`)
          : ''}
      </div>
      <div class="drawer-field"><span class="drawer-field-label">Interface</span><select class="drawer-input drawer-srcintf">${ifOpts}</select></div>
    </div>`;
  } else {
    // ── Single source subnet ──
    let srcHostsHtml = '';
    if (srcHosts.length > 0 && srcMode === 'hosts') {
      const visibleSrcHostsSingle = srcHosts.filter(h => !p._excludedSrcHosts?.has(h));
      srcHostsHtml = `<div class="drawer-host-list">${visibleSrcHostsSingle.slice(0, 80).map(h => {
        const foundSet = new Set(p._srcHostsFound || []);
        const hostFound = foundSet.has(h);
        const name = (p._srcHostNames || {})[h] || `FF_HOST_${h.replace(/\./g,'_')}`;
        return `<div class="drawer-host-row">
          <span class="drawer-host-ip">${escHtml(h)}</span>
          ${hostFound
            ? `<span style="color:var(--success);font-size:10px" title="${escHtml(h)}/32">&#10003; ${escHtml(name)}</span>`
            : `<input class="drawer-host-input" data-type="src" data-host="${escHtml(h)}" value="${escHtml(inputVal(p._srcHostNames?.[h], `FF_HOST_${h.replace(/\./g,'_')}`))}" placeholder="${escHtml(name)}">`}
          <button class="btn-del-item" data-del-type="src-host" data-host="${escHtml(h)}" title="Retirer cet hôte">✕</button>
        </div>`;
      }).join('')}</div>`;
      if (srcHosts.length > 1) {
        const srcGrpFound = p._srcAddrGrpFound;
        srcHostsHtml += `<div class="drawer-toggle-row" style="margin-top:4px">
          <button class="drawer-toggle-btn drawer-grp-toggle ${p._useSrcGroup ? 'active' : ''}" data-type="src">Grouper (addrgrp)</button>
          ${p._useSrcGroup ? (srcGrpFound
            ? `<span style="color:var(--success);font-size:11px" title="${escHtml(srcHosts.map(h => h + '/32').join(', '))}">&#10003; ${escHtml(p._srcAddrName)}</span>`
            : `<input class="drawer-input drawer-src-grp-name" value="${escHtml(p._srcAddrName || '')}" placeholder="${escHtml(suggestedSrcGrp)}" style="width:160px">`)
            : ''}
        </div>`;
      }
    }
    srcSection = `<div class="drawer-section">
      <div class="drawer-section-title">Source</div>
      <div class="drawer-field"><span class="drawer-field-label">Subnet</span><span class="drawer-field-value">${escHtml(p.srcSubnet || '')}</span></div>
      <div class="drawer-toggle-row">
        <span style="font-size:11px;color:var(--text2)">Mode :</span>
        <button class="drawer-toggle-btn drawer-mode-btn ${srcMode==='subnet'?'active':''}" data-type="src" data-mode="subnet">/24 subnet</button>
        <button class="drawer-toggle-btn drawer-mode-btn ${srcMode==='hosts'?'active':''} ${srcHosts.length<1?'disabled':''}" data-type="src" data-mode="hosts">/32 hôtes (${srcHosts.length})</button>
      </div>
      ${srcMode === 'subnet' ? `<div class="drawer-field">
        <span class="drawer-field-label">Objet addr</span>
        ${srcFound ? `<span class="drawer-field-value" style="color:var(--success)" title="${escHtml(a.srcAddr?.cidr || p.srcSubnet || '')}">&#10003; ${escHtml(srcAddrName)}${badgeHtml('config')}</span>`
          : `<input class="drawer-input drawer-src-name" value="${escHtml(inputVal(srcAddrName, a.srcAddr?.suggestedName || suggestAddrNameFE(p.srcSubnet)))}" placeholder="${escHtml(srcAddrName || 'FF_...')}">${badgeHtml('auto')}`}
      </div>` : ''}
      ${srcHostsHtml}
      <div class="drawer-field"><span class="drawer-field-label">Interface</span><select class="drawer-input drawer-srcintf">${ifOpts}</select></div>
    </div>`;
  }

  // Dst section — depends on multi-dst or single
  let dstSection = '';
  if (p._isMultiDst && p._multiDstSubnets?.length) {
    const subs = p._multiDstSubnets;
    const subRows = subs.map((s, si) => {
      const isSubnet = s.useSubnet !== false;
      const statusIcon = s.addrFound ? `<span style="color:var(--success)">&#10003;</span>` : `<span style="color:var(--warn)">+</span>`;
      const nameInput = `<input class="drawer-input drawer-multidst-name" data-si="${si}" value="${escHtml(inputVal(s.addrName, suggestAddrNameFE(s.subnet)))}" placeholder="${escHtml(s.addrName)}" style="flex:1;font-size:10px">`;
      let hostsHtml = '';
      if (!isSubnet && s.hosts?.length > 0) {
        const visibleDstHosts = s.hosts.filter(h => !p._excludedDstHosts?.has(h));
        hostsHtml = `<div style="padding-left:16px;margin-top:2px;margin-bottom:6px">${visibleDstHosts.slice(0, 50).map(h => {
          const foundSet = new Set(p._dstHostsFound || []);
          const hostName = (p._dstHostNames || {})[h] || `FF_HOST_${h.replace(/\./g,'_')}`;
          const hostFound = foundSet.has(h);
          return `<div class="drawer-host-row">
            <span class="drawer-host-ip">${escHtml(h)}</span>
            ${hostFound
              ? `<span style="color:var(--success);font-size:10px" title="${escHtml(h)}/32">&#10003; ${escHtml(hostName)}</span>`
              : `<input class="drawer-host-input" data-type="dst" data-host="${escHtml(h)}" value="${escHtml(inputVal(p._dstHostNames?.[h], `FF_HOST_${h.replace(/\./g,'_')}`))}" placeholder="${escHtml(hostName)}">`}
            <button class="btn-del-item" data-del-type="dst-host" data-host="${escHtml(h)}" title="Retirer cet hôte">✕</button>
          </div>`;
        }).join('')}${visibleDstHosts.length > 50 ? `<div style="font-size:10px;color:var(--text2)">+${visibleDstHosts.length - 50} autres…</div>` : ''}</div>`;
      }
      return `<div class="drawer-multidst-row">
        <span class="drawer-multidst-subnet">${escHtml(s.subnet)}</span>
        <button class="btn-sm drawer-multidst-mode" data-si="${si}" style="font-size:9px;padding:2px 8px">${isSubnet ? '/24' : `/32 (${s.hosts?.length || 0}h)`}</button>
        ${isSubnet ? statusIcon : ''}
        ${isSubnet ? (s.addrFound ? `<span style="color:var(--success);font-size:10px" title="${escHtml(s.subnet)}">${escHtml(s.addrName)}</span>` : nameInput) : ''}
        <button class="btn-del-item" data-del-type="dst-subnet" data-si="${si}" title="Retirer ce subnet">✕</button>
      </div>${hostsHtml}`;
    }).join('');
    dstSection = `<div class="drawer-section">
      <div class="drawer-section-title">Destinations (${subs.length})</div>
      ${subRows}
      <div class="drawer-toggle-row" style="margin-top:8px">
        <button class="drawer-toggle-btn drawer-grp-toggle ${p._useDstGroup ? 'active' : ''}" data-type="dst">Grouper (addrgrp)</button>
        ${p._useDstGroup ? (p._dstAddrGrpFound
          ? `<span style="color:var(--success);font-size:11px" title="${escHtml(subs.map(s => s.subnet).join(', '))}">&#10003; ${escHtml(p._dstAddrName)}</span>`
          : `<input class="drawer-input drawer-grp-name" value="${escHtml(p._dstAddrName || '')}" placeholder="${escHtml(suggestedDstGrp)}" style="width:160px">`)
          : ''}
      </div>
    </div>`;
  } else {
    const dstAddrName = p._dstAddrName || a.dstAddr?.name || '';
    const dstFound = a.dstAddr?.found;
    let dstHostsHtml = '';
    if (dstHosts.length > 0 && dstMode === 'hosts') {
      const dstFoundSet = new Set(p._dstHostsFound || []);
      const visibleDstHostsSingle = dstHosts.filter(h => !p._excludedDstHosts?.has(h));
      dstHostsHtml = `<div class="drawer-host-list">${visibleDstHostsSingle.slice(0, 80).map(h => {
        const name = (p._dstHostNames || {})[h] || `FF_HOST_${h.replace(/\./g,'_')}`;
        const hostFound = dstFoundSet.has(h);
        return `<div class="drawer-host-row">
          <span class="drawer-host-ip">${escHtml(h)}</span>
          ${hostFound
            ? `<span style="color:var(--success);font-size:10px" title="${escHtml(h)}/32">&#10003; ${escHtml(name)}</span>`
            : `<input class="drawer-host-input" data-type="dst" data-host="${escHtml(h)}" value="${escHtml(inputVal(p._dstHostNames?.[h], `FF_HOST_${h.replace(/\./g,'_')}`))}" placeholder="${escHtml(name)}">`}
          <button class="btn-del-item" data-del-type="dst-host" data-host="${escHtml(h)}" title="Retirer cet hôte">✕</button>
        </div>`;
      }).join('')}</div>`;
    }
    dstSection = `<div class="drawer-section">
      <div class="drawer-section-title">Destination</div>
      <div class="drawer-field">
        <span class="drawer-field-label">Target</span>
        <span class="drawer-field-value">${escHtml(p.dstTarget || '—')}</span>
      </div>
      ${p.dstType === 'private' ? `<div class="drawer-toggle-row">
        <span style="font-size:11px;color:var(--text2)">Mode :</span>
        <button class="drawer-toggle-btn drawer-mode-btn ${dstMode==='subnet'?'active':''}" data-type="dst" data-mode="subnet">/24 subnet</button>
        <button class="drawer-toggle-btn drawer-mode-btn ${dstMode==='hosts'?'active':''} ${dstHosts.length<1?'disabled':''}" data-type="dst" data-mode="hosts">/32 hôtes (${dstHosts.length})</button>
      </div>` : ''}
      ${dstMode === 'subnet' ? `<div class="drawer-field">
        <span class="drawer-field-label">Objet addr</span>
        ${dstFound ? `<span class="drawer-field-value" style="color:var(--success)" title="${escHtml(a.dstAddr?.cidr || p.dstTarget || '')}">&#10003; ${escHtml(dstAddrName)}${badgeHtml('config')}</span>`
          : `<input class="drawer-input drawer-dst-name" value="${escHtml(inputVal(dstAddrName, a.dstAddr?.suggestedName || suggestAddrNameFE(p.dstTarget)))}" placeholder="${escHtml(dstAddrName || 'FF_...')}">${badgeHtml('auto')}`}
      </div>` : ''}
      ${dstHostsHtml}
    </div>`;
  }

  // Services
  const svcList = a.services || [];
  if (!p._selectedSvcKeys) p._selectedSvcKeys = new Set();
  const selKeys = p._selectedSvcKeys;
  // Compute merge bar state
  const getSvcPortProto = s => { const m = s.label?.match(/^(TCP|UDP)\/(\d+)$/i); return m ? { port: parseInt(m[2],10), proto: m[1].toUpperCase() } : { port: s.port, proto: (s.proto||'').toUpperCase() }; };
  const selectableSvcs = svcList.filter(s => { if (s.found) return false; const m = s.label?.match(/^(TCP|UDP)\/(\d+)$/i); return m || (!s.isNamed && s.port); });
  const selectedSvcs = selectableSvcs.filter(s => { const { port, proto } = getSvcPortProto(s); return selKeys.has(`${port}/${proto}`); });
  const canMerge = selectedSvcs.length >= 2 && new Set(selectedSvcs.map(s => getSvcPortProto(s).proto)).size === 1;
  const mergeProto = canMerge ? getSvcPortProto(selectedSvcs[0]).proto : '';
  const mergePorts = canMerge ? selectedSvcs.map(s => getSvcPortProto(s).port).sort((a, b) => a - b) : [];
  const mergeRangeSuggestion = canMerge ? `${mergePorts[0]}-${mergePorts[mergePorts.length - 1]}` : '';
  const mergeName = p._mergedSvcName || (canMerge ? `FF_SVC_${mergeProto}_MULTI` : '');
  const mergeMode = p._mergeMode || 'list';
  const mergeBar = canMerge ? `
    <div class="svc-merge-bar" style="background:var(--bg3);border-radius:6px;padding:8px;margin-top:8px;display:flex;flex-wrap:wrap;gap:6px;align-items:center">
      <span style="font-size:11px;color:var(--text2)">${selectedSvcs.length} ports ${mergeProto} sélectionnés</span>
      <input class="drawer-input svc-merge-name" value="${escHtml(mergeName)}" placeholder="FF_SVC_${mergeProto}_MULTI" style="width:160px;font-size:11px">
      <button class="btn-sm svc-merge-type ${mergeMode==='list'?'active':''}" data-mode="list" style="font-size:10px">Ports individ.</button>
      <button class="btn-sm svc-merge-type ${mergeMode==='range'?'active':''}" data-mode="range" style="font-size:10px">Range</button>
      ${mergeMode === 'range' ? `<input class="drawer-input svc-merge-range" value="${escHtml(p._mergeRange || mergeRangeSuggestion)}" placeholder="${mergeRangeSuggestion}" style="width:100px;font-size:11px">` : `<span style="font-size:10px;color:var(--text2)">${mergePorts.join(', ')}</span>`}
      <button class="btn-sm btn-accent svc-do-merge" style="font-size:10px">Fusionner</button>
    </div>` : '';
  const stripPd = n => (n || '').replace(/PREDEFINED$/i, '');
  const svcsHtml = svcList.map(svc => {
    if (svc.found) {
      const dispLabel = stripPd(svc.label || svc.name);
      const dispName  = stripPd(svc.name);
      const rawKey    = svc.label || svc.name; // keep raw for data-svc-key (CLI needs full name)
      return `<div class="drawer-field" title="${escHtml(svc.portHint || '')}"><span class="drawer-field-label">${escHtml(dispLabel)}</span><span class="drawer-field-value" style="color:var(--success)">&#10003; ${escHtml(dispName)}${badgeHtml(svc.source === 'predefined' ? 'predefined' : 'config')}</span><button class="btn-del-item" data-del-type="svc" data-svc-key="${escHtml(rawKey)}" title="Retirer ce service de la policy">✕</button></div>`;
    }
    // Detect port-notation labels like "UDP/11436" from FortiGate logs
    const _pnm = svc.label?.match(/^(TCP|UDP)\/(\d+)$/i);
    const svcProto = _pnm ? _pnm[1].toUpperCase() : (svc.proto || '').toUpperCase();
    const svcPort  = _pnm ? parseInt(_pnm[2], 10) : svc.port;
    const svcKey = _pnm ? `${svcPort}/${svcProto}` : (svc.isNamed ? `label:${svc.label}` : `${svc.port}/${svc.proto}`);
    const isSelectable = !svc.found && (_pnm || (!svc.isNamed && svc.port));
    const isSelected = selKeys.has(svcKey);
    const svcAutoName = _pnm ? `FF_SVC_${svcPort}_${svcProto}` : (svc.isNamed ? svc.label : `FF_SVC_${svc.port}_${svc.proto}`);
    const svcDefaultName = svc.suggestedName || svcAutoName;
    // Show inline port hint only when it's precise (predefined/custom/port-notation resolved)
    // — never when it's the raw multi-port "observé" fallback (misleading for named services)
    const precisHint = svc.portHint && !svc.portHint.includes('observé');
    const hintTitle = svc.portHint || '(nom issu des logs FortiGate — port/protocol non résolu dans la config chargée)';
    const hintText = precisHint
      ? `<span style="font-size:9px;color:var(--text2);margin-left:4px" title="${escHtml(hintTitle)}">${escHtml(svc.portHint)}</span>`
      : '';
    return `<div class="drawer-field${isSelectable ? ' svc-selectable' : ''}" data-svc-key="${escHtml(svcKey)}" style="cursor:${isSelectable?'pointer':'default'};${isSelected ? 'background:rgba(99,179,237,0.10);border-radius:4px;outline:1px solid var(--accent);' : ''}">
      ${isSelectable ? `<input type="checkbox" class="svc-sel-chk" ${isSelected?'checked':''} style="margin-right:4px;cursor:pointer;flex-shrink:0">` : ''}
      <span class="drawer-field-label" title="${escHtml(hintTitle)}">${escHtml(svc.label || `${svc.port}/${svc.proto}`)}</span>
      ${svc.isNamed && !_pnm ? hintText : ''}
      <input class="drawer-input drawer-svc-name" data-svc-key="${escHtml(svcKey)}" value="${escHtml(inputVal(svc.suggestedName, svcAutoName))}" placeholder="${escHtml(svcDefaultName)}" onclick="event.stopPropagation()">${badgeHtml('auto')}
      <button class="btn-del-item" data-del-type="svc" data-svc-key="${escHtml(svcKey)}" title="Retirer ce service de la policy">✕</button>
    </div>`;
  }).join('');

  // Propagation banner (shown after blur on svc name when other policies have same port/proto)
  const pp = p._propagatePending;
  const propagateBanner = pp ? `<div class="svc-propagate-banner">
    <span>${pp.count} autre${pp.count>1?'s':''} policy${pp.count>1?'s':''} ${pp.count>1?'ont':'a'} <code style="font-family:var(--mono)">${escHtml(pp.label || `${pp.proto}/${pp.port}`)}</code>${pp.portHint ? ` <span style="font-size:9px;color:var(--text2)">(${escHtml(pp.portHint)})</span>` : ''} — Appliquer <strong>${escHtml(pp.newName)}</strong> à toutes ?</span>
    <button class="btn-sm btn-accent svc-prop-yes">Oui</button>
    <button class="btn-sm svc-prop-no">Non</button>
  </div>` : '';

  const body = document.getElementById('drawer-body');
  body.innerHTML = `
    <div class="drawer-section">
      <div class="drawer-section-title">General</div>
      <div class="drawer-field"><span class="drawer-field-label">Direction</span><span class="drawer-field-value">${p._isWan ? '<span class="dir-badge wan">WAN</span>' : '<span class="dir-badge lan">LAN</span>'}</span></div>
      <div class="drawer-field"><span class="drawer-field-label">Policy IDs</span><span class="drawer-field-value">${(p.policyIds||[]).join(', ') || '—'}</span></div>
      <div class="drawer-field"><span class="drawer-field-label">Sessions</span><span class="drawer-field-value">${fmtNum(p.sessions||0)}</span></div>
      <div class="drawer-field"><span class="drawer-field-label">NAT</span><label style="display:flex;align-items:center;gap:6px"><input type="checkbox" class="drawer-nat" ${p._nat ? 'checked' : ''}> <span style="font-size:11px;color:var(--text2)">Activer le NAT</span></label></div>
      <div class="drawer-field"><span class="drawer-field-label">Nom policy</span><input class="drawer-input drawer-policy-name" value="${escHtml(p._policyName || '')}" placeholder="FF_POLICY_..."></div>
    </div>
    ${srcSection}
    ${dstSection}
    <div class="drawer-section">
      <div class="drawer-section-title">Interfaces destination</div>
      <div class="drawer-field"><span class="drawer-field-label">Interface</span><select class="drawer-input drawer-dstintf">${ifOptsDst}</select></div>
    </div>
    ${svcList.length ? `<div class="drawer-section"><div class="drawer-section-title">Services (${svcList.length})${selectableSvcs.length > 1 ? `<label style="font-size:10px;color:var(--text2);font-weight:400;margin-left:8px;display:inline-flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" class="svc-sel-all" ${selectedSvcs.length === selectableSvcs.length ? 'checked' : ''} style="cursor:pointer;margin:0"> Tout sélectionner</label>` : ''}</div>${svcsHtml}${mergeBar}${propagateBanner}</div>` : ''}
  `;
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
  try {
    const subViews = { flows, matrix, groups, ports };
    await (subViews[sub] || flows)();
  } finally { _renderTarget = null; }
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
  try {
    const subViews = { policies, consilpolicies, denied };
    await (subViews[sub] || policies)();
  } finally { _renderTarget = null; }
}

// ═══════════════════════════════════════════════════════════════
// View: Deploy
// ═══════════════════════════════════════════════════════════════

// ── F8: Predefined tags ──
const POLICY_TAGS = ['critique', 'temporaire', 'a valider', 'segmentation'];
const AUTO32_THRESHOLD = 3; // auto-activer /32 si ≤ N hôtes réels

async function deploy() {
  // Reset delegation flag — deploy() replaces the entire DOM tree
  resetDeployTableWiring();

  // Auto-advance wizard based on state
  if (deployState.fortiConfig && deployState.wizardStep < 2) deployState.wizardStep = 2;
  if (deployState.analyzed && deployState.wizardStep < 4) deployState.wizardStep = 4;
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
          <span class="wizard-num">2</span> Routes
        </div>
        <div class="wizard-connector ${ws > 2 ? 'done' : ''}"></div>
        <div class="wizard-step-indicator ${ws >= 3 ? 'active' : ''} ${ws > 3 ? 'done' : ''}" data-step="3">
          <span class="wizard-num">3</span> Interfaces
        </div>
        <div class="wizard-connector ${ws > 3 ? 'done' : ''}"></div>
        <div class="wizard-step-indicator ${ws >= 4 ? 'active' : ''}" data-step="4">
          <span class="wizard-num">4</span> Policies
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
        ${deployState.fortiConfig ? `<div class="wizard-nav"><span></span><button class="btn-accent wizard-next" data-to="2">Suivant ›</button></div>` : ''}
      </div>

      <!-- Step 2: routing table -->
      <div class="deploy-step" id="deploy-step2" ${ws !== 2 ? 'style="display:none"' : ''}>
        <div class="deploy-step-header">
          <span class="deploy-step-num">2</span>
          Table de routage réelle
        </div>
        <div class="deploy-step-body">
          ${renderDynamicRoutesPanel()}
        </div>
        <div class="wizard-nav">
          <button class="btn-sm wizard-prev" data-to="1">← Précédent</button>
          <button class="btn-accent wizard-next" data-to="3">Suivant ›</button>
        </div>
      </div>

      <!-- Step 3: interfaces -->
      <div class="deploy-step" id="deploy-step3" ${ws !== 3 ? 'style="display:none"' : ''}>
        <div class="deploy-step-header" id="deploy-iface-toggle" style="cursor:pointer">
          <span class="deploy-step-num">3</span>
          Interfaces &amp; Zones
          <span id="deploy-iface-arrow" style="margin-left:auto;font-size:11px">▾</span>
        </div>
        <div class="deploy-step-body" id="deploy-iface-body">
          ${deployState.interfaces ? renderInterfaces(deployState.interfaces) : ''}
        </div>
        <div class="wizard-nav">
          <button class="btn-sm wizard-prev" data-to="2">← Précédent</button>
          <button class="btn-accent wizard-next" data-to="4">Suivant ›</button>
        </div>
      </div>

      <!-- Step 4: policy table -->
      <div class="deploy-step" id="deploy-step4" ${ws !== 4 ? 'style="display:none"' : ''}>
        <div class="deploy-step-header">
          <span class="deploy-step-num">4</span>
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
            <button class="btn-accent" id="btn-analyze">⚡ Analyser les policies</button>
          </div>
        </div>
        <div class="deploy-toolbar" id="deploy-merge-bar" style="display:none">
          <span id="deploy-merge-info" style="font-size:11px;color:var(--text2)"></span>
          <div class="dropdown-wrap">
            <button class="btn-sm dropdown-trigger">⚡ Fusion ▾</button>
            <div class="dropdown-menu">
              <div class="dropdown-item" data-merge="internet">Fusionner Internet</div>
              <div class="dropdown-item" data-merge="lan">Fusionner LAN</div>
              <div class="dropdown-item" data-merge="all">Tout fusionner</div>
              <div class="dropdown-item" data-merge="policy">Fusionner par policy</div>
              <div class="dropdown-item" data-merge="service">Fusionner par service</div>
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
          <span class="toolbar-sep"></span>
          <span style="margin-left:auto"></span>
          <input type="text" id="deploy-search" class="deploy-search-input" placeholder="Rechercher (IP, subnet, service, policy...)" value="${escHtml(deployState.searchFilter || '')}" title="Filtrer les policies par texte libre">
        </div>
        <div class="missing-bar" id="deploy-missing-bar" style="display:none">
          <span id="deploy-missing-text"></span>
          <span style="margin-left:auto;font-size:10px;opacity:0.7">Cliquez sur une policy pour éditer</span>
        </div>
        <div class="deploy-legend" id="deploy-legend" style="display:none">
          <div class="deploy-legend-item"><span class="deploy-legend-dot found"></span> Objet existant</div>
          <div class="deploy-legend-item"><span class="deploy-legend-dot missing"></span> A créer</div>
          <div class="deploy-legend-item"><span class="deploy-legend-dot auto"></span> Auto-détecté</div>
          <span style="margin-left:auto;font-size:10px;color:var(--text2)">Cliquez sur une ligne pour la personnaliser</span>
        </div>
        <div class="deploy-step-body" id="deploy-policy-body">
          <div class="empty-state" style="padding:24px">Cliquez sur <strong>Analyser les policies</strong> pour commencer</div>
        </div>
        <div class="deploy-step-footer" id="deploy-step4-footer" style="display:none">
          <div id="security-profiles-bar" style="display:none;margin-bottom:10px;padding:8px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);font-size:11px">
            <span style="font-weight:600;margin-right:12px">Profils de sécurité :</span>
            <select id="sp-av" class="deploy-select" style="font-size:10px;max-width:140px" title="Antivirus"><option value="">— AV —</option></select>
            <select id="sp-wf" class="deploy-select" style="font-size:10px;max-width:140px" title="Web filter"><option value="">— WebFilter —</option></select>
            <select id="sp-ips" class="deploy-select" style="font-size:10px;max-width:140px" title="IPS"><option value="">— IPS —</option></select>
            <select id="sp-ssl" class="deploy-select" style="font-size:10px;max-width:140px" title="SSL/SSH"><option value="">— SSL/SSH —</option></select>
          </div>
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
              <button class="btn-sm" id="btn-diff-toggle" style="display:none">⊕ Diff</button>
              <button class="btn-sm" id="btn-cli-toggle" style="margin-left:auto">▾ Réduire</button>
            </div>
            <textarea id="deploy-cli-pre" class="deploy-cli-pre" spellcheck="false" style="width:100%;min-height:300px;resize:vertical;font-family:monospace;white-space:pre;overflow-x:auto;tab-size:2"></textarea>
            <div id="deploy-diff-wrap" style="display:none"></div>
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

  // Fold/unfold interface category groups + zones section (délégation)
  el('deploy-iface-body')?.addEventListener('click', e => {
    // Groupes LAN/WAN/VPN (tr headers)
    const hdr = e.target.closest('tr.iface-group-header[data-group-key]');
    if (hdr) {
      const key = hdr.dataset.groupKey;
      ifaceGroupCollapsed[key] = !ifaceGroupCollapsed[key];
      const collapsed = ifaceGroupCollapsed[key];
      hdr.querySelector('.iface-group-arrow').textContent = collapsed ? '▸' : '▾';
      const tbody = hdr.closest('tbody');
      tbody.querySelectorAll(`tr.iface-data-row[data-group-key="${key}"]`).forEach(r => {
        r.style.display = collapsed ? 'none' : '';
      });
      return;
    }
    // Sections (Zones, SD-WAN…)
    const sec = e.target.closest('[data-section-key]');
    if (sec) {
      const key = sec.dataset.sectionKey;
      ifaceGroupCollapsed[key] = !ifaceGroupCollapsed[key];
      const collapsed = ifaceGroupCollapsed[key];
      sec.querySelector('.iface-group-arrow').textContent = collapsed ? '▸' : '▾';
      const target = document.getElementById(sec.dataset.sectionTarget);
      if (target) target.style.display = collapsed ? 'none' : '';
    }
  });

  // SD-WAN priority radio + interface type select (délégation)
  el('deploy-iface-body')?.addEventListener('change', e => {
    if (e.target.name === 'sdwan-priority') {
      deployState.selectedSdwan = e.target.value;
      return;
    }
    const sel = e.target.closest('select[data-iface-idx]');
    if (sel) {
      const idx   = +sel.dataset.ifaceIdx;
      const iface = deployState.interfaces?.interfaces?.[idx];
      if (!iface) return;
      iface.isWan    = sel.value === 'wan';
      iface.isTunnel = sel.value === 'vpn';
      refreshIfacePanel();
    }
  });

  // Interface filter
  el('deploy-iface-body')?.addEventListener('input', e => {
    if (e.target.id !== 'iface-search') return;
    const q = e.target.value.toLowerCase().trim();
    const tbody = document.getElementById('iface-tbody');
    if (!tbody) return;
    let lastGroupHdr = null;
    let groupHasVisible = false;
    for (const row of tbody.querySelectorAll('tr')) {
      if (row.classList.contains('iface-group-header')) {
        if (lastGroupHdr) lastGroupHdr.style.display = groupHasVisible ? '' : 'none';
        lastGroupHdr = row;
        groupHasVisible = false;
      } else if (row.classList.contains('iface-data-row')) {
        const name  = row.dataset.name  || '';
        const alias = row.dataset.alias || '';
        const match = !q || name.includes(q) || alias.includes(q);
        row.style.display = match ? '' : 'none';
        if (match) groupHasVisible = true;
      }
    }
    if (lastGroupHdr) lastGroupHdr.style.display = groupHasVisible ? '' : 'none';
  });

  // ── Dynamic routes copy cmd (wired once) ──
  if (!window._dynCopyWired) {
    window._dynCopyWired = true;
    document.addEventListener('click', e => {
      const btn = e.target.closest('.dyn-copy-cmd');
      if (!btn) return;
      const cmd = btn.dataset.cmd;
      navigator.clipboard.writeText(cmd).then(() => {
        const orig = btn.textContent;
        btn.textContent = '✓ Copié';
        btn.disabled = true;
        setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 1500);
      });
    });
  }

  // ── Dynamic routes inject (wired once) ──
  if (!window._dynRouteWired) {
    window._dynRouteWired = true;
    document.addEventListener('click', async e => {
    const btn = e.target.closest('.dyn-route-inject');
    if (!btn) return;
    const proto = btn.dataset.proto;
    const ta = btn.closest('.dyn-route-block')?.querySelector('.dyn-route-ta');
    const text = ta?.value?.trim();
    if (!text) { alert('Collez le output CLI avant d\'injecter.'); return; }

    btn.disabled = true;
    btn.textContent = '⏳ Injection…';
    try {
      const r = await fetch(`/api/deploy/dynamic-routes?session=${state.session}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ protocol: proto, cliOutput: text }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
      if (!deployState.dynRouteStatus) deployState.dynRouteStatus = {};
      deployState.dynRouteStatus[proto] = { added: data.added, total: data.total };
      // Re-fetch interfaces : la table injectée peut avoir corrigé isWan/LAN
      if (proto === 'all') {
        const ir = await fetch(`/api/deploy/interfaces?session=${state.session}`);
        if (ir.ok) deployState.interfaces = await ir.json();
      }
    } catch (err) {
      if (!deployState.dynRouteStatus) deployState.dynRouteStatus = {};
      deployState.dynRouteStatus[proto] = { error: err.message };
    } finally {
      btn.disabled = false;
      btn.textContent = 'Appliquer la table de routage';
      // Re-render only the panel badge (avoid full redeploy)
      const panel = document.querySelector('.dyn-routes-panel');
      if (panel) panel.outerHTML = renderDynamicRoutesPanel();
      // Re-render interfaces panel si visible
      const ifPanel = document.querySelector('#deploy-step3 .interfaces-panel, .iface-panel');
      if (ifPanel) { const fresh = renderInterfaces(deployState.interfaces); if (fresh) ifPanel.outerHTML = fresh; }
    }
  });
  } // end _dynRouteWired

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

  // Close dropdowns on outside click (guard: single listener)
  if (!window._deployDropdownWired) {
    window._deployDropdownWired = true;
    document.addEventListener('click', () => {
      document.querySelectorAll('.dropdown-wrap.open').forEach(w => w.classList.remove('open'));
    });
  }

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
      if (step === 1 || (step === 2 && deployState.fortiConfig) || (step === 3 && deployState.fortiConfig) || (step === 4 && deployState.fortiConfig)) {
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

  // (missing objects bar is now info-only — no modal, edit via drawer)

  // Global /32 toggle (wired once — button persists in DOM)
  el('btn-32-global')?.addEventListener('click', () => {
    deployState.use32Global = !deployState.use32Global;
    if (deployState.analyzed) {
      for (const p of deployState.analyzed) {
        if ((p.srcHosts || []).length >= 1) p._use32Src = deployState.use32Global;
        if ((p.dstHosts || []).length >= 1) p._use32Dst = deployState.use32Global;
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
      if (pre)  pre.value = deployState.generatedCli;
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

// ─── Dynamic routes panel ────────────────────────────────────────────────────

function renderDynamicRoutesPanel() {
  if (!deployState.fortiConfig) return '';

  const st = (deployState.dynRouteStatus || {})['all'];

  const badge = st
    ? `<span class="dyn-route-badge ${st.error ? 'err' : 'ok'}">${
        st.error
          ? '✗ ' + st.error
          : `✓ Table remplacée — ${st.added} route(s) (${st.replaced ? 'remplacement complet' : 'injection'})`
      }</span>`
    : '';

  return `
  <div class="dyn-routes-panel">
    <div class="dyn-routes-title">🗺 Table de routage réelle</div>
    <div style="font-size:13px;color:var(--text2);margin-bottom:12px">
      Collez le output de la commande ci-dessous pour remplacer la table de routage parsée par la <strong>table réelle</strong> du FortiGate.
      Permet un mapping interfaces/WAN exact, incluant routes dynamiques et chemins actifs.
    </div>
    <div class="dyn-route-block">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <code style="font-size:13px;font-family:var(--mono);color:var(--text2)">FG# </code><strong style="font-size:13px;font-family:var(--mono);color:var(--text)">get router info routing-table all</strong>
        <button class="btn-sm dyn-copy-cmd" data-cmd="get router info routing-table all" title="Copier la commande" style="margin-left:4px">📋 Copier</button>
      </div>
      <textarea class="dyn-route-ta" data-proto="all" rows="6"
        placeholder="Collez ici le résultat de : get router info routing-table all"></textarea>
      <div style="display:flex;align-items:center;gap:10px;margin-top:6px">
        <button class="btn-sm dyn-route-inject" data-proto="all">Appliquer la table de routage</button>
        ${badge}
      </div>
    </div>
  </div>`;
}

function renderInterfaces({ interfaces, zones, sdwanMembers, sdwanZoneNames, sdwanEnabled, sdwanIntfName }) {
  // Build interface → zone names map
  const ifaceZoneMap = {};
  zones.forEach(z => z.members.forEach(m => {
    if (!ifaceZoneMap[m]) ifaceZoneMap[m] = [];
    ifaceZoneMap[m].push(z.name);
  }));

  // Group interfaces by type
  const groups = { lan: [], wan: [], vpn: [] };
  interfaces.forEach((iface, idx) => {
    const key = iface.isTunnel ? 'vpn' : (iface.isWan ? 'wan' : 'lan');
    groups[key].push({ iface, idx });
  });

  const groupMeta = {
    lan: { label: 'LAN',         color: 'var(--success)' },
    wan: { label: 'WAN',         color: 'var(--accent3)' },
    vpn: { label: 'VPN / Tunnels', color: 'var(--brand)' },
  };

  let ifaceRows = '';
  for (const key of ['lan', 'wan', 'vpn']) {
    const items = groups[key];
    if (!items.length) continue;
    const { label, color } = groupMeta[key];
    const collapsed = !!ifaceGroupCollapsed[key];
    ifaceRows += `<tr class="iface-group-header" data-group-key="${key}" style="cursor:pointer" title="Cliquer pour plier/déplier">
      <td colspan="5" style="color:${color}">
        <span class="iface-group-arrow">${collapsed ? '▸' : '▾'}</span> ${label} <span class="iface-group-count">${items.length}</span>
      </td>
    </tr>`;
    for (const { iface, idx } of items) {
      const zoneNames = ifaceZoneMap[iface.name] || [];
      const zoneBadges = zoneNames.map(z => `<span class="iface-zone-chip">${escHtml(z)}</span>`).join('');
      const cidrDisplay = (iface.cidr || iface.rawIp)
        ? escHtml(iface.cidr || iface.rawIp)
        : '<span class="iface-no-ip">no IP</span>';
      ifaceRows += `<tr class="iface-data-row" data-name="${escHtml(iface.name.toLowerCase())}" data-alias="${escHtml((iface.alias || '').toLowerCase())}" data-group-key="${key}"${collapsed ? ' style="display:none"' : ''}>
        <td class="mono">${escHtml(iface.name)}</td>
        <td class="mono iface-cidr-cell" style="color:var(--text2)">${cidrDisplay}</td>
        <td>
          <select class="deploy-itype-select ${key}" data-iface-idx="${idx}">
            <option value="lan"${key === 'lan' ? ' selected' : ''}>LAN</option>
            <option value="wan"${key === 'wan' ? ' selected' : ''}>WAN</option>
            <option value="vpn"${key === 'vpn' ? ' selected' : ''}>VPN</option>
          </select>
        </td>
        <td style="color:var(--text2);font-size:11px">${escHtml(iface.alias || '')}</td>
        <td>${zoneBadges}</td>
      </tr>`;
    }
  }

  // Zones section with type badge
  const getZoneTypeKey = (z) => {
    if (!z.members.length) return 'unknown';
    const keys = z.members.map(m => {
      const iface = interfaces.find(i => i.name === m);
      if (!iface) return null;
      return iface.isTunnel ? 'vpn' : (iface.isWan ? 'wan' : 'lan');
    }).filter(Boolean);
    const uniq = [...new Set(keys)];
    if (!uniq.length) {
      // Fallback : membres introuvables (ex: tunnels status=down filtrés) — inférer depuis le nom de zone
      const zn = z.name.toUpperCase();
      if (/VPN|TUNNEL|TUN[^A-Z]|IPSEC|GRE/.test(zn)) return 'vpn';
      if (/WAN|INTERNET|EXTERNAL|EXT[^E]/.test(zn))   return 'wan';
      if (/LAN|INTERNAL|INT[^E]|DMZ|LOCAL/.test(zn))  return 'lan';
      return 'unknown';
    }
    return uniq.length === 1 ? uniq[0] : 'mixed';
  };

  const zoneTypeLabel = { lan: 'LAN', wan: 'WAN', vpn: 'VPN', mixed: 'MIXED', unknown: '?' };
  const zoneRows = zones.map(z => {
    const tk = getZoneTypeKey(z);
    const badge = `<span class="deploy-itype-toggle ${tk === 'unknown' ? '' : tk}" style="pointer-events:none">${zoneTypeLabel[tk]}</span>`;
    return `<tr>
      <td class="mono">${escHtml(z.name)}</td>
      <td class="mono iface-members-cell" style="color:var(--text2)" title="${z.members.map(escHtml).join(', ')}">${z.members.map(escHtml).join(', ')}</td>
      <td>${badge}</td>
      <td colspan="2"></td>
    </tr>`;
  }).join('');

  // SD-WAN section
  let sdwanSection = '';
  if (sdwanEnabled) {
    const zoneOptions = sdwanZoneNames && sdwanZoneNames.length > 0
      ? sdwanZoneNames
      : [sdwanIntfName || 'virtual-wan-link'];
    const currentSel = deployState.selectedSdwan || zoneOptions[0];
    const radios = zoneOptions.map(o => `
      <label style="display:flex;align-items:center;gap:6px;cursor:pointer;white-space:nowrap">
        <input type="radio" name="sdwan-priority" value="${escHtml(o)}" ${currentSel === o ? 'checked' : ''}>
        <span class="mono" style="font-size:12px">${escHtml(o)}</span>
      </label>`).join('');
    sdwanSection = `
      <div class="deploy-sdwan-panel">
        <div style="font-size:11px;font-weight:600;color:var(--accent2);margin-bottom:6px">
          ⚡ SD-WAN — Interface de sortie pour les policies WAN
        </div>
        <div style="font-size:11px;color:var(--text2);margin-bottom:8px">
          Sélectionnez l'interface à utiliser comme dstintf pour les règles Internet :
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:10px">${radios}</div>
      </div>`;
  } else if (sdwanMembers.length > 0) {
    sdwanSection = `<div style="color:var(--accent2);font-size:11px;margin-top:8px">SD-WAN: ${sdwanMembers.map(escHtml).join(', ')}</div>`;
  }

  const zonesCollapsed = !!ifaceGroupCollapsed['zones'];
  const zonesSection = zones.length > 0 ? `
    <div class="iface-section-title" data-section-key="zones" data-section-target="iface-zones-table" style="cursor:pointer" title="Cliquer pour plier/déplier">
      <span class="iface-group-arrow">${zonesCollapsed ? '▸' : '▾'}</span> Zones <span class="iface-group-count">${zones.length}</span>
    </div>
    <table class="deploy-iface-table" id="iface-zones-table"${zonesCollapsed ? ' style="display:none"' : ''}>
      <thead><tr><th>Zone</th><th>Membres</th><th>Type</th><th colspan="2"></th></tr></thead>
      <tbody>${zoneRows}</tbody>
    </table>` : '';

  return `
    <div class="iface-toolbar">
      <input id="iface-search" type="text" placeholder="Filtrer interfaces…" class="iface-search-input">
      <span style="font-size:11px;color:var(--text2)">Cliquer l'entête pour plier/déplier • Changer le type via le menu déroulant</span>
    </div>
    <table class="deploy-iface-table" id="iface-main-table">
      <thead><tr><th>Interface</th><th>IP/CIDR</th><th>Type</th><th>Alias</th><th>Zone</th></tr></thead>
      <tbody id="iface-tbody">${ifaceRows}</tbody>
    </table>
    ${zonesSection}
    ${sdwanSection}`;
}

// Helper: re-render the interfaces panel (used by type select + upload)
function refreshIfacePanel() {
  const body = el('deploy-iface-body');
  if (body) body['innerHTML'] = renderInterfaces(deployState.interfaces);
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
      _mergedFrom:  group.map(p => ({ srcSubnet: p.srcSubnet, dstTarget: p.dstTarget, analysis: { services: p.analysis?.services } })),
      _srcAddrName: base._srcAddrName || '',
      _dstAddrName: 'all',
      _policyName:  '',
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
      _mergedFrom:  group.map(p => ({ srcSubnet: p.srcSubnet, dstTarget: p.dstTarget, analysis: { services: p.analysis?.services } })),
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

// Cellule dstTarget — simplified: compact summary, details in drawer
function dstTargetCell(p, idx) {
  // ── Multi-dst policy ──
  if (p._isMultiDst && p._multiDstSubnets?.length) {
    const subs = p._multiDstSubnets;
    const firstTwo = subs.slice(0, 2).map(s => escHtml(s.subnet));
    const more = subs.length > 2 ? ` <span class="dst-count-badge">+${subs.length - 2}</span>` : '';
    return `<span class="mono" style="font-size:10px">${firstTwo.join(', ')}${more}</span>`;
  }

  const label = p.dstTarget === 'all' ? 'all (internet)' : p.dstTarget;
  const ips   = p._dstIPs;
  const dstHosts = p.dstHosts || [];
  const dstMode  = p._dstMode || (p._use32Dst ? 'hosts' : 'subnet');

  let modeBadge = '';
  if (p.dstType === 'private' && dstHosts.length > 0) {
    modeBadge = dstMode === 'hosts'
      ? ` <span class="dst-count-badge" title="${dstHosts.length} hôtes /32">/32 · ${dstHosts.length}h</span>`
      : '';
  }

  const ipsBadge = ips && ips.length > 0 ? ` <span class="dst-count-badge">${ips.length} IPs</span>` : '';

  return `<span class="mono">${escHtml(label)}</span>${modeBadge}${ipsBadge}`;
}

// Legacy dstTargetCell for contexts that still need full inline controls
function dstTargetCellFull(p, idx) {
  if (p._isMultiDst && p._multiDstSubnets?.length) {
    const subs = p._multiDstSubnets;
    const rows = subs.map((s, si) => {
      const badge = s.addrFound
        ? `<span class="match-ok" style="font-size:9px" title="${escHtml(s.subnet)}">&#10003; ${escHtml(s.addrName)}</span>`
        : `<span style="color:var(--warn);font-size:9px">+ ${escHtml(s.addrName)}</span>`;
      const modeBtn = `<button class="btn-sm btn-dst-subnet-toggle" data-idx="${idx}" data-si="${si}"
        title="${s.useSubnet ? 'Mode /24' : 'Mode /32'}"
        style="font-size:9px;padding:1px 5px">${s.useSubnet ? '/24' : `/32 (${s.hosts.length}h)`}</button>`;
      return `<div style="display:flex;align-items:center;gap:4px;padding:2px 0;border-bottom:1px solid var(--border)">
        <span class="mono" style="font-size:10px;min-width:120px">${escHtml(s.subnet)}</span>
        ${modeBtn}${badge}
      </div>`;
    }).join('');
    return `<div style="max-height:200px;overflow-y:auto">${rows}</div>`;
  }
  const label = p.dstTarget === 'all' ? 'all (internet)' : p.dstTarget;
  return `<span class="mono">${escHtml(label)}</span>`;
}

// Render one host row inside a /32 popup: green ✓ if object exists, editable input otherwise
function buildHostRow(h, nameMap, idx, type) {
  const existingName = (nameMap || {})[h];
  const defaultName  = `FF_HOST_${h.replace(/\./g, '_')}`;
  const ipSpan = `<span class="mono" style="font-size:10px;min-width:105px;display:inline-block;color:var(--text2)">${escHtml(h)}</span>`;
  if (existingName) {
    return `<div style="display:flex;align-items:center;gap:6px;padding:2px 0">${ipSpan}<span class="match-ok" style="font-size:9px" title="${escHtml(h)}/32">✓ ${escHtml(existingName)}</span></div>`;
  }
  return `<div style="display:flex;align-items:center;gap:6px;padding:2px 0">${ipSpan}<input class="host-name-input deploy-name-input" data-idx="${idx}" data-type="${type}" data-host="${escHtml(h)}" value="${escHtml(defaultName)}" style="font-size:10px;width:180px;padding:2px 6px" placeholder="FF_HOST_…"></div>`;
}

// Clé de service normalisée pour comparer les ensembles de services entre policies
function serviceSetKey(p) {
  return (p.analysis?.services || [])
    .map(s => s.label || `${s.port}/${s.proto}`)
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

    // ── Pré-pass : grouper par srcSubnet|srcIntf|dstIntf pour détecter multi-dst ──
    // Avant même le subgrouping par services, on groupe par interface pair.
    // Cela évite que des services légèrement différents empêchent la fusion multi-dst.
    const ifaceGroups = new Map();
    for (const p of group) {
      const src = p._srcintf || p.srcintf || '';
      const dst = p._dstintf || p.dstintf || '';
      const ik  = `${p.srcSubnet}|${src}|${dst}`;
      if (!ifaceGroups.has(ik)) ifaceGroups.set(ik, []);
      ifaceGroups.get(ik).push(p);
    }

    // Pour chaque groupe interface-pair avec plusieurs destinations → multi-dst
    const remainingForSvcMerge = [];
    for (const [, ifGroup] of ifaceGroups) {
      const dsts = [...new Set(ifGroup.map(p => p.dstTarget).filter(Boolean))];
      if (dsts.length > 1) {
        // Plusieurs destinations → multi-dst (union services)
        const base          = ifGroup[0];
        const isWan         = ifGroup.some(p => p.dstType === 'public' || p.dstTarget === 'all' || p._isWan);
        const allServices   = mergeServices(ifGroup);
        const totalSessions = ifGroup.reduce((s, p) => s + (p.sessions || 0), 0);
        const srcSubnets    = [...new Set(ifGroup.map(p => p.srcSubnet).filter(Boolean))].sort();
        const allPolicyIds  = [...new Set(ifGroup.flatMap(p => p.policyIds || []))].sort((a, b) => Number(a) - Number(b));
        const allSrcHosts   = [...new Set(ifGroup.flatMap(p => p.srcHosts || []))].sort();
        const DST_SUBNET_THRESHOLD = 5;
        const dstSubnets = dsts.map(subnet => {
          const subnetPols = ifGroup.filter(p => p.dstTarget === subnet);
          const hosts      = [...new Set(subnetPols.flatMap(p => p.dstHosts || []))].sort();
          const dstAddr    = subnetPols.find(p => p.analysis?.dstAddr?.found)?.analysis?.dstAddr
                          || subnetPols[0]?.analysis?.dstAddr;
          return { subnet, hosts, useSubnet: hosts.length >= DST_SUBNET_THRESHOLD,
            addrName: dstAddr?.found ? dstAddr.name : '', addrFound: !!(dstAddr?.found) };
        });
        // Fusionner _srcHostNames/_dstHostNames et _hostsFound de TOUTES les policies du groupe
        const mergedDstHostNames = {};
        const mergedSrcHostNames1 = {};
        const mergedSrcHostsFound = new Set();
        const mergedDstHostsFound = new Set();
        for (const p of ifGroup) {
          Object.assign(mergedSrcHostNames1, p._srcHostNames || {});
          Object.assign(mergedDstHostNames, p._dstHostNames || {});
          (p._srcHostsFound || []).forEach(h => mergedSrcHostsFound.add(h));
          (p._dstHostsFound || []).forEach(h => mergedDstHostsFound.add(h));
        }
        const allDstHosts = [...new Set(ifGroup.flatMap(p => p.dstHosts || []))].sort();
        // Chercher un groupe d'adresses existant pour les destinations
        let existingDstGrp1 = null;
        if (dstSubnets.length > 1 && deployState.addrGroups) {
          const dstAddrNames = dstSubnets.filter(s => s.addrFound).map(s => s.addrName);
          if (dstAddrNames.length === dstSubnets.length) {
            const memberNames = new Set(dstAddrNames);
            for (const [grpName, grp] of Object.entries(deployState.addrGroups)) {
              const grpMembers = new Set(grp.members);
              if (grpMembers.size === memberNames.size && [...memberNames].every(m => grpMembers.has(m))) {
                existingDstGrp1 = grpName; break;
              }
            }
          }
        }
        merged.push({
          ...base, srcSubnet: srcSubnets[0], srcSubnets,
          dstTarget: dsts[0], dstTargets: dsts,
          _multiDstSubnets: dstSubnets, _isMultiDst: true,
          dstType: base.dstType, sessions: totalSessions,
          serviceDesc: allServices.map(s => s.label).join(', '),
          policyIds: allPolicyIds, srcHosts: allSrcHosts, dstHosts: allDstHosts,
          _use32Src: allSrcHosts.length >= 1 && allSrcHosts.length <= AUTO32_THRESHOLD,
          _use32Dst: false, _mergedCount: ifGroup.length, _isWan: isWan, _nat: isWan,
          _srcAddrName: base._srcAddrName || '',
          _dstAddrName: existingDstGrp1 || '',
          _dstAddrGrpFound: !!existingDstGrp1,
          _useDstGroup: !!existingDstGrp1,
          _useSrcGroup: false,
          _policyName: '',
          _srcHostNames: Object.keys(mergedSrcHostNames1).length ? mergedSrcHostNames1 : undefined,
          _dstHostNames: Object.keys(mergedDstHostNames).length ? mergedDstHostNames : undefined,
          _srcHostsFound: mergedSrcHostsFound.size ? [...mergedSrcHostsFound] : undefined,
          _dstHostsFound: mergedDstHostsFound.size ? [...mergedDstHostsFound] : undefined,
          srcAddrNames: srcSubnets.length > 1 ? srcSubnets.map(s => `FF_${escSlug(s)}`) : null,
          analysis: { ...base.analysis, services: allServices, needsWork: allServices.some(s => !s.found) },
        });
      } else {
        // Une seule destination → traiter via le subgrouping services classique
        remainingForSvcMerge.push(...ifGroup);
      }
    }

    // Sous-grouper par ensemble de services identiques (pour les policies restantes)
    const svcSubGroups = new Map(); // serviceSetKey → [policies]
    for (const p of remainingForSvcMerge) {
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
      const allDstTargets = [...new Set(subGroup.map(p => p.dstTarget).filter(t => t && t !== 'all'))];
      // Compute supernet only if it's specific enough (≥ /24) — avoid broad /9, /8 etc.
      const supernet     = cidrSupernet(allDstTargets);
      const supernetBits = supernet ? parseInt(supernet.split('/')[1] || '32', 10) : 0;
      if (!isWan && supernetBits < 24 && allDstTargets.length > 1) {
        // Too many diverse destinations — split into separate policies per dstTarget
        for (const sub of subGroup) merged.push({ ...sub });
        continue;
      }
      const allDstIPs   = [...new Set(subGroup.flatMap(p => p.dstIPs || (p.dstType === 'public' ? [p.dstTarget] : [])).filter(t => t && t !== 'all'))];
      const allSrcHosts = [...new Set(subGroup.flatMap(p => p.srcHosts || []))].sort();
      const allDstHosts = [...new Set(subGroup.flatMap(p => p.dstHosts || []))].sort();
      const multiSrc    = srcSubnets.length > 1;

      // Fusionner _srcHostNames/_dstHostNames et _hostsFound de TOUTES les policies du sous-groupe
      const mergedSrcHostNames = {};
      const mergedDstHostNames3 = {};
      const mergedSrcHF = new Set();
      const mergedDstHF = new Set();
      for (const pp of subGroup) {
        Object.assign(mergedSrcHostNames, pp._srcHostNames || {});
        Object.assign(mergedDstHostNames3, pp._dstHostNames || {});
        (pp._srcHostsFound || []).forEach(h => mergedSrcHF.add(h));
        (pp._dstHostsFound || []).forEach(h => mergedDstHF.add(h));
      }

      // Build multi-src subnets info (like _multiDstSubnets but for sources)
      let multiSrcSubnets = null;
      if (multiSrc) {
        multiSrcSubnets = srcSubnets.map(subnet => {
          const subnetPols = subGroup.filter(pp => pp.srcSubnet === subnet);
          const hosts = [...new Set(subnetPols.flatMap(pp => pp.srcHosts || []))].sort();
          const srcAddr = subnetPols.find(pp => pp.analysis?.srcAddr?.found)?.analysis?.srcAddr
                        || subnetPols[0]?.analysis?.srcAddr;
          return {
            subnet, hosts, useSubnet: hosts.length >= 5,
            addrName: srcAddr?.found ? srcAddr.name : '',
            addrFound: !!(srcAddr?.found),
          };
        });
      }

      // Chercher un groupe d'adresses existant pour les sources
      let existingGrp = null;
      if (multiSrc && deployState.addrGroups) {
        const subnetAddrNames = subGroup.map(p => p.analysis?.srcAddr?.found ? p.analysis.srcAddr.name : null);
        if (subnetAddrNames.every(Boolean)) {
          const memberNames = new Set(subnetAddrNames);
          for (const [grpName, grp] of Object.entries(deployState.addrGroups)) {
            const grpMembers = new Set(grp.members);
            if (grpMembers.size === memberNames.size && [...memberNames].every(m => grpMembers.has(m))) {
              existingGrp = grpName; break;
            }
          }
        }
      }

      // ── Multi-dst : destinations trop diverses pour un supernet ──
      if (!isWan && supernetBits < 24 && allDstTargets.length > 1) {
        const DST_SUBNET_THRESHOLD = 5;
        const dstSubnets = allDstTargets.map(subnet => {
          const subnetPols = subGroup.filter(p => p.dstTarget === subnet);
          const hosts      = [...new Set(subnetPols.flatMap(p => p.dstHosts || []))].sort();
          const dstAddr    = subnetPols.find(p => p.analysis?.dstAddr?.found)?.analysis?.dstAddr
                          || subnetPols[0]?.analysis?.dstAddr;
          return {
            subnet,
            hosts,
            useSubnet: hosts.length >= DST_SUBNET_THRESHOLD,
            addrName:  dstAddr?.found ? dstAddr.name : '',
            addrFound: !!(dstAddr?.found),
          };
        });
        // Fusionner _dstHostNames de TOUTES les policies du sous-groupe
        const mergedDstHostNames2 = {};
        for (const p of subGroup) Object.assign(mergedDstHostNames2, p._dstHostNames || {});

        // Chercher un groupe d'adresses existant pour les destinations
        let existingDstGrp = null;
        if (dstSubnets.length > 1 && deployState.addrGroups) {
          const dstAddrNames = dstSubnets.filter(s => s.addrFound).map(s => s.addrName);
          if (dstAddrNames.length === dstSubnets.length) {
            const memberNames = new Set(dstAddrNames);
            for (const [grpName, grp] of Object.entries(deployState.addrGroups)) {
              const grpMembers = new Set(grp.members);
              if (grpMembers.size === memberNames.size && [...memberNames].every(m => grpMembers.has(m))) {
                existingDstGrp = grpName; break;
              }
            }
          }
        }

        merged.push({
          ...base,
          srcSubnet:        srcSubnets[0],
          srcSubnets,
          dstTarget:        allDstTargets[0],
          dstTargets:       allDstTargets,
          _multiDstSubnets: dstSubnets,
          _isMultiDst:      true,
          dstType:          base.dstType,
          sessions:         totalSessions,
          serviceDesc:      allServices.map(s => s.label).join(', '),
          policyIds:        allPolicyIds,
          srcHosts:         allSrcHosts,
          dstHosts:         allDstHosts,
          _use32Src:        allSrcHosts.length >= 1 && allSrcHosts.length <= AUTO32_THRESHOLD,
          _use32Dst:        false,
          _mergedCount:     subGroup.length,
          _isWan:           false,
          _nat:             false,
          _srcAddrName:     existingGrp || '',
          _srcAddrGrpFound: !!existingGrp,
          _useSrcGroup:     !!existingGrp,
          _dstAddrName:     existingDstGrp || '',
          _dstAddrGrpFound: !!existingDstGrp,
          _useDstGroup:     !!existingDstGrp,
          _policyName:      '',
          _dstHostNames:    Object.keys(mergedDstHostNames2).length ? mergedDstHostNames2 : undefined,
          _srcHostNames:    Object.keys(mergedSrcHostNames).length ? mergedSrcHostNames : undefined,
          _srcHostsFound:   mergedSrcHF.size ? [...mergedSrcHF] : undefined,
          _dstHostsFound:   mergedDstHF.size ? [...mergedDstHF] : undefined,
          _multiSrcSubnets: multiSrcSubnets,
          srcAddrNames:     existingGrp ? null : (multiSrc ? srcSubnets.map(s => `FF_${escSlug(s)}`) : null),
          analysis:         { ...base.analysis, services: allServices, needsWork: allServices.some(s => !s.found) },
        });
        continue;
      }

      const dstTarget = isWan ? 'all' : (supernetBits >= 24 ? supernet : base.dstTarget);

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
        _use32Src:    allSrcHosts.length >= 1 && allSrcHosts.length <= AUTO32_THRESHOLD,
        _use32Dst:    !isWan && allDstHosts.length >= 1 && allDstHosts.length <= AUTO32_THRESHOLD,
        _mergedCount: subGroup.length,
        _isWan:       isWan,
        _nat:         isWan,
        _srcAddrName: existingGrp || '',
        _srcAddrGrpFound: !!existingGrp,
        _useSrcGroup:     !!existingGrp,
        _multiSrcSubnets: multiSrcSubnets,
        _srcHostNames:    Object.keys(mergedSrcHostNames).length ? mergedSrcHostNames : undefined,
        _dstHostNames:    Object.keys(mergedDstHostNames3).length ? mergedDstHostNames3 : undefined,
        _srcHostsFound:   mergedSrcHF.size ? [...mergedSrcHF] : undefined,
        _dstHostsFound:   mergedDstHF.size ? [...mergedDstHF] : undefined,
        _dstAddrName: isWan ? 'all' : (dstTarget !== base.dstTarget ? '' : base._dstAddrName),
        _policyName:  '',
        srcAddrNames: existingGrp ? null : (multiSrc ? srcSubnets.map(s => `FF_${escSlug(s)}`) : null),
        analysis: { ...base.analysis, services: allServices, needsWork: allServices.some(s => !s.found) },
      });
    }
  }

  return merged;
}

// ── Fusion par service : policies partageant le même ensemble de services
//    ET la même paire d'interfaces sont regroupées en une seule règle multi-src/multi-dst.
function mergeByService(policies) {
  const groups = new Map(); // serviceKey||srcintf||dstintf → [policies]

  for (const p of policies) {
    const svcKey = serviceSetKey(p);
    const src    = p._srcintf || p.analysis?.srcIface || '';
    const dst    = p._dstintf || p.analysis?.dstIface || '';
    const key    = `${svcKey}||${src}||${dst}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(p);
  }

  const merged = [];

  for (const [, group] of groups) {
    if (group.length === 1) { merged.push({ ...group[0] }); continue; }

    const base          = group[0];
    const allServices   = mergeServices(group);
    const totalSessions = group.reduce((s, p) => s + (p.sessions || 0), 0);
    const allPolicyIds  = [...new Set(group.flatMap(p => p.policyIds || []))].sort((a, b) => Number(a) - Number(b));

    const isWan      = group.some(p => p.dstType === 'public' || p.dstTarget === 'all' || p._isWan);
    const srcSubnets = [...new Set(group.map(p => p.srcSubnet).filter(Boolean))].sort();
    const dstTargets = isWan
      ? ['all']
      : [...new Set(group.map(p => p.dstTarget).filter(t => t && t !== 'all'))];
    const multiSrc   = srcSubnets.length > 1;
    const multiDst   = !isWan && dstTargets.length > 1;

    const allSrcHosts = [...new Set(group.flatMap(p => p.srcHosts || []))].sort();
    const allDstHosts = [...new Set(group.flatMap(p => p.dstHosts || []))].sort();

    // Merge host name maps
    const mergedSrcHostNames = {};
    const mergedDstHostNames = {};
    const mergedSrcHF = new Set();
    const mergedDstHF = new Set();
    for (const p of group) {
      Object.assign(mergedSrcHostNames, p._srcHostNames || {});
      Object.assign(mergedDstHostNames, p._dstHostNames || {});
      (p._srcHostsFound || []).forEach(h => mergedSrcHF.add(h));
      (p._dstHostsFound || []).forEach(h => mergedDstHF.add(h));
    }

    // Build _multiSrcSubnets
    let multiSrcSubnets = null;
    if (multiSrc) {
      multiSrcSubnets = srcSubnets.map(subnet => {
        const subnetPols = group.filter(p => p.srcSubnet === subnet);
        const hosts      = [...new Set(subnetPols.flatMap(p => p.srcHosts || []))].sort();
        const srcAddr    = subnetPols.find(p => p.analysis?.srcAddr?.found)?.analysis?.srcAddr
                         || subnetPols[0]?.analysis?.srcAddr;
        return { subnet, hosts, useSubnet: hosts.length >= 5,
          addrName: srcAddr?.found ? srcAddr.name : '', addrFound: !!(srcAddr?.found) };
      });
    }

    // Build _multiDstSubnets
    const DST_SUBNET_THRESHOLD = 5;
    let multiDstSubnets = null;
    if (multiDst) {
      multiDstSubnets = dstTargets.map(subnet => {
        const subnetPols = group.filter(p => p.dstTarget === subnet);
        const hosts      = [...new Set(subnetPols.flatMap(p => p.dstHosts || []))].sort();
        const dstAddr    = subnetPols.find(p => p.analysis?.dstAddr?.found)?.analysis?.dstAddr
                         || subnetPols[0]?.analysis?.dstAddr;
        return { subnet, hosts, useSubnet: hosts.length >= DST_SUBNET_THRESHOLD,
          addrName: dstAddr?.found ? dstAddr.name : '', addrFound: !!(dstAddr?.found) };
      });
    }

    // Check for existing address groups (src)
    let existingSrcGrp = null;
    if (multiSrc && deployState.addrGroups) {
      const srcAddrNames = srcSubnets.map(s => {
        const sp = group.find(p => p.srcSubnet === s);
        return sp?.analysis?.srcAddr?.found ? sp.analysis.srcAddr.name : null;
      });
      if (srcAddrNames.every(Boolean)) {
        const memberNames = new Set(srcAddrNames);
        for (const [grpName, grp] of Object.entries(deployState.addrGroups)) {
          const grpMembers = new Set(grp.members);
          if (grpMembers.size === memberNames.size && [...memberNames].every(m => grpMembers.has(m))) {
            existingSrcGrp = grpName; break;
          }
        }
      }
    }

    // Check for existing address groups (dst)
    let existingDstGrp = null;
    if (multiDst && deployState.addrGroups) {
      const dstAddrNames = dstTargets.map(s => {
        const dp = group.find(p => p.dstTarget === s);
        return dp?.analysis?.dstAddr?.found ? dp.analysis.dstAddr.name : null;
      }).filter(Boolean);
      if (dstAddrNames.length === dstTargets.length) {
        const memberNames = new Set(dstAddrNames);
        for (const [grpName, grp] of Object.entries(deployState.addrGroups)) {
          const grpMembers = new Set(grp.members);
          if (grpMembers.size === memberNames.size && [...memberNames].every(m => grpMembers.has(m))) {
            existingDstGrp = grpName; break;
          }
        }
      }
    }

    merged.push({
      ...base,
      srcSubnet:        srcSubnets[0],
      srcSubnets,
      dstTarget:        isWan ? 'all' : dstTargets[0],
      dstTargets,
      dstType:          isWan ? 'public' : base.dstType,
      _isMultiDst:      multiDst,
      _multiDstSubnets: multiDst ? multiDstSubnets : null,
      _multiSrcSubnets: multiSrcSubnets,
      sessions:         totalSessions,
      serviceDesc:      allServices.map(s => s.label).join(', '),
      policyIds:        allPolicyIds,
      srcHosts:         allSrcHosts,
      dstHosts:         allDstHosts,
      _use32Src:        !multiSrc && allSrcHosts.length >= 1 && allSrcHosts.length <= AUTO32_THRESHOLD,
      _use32Dst:        !multiDst && !isWan && allDstHosts.length >= 1 && allDstHosts.length <= AUTO32_THRESHOLD,
      _isWan:           isWan,
      _nat:             isWan,
      _mergedCount:     group.length,
      _isSvcMerge:      true,
      _mergedFrom:      group.map(p => ({ srcSubnet: p.srcSubnet, dstTarget: p.dstTarget, analysis: { services: p.analysis?.services } })),
      _srcAddrName:     existingSrcGrp || '',
      _srcAddrGrpFound: !!existingSrcGrp,
      _useSrcGroup:     !!existingSrcGrp,
      _dstAddrName:     isWan ? 'all' : (existingDstGrp || ''),
      _dstAddrGrpFound: !!existingDstGrp,
      _useDstGroup:     !!existingDstGrp,
      _policyName:      '',
      _srcHostNames:    Object.keys(mergedSrcHostNames).length ? mergedSrcHostNames : undefined,
      _dstHostNames:    Object.keys(mergedDstHostNames).length ? mergedDstHostNames : undefined,
      _srcHostsFound:   mergedSrcHF.size ? [...mergedSrcHF] : undefined,
      _dstHostsFound:   mergedDstHF.size ? [...mergedDstHF] : undefined,
      srcAddrNames:     existingSrcGrp ? null : (multiSrc ? srcSubnets.map(s => `FF_${escSlug(s)}`) : null),
      analysis: {
        ...base.analysis,
        dstAddr:   isWan ? { found: true, name: 'all', cidr: 'all' } : base.analysis?.dstAddr,
        services:  allServices,
        needsWork: allServices.some(s => !s.found),
      },
    });
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
        _use32Src:    p._use32Src,
        _use32Dst:    p._use32Dst,
        _srcMode:     p._srcMode,
        _dstMode:     p._dstMode,
        _useSrcGroup: p._useSrcGroup,
        _useDstGroup: p._useDstGroup,
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
    } else if (mode === 'service') {
      deployState.analyzed = mergeByService(deployState._analyzedOriginal);
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
    // Determine preferred WAN interface — SD-WAN zone has priority
    const ifData = deployState.interfaces;
    const preferredWanIntf = deployState.selectedSdwan
      || (ifData?.sdwanEnabled ? (ifData?.sdwanIntfName || null) : null);

    // Interfaces manually toggled to WAN by the user (sent as overrides to the server)
    const wanOverrides = (ifData?.interfaces || [])
      .filter(i => i.isWan)
      .map(i => i.name);

    const r = await fetch(`/api/deploy/generate?session=${state.session}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ selectedPolicies: rawPolicies, opts: { preferredWanIntf, wanOverrides } }),
    });
    setLoadingPct(80);
    if (!r.ok) {
      const text = await r.text();
      const msg  = (() => { try { return JSON.parse(text).error; } catch { return `HTTP ${r.status}`; } })();
      resetAnalyzeBtn(); alert('Erreur analyse : ' + msg); return;
    }
    const respData = await r.json();
    analyzed = respData.analyzed;
    deployState.addrGroups   = respData.addrGroups   || {};
    deployState.warnings     = respData.warnings     || [];
    deployState.resolvedHosts = respData.resolvedHosts || {};
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
  const resolvedHosts = deployState.resolvedHosts || {};
  analyzed = analyzed.map(p => {
    const isWan = p.dstType === 'public' || p.dstTarget === 'all';
    const rawSrcIntf = p.analysis?.srcZone || p.analysis?.srcIface || ifaces.find(i => i.name === p.srcintf)?.name || '';
    const rawDstIntf = p.analysis?.dstZone || p.analysis?.dstIface || ifaces.find(i => i.name === p.dstintf)?.name || '';
    // Pre-fill host names from global resolved map (existing FortiGate objects)
    const srcHostNames = {};
    const srcHostsFoundExtra = [];
    for (const h of (p.srcHosts || [])) {
      if (resolvedHosts[h]) { srcHostNames[h] = resolvedHosts[h]; srcHostsFoundExtra.push(h); }
    }
    const dstHostNames = {};
    const dstHostsFoundExtra = [];
    for (const h of (p.dstHosts || [])) {
      if (resolvedHosts[h]) { dstHostNames[h] = resolvedHosts[h]; dstHostsFoundExtra.push(h); }
    }
    // Merge found hosts: backend _hostsFound + resolvedHosts matches
    const mergedSrcFound = [...new Set([...(p._srcHostsFound || []), ...srcHostsFoundExtra])];
    const mergedDstFound = [...new Set([...(p._dstHostsFound || []), ...dstHostsFoundExtra])];
    return {
      ...p,
      srcAddrExists: p.analysis?.srcAddr?.found ?? false,
      dstAddrExists: p.analysis?.dstAddr?.found ?? false,
      _srcintf:          resolveZone(rawSrcIntf),
      _srcIfaceSource:   p.analysis?.srcIfaceSource || 'auto',
      _dstintf:          resolveZone(rawDstIntf),
      _dstIfaceSource:   p.analysis?.dstIfaceSource || 'auto',
      _srcAddrName:  p.analysis?.srcAddr?.name || '',
      _dstAddrName:  p.analysis?.dstAddr?.name || '',
      _policyName:   '',
      _nat:          isWan,
      _isWan:        isWan,
      _checked:      true,
      _srcHostNames:  Object.keys(srcHostNames).length ? { ...(p._srcHostNames || {}), ...srcHostNames } : (p._srcHostNames || undefined),
      _dstHostNames:  Object.keys(dstHostNames).length ? { ...(p._dstHostNames || {}), ...dstHostNames } : (p._dstHostNames || undefined),
      _srcHostsFound: mergedSrcFound.length ? mergedSrcFound : undefined,
      _dstHostsFound: mergedDstFound.length ? mergedDstFound : undefined,
    };
  });

  // Tri par srcSubnet pour faciliter la lecture
  analyzed.sort((a, b) => (a.srcSubnet || '').localeCompare(b.srcSubnet || ''));

  // Auto /32 : peu d'hôtes réels = utiliser les /32 par défaut (≤ AUTO32_THRESHOLD hôtes)
  for (const p of analyzed) {
    if ((p.srcHosts || []).length >= 1 && (p.srcHosts || []).length <= AUTO32_THRESHOLD) p._use32Src = true;
    if ((p.dstHosts || []).length >= 1 && (p.dstHosts || []).length <= AUTO32_THRESHOLD) p._use32Dst = true;
    // Initialize per-policy mode from _use32 flags
    p._srcMode = p._use32Src ? 'hosts' : 'subnet';
    p._dstMode = p._use32Dst ? 'hosts' : 'subnet';
  }

  deployState.analyzed              = analyzed;
  deployState._analyzedOriginal     = null;
  deployState.baseAnalyzedPolicies  = analyzed.map(p => ({ ...p })); // snapshot for reset
  deployState.generatedCli          = null;
  deployState.selected              = new Set(analyzed.map((_, i) => i));
  _drawerHistory = [];  // clear undo history from previous session

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

  // Load available security profiles for the dropdown selectors
  try {
    const spRes = await fetch(`/api/security-profiles?session=${state.session}`);
    if (spRes.ok) {
      const sp = await spRes.json();
      const fillSel = (selId, options) => {
        const sel = el(selId);
        if (!sel || !options?.length) return;
        for (const name of options) sel.insertAdjacentHTML('beforeend', `<option value="${escHtml(name)}">${escHtml(name)}</option>`);
      };
      fillSel('sp-av', sp.antivirus);
      fillSel('sp-wf', sp.webfilter);
      fillSel('sp-ips', sp.ips);
      fillSel('sp-ssl', sp.sslSsh);
      const hasAny = (sp.antivirus?.length || sp.webfilter?.length || sp.ips?.length || sp.sslSsh?.length);
      const spBar = el('security-profiles-bar');
      if (spBar && hasAny) spBar.style.display = '';
    }
  } catch { /* non-bloquant */ }

  deployState.wizardStep = 4;
  // Update wizard progress indicators
  document.querySelectorAll('.wizard-step-indicator').forEach(ind => {
    const s = +ind.dataset.step;
    ind.classList.toggle('active', s <= 4);
    ind.classList.toggle('done', s < 4);
  });
  document.querySelectorAll('.wizard-connector').forEach((c, i) => c.classList.toggle('done', i < 3));

  resetAnalyzeBtn();
  renderDeployPolicies(analyzed);
}

function resetAnalyzeBtn() {
  const btn = el('btn-analyze');
  if (btn) { btn.disabled = false; btn.textContent = '⚡ Analyser les policies'; }
}

function suggestAddrNameFE(cidr) {
  if (!cidr) return '';
  return 'FF_' + cidr.replace(/[./]/g, '_');
}

// ─── CIDR supernet helpers ────────────────────────────────────────────────────

function ip2intFE(ip) {
  return ip.split('.').reduce((a, o) => (a * 256) + parseInt(o, 10), 0) >>> 0;
}

function int2ipFE(n) {
  return [(n >>> 24) & 0xFF, (n >>> 16) & 0xFF, (n >>> 8) & 0xFF, n & 0xFF].join('.');
}

// Retourne le plus petit supernet CIDR couvrant tous les CIDRs donnés.
// Ex : ['10.1.2.0/24','10.1.6.0/24','10.1.16.0/24'] → '10.1.0.0/19'
function cidrSupernet(cidrs) {
  if (!cidrs || cidrs.length === 0) return null;
  const unique = [...new Set(cidrs)];
  if (unique.length === 1) return unique[0];

  const nets = unique.map(c => {
    const [ip, p] = c.split('/');
    const plen = parseInt(p || '32', 10);
    const mask = plen === 0 ? 0 : (0xFFFFFFFF << (32 - plen)) >>> 0;
    return { int: ip2intFE(ip) & mask, prefix: plen };
  });

  let supInt    = nets[0].int;
  let supPrefix = nets[0].prefix;

  for (let i = 1; i < nets.length; i++) {
    const xor = (supInt ^ nets[i].int) >>> 0;
    const common = xor === 0
      ? Math.min(supPrefix, nets[i].prefix)
      : Math.min(Math.clz32(xor), supPrefix, nets[i].prefix);
    supPrefix = common;
    const mask = supPrefix === 0 ? 0 : (0xFFFFFFFF << (32 - supPrefix)) >>> 0;
    supInt = supInt & mask;
  }

  return `${int2ipFE(supInt)}/${supPrefix}`;
}

function escSlug(s) {
  return (s || '').replace(/[./]/g, '_').replace(/[^a-zA-Z0-9_]/g, '');
}

// ── Per-policy address mode pills (/24 | /32) ──────────────────────────
function buildModePills(idx, type, currentMode, hasHosts) {
  return `<span class="mode-pills">
    <button class="btn-addr-mode ${currentMode==='subnet'?'active':''}" data-idx="${idx}" data-type="${type}" data-mode="subnet">/24</button>
    <button class="btn-addr-mode ${currentMode==='hosts'?'active':''} ${hasHosts?'':'disabled'}" data-idx="${idx}" data-type="${type}" data-mode="hosts">/32</button>
  </span>`;
}

// Build an address cell — simplified: inline-editable text (click to edit in drawer)
function addrCell(addrAnalysis, currentName, idx, field) {
  if (!addrAnalysis?.found) {
    const displayName = currentName || addrAnalysis?.suggestedName || '';
    return `<span class="inline-editable missing" data-idx="${idx}" data-field="${field}" title="Cliquer pour modifier">${displayName ? escHtml(displayName) + ' ' : ''}${badgeHtml('auto')}</span>`;
  }
  const matches = addrAnalysis.allMatches || [{ name: addrAnalysis.name, source: addrAnalysis.source }];
  const cidrTip = addrAnalysis.cidr ? ` (${addrAnalysis.cidr})` : '';
  const src = (matches[0].source || addrAnalysis.source || '').replace('config-range', 'config');
  const badge = src === 'config' ? badgeHtml('config') : badgeHtml('auto');
  if (matches.length === 1) {
    return `<span class="inline-editable found" data-idx="${idx}" data-field="${field}" title="${escHtml(matches[0].name + cidrTip)}">${escHtml(matches[0].name)}${badge}</span>`;
  }
  return `<span class="inline-editable found" data-idx="${idx}" data-field="${field}" title="${escHtml(matches.length + ' objets correspondent' + cidrTip)}">${escHtml(matches[0].name)}${badge}</span>`;
}

// Legacy addrCell for drawer/modal contexts (with full input)
function addrCellInput(addrAnalysis, currentName, idx, field) {
  if (!addrAnalysis?.found) {
    return `<input class="deploy-name-input" data-idx="${idx}" data-field="${field}" value="${escHtml(currentName)}" placeholder="FF_...">`;
  }
  const matches = addrAnalysis.allMatches || [{ name: addrAnalysis.name, source: addrAnalysis.source }];
  const cidrInfo = addrAnalysis.cidr ? ` (${addrAnalysis.cidr})` : '';
  const srcTip = (addrAnalysis.source === 'config' ? 'Objet existant' : '') + cidrInfo;
  if (matches.length === 1) {
    return `<span class="match-ok" ${srcTip ? `title="${escHtml(srcTip)}"` : ''}>✓ ${escHtml(matches[0].name)}</span>`;
  }
  const opts = matches.map(m =>
    `<option value="${escHtml(m.name)}" ${m.name === currentName ? 'selected' : ''}>${escHtml(m.name)}</option>`
  ).join('');
  return `<select class="deploy-name-sel match-ok-sel" data-idx="${idx}" data-field="${field}" title="${srcTip || matches.length + ' objets correspondent'}">
    ${opts}
  </select>`;
}

// Build a service match cell: green text if 1 match, green select if multiple
function svcMatchCell(svc, idx) {
  const matches  = svc.allMatches || [{ name: svc.name, source: svc.source }];
  const portPart = svc.portHint ? `\nPorts: ${svc.portHint}` : '';
  const srcLabel = matches[0].source === 'custom' ? 'Service existant dans la config FortiGate'
                 : matches[0].source === 'predefined' ? 'Service prédéfini FortiGate'
                 : (matches[0].source || '');
  const tip1     = `${srcLabel}${portPart}`;
  if (matches.length === 1) {
    return `<span class="match-ok" title="${escHtml(tip1)}">✓ ${escHtml(matches[0].name)}</span>`;
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
  return shown.map(id => `<span class="policy-id-badge" ${tip ? `title="${escHtml(tip)}"` : ''}>${escHtml(id)}</span>`).join(' ') + more;
}

function isPolicyComplete(p) {
  const a = p.analysis || {};

  // Interfaces must be explicitly selected
  if (!p._srcintf) return false;
  if (!p._dstintf) return false;

  // Source addresses / hosts
  if (p._multiSrcSubnets?.length) {
    const srcFoundSet = new Set(p._srcHostsFound || []);
    for (const s of p._multiSrcSubnets) {
      if (s.useSubnet !== false) {
        if (!s.addrFound && !s.addrName) return false;
      } else {
        for (const h of (s.hosts || [])) {
          if (!srcFoundSet.has(h) && !(p._srcHostNames?.[h])) return false;
        }
      }
    }
  } else if (p._srcMode === 'hosts' || p._use32Src) {
    const foundSet = new Set(p._srcHostsFound || []);
    for (const h of (p.srcHosts || [])) {
      if (!foundSet.has(h) && !(p._srcHostNames?.[h])) return false;
    }
  } else {
    if (!a.srcAddr?.found && !p._srcAddrName) return false;
  }

  // Source group (addrgrp): if active and not already found, must have a typed name
  if (p._useSrcGroup && !p._srcAddrGrpFound && !p._srcAddrName) return false;

  // Destination addresses / hosts
  if (p._isMultiDst && p._multiDstSubnets?.length) {
    const dstFoundSet = new Set(p._dstHostsFound || []);
    for (const s of p._multiDstSubnets) {
      if (s.useSubnet !== false) {
        if (!s.addrFound && !s.addrName) return false;
      } else {
        for (const h of (s.hosts || [])) {
          if (!dstFoundSet.has(h) && !(p._dstHostNames?.[h])) return false;
        }
      }
    }
  } else if (p._dstMode === 'hosts' || p._use32Dst) {
    const foundSet = new Set(p._dstHostsFound || []);
    for (const h of (p.dstHosts || [])) {
      if (!foundSet.has(h) && !(p._dstHostNames?.[h])) return false;
    }
  } else if (p.dstType !== 'public') {
    if (!a.dstAddr?.found && !p._dstAddrName) return false;
  }

  // Destination group (addrgrp)
  if (p._useDstGroup && !p._dstAddrGrpFound && !p._dstAddrName) return false;

  // Services — must be found, merged, or explicitly renamed by user
  for (const svc of a.services || []) {
    if (svc.found || svc._isMerged) continue;
    const isPortNotation = /^(TCP|UDP)\/\d+$/i.test(svc.suggestedName || '');
    // Named service (from logs): user must have changed the name from the auto-label
    const isUnchangedLabel = svc.isNamed && svc.suggestedName === svc.label;
    if (!svc.suggestedName || isPortNotation || isUnchangedLabel) return false;
  }

  return true;
}

function syncRowStatus(idx) {
  const p = deployState.analyzed?.[idx];
  if (!p) return;
  const bar = document.querySelector(`.deploy-policy-row[data-idx="${idx}"] .status-bar`);
  if (!bar) return;
  bar.className = `status-bar status-${isPolicyComplete(p) ? 'ok' : (p.analysis?.status || 'warn')}`;
}

function countMissingObjects(analyzed) {
  const addrs = new Set(), svcs = new Set();
  for (const p of analyzed) {
    if (!p.analysis?.srcAddr?.found && p.analysis?.srcAddr?.cidr) addrs.add(p.analysis.srcAddr.cidr);
    if (!p.analysis?.dstAddr?.found && p.analysis?.dstAddr?.cidr && p.analysis?.dstAddr?.cidr !== 'all') addrs.add(p.analysis.dstAddr.cidr);
    if (p._isMultiDst && p._multiDstSubnets?.length) {
      for (const s of p._multiDstSubnets) { if (!s.addrFound && s.subnet) addrs.add(s.subnet); }
    }
    for (const svc of p.analysis?.services || []) {
      if (!svc.found) svcs.add(svc.port ? `${svc.port}/${svc.proto}` : svc.label || svc.name);
    }
  }
  return { addrs: addrs.size, svcs: svcs.size };
}

// ── F7: Event delegation on the deploy table ──────────────────────────────────
// Searchable interface dropdown — replaces native <select> for iface fields
function buildIfaceDropdown(idx, field, currentVal) {
  const opts = deployState.ifaceOpts || [];
  const cur = opts.find(o => o.value === currentVal) || opts[0];
  const btnLabel = cur ? cur.label : '— auto —';
  const listItems = opts.map(o => `
    <li data-value="${escHtml(o.value)}" ${o.value === currentVal ? 'class="selected"' : ''}>
      ${escHtml(o.label)}
    </li>`).join('');
  return `<div class="iface-dd" data-idx="${idx}" data-field="${field}">
    <button class="iface-dd-btn" type="button" title="${escHtml(btnLabel)}">${escHtml(btnLabel)}</button>
    <div class="iface-dd-panel">
      <input class="iface-dd-search" type="text" placeholder="Rechercher…" autocomplete="off">
      <ul class="iface-dd-list">${listItems}</ul>
    </div>
  </div>`;
}

// Called once after the deploy-policy-body container exists.
// Installs delegated listeners on the stable container — avoids re-attaching
// hundreds of listeners on every render.

let _deployTableWired = false;
let _dragSrcIdx       = null;

function wireDeployTable() {
  const container = el('deploy-policy-body');
  if (!container || _deployTableWired) return;
  _deployTableWired = true;

  // ── click: row → open drawer ──
  container.addEventListener('click', e => {
    // Don't open drawer for checkboxes, inputs, selects, or buttons
    if (e.target.closest('input, select, button, .deploy-chk, .inline-editing')) return;
    const row = e.target.closest('.deploy-policy-row');
    if (!row) return;
    const idx = +row.dataset.idx;
    if (isNaN(idx) || idx < 0) return;
    openDrawer(idx);
  });

  // ── click: .inline-editable → inline editing ──
  container.addEventListener('click', e => {
    const cell = e.target.closest('.inline-editable');
    if (!cell || cell.classList.contains('found')) return; // Only edit missing objects
    e.stopPropagation(); // Don't open drawer
    const idx   = +cell.dataset.idx;
    const field = cell.dataset.field;
    const p     = deployState.analyzed[idx];
    if (!p) return;
    const currentVal = p[field] || cell.textContent;
    const input = document.createElement('input');
    input.className = 'inline-editing';
    input.value = currentVal;
    input.dataset.idx = idx;
    input.dataset.field = field;
    cell.replaceWith(input);
    input.focus();
    input.select();
    const commit = () => {
      const val = input.value.trim();
      if (val) p[field] = val;
      const span = document.createElement('span');
      span.className = 'inline-editable missing';
      span.dataset.idx = idx;
      span.dataset.field = field;
      span.textContent = val || currentVal;
      span.title = 'Cliquer pour modifier';
      input.replaceWith(span);
    };
    input.addEventListener('blur', commit);
    input.addEventListener('keydown', e2 => { if (e2.key === 'Enter') { e2.preventDefault(); input.blur(); } if (e2.key === 'Escape') { input.value = currentVal; input.blur(); } });
  });

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

  // ── click: .iface-dd-btn (open/close) ──
  container.addEventListener('click', e => {
    const btn = e.target.closest('.iface-dd-btn');
    if (!btn) return;
    const dd = btn.closest('.iface-dd');
    const isOpen = dd.classList.contains('open');
    document.querySelectorAll('.iface-dd.open').forEach(d => d.classList.remove('open'));
    if (!isOpen) {
      dd.classList.add('open');
      dd.querySelector('.iface-dd-search').value = '';
      dd.querySelectorAll('.iface-dd-list li').forEach(li => { li.hidden = false; });
      dd.querySelector('.iface-dd-search').focus();
    }
    e.stopPropagation();
  });

  // ── click: .iface-dd-list li (select value) ──
  container.addEventListener('click', e => {
    const li = e.target.closest('.iface-dd-list li');
    if (!li) return;
    const dd = li.closest('.iface-dd');
    const { idx, field } = dd.dataset;
    const value = li.dataset.value;
    const label = (deployState.ifaceOpts || []).find(o => o.value === value)?.label || '— auto —';
    dd.querySelector('.iface-dd-btn').textContent = label;
    dd.querySelector('.iface-dd-btn').title = label;
    dd.querySelectorAll('.iface-dd-list li').forEach(l => l.classList.toggle('selected', l.dataset.value === value));
    dd.classList.remove('open');
    deployState.analyzed[+idx][field] = value || undefined;
  });

  // ── input: .iface-dd-search (filter list) ──
  container.addEventListener('input', e => {
    if (!e.target.matches('.iface-dd-search')) return;
    const q = e.target.value.toLowerCase();
    e.target.closest('.iface-dd-panel').querySelectorAll('.iface-dd-list li').forEach(li => {
      li.hidden = !!q && !li.textContent.toLowerCase().includes(q);
    });
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
      const svc = (policy?.analysis?.services || []).find(s => String(s.port) === parts[1] && s.proto === parts[2]);
      if (svc) svc.suggestedName = e.target.value;
    } else {
      if (deployState.analyzed[+idx]) deployState.analyzed[+idx][field] = e.target.value;
    }
  });

  // ── click: .btn-toggle32 — toggle /32 mode directement (un clic) ──
  container.addEventListener('click', e => {
    const btn = e.target.closest('.btn-toggle32');
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

  // ── click: .btn-addr-mode — per-policy mode pill (/24 | /32 | grp) ──
  container.addEventListener('click', e => {
    if (!e.target.matches('.btn-addr-mode')) return;
    if (e.target.classList.contains('disabled')) return;
    const idx  = +e.target.dataset.idx;
    const type = e.target.dataset.type; // 'src' or 'dst'
    const mode = e.target.dataset.mode;
    const p    = deployState.analyzed[idx];
    if (!p) return;
    if (type === 'src') {
      p._srcMode  = mode;
      p._use32Src = mode === 'hosts';
    } else {
      p._dstMode  = mode;
      p._use32Dst = mode === 'hosts';
    }
    renderDeployPolicies(filterDeployPolicies(), false);
  });

  // ── input: .host-name-input — mise à jour du nom d'hôte /32 ──
  container.addEventListener('input', e => {
    const input = e.target.closest('.host-name-input');
    if (!input) return;
    const idx  = +input.dataset.idx;
    const type = input.dataset.type;
    const host = input.dataset.host;
    const p    = deployState.analyzed[idx];
    if (!p) return;
    if (type === 'src') {
      if (!p._srcHostNames) p._srcHostNames = {};
      p._srcHostNames[host] = input.value;
    } else {
      if (!p._dstHostNames) p._dstHostNames = {};
      p._dstHostNames[host] = input.value;
    }
  });

  // ── click: .btn-hosts-edit — afficher/masquer les noms d'objets /32 ──
  container.addEventListener('click', e => {
    const btn = e.target.closest('.btn-hosts-edit');
    if (!btn) return;
    const idx  = btn.dataset.idx;
    const type = btn.dataset.type;
    const detail = document.getElementById(`${type}-hosts-${idx}`);
    if (detail) detail.style.display = detail.style.display === 'none' ? '' : 'none';
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

  // ── click: .btn-multidst-toggle — afficher/masquer la liste multi-dst ──
  container.addEventListener('click', e => {
    const btn = e.target.closest('.btn-multidst-toggle');
    if (!btn) return;
    const idx    = btn.dataset.idx;
    const detail = document.getElementById(`multidst-${idx}`);
    if (!detail) return;
    const open = detail.style.display !== 'none';
    detail.style.display = open ? 'none' : '';
    const count = (deployState.analyzed[+idx]?._multiDstSubnets || []).length;
    btn.textContent = open ? `${count} destinations ▾` : `${count} destinations ▴`;
  });

  // ── click: .btn-dst-subnet-toggle — basculer /24↔/32 par subnet dans multi-dst ──
  container.addEventListener('click', e => {
    const btn = e.target.closest('.btn-dst-subnet-toggle');
    if (!btn) return;
    const idx = +btn.dataset.idx;
    const si  = +btn.dataset.si;
    const p   = deployState.analyzed[idx];
    if (!p?._multiDstSubnets?.[si]) return;
    p._multiDstSubnets[si].useSubnet = !p._multiDstSubnets[si].useSubnet;
    renderDeployPolicies(filterDeployPolicies(), false);
  });

  // ── click: .btn-dst-grp-toggle — basculer inline ↔ groupe pour multi-dst ──
  container.addEventListener('click', e => {
    const btn = e.target.closest('.btn-dst-grp-toggle');
    if (!btn) return;
    const idx = +btn.dataset.idx;
    const p   = deployState.analyzed[idx];
    if (!p) return;
    p._useDstGroup = !p._useDstGroup;
    renderDeployPolicies(filterDeployPolicies(), false);
  });

  // ── change: .dst-grp-name-input — nom custom du groupe destination ──
  container.addEventListener('input', e => {
    if (!e.target.classList.contains('dst-grp-name-input')) return;
    const idx = +e.target.dataset.idx;
    const p   = deployState.analyzed[idx];
    if (p) p._dstAddrName = e.target.value.trim();
  });

  // ── click: .btn-src-grp-toggle — basculer inline ↔ groupe pour source /32 ──
  container.addEventListener('click', e => {
    const btn = e.target.closest('.btn-src-grp-toggle');
    if (!btn) return;
    const idx = +btn.dataset.idx;
    const p   = deployState.analyzed[idx];
    if (!p) return;
    p._useSrcGroup = !p._useSrcGroup;
    renderDeployPolicies(filterDeployPolicies(), false);
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
    // Remap selected indices after splice
    const wasSrcSelected = deployState.selected.has(srcPos);
    const newSelected = new Set();
    for (const idx of deployState.selected) {
      if (idx === srcPos) continue; // handled separately after splice
      let adj = idx;
      if (idx > srcPos) adj--;
      if (adj >= tgtPos) adj++;
      newSelected.add(adj);
    }
    const [moved] = arr.splice(srcPos, 1);
    arr.splice(tgtPos, 0, moved);
    if (wasSrcSelected) newSelected.add(tgtPos);
    deployState.selected = newSelected;
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
  deployState.ifaceOpts = [
    { value: '', label: '— auto —' },
    ...zoneNames.map(n => ({ value: n, label: `${n} (zone)` })),
    ...ifaceNotInZone.map(n => ({ value: n, label: n })),
  ];
  const allIfOpts = deployState.ifaceOpts
    .filter(o => o.value)
    .map(o => `<option value="${escHtml(o.value)}">${escHtml(o.label)}</option>`)
    .join('');

  // Adaptive columns: hide intf columns if all are auto (computed before buildRow)
  const allSrcAutoFlag = analyzed.every(p => !p._srcintf);
  const allDstAutoFlag = analyzed.every(p => !p._dstintf);

  // rows use the real index in deployState.analyzed (not filtered position)
  // so that data-idx always references the correct policy in the full array
  const maxSessions = displayList.reduce((m, pp) => Math.max(m, pp.sessions || 0), 1);

  // Pre-build index map to avoid O(n²) indexOf in buildRow
  const policyIndexMap = new Map(deployState.analyzed.map((p, i) => [p, i]));

  function buildRow(p) {
    const isAgg = p._isAggregated;
    const idx = isAgg ? (p._sequenceMembers?.[0] ?? -1) : (policyIndexMap.get(p) ?? -1);

    // Checkbox
    const chkChecked = isAgg
      ? p._sequenceMembers.every(i => deployState.selected.has(i))
      : deployState.selected.has(idx);
    const chkAttr = isAgg
      ? `class="deploy-chk deploy-chk-seq" data-seq-members="${p._sequenceMembers.join(',')}" ${chkChecked ? 'checked' : ''}`
      : `class="deploy-chk" data-idx="${idx}" ${chkChecked ? 'checked' : ''}`;

    // Src addr — simplified inline-editable
    let srcAddrCell;
    if (p.srcSubnets && p.srcSubnets.length > 1) {
      if (p._useSrcGroup) {
        // Group mode: show group name
        const srcGrpDisplay = p._srcAddrName || `FF_POLICY_${(p.policyIds||[])[0] || idx}_SRC`;
        srcAddrCell = p._srcAddrGrpFound
          ? `<span class="inline-editable found" data-idx="${idx}" data-field="_srcAddrName">${escHtml(p._srcAddrName)}</span>`
          : `<span class="inline-editable missing" data-idx="${idx}" data-field="_srcAddrName">${escHtml(srcGrpDisplay)} ${badgeHtml('auto')}</span>`;
      } else {
        // No group: show individual subnet names / host counts
        const subs = p._multiSrcSubnets || [];
        const srcFoundSet = new Set(p._srcHostsFound || []);
        const allDone = subs.every(s => {
          if (s.useSubnet !== false) return s.addrFound || !!s.addrName;
          return (s.hosts || []).every(h => srcFoundSet.has(h) || !!(p._srcHostNames?.[h]));
        });
        const names = subs.map(s => {
          if (s.useSubnet !== false) return s.addrName || s.subnet;
          const srcFoundSet2 = new Set(p._srcHostsFound || []);
          return (s.hosts || []).map(h => {
            if (srcFoundSet2.has(h)) return (p._srcHostNames?.[h]) || h;
            return (p._srcHostNames?.[h]) || h;
          }).join(', ');
        }).join(', ');
        srcAddrCell = allDone
          ? `<span class="inline-editable found" data-idx="${idx}" data-field="_srcAddrName" title="${escHtml(names)}">${escHtml(names)}</span>`
          : `<span class="inline-editable missing" data-idx="${idx}" data-field="_srcAddrName" title="${escHtml(names)}">${escHtml(names)} ${badgeHtml('auto')}</span>`;
      }
    } else if ((p._srcMode === 'hosts' || p._use32Src) && p.srcHosts?.length) {
      // /32 hosts mode (single src): show host names
      const hFoundSet = new Set(p._srcHostsFound || []);
      const hNames = p.srcHosts.map(h => (p._srcHostNames?.[h]) || (hFoundSet.has(h) ? h : h));
      const allNamed = p.srcHosts.every(h => hFoundSet.has(h) || !!(p._srcHostNames?.[h]));
      const hDisplay = hNames.join(', ');
      srcAddrCell = allNamed
        ? `<span class="inline-editable found" data-idx="${idx}" data-field="_srcAddrName" title="${escHtml(hDisplay)}">${escHtml(hDisplay)}</span>`
        : `<span class="inline-editable missing" data-idx="${idx}" data-field="_srcAddrName" title="${escHtml(hDisplay)}">${escHtml(hDisplay)} ${badgeHtml('auto')}</span>`;
    } else {
      srcAddrCell = addrCell(p.analysis?.srcAddr, p._srcAddrName, idx, '_srcAddrName');
    }

    // Dst addr — simplified
    const _dstModeResolved = p._dstMode || (p._use32Dst ? 'hosts' : 'subnet');
    let dstAddrCell;
    if (_dstModeResolved === 'hosts' && (p.dstHosts || []).length > 0) {
      const dhFoundSet = new Set(p._dstHostsFound || []);
      const dhNames = p.dstHosts.map(h => (p._dstHostNames?.[h]) || (dhFoundSet.has(h) ? h : h));
      const dhAllNamed = p.dstHosts.every(h => dhFoundSet.has(h) || !!(p._dstHostNames?.[h]));
      const dhDisplay = dhNames.join(', ');
      dstAddrCell = dhAllNamed
        ? `<span class="inline-editable found" data-idx="${idx}" data-field="_dstAddrName" title="${escHtml(dhDisplay)}">${escHtml(dhDisplay)}</span>`
        : `<span class="inline-editable missing" data-idx="${idx}" data-field="_dstAddrName" title="${escHtml(dhDisplay)}">${escHtml(dhDisplay)} ${badgeHtml('auto')}</span>`;
    } else if (p._isMultiDst && p._multiDstSubnets?.length) {
      if (p._useDstGroup) {
        const dstGrpDisplay = p._dstAddrName || `GRP_${(p.policyIds||[])[0] || idx}_DST`;
        dstAddrCell = p._dstAddrGrpFound
          ? `<span class="inline-editable found" data-idx="${idx}" data-field="_dstAddrName">${escHtml(p._dstAddrName)}</span>`
          : `<span class="inline-editable missing" data-idx="${idx}" data-field="_dstAddrName">${escHtml(dstGrpDisplay)} ${badgeHtml('auto')}</span>`;
      } else {
        const subs = p._multiDstSubnets;
        const dstFoundSet = new Set(p._dstHostsFound || []);
        const allDone = subs.every(s => {
          if (s.useSubnet !== false) return s.addrFound || !!s.addrName;
          return (s.hosts || []).every(h => dstFoundSet.has(h) || !!(p._dstHostNames?.[h]));
        });
        const names = subs.map(s => {
          if (s.useSubnet !== false) return s.addrName || s.subnet;
          const dstFoundSet2 = new Set(p._dstHostsFound || []);
          return (s.hosts || []).map(h => {
            return (p._dstHostNames?.[h]) || (dstFoundSet2.has(h) ? h : h);
          }).join(', ');
        }).join(', ');
        dstAddrCell = allDone
          ? `<span class="inline-editable found" data-idx="${idx}" data-field="_dstAddrName" title="${escHtml(names)}">${escHtml(names)}</span>`
          : `<span class="inline-editable missing" data-idx="${idx}" data-field="_dstAddrName" title="${escHtml(names)}">${escHtml(names)} ${badgeHtml('auto')}</span>`;
      }
    } else {
      dstAddrCell = addrCell(p.analysis?.dstAddr, p._dstAddrName, idx, '_dstAddrName');
    }

    // Services — compact
    const svcList = p.analysis?.services || [];
    const stripPredef = n => (n || '').replace(/PREDEFINED$/i, '');
    const svcCells = svcList.map(svc => {
      if (svc.found) {
        const dispName = stripPredef(svc.name);
        return `<span class="match-ok" style="font-size:10px" title="${escHtml(svc.portHint || stripPredef(svc.label) || dispName)}">&#10003; ${escHtml(dispName)}${badgeHtml('config')}</span>`;
      }
      const customName = svc.suggestedName && svc.suggestedName !== (svc.isNamed ? svc.label : `FF_SVC_${svc.port}_${svc.proto}`) ? svc.suggestedName : '';
      const displayName = customName || svc.label || (svc.port ? `${svc.port}/${svc.proto}` : '');
      return `<span class="match-ok" style="font-size:10px;color:var(--warn)" title="${escHtml(svc.portHint || displayName)}">${displayName ? escHtml(displayName) + ' ' : ''}${badgeHtml('auto')}</span>`;
    }).join(' ');

    // Interfaces — read-only text, editable in drawer
    let srcIntf, dstIntf;
    if (isAgg) {
      srcIntf = `<span class="mono" style="font-size:10px;color:var(--accent2)">${escHtml((p._srcintfList || []).join(', ') || '—')}</span>`;
      dstIntf = `<span class="mono" style="font-size:10px;color:var(--accent2)">${escHtml((p._dstintfList || []).join(', ') || '—')}</span>`;
    } else {
      const srcLabel = p._srcintf || 'auto';
      const dstLabel = p._dstintf || 'auto';
      const sameWarn = (p._srcintf && p._dstintf && p._srcintf === p._dstintf) ? ' ⚠' : '';
      const srcIfSrc = p._srcIfaceSource || 'auto';
      const dstIfSrc = p._dstIfaceSource || 'auto';
      const srcIfBadge = srcIfSrc === 'route' ? badgeHtml('route') : srcIfSrc === 'sdwan' ? badgeHtml('sdwan') : '';
      const dstIfBadge = dstIfSrc === 'route' ? badgeHtml('route') : dstIfSrc === 'sdwan' ? badgeHtml('sdwan') : '';
      srcIntf = `<span class="mono" style="font-size:10px;color:${p._srcintf ? 'var(--text)' : 'var(--text2)'}">${escHtml(srcLabel)}${srcIfBadge}</span>`;
      dstIntf = `<span class="mono" style="font-size:10px;color:${p._dstintf ? 'var(--text)' : 'var(--text2)'}">${escHtml(dstLabel)}${sameWarn}${dstIfBadge}</span>`;
    }

    const dirBadge = p._isWan
      ? `<span class="dir-badge wan">WAN</span>`
      : `<span class="dir-badge lan">LAN</span>`;

    // Impact
    const barW = Math.round(((p.sessions || 0) / maxSessions) * 100);

    // Warnings
    const rowWarnings = (deployState.warnings || []).filter(w => w.generatedIdx === idx);
    const warnBadge = rowWarnings.length > 0
      ? `<span class="conflict-warn" title="${escHtml(rowWarnings.map(w => w.detail).join('\n'))}">${rowWarnings[0].type === 'duplicate' ? '⚠ doublon' : '⚠ conflit'}</span>`
      : '';

    const seqBadge = isAgg ? `<span class="seq-badge">×${p._sequenceCount}</span> ` : '';
    const mergeBadge = (!isAgg && p._mergedCount > 1) ? ` <span class="merge-badge">×${p._mergedCount}</span>` : '';

    // Src subnet — compact
    const srcSubnetText = p.srcSubnets && p.srcSubnets.length > 1
      ? `${escHtml(p.srcSubnets[0])} <span class="dst-count-badge">+${p.srcSubnets.length - 1}</span>`
      : `${escHtml(p.srcSubnet)}${mergeBadge}`;

    // Mode indicator
    const srcMode = p._srcMode || (p._use32Src ? 'hosts' : 'subnet');
    const srcModeBadge = srcMode === 'hosts' ? ` <span class="dst-count-badge">/32</span>` : '';

    const rowStatus = isPolicyComplete(p) ? 'ok' : (p.analysis?.status || 'warn');
    const statusTitle = (p.analysis?.missingFields || []).join(', ') || '';
    return `
      <tr class="deploy-policy-row ${isAgg ? 'seq-row' : ''}" data-idx="${idx}" ${isAgg ? `data-seq-members="${p._sequenceMembers.join(',')}"` : ''}>
        <td><input type="checkbox" ${chkAttr}></td>
        <td class="status-cell" title="${escHtml(statusTitle)}"><div class="status-bar status-${rowStatus}"></div></td>
        <td class="impact-cell"><div class="impact-bar" style="width:${barW}%"></div><span class="impact-val">${fmtNum(p.sessions || 0)}</span></td>
        <td>${dirBadge}</td>
        <td>${warnBadge}${seqBadge}${srcSubnetText}${srcModeBadge}</td>
        <td>${srcAddrCell}</td>
        ${allSrcAutoFlag ? '' : `<td>${srcIntf}</td>`}
        <td>${dstTargetCell(p, idx)}</td>
        <td>${dstAddrCell}</td>
        ${allDstAutoFlag ? '' : `<td>${dstIntf}</td>`}
        <td>${svcCells || '<span style="color:var(--text2)">–</span>'}</td>
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
        <td colspan="10"><div class="intf-pair-header-inner">
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

  // (adaptive column flags computed above as allSrcAutoFlag / allDstAutoFlag)

  const body = el('deploy-policy-body');
  body.innerHTML = `
    <div style="margin-bottom:8px;font-size:12px;color:var(--text2);display:flex;align-items:center;gap:12px">
      <span>${total} policy(s) · <strong>${selCount}</strong> sélectionnées${hasMerge ? ' · <span style="color:var(--accent2)">⚡ fusion</span>' : ''}${
        (deployState.warnings || []).length > 0
          ? ` · <span style="color:var(--warn)">⚠ ${deployState.warnings.length} conflit${deployState.warnings.length > 1 ? 's' : ''}</span>`
          : ''
      }</span>
    </div>
    ${paginationBar}
    <div style="overflow-x:auto">
      <table class="deploy-policy-table">
        <thead><tr>
          <th><input type="checkbox" id="chk-all-deploy"></th>
          <th></th>
          <th>Sessions</th>
          <th>Dir.</th>
          <th>Source</th><th>Src addr</th>${allSrcAutoFlag ? '' : '<th>Src intf</th>'}
          <th>Destination</th><th>Dst addr</th>${allDstAutoFlag ? '' : '<th>Dst intf</th>'}
          <th>Services</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    ${paginationBar}`;

  el('deploy-step4-footer').style.display = '';

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

  // Update missing objects notification bar (info only)
  const missingBar = el('deploy-missing-bar');
  if (missingBar) {
    const missing = collectMissingObjects();
    missingBar.style.display = missing.total > 0 ? '' : 'none';
    const missingText = el('deploy-missing-text');
    if (missingText) missingText.textContent = `${missing.total} objet${missing.total > 1 ? 's' : ''} à nommer avant le déploiement (${missing.addresses.length + missing.hosts.length} adresses, ${missing.services.length} services)`;
  }
  // Show legend
  const legend = el('deploy-legend');
  if (legend) legend.style.display = '';

  // Wire select-all (current page only) — re-wired each render (pageIdxs change)
  const chkAll = el('chk-all-deploy');
  if (chkAll) {
    const pageIdxs = [];
    for (const p of pageSlice) {
      if (p._isAggregated && p._sequenceMembers) {
        pageIdxs.push(...p._sequenceMembers);
      } else {
        pageIdxs.push(policyIndexMap.get(p) ?? -1);
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

  // (iface dropdowns are pre-selected via buildIfaceDropdown — no post-render step needed)

  // Wire event delegation on deploy-policy-body (idempotent — only installed once)
  wireDeployTable();
}

async function generateDeployConf() {
  if (!deployState.analyzed) return;

  let selectedPolicies;
  if (deployState.viewMode === 'sequence') {
    // In sequence mode, aggregate selected policies before sending
    const selected = deployState.analyzed.filter((_, i) => deployState.selected.has(i) && isPolicyComplete(deployState.analyzed[i]));
    const aggregated = buildSequenceAggregated(selected);
    selectedPolicies = aggregated.map(p => ({
      ...p,
      services:        (p.analysis?.services || []).filter(s => !s._isMerged).map(s => s.label),
      _mergedServices: (p.analysis?.services || []).filter(s => s._isMerged).map(s => ({ name: s.suggestedName, ports: s.ports || null, portRange: s.portRange || null, proto: s.proto })),
      srcintf:      p._isAggregated ? (p._srcintfList || []) : (p._srcintf || p.srcintf || ''),
      dstintf:      p._isAggregated ? (p._dstintfList || []) : (p._dstintf || p.dstintf || ''),
      srcAddrName:  p._srcAddrName,
      dstAddrName:  p._dstAddrName,
      policyName:   p._policyName,
      nat:          p._nat ?? p._isWan,
      srcAddrNames: p.srcAddrNames || null,
      srcHosts:     (p.srcHosts || []).filter(h => !p._excludedSrcHosts?.has(h)),
      dstHosts:     (p.dstHosts || []).filter(h => !p._excludedDstHosts?.has(h)),
      tags:         p._tags || [],
    }));
  } else {
    selectedPolicies = deployState.analyzed
      .filter((_, i) => deployState.selected.has(i) && isPolicyComplete(deployState.analyzed[i]))
      .map(p => ({
        ...p,
        services:        (p.analysis?.services || []).filter(s => !s._isMerged).map(s => s.label),
        _mergedServices: (p.analysis?.services || []).filter(s => s._isMerged).map(s => ({ name: s.suggestedName, ports: s.ports || null, portRange: s.portRange || null, proto: s.proto })),
        srcintf:      p._srcintf || p.srcintf || '',
        dstintf:      p._dstintf || p.dstintf || '',
        srcAddrName:  p._srcAddrName,
        dstAddrName:  p._dstAddrName,
        policyName:   p._policyName,
        nat:          p._nat ?? p._isWan,
        srcAddrNames: p.srcAddrNames || null,
        srcHosts:     (p.srcHosts || []).filter(h => !p._excludedSrcHosts?.has(h)),
        dstHosts:     (p.dstHosts || []).filter(h => !p._excludedDstHosts?.has(h)),
        tags:         p._tags || [],
      }));
  }

  const skippedCount = deployState.analyzed.filter((_, i) => deployState.selected.has(i) && !isPolicyComplete(deployState.analyzed[i])).length;
  if (!selectedPolicies.length) {
    alert(skippedCount > 0
      ? `Aucune policy complète à générer.\n${skippedCount} policy${skippedCount > 1 ? 's' : ''} incomplète${skippedCount > 1 ? 's' : ''} ignorée${skippedCount > 1 ? 's' : ''} (badge rouge/orange sur la gauche).`
      : 'Sélectionnez au moins une policy');
    return;
  }
  if (skippedCount > 0) {
    const proceed = confirm(`${skippedCount} policy${skippedCount > 1 ? 's' : ''} incomplète${skippedCount > 1 ? 's' : ''} ignorée${skippedCount > 1 ? 's' : ''} (badge non vert).\n${selectedPolicies.length} policy${selectedPolicies.length > 1 ? 's' : ''} complète${selectedPolicies.length > 1 ? 's' : ''} seront générées.\n\nContinuer ?`);
    if (!proceed) return;
  }

  // Security profiles from dropdowns
  const securityProfiles = {};
  const spAv  = el('sp-av')?.value;   if (spAv)  securityProfiles.antivirus  = spAv;
  const spWf  = el('sp-wf')?.value;   if (spWf)  securityProfiles.webfilter  = spWf;
  const spIps = el('sp-ips')?.value;   if (spIps) securityProfiles.ips        = spIps;
  const spSsl = el('sp-ssl')?.value;   if (spSsl) securityProfiles.sslSsh     = spSsl;

  const opts = {
    nat:    el('opt-nat')?.checked || false,
    action: el('opt-action')?.value || 'accept',
    log:    el('opt-log')?.value   || 'all',
    securityProfiles,
  };

  const btn = el('btn-generate');
  if (btn) { btn.disabled = true; btn.textContent = 'Validation…'; }

  // Preflight validation
  try {
    const pfRes = await fetch(`/api/deploy/preflight?session=${state.session}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ selectedPolicies }),
    });
    if (pfRes.ok) {
      const pf = await pfRes.json();
      if (pf.errors > 0 || pf.warnings > 0) {
        const proceed = await showPreflightModal(pf);
        if (!proceed) { if (btn) { btn.disabled = false; btn.textContent = '⬇ Générer config FortiGate'; } return; }
      }
    }
  } catch { /* non-bloquant */ }

  if (btn) btn.textContent = 'Génération…';

  try {
    // Fetch JSON (not download) to get CLI text for inline preview
    const r = await fetch(`/api/deploy/generate?session=${state.session}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ selectedPolicies, opts }),
    });
    if (!r.ok) { const e = await r.json(); alert(e.error || 'Erreur génération'); return; }
    const { cli, existingPoliciesCli } = await r.json();

    deployState.generatedCli      = cli;
    deployState.existingPoliciesCli = existingPoliciesCli || '';

    // Show inline preview
    const wrap = el('deploy-cli-wrap');
    const pre  = el('deploy-cli-pre');
    const info = el('deploy-gen-info');
    if (pre)  pre.value = cli;
    if (wrap) wrap.style.display = '';
    if (info) info.textContent = `${selectedPolicies.length} policies · ${cli.split('\n').length} lignes`;

    // Show diff button only if existing config available
    const diffBtn = el('btn-diff-toggle');
    if (diffBtn) diffBtn.style.display = existingPoliciesCli ? '' : 'none';

    // Sync textarea edits back to state
    pre.addEventListener('input', () => { deployState.generatedCli = pre.value; });

    // Wire copy + download buttons (onclick= to avoid accumulating listeners)
    const btnCopy = el('btn-copy-cli');
    if (btnCopy) btnCopy.onclick = () => {
      const text = el('deploy-cli-pre')?.value || deployState.generatedCli || '';
      navigator.clipboard.writeText(text).then(() => {
        if (btnCopy) { const old = btnCopy.textContent; btnCopy.textContent = '✓ Copié !'; setTimeout(() => { btnCopy.textContent = old; }, 1800); }
      });
    };
    const btnDl = el('btn-download-cli');
    if (btnDl) btnDl.onclick = () => {
      const text = el('deploy-cli-pre')?.value || deployState.generatedCli || '';
      const blob = new Blob([text], { type: 'text/plain' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href = url; a.download = 'fortiflow_deploy.conf'; a.click();
      URL.revokeObjectURL(url);
    };
    const btnToggle = el('btn-cli-toggle');
    if (btnToggle) btnToggle.onclick = () => {
      const p2 = el('deploy-cli-pre');
      const b  = el('btn-cli-toggle');
      if (!p2 || !b) return;
      const collapsed = p2.style.display === 'none';
      p2.style.display = collapsed ? '' : 'none';
      b.textContent = collapsed ? '▾ Réduire' : '▸ Développer';
    };
    const btnDiff = el('btn-diff-toggle');
    if (btnDiff) btnDiff.onclick = () => {
      const wrap = el('deploy-diff-wrap');
      const btn  = el('btn-diff-toggle');
      if (!wrap) return;
      const visible = wrap.style.display !== 'none';
      if (visible) { wrap.style.display = 'none'; btn.textContent = '⊕ Diff'; return; }
      // Build diff
      const genLines = (deployState.generatedCli || '').split('\n');
      const extLines = (deployState.existingPoliciesCli || '').split('\n');
      const extSet   = new Set(extLines);
      const genSet   = new Set(genLines);
      const renderPanel = (lines, refSet, label, addCls, delCls) =>
        `<div class="diff-panel"><div class="diff-panel-header">${label}</div><div class="diff-panel-body">${
          lines.map(l => {
            const cls = refSet.has(l) ? 'diff-line-same' : (label === 'Généré' ? addCls : delCls);
            return `<div class="diff-line ${cls}">${escHtml(l)}</div>`;
          }).join('')
        }</div></div>`;
      const html = `<div class="diff-panel-wrap">${
        renderPanel(extLines, genSet, 'Existant',  'diff-line-del', 'diff-line-del') +
        renderPanel(genLines, extSet, 'Généré',    'diff-line-add', 'diff-line-add')
      }</div>`;
      wrap.style.display = '';
      btn.textContent = '✕ Fermer diff';
      // safe: only escHtml user content used
      wrap.innerHTML = html; // nosec — content sanitized via escHtml
    };

    // Scroll to preview
    wrap?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (err) {
    alert('Erreur : ' + err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '⬇ Générer config FortiGate'; }
  }
}

// ─── Preflight modal ─────────────────────────────────────────────────────────

function showPreflightModal(pf) {
  return new Promise(resolve => {
    const errors  = pf.issues.filter(i => i.level === 'error');
    const warns   = pf.issues.filter(i => i.level === 'warn');
    const icon    = pf.errors > 0 ? '🛑' : '⚠️';
    const title   = pf.errors > 0 ? 'Erreurs détectées' : 'Avertissements';

    const errHtml = errors.map(i => `<div class="preflight-item pf-error">✗ ${escHtml(i.msg)}</div>`).join('');
    const warnHtml = warns.map(i => `<div class="preflight-item pf-warn">⚠ ${escHtml(i.msg)}</div>`).join('');

    const overlay = document.createElement('div');
    overlay.className = 'preflight-overlay';
    overlay.innerHTML = `
      <div class="preflight-modal">
        <div class="preflight-title">${icon} ${title}</div>
        ${errors.length ? `<div class="preflight-section"><div class="preflight-section-title">Erreurs (${errors.length})</div>${errHtml}</div>` : ''}
        ${warns.length ? `<div class="preflight-section"><div class="preflight-section-title">Avertissements (${warns.length})</div>${warnHtml}</div>` : ''}
        <div class="preflight-actions">
          <button class="btn-sm" id="pf-cancel">Annuler</button>
          ${pf.errors === 0 ? `<button class="btn-accent" id="pf-continue">Continuer quand même</button>` : `<button class="btn-accent" id="pf-continue">Forcer la génération</button>`}
        </div>
      </div>`;

    document.body.appendChild(overlay);
    overlay.querySelector('#pf-cancel').addEventListener('click', () => { overlay.remove(); resolve(false); });
    overlay.querySelector('#pf-continue').addEventListener('click', () => { overlay.remove(); resolve(true); });
    overlay.addEventListener('click', e => { if (e.target === overlay) { overlay.remove(); resolve(false); } });
  });
}

// ═══════════════════════════════════════════════════════════════
// Init & event wiring
// ═══════════════════════════════════════════════════════════════

document.querySelectorAll('.nav-item[data-view]').forEach(item => {
  item.addEventListener('click', () => navigateTo(item.dataset.view));
  item.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); navigateTo(item.dataset.view); }
  });
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


// Close any open iface-dd when clicking outside
document.addEventListener('click', () => {
  document.querySelectorAll('.iface-dd.open').forEach(d => d.classList.remove('open'));
});

// Start
navigateTo('dashboard');
