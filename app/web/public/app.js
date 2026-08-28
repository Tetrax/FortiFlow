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
  flows:    { page: 1, filters: {}, sort: 'count', order: 'desc', total: 0, _fromPolicy: null },
  policies: { dst_type: '', viewMode: 'aggregated', includeNoRcvd: false },
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
const tsNow  = () => new Date().toISOString().slice(0, 19).replace('T', '_').replace(/:/g, '-');

function fmtBytes(n) {
  n = n || 0;
  if (n < 1024)         return `${n} B`;
  if (n < 1024 ** 2)    return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3)    return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

function fmtRelDate(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)   return 'à l\'instant';
  if (m < 60)  return `il y a ${m}min`;
  const h = Math.floor(m / 60);
  if (h < 24)  return `il y a ${h}h`;
  const d = Math.floor(h / 24);
  return `il y a ${d}j`;
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

  // Proposer de nommer et sauvegarder le workspace dans l'historique
  const defaultName = (state.meta?.filename || 'workspace').replace(/\.[^.]+$/, '');
  const wsName = await promptWorkspaceName(defaultName);
  if (wsName) {
    try {
      await fetch(`/api/workspaces?session=${state.session}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: wsName }),
      });
      await loadWsHistory();
    } catch {}
  }
}

function showError(msg) {
  el(_renderTarget || 'content').innerHTML = `<div class="alert alert-error">⚠ ${escHtml(msg)}</div>`;
}

// ═══════════════════════════════════════════════════════════════
// Workspace history
// ═══════════════════════════════════════════════════════════════

async function loadWsHistory() {
  try {
    const r = await fetch('/api/workspaces');
    if (!r.ok) return;
    const list = await r.json();
    const section = el('sidebar-history');
    const container = el('ws-history-list');
    if (!section || !container) return;
    if (!list.length) { section.style.display = 'none'; return; }
    section.style.display = '';
    container.innerHTML = list.map(ws => `
      <div class="ws-history-item" data-wsid="${escHtml(ws.id)}" title="${escHtml(ws.name)}">
        <span class="ws-name">${escHtml(ws.name)}</span>
        <span class="ws-date">${fmtRelDate(ws.createdAt)}</span>
        <button class="ws-del" data-del="${escHtml(ws.id)}" title="Supprimer">×</button>
      </div>
    `).join('');

    // Clic sur un workspace → charger
    container.querySelectorAll('.ws-history-item').forEach(item => {
      item.addEventListener('click', async (e) => {
        if (e.target.dataset.del) {
          e.stopPropagation();
          await deleteWsHistory(e.target.dataset.del);
          return;
        }
        loadWsFromHistory(item.dataset.wsid);
      });
    });
  } catch {}
}

async function deleteWsHistory(id) {
  try {
    await fetch(`/api/workspaces/${id}`, { method: 'DELETE' });
    await loadWsHistory();
  } catch {}
}

async function loadWsFromHistory(id) {
  try {
    const r = await fetch(`/api/workspaces/${id}`);
    if (!r.ok) { const e = await r.json().catch(() => ({})); alert(e.error || 'Erreur chargement'); return; }
    const { sessionId } = await r.json();
    state.session = sessionId;
    try {
      const sr = await fetch(`/api/stats?session=${sessionId}`);
      if (sr.ok) { const d = await sr.json(); state.stats = d.stats; state.meta = d.meta; }
    } catch {}
    updateSidebar();
    navigateTo('dashboard');
  } catch (err) { alert('Erreur: ' + err.message); }
}

function promptWorkspaceName(defaultName) {
  return new Promise(resolve => {
    const modal = document.createElement('div');
    modal.className = 'ws-name-modal-overlay';
    modal.innerHTML = `
      <div class="ws-name-modal">
        <h3>💾 Nommer ce workspace</h3>
        <p>Donnez un nom à cette analyse pour la retrouver facilement dans l'historique.</p>
        <input id="ws-name-input" type="text" maxlength="80" placeholder="Ex: Client XYZ — Audit VPN" value="${escHtml(defaultName)}">
        <div class="ws-modal-btns">
          <button class="btn-sm" id="ws-skip">Passer</button>
          <button class="btn-accent" id="ws-save-name">Sauvegarder</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
    const input = modal.querySelector('#ws-name-input');
    input.select();
    const doSave = () => { modal.remove(); resolve(input.value.trim() || defaultName); };
    const doSkip = () => { modal.remove(); resolve(null); };
    modal.querySelector('#ws-save-name').addEventListener('click', doSave);
    modal.querySelector('#ws-skip').addEventListener('click', doSkip);
    input.addEventListener('keydown', e => { if (e.key === 'Enter') doSave(); if (e.key === 'Escape') doSkip(); });
  });
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
      <div style="text-align:center;margin-bottom:18px">
        <label style="display:inline-flex;align-items:center;gap:8px;cursor:pointer;
          padding:9px 20px;border-radius:6px;border:1px solid var(--border2);
          background:var(--bg2);color:var(--text2);font-size:13px;
          transition:border-color .2s,color .2s"
          onmouseover="this.style.borderColor='var(--brand)';this.style.color='var(--text)'"
          onmouseout="this.style.borderColor='var(--border2)';this.style.color='var(--text2)'">
          💾 Reprendre un workspace <em style="font-size:11px;opacity:.7">(.ffws)</em>
          <input type="file" id="btn-import-workspace-upload" accept=".ffws,.json" style="display:none">
        </label>
      </div>
      <div class="drop-area" id="drop-area">
        <div class="drop-icon">📂</div>
        <div class="drop-title">Déposez votre fichier de log</div>
        <div class="drop-sub">
          Formats supportés : <em>.log</em> · <em>.txt</em> · <em>.csv</em> · <em>.xlsx</em> · <em>.gz</em> · <em>.zip</em><br>
          FortiGate syslog (key=value) et exports FortiAnalyzer (CSV / XLSX)<br>
          Fichiers jusqu'à 400 Mo — parsing streamé côté serveur
        </div>
        <br>
        <button class="upload-btn" id="btn-pick">Choisir un fichier</button>
      </div>
    </div>`;

  el('btn-pick').addEventListener('click', () => el('file-input').click());
  el('btn-import-workspace-upload').addEventListener('change', e => {
    const f = e.target.files[0];
    if (f) importSession(f);
  });

  const drop = el('drop-area');
  drop.addEventListener('dragover',  e => { e.preventDefault(); drop.classList.add('dragover'); });
  drop.addEventListener('dragleave', ()=> drop.classList.remove('dragover'));
  drop.addEventListener('drop', e => {
    e.preventDefault();
    drop.classList.remove('dragover');
    const f = e.dataTransfer.files[0];
    // Si c'est un workspace, on le redirige vers importSession
    if (f && (f.name.endsWith('.ffws') || f.name.endsWith('.json'))) {
      importSession(f);
    } else {
      handleUpload(f);
    }
  });
}

// ═══════════════════════════════════════════════════════════════
// View: Dashboard
// ═══════════════════════════════════════════════════════════════

async function dashboard() {
  if (!state.session) { renderUpload(); return; }

  const s  = state.stats;
  const m  = state.meta;
  let policyCount = 0;
  try {
    const policyData = await api('/api/policies?include_no_rcvd=1');
    policyCount = (policyData.policies || policyData || []).length;
  } catch { /* le dashboard reste disponible si les policies ne sont pas prêtes */ }

  el(_renderTarget || 'content').innerHTML = `
    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-value">${fmtNum(s.totalSessions)}</div>
        <div class="stat-label">Sessions analysées</div>
      </div>
      <div class="stat-card">
        <div class="stat-value blue">${fmtNum(s.uniqueFlows)}</div>
        <div class="stat-label">Flux analysés</div>
      </div>
      <div class="stat-card">
        <div class="stat-value blue">${fmtNum(s.srcSubnets)}</div>
        <div class="stat-label">Réseaux détectés</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${fmtNum(policyCount)}</div>
        <div class="stat-label">Policies proposées</div>
      </div>
    </div>

    <div class="section-header" style="margin-top:8px;">
      <div>
        <div class="section-title">Fichier analysé</div>
        <div class="section-sub">${m?.filename || ''} — ${fmtNum(s.totalSessions)} sessions · ${fmtBytes(s.totalBytes)} · ${fmtNum(m?.lineCount)} lignes · ${fmtNum(m?.skipped || 0)} ignorées${m?.skipReasons ? ` (${fmtNum(m.skipReasons.nonTraffic || 0)} non-traffic, ${fmtNum(m.skipReasons.invalidFlow || 0)} invalides)` : ''}</div>
      </div>
      <div style="display:flex;gap:8px;">
        <button class="export-btn primary" onclick="navigateTo('policies')">◎ Voir les policies</button>
        <button class="upload-btn" style="font-size:12px;padding:7px 14px;" onclick="el('file-input').click()">+ Nouveau fichier</button>
        <button class="btn-sm" onclick="exportSession()" title="Sauvegarder tout le workspace (logs + conf + policies) pour reprendre plus tard">💾 Sauvegarder workspace</button>
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
      <div class="stat-card" style="cursor:pointer;" onclick="state.subView.analyse='matrix';navigateTo('analyse')">
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
    <div id="policy-filter-banner"></div>
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
    state.flows._fromPolicy = null;
    state.flows.page = 1;
    ['f-srcip','f-dstip','f-port','f-proto','f-action','f-dst-type'].forEach(id => {
      const e = el(id);
      if (e.tagName === 'SELECT') e.value = '';
      else e.value = '';
    });
    const banner = el('policy-filter-banner');
    if (banner) banner.textContent = '';
    loadFlows();
  }, { signal });

  // Bannière filtre depuis déploiement
  if (state.flows._fromPolicy) {
    const banner = el('policy-filter-banner');
    if (banner) {
      const f = state.flows.filters;
      const parts = [];
      if (f.srcSubnet) parts.push(`src : ${f.srcSubnet}`);
      if (f.dstTarget) parts.push(`dst : ${f.dstTarget}`);
      if (f.service)   parts.push(`svc : ${f.service}`);
      const wrap = document.createElement('div');
      wrap.style.cssText = 'background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.27);border-radius:6px;padding:6px 12px;margin-bottom:6px;font-size:12px;display:flex;justify-content:space-between;align-items:center;gap:8px';
      const info = document.createElement('span');
      const bold = document.createElement('strong');
      bold.textContent = state.flows._fromPolicy;
      const hint = document.createElement('span');
      hint.style.cssText = 'color:var(--text3);margin-left:8px';
      hint.textContent = parts.join(' · ');
      info.append('Filtré depuis deploy — ', bold, hint);
      const clearBtn = document.createElement('button');
      clearBtn.className = 'btn-sm';
      clearBtn.textContent = '✕ Effacer';
      clearBtn.addEventListener('click', () => {
        state.flows.filters = {};
        state.flows._fromPolicy = null;
        state.flows.page = 1;
        banner.textContent = '';
        loadFlows();
      }, { signal });
      wrap.append(info, clearBtn);
      banner.append(wrap);
    }
  }

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
        <div class="section-title">Matrice réseau LAN → LAN</div>
        <div class="section-sub">Communications observées entre réseaux privés · intensité selon le nombre de sessions</div>
      </div>
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <div class="matrix-toggle">
          <button class="toggle-btn ${state.matrix.action === 'accept' ? 'active accept' : ''}" data-action="accept">✔ Acceptés</button>
          <button class="toggle-btn ${state.matrix.action === 'deny'   ? 'active deny'   : ''}" data-action="deny">✖ Refusés</button>
        </div>
        <div style="display:flex;gap:6px">
          <button id="btn-matrix-export-img"  class="btn-sm" title="Exporter en image PNG">⬇ PNG</button>
          <button id="btn-matrix-export-xlsx" class="btn-sm" title="Exporter en Excel">⬇ Excel</button>
        </div>
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

  // ── Export PNG ──
  el('btn-matrix-export-img')?.addEventListener('click', () => {
    const canvas = el('matrix-canvas');
    if (!canvas) return;
    canvas.toBlob(blob => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `fortiflow_matrix_${state.matrix.action}_${tsNow()}.png`;
      a.click();
      URL.revokeObjectURL(url);
    });
  }, { signal });

  // ── Export Excel ──
  el('btn-matrix-export-xlsx')?.addEventListener('click', () => {
    window.location = `/api/export/matrix?action=${state.matrix.action}&session=${state.session}`;
  }, { signal });

  try {
    const data = await api(`/api/matrix?action=${state.matrix.action}`);
    renderMatrix(data, state.matrix.action, signal);
  } catch (e) {
    el('matrix-wrap').innerHTML = `<div class="alert alert-error">${escHtml(e.message)}</div>`; // eslint-disable-line
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

  const availableMatrixWidth = Math.max(480, (el('matrix-wrap')?.clientWidth || 900) - 180);
  const CELL  = Math.max(38, Math.min(92, Math.floor(availableMatrixWidth / Math.max(srcSubnets.length, dstSubnets.length))));
  const FONT  = `${CELL >= 72 ? 12 : 11}px monospace`;
  const PAD   = 8;

  // Measure the longest label to set left margin dynamically
  const tmpCanvas = document.createElement('canvas');
  const tmpCtx    = tmpCanvas.getContext('2d');
  tmpCtx.font = FONT;
  const longestSrc = Math.max(...srcSubnets.map(s => tmpCtx.measureText(s).width));
  const longestDst = Math.max(...dstSubnets.map(s => tmpCtx.measureText(s).width));

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
  const rootStyle = getComputedStyle(document.documentElement);
  const cssColor = (name, fallback) => rootStyle.getPropertyValue(name).trim() || fallback;
  const parseColor = (value) => {
    const hex = value.match(/^#([0-9a-f]{6})$/i);
    if (hex) return [parseInt(hex[1].slice(0,2),16), parseInt(hex[1].slice(2,4),16), parseInt(hex[1].slice(4,6),16)];
    const rgb = value.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/i);
    return rgb ? [Number(rgb[1]), Number(rgb[2]), Number(rgb[3])] : [80, 80, 110];
  };
  const mix = (from, to, amount) => {
    const a = parseColor(from), b = parseColor(to);
    return `rgb(${a.map((value, i) => Math.round(value + (b[i] - value) * amount)).join(',')})`;
  };
  const matrixBg = cssColor('--bg1', '#101018');
  const matrixCell = cssColor('--bg2', '#161622');
  const matrixDiagonal = cssColor('--bg3', '#202034');
  const matrixAccept = cssColor('--accent2', '#6b9ee8');
  const matrixDeny = cssColor('--danger', '#c95252');
  const matrixText = cssColor('--text2', '#9090b0');

  // Background
  ctx.fillStyle = matrixBg;
  ctx.fillRect(0, 0, W, H);

  // Legend canvas — vert pour accept, rouge pour deny
  const lc = el('legend-canvas');
  if (lc) {
    const lctx = lc.getContext('2d');
    const grad = lctx.createLinearGradient(0, 0, 120, 0);
    grad.addColorStop(0, matrixBg);
    if (mode === 'deny') {
      grad.addColorStop(0.5, mix(matrixBg, matrixDeny, 0.55));
      grad.addColorStop(1, matrixDeny);
    } else {
      grad.addColorStop(0.5, mix(matrixBg, matrixAccept, 0.55));
      grad.addColorStop(1, matrixAccept);
    }
    lctx.fillStyle = grad;
    lctx.fillRect(0, 0, 120, 12);
  }

  // Cell map for hit detection
  const cellMap = new Map();
  cells.forEach(c => cellMap.set(`${c.si},${c.di}`, c));

  // Draw column labels (dst subnets) — rotated -45°, anchored at bottom-left of each column
  ctx.font = FONT;
  ctx.fillStyle = matrixText;
  ctx.textAlign = 'left';
  for (let di = 0; di < dstSubnets.length; di++) {
    const x = LABEL_LEFT + di * CELL + CELL / 2;
    const y = LABEL_TOP - 6;
    ctx.save();
    ctx.translate(x, y);
    ctx.rotate(-Math.PI / 4);
    ctx.fillText(dstSubnets[di], 0, 0);
    ctx.restore();
  }

  // Draw row labels (src subnets) — right-aligned, vertically centred on each row
  ctx.font = FONT;
  ctx.fillStyle = matrixText;
  ctx.textAlign = 'right';
  ctx.textBaseline = 'middle';
  for (let si = 0; si < srcSubnets.length; si++) {
    const y = LABEL_TOP + si * CELL + CELL / 2;
    ctx.fillText(srcSubnets[si], LABEL_LEFT - 8, y);
  }
  ctx.textBaseline = 'alphabetic';

  // Draw cells
  for (let si = 0; si < srcSubnets.length; si++) {
    for (let di = 0; di < dstSubnets.length; di++) {
      const x = LABEL_LEFT + di * CELL;
      const y = LABEL_TOP  + si * CELL;

      // Grid cell background
      ctx.fillStyle = si === di ? matrixDiagonal : matrixCell;
      ctx.beginPath();
      ctx.roundRect(x + 2, y + 2, CELL - 4, CELL - 4, 4);
      ctx.fill();

      const c = cellMap.get(`${si},${di}`);
      if (c) {
        const t = maxCount > 0 ? Math.log1p(c.count) / Math.log1p(maxCount) : 0;
        ctx.fillStyle = mix(matrixCell, mode === 'deny' ? matrixDeny : matrixAccept, 0.25 + t * 0.75);
        ctx.beginPath();
        ctx.roundRect(x + 2, y + 2, CELL - 4, CELL - 4, 4);
        ctx.fill();

        // Session count inside cell
        const textColor = t > 0.55 ? cssColor('--bg0', '#09090e') : cssColor('--text', '#f0eef8');
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
            <div class="dst-ip">${typeTag(d.type)} ${d.key}</div>
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
  state.flows._fromPolicy = null;
  state.flows.page = 1;
  navigateTo('flows');
}
window.filterFlowsByHost = filterFlowsByHost;

function filterFlowsByPolicy(idx) {
  const p = deployState.analyzed?.[idx];
  if (!p) return;
  const filters = {};
  if (!p._multiSrcSubnets?.length && p.srcSubnet) filters.srcSubnet = p.srcSubnet;
  if (p.dstTarget) filters.dstTarget = p.dstTarget;
  const svcs = p.analysis?.services || [];
  const svcLabel = svcs.length === 1
    ? (svcs[0].label || svcs[0].name || '')
    : (p.serviceDesc || '');
  if (svcLabel) filters.service = svcLabel.toUpperCase();
  state.flows.filters = filters;
  state.flows._fromPolicy = p._policyName || (p.policyIds || [])[0] || `#${idx}`;
  state.flows.page = 1;
  state.subView.analyse = 'flows';
  closeDrawer();
  navigateTo('analyse');
}
window.filterFlowsByPolicy = filterFlowsByPolicy;

// ═══════════════════════════════════════════════════════════════
// View: Policies
// ═══════════════════════════════════════════════════════════════

async function policies() {
  if (_viewAbort) _viewAbort.abort();
  _viewAbort = new AbortController();
  const { signal } = _viewAbort;

  const wrap0 = el(_renderTarget || 'content');
  wrap0.innerHTML = [
    '<div class="filter-bar">',
    '  <select class="filter-select" id="p-dst-type">',
    '    <option value="">Toutes destinations</option>',
    '    <option value="private">LAN uniquement</option>',
    '    <option value="public">WAN uniquement</option>',
    '  </select>',
    '  <button class="filter-btn" id="btn-apply-policy-filter">Filtrer</button>',
    '  <div class="view-toggle-group" id="policy-view-toggle">',
    '    <button class="view-toggle-btn active" data-vmode="aggregated">Agr\u00e9g\u00e9e</button>',
    '    <button class="view-toggle-btn" data-vmode="raw">D\u00e9taill\u00e9e</button>',
    '  </div>',
    '  <span style="margin-left:auto;display:flex;gap:8px;">',
    '    <a class="export-btn primary" id="btn-export-policies" href="#">\u2b07 Export CSV FortiGate</a>',
    '  </span>',
    '</div>',
    '<div id="policies-wrap"></div>',
  ].join('\n');

  // Restore active state from current viewMode
  el('policy-view-toggle').querySelectorAll('.view-toggle-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.vmode === state.policies.viewMode);
  });

  el('btn-apply-policy-filter').addEventListener('click', () => {
    state.policies.dst_type = el('p-dst-type').value;
    loadPolicies();
  }, { signal });

  el('policy-view-toggle').addEventListener('click', e => {
    const btn = e.target.closest('[data-vmode]');
    if (!btn) return;
    state.policies.viewMode = btn.dataset.vmode;
    el('policy-view-toggle').querySelectorAll('.view-toggle-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.vmode === state.policies.viewMode);
    });
    loadPolicies();
  }, { signal });

  el('btn-export-policies').addEventListener('click', e => {
    e.preventDefault();
    const q = state.policies.dst_type ? 'dst_type=' + state.policies.dst_type : '';
    window.location = '/api/export/policies' + (q ? '?' + q : '') + (q ? '&' : '?') + 'session=' + state.session;
  }, { signal });

  loadPolicies();
}

async function loadPolicies() {
  const wrap = el('policies-wrap');
  if (!wrap) return;
  wrap.innerHTML = '<div class="empty-state"><div class="progress-spinner" style="margin:0 auto"></div></div>';

  try {
    const params = new URLSearchParams();
    if (state.policies.dst_type)    params.set('dst_type', state.policies.dst_type);
    if (state.policies.includeNoRcvd) params.set('include_no_rcvd', '1');
    const qs = params.toString() ? '?' + params.toString() : '';

    const endpoint = state.policies.viewMode === 'raw' ? '/api/raw-policies' : '/api/policies';
    const data = await api(endpoint + qs);
    const { policies, excluded } = data;

    el('badge-policies').textContent = fmtNum(policies.length);
    const policesEl = el('badge-polices');
    if (policesEl) policesEl.textContent = fmtNum(policies.length);
    renderPoliciesTable(policies, excluded);
  } catch (e) {
    wrap.innerHTML = '<div class="alert alert-error">' + escHtml(e.message) + '</div>';
  }
}

function renderPoliciesTable(policies, excluded) {
  const wrap = el('policies-wrap');
  if (!policies.length) {
    wrap.innerHTML = '<div class="empty-state"><div class="empty-icon">\u25ce</div><div class="empty-msg">Aucune policy trouvée</div></div>';
    return;
  }

  const rows = policies.map((p, i) => {
    const pid    = 'pd-' + i;
    const srcB64 = btoa(p.srcSubnet);
    const dstB64 = btoa(p.dstTarget);
    const serviceItems = String(p.serviceDesc || '').split(',').map(item => item.trim()).filter(Boolean);
    const serviceCell = `${serviceItems.slice(0, 8).map(escHtml).join(', ')}${serviceItems.length > 8 ? ` <span class="compact-more">+${serviceItems.length - 8} autres</span>` : ''}`;
    const drillBtn = p.srcSubnet && p.dstTarget
      ? '<button class="drill-btn" onclick="togglePolicyDrill(' + i + ',\'' + srcB64 + '\',\'' + dstB64 + '\')">&#9662; H\u00f4tes</button>'
      : '';
    return '<tr id="pr-' + i + '">'
      + '<td class="mono" style="color:var(--text2)">' + (i + 1) + '</td>'
      + '<td class="mono">' + typeTag('private') + ' ' + escHtml(p.srcSubnet) + '</td>'
      + '<td class="mono">' + typeTag(p.dstType) + ' ' + escHtml(p.dstTarget) + '</td>'
      + '<td style="max-width:320px;white-space:normal;font-family:var(--mono);font-size:11px;line-height:1.7">' + serviceCell + '</td>'
      + '<td class="mono">' + (p.sessions > 0 ? fmtNum(p.sessions) : '\u2013') + '</td>'
      + '<td class="mono">' + fmtBytes(p.sentBytes + p.rcvdBytes) + '</td>'
      + '<td>' + actionTag(p.action) + '</td>'
      + '<td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;font-family:var(--mono);font-size:10px;color:var(--text2)">' + escHtml(p.name || '') + '</td>'
      + '<td>' + drillBtn + '</td>'
      + '</tr>'
      + '<tr id="' + pid + '" class="policy-drill-row" style="display:none;">'
      + '<td colspan="9"><div id="' + pid + '-content" class="policy-drill-content"></div></td>'
      + '</tr>';
  }).join('');

  const isRaw = state.policies.viewMode === 'raw';
  const srcHeader = isRaw ? 'Source /32' : 'Source (réseau)';
  const dstHeader = isRaw ? 'Destination /32' : 'Destination';
  const countLabel = fmtNum(policies.length) + ' règle' + (policies.length > 1 ? 's' : '') + ' — ordonnées par volume de sessions';

  // Banner exclusions
  const parts = ['<div id="policies-wrap-inner">'];
  if (excluded && excluded.total > 0) {
    const sample = excluded.dstTargets.length > 0
      ? ' (ex\u00a0: ' + excluded.dstTargets.slice(0, 3).map(escHtml).join(', ') + (excluded.dstTargets.length > 3 ? '\u2026' : '') + ')'
      : '';
    parts.push('<div class="excluded-banner">');
    parts.push('<span class="excluded-icon">\u26a0</span>');
    parts.push('<span>' + fmtNum(excluded.total) + ' r\u00e8gle' + (excluded.total > 1 ? 's exclues' : ' exclue') + ' — aucun trafic re\u00e7u en retour' + sample + '</span>');
    parts.push('<button class="excluded-toggle" onclick="toggleIncludeNoRcvd()">Inclure quand m\u00eame</button>');
    parts.push('</div>');
  } else if (state.policies.includeNoRcvd) {
    parts.push('<div class="excluded-banner excluded-banner-info">');
    parts.push('<span>Flux sans r\u00e9ponse inclus dans ces r\u00e8gles</span>');
    parts.push('<button class="excluded-toggle" onclick="toggleIncludeNoRcvd()">Filtrer \u00e0 nouveau</button>');
    parts.push('</div>');
  }
  parts.push('<div style="margin-bottom:8px;font-size:12px;color:var(--text2)">' + countLabel + '</div>');
  parts.push('<div class="table-wrap"><table>');
  parts.push('<thead><tr><th>#</th><th>' + srcHeader + '</th><th>' + dstHeader + '</th><th>Services / Ports</th><th>Sessions</th><th>Volume</th><th>Action</th><th>Nom sugg\u00e9r\u00e9</th><th></th></tr></thead>');
  parts.push('<tbody>' + rows + '</tbody>');
  parts.push('</table></div>');
  parts.push('</div>');
  wrap.innerHTML = parts.join('');
}

function toggleIncludeNoRcvd() {
  state.policies.includeNoRcvd = !state.policies.includeNoRcvd;
  loadPolicies();
}
window.toggleIncludeNoRcvd = toggleIncludeNoRcvd;

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

let _consilData = null; // { consolidated: [...], stats: { ... } } — pour le merge

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
    _consilData = data;
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
            <th style="width:28px"></th>
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

  // Merge bar (DOM, pas d'innerHTML dynamique)
  const mergeBar = document.createElement('div');
  mergeBar.id = 'cp-merge-bar';
  mergeBar.className = 'cp-merge-bar';
  mergeBar.style.display = 'none';
  const mergeCount = document.createElement('span');
  mergeCount.id = 'cp-merge-count';
  mergeCount.textContent = '0 policies sélectionnées';
  const mergeBtn = document.createElement('button');
  mergeBtn.className = 'btn-merge';
  mergeBtn.textContent = 'Fusionner';
  mergeBtn.addEventListener('click', mergeConsilPolicies);
  const cancelBtn = document.createElement('button');
  cancelBtn.className = 'filter-btn reset';
  cancelBtn.textContent = 'Annuler';
  cancelBtn.addEventListener('click', clearCpSelection);
  mergeBar.appendChild(mergeCount);
  mergeBar.appendChild(mergeBtn);
  mergeBar.appendChild(cancelBtn);
  wrap.insertBefore(mergeBar, wrap.firstChild);

  // Ajouter une checkbox à chaque ligne data (pas les drill-rows)
  wrap.querySelectorAll('tbody tr[id^="cpr-"]').forEach(row => {
    const idx = row.id.replace('cpr-', '');
    const td = document.createElement('td');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.className = 'cp-check';
    cb.dataset.idx = idx;
    cb.addEventListener('change', onCpCheck);
    td.appendChild(cb);
    row.insertBefore(td, row.firstChild);
  });

  // Aligner le colspan des drill-rows (+1 pour la colonne checkbox)
  wrap.querySelectorAll('tbody tr.policy-drill-row td[colspan]').forEach(td => {
    td.colSpan = parseInt(td.getAttribute('colspan'), 10) + 1;
  });
}

function onCpCheck() {
  const checked = document.querySelectorAll('.cp-check:checked');
  const bar = el('cp-merge-bar');
  if (!bar) return;
  if (checked.length >= 2) {
    bar.style.display = 'flex';
    el('cp-merge-count').textContent = checked.length + ' policies sélectionnées';
  } else {
    bar.style.display = 'none';
  }
}
window.onCpCheck = onCpCheck;

function clearCpSelection() {
  document.querySelectorAll('.cp-check:checked').forEach(c => { c.checked = false; });
  onCpCheck();
}
window.clearCpSelection = clearCpSelection;

function mergeConsilPolicies() {
  if (!_consilData) return;
  const checked = [...document.querySelectorAll('.cp-check:checked')];
  if (checked.length < 2) return;

  const indices  = checked.map(c => parseInt(c.dataset.idx, 10));
  const toMerge  = indices.map(i => _consilData.consolidated[i]);

  // Union de toutes les sources, destinations, services
  const srcSubnets = [...new Set(toMerge.flatMap(p => p.srcSubnets))].sort();
  const dstTargets = [...new Set(toMerge.flatMap(p => p.dstTargets))].sort();
  const dstTypes   = Object.assign({}, ...toMerge.map(p => p.dstTypes));
  const services   = [...new Set(toMerge.flatMap(p => p.services || []))].sort();
  const ports      = [...new Set(toMerge.flatMap(p => p.ports    || []))].sort((a, b) => a - b);
  const protos     = [...new Set(toMerge.flatMap(p => p.protos   || []))].sort();
  const sessions   = toMerge.reduce((s, p) => s + p.sessions,  0);
  const sentBytes  = toMerge.reduce((s, p) => s + p.sentBytes, 0);
  const rcvdBytes  = toMerge.reduce((s, p) => s + p.rcvdBytes, 0);

  let serviceDesc;
  if (services.length > 0) {
    serviceDesc = services.join(', ');
  } else if (ports.length > 0) {
    const proto = protos[0] || 'TCP';
    serviceDesc = ports.slice(0, 10).map(p => p + '/' + proto).join(', ');
    if (ports.length > 10) serviceDesc += ' +' + (ports.length - 10) + ' autres';
  } else {
    serviceDesc = protos.join(', ') || 'ANY';
  }

  const types          = [...new Set(dstTargets.map(d => dstTypes[d]))];
  const dstTypeSummary = types.length > 1 ? 'mixed' : types[0];
  const rawCount       = srcSubnets.length * dstTargets.length;

  const merged = {
    srcSubnets, dstTargets, dstTypes, dstTypeSummary,
    services, ports, protos, serviceDesc,
    sessions, sentBytes, rcvdBytes,
    rawCount, savedCount: rawCount - 1,
    action: 'accept', name: 'FF-CONS-MERGED',
  };

  // Remplacer les sélectionnées par la fusion
  const kept         = _consilData.consolidated.filter((_, i) => !indices.includes(i));
  const newList      = [...kept, merged].sort((a, b) => b.sessions - a.sessions);
  newList.forEach((p, i) => { p.id = i + 1; });

  const totalCons = newList.length;
  const saved     = newList.reduce((s, c) => s + c.savedCount, 0);
  _consilData = { consolidated: newList, stats: { ..._consilData.stats, totalCons, saved } };

  renderConsilPolicies(_consilData);
}
window.mergeConsilPolicies = mergeConsilPolicies;

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
  mergeSelected: new Set(),
  mergeScope:    'all',       // 'all' | 'internet' | 'lan'
  mergeStrategy: 'max',       // 'max' | 'service' | 'policy'
  page:          1,
  pageSize:      100,
  selectedSdwan: null,  // user-selected SD-WAN priority interface
  warnings:      [],
  viewMode:      'interface-pair',  // 'interface-pair' | 'sequence'
  collapsedGroups: new Set(),      // collapsed group keys for interface-pair view
  wizardStep:    1,                // 1: config upload, 2: routes, 3: interfaces, 4: policies
  use32Global:   false,            // global /32 mode (use real hosts instead of /24)
  bruteMode:     'off',            // 'off' | 'service' (split by svc) | 'host' (split by src+svc)
  _detailOriginal: null,           // M3: snapshot pré-détail (≠ _analyzedOriginal pré-fusion)
  riskPanelOpen: false,
  sortCol:       null,             // active sort column key
  sortDir:       'desc',           // 'asc' | 'desc'
  availableProfiles: null,         // { antivirus, webfilter, ips, sslSsh } chargés depuis l'API
  hideNoRcvd:    true,             // masquer par défaut les policies sans réponse (rcvdBytes=0)
};

// Collapsed state for interface category groups (persists across re-renders)
const ifaceGroupCollapsed = { lan: false, wan: false, vpn: false };

// ── Sérialisation des policies (Set → Array pour JSON) ──────────────────────
function serializeAnalyzed(analyzed) {
  if (!analyzed) return analyzed;
  return analyzed.map(p => {
    const out = { ...p };
    if (p._selectedSvcKeys  instanceof Set) out._selectedSvcKeys  = [...p._selectedSvcKeys];
    if (p._excludedSrcHosts instanceof Set) out._excludedSrcHosts = [...p._excludedSrcHosts];
    if (p._excludedDstHosts instanceof Set) out._excludedDstHosts = [...p._excludedDstHosts];
    return out;
  });
}
function deserializeAnalyzed(analyzed) {
  if (!analyzed) return analyzed;
  return analyzed.map(p => {
    const out = { ...p };
    if (Array.isArray(p._selectedSvcKeys))  out._selectedSvcKeys  = new Set(p._selectedSvcKeys);
    if (Array.isArray(p._excludedSrcHosts)) out._excludedSrcHosts = new Set(p._excludedSrcHosts);
    if (Array.isArray(p._excludedDstHosts)) out._excludedDstHosts = new Set(p._excludedDstHosts);
    return out;
  });
}

async function backupServiceRecoveryState(analyzed, reason) {
  if (!state.session) throw new Error('session absente pour la sauvegarde');
  const response = await fetch(`/api/deploy/recovery-backup?session=${state.session}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ analyzed: serializeAnalyzed(analyzed), reason }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload.backupId) {
    throw new Error(payload.error || 'sauvegarde de récupération refusée');
  }
  return payload.backupId;
}

async function recoverInvalidSpecificServiceState(analyzed, reason = 'service-name-conflict') {
  const plan = planInvalidSpecificServiceAssociations(analyzed);
  if (plan.repairs.length === 0) return { applied: [], ambiguous: plan.ambiguous, backupId: null };
  const backupId = await backupServiceRecoveryState(analyzed, reason);
  const result = applyInvalidSpecificServiceRecovery(analyzed, plan);
  return { ...result, backupId };
}

// ── F6b: Export/Import policies Excel ──────────────────────
async function exportPoliciesExcel() {
  if (!deployState.analyzed?.length) { alert('Aucune policy à exporter'); return; }
  try {
    const r = await fetch('/api/export/policies-xlsx', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ policies: serializeAnalyzed(deployState.analyzed) }),
    });
    if (!r.ok) { const e = await r.json().catch(() => ({})); alert(e.error || 'Erreur export'); return; }
    const blob = await r.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `fortiflow_policies_${tsNow()}.xlsx`;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (err) { alert('Erreur: ' + err.message); }
}

async function importPoliciesExcel(file) {
  try {
    const form = new FormData();
    form.append('policies', file);
    const r = await fetch('/api/import/policies-xlsx', { method: 'POST', body: form });
    if (!r.ok) { const e = await r.json().catch(() => ({})); alert(e.error || 'Erreur import'); return; }
    const { patches } = await r.json();
    if (!patches?.length) { alert('Aucune modification trouvée'); return; }

    let applied = 0;
    for (const patch of patches) {
      const p = deployState.analyzed[patch.index];
      if (!p) continue;
      let changed = false;
      // Nom policy — export: p._policyName || ''
      if (patch.policyName !== null && patch.policyName !== (p._policyName || '')) { p._policyName = patch.policyName; changed = true; }
      // Addr source/dest — format mixte :
      //   "CIDR/Mask=AddrName" → nom du subnet /24 (dans _multiSrcSubnets[i].addrName)
      //   "IP=HostName"        → nom de l'hôte /32 (dans _srcHostNames[ip])
      //   "PlainName"          → nom simple /24 mono-subnet (_srcAddrName)
      const applyAddrPatch = (val, hostNamesKey, multiSubsKey, addrNameKey) => {
        if (!val) return;
        const hasEq = val.includes('=');
        const looksLikeStructured = hasEq && /\d+\.\d+/.test(val);
        if (looksLikeStructured) {
          for (const entry of val.split(',')) {
            const eq = entry.indexOf('=');
            if (eq < 0) continue;
            const lhs = entry.slice(0, eq).trim();
            const n   = entry.slice(eq + 1).trim();
            if (!lhs || !n) continue;
            if (lhs.includes('/')) {
              // Format CIDR=AddrName → met à jour le subnet dans _multiXxxSubnets
              const sub = p[multiSubsKey]?.find(s => s.subnet === lhs);
              if (sub && n !== (sub.addrName || '')) { sub.addrName = n; changed = true; }
            } else {
              // Format IP=HostName → met à jour _xxxHostNames
              if (n !== (cleanHostName(lhs, p[hostNamesKey]?.[lhs]) || '')) {
                if (!p[hostNamesKey]) p[hostNamesKey] = {};
                p[hostNamesKey][lhs] = n; changed = true;
              }
            }
          }
        } else {
          if (val !== (p[addrNameKey] || '')) { p[addrNameKey] = val; changed = true; }
        }
      };
      if (patch.srcAddr !== null) applyAddrPatch(patch.srcAddr, '_srcHostNames', '_multiSrcSubnets', '_srcAddrName');
      if (patch.dstAddr !== null) applyAddrPatch(patch.dstAddr, '_dstHostNames', '_multiDstSubnets', '_dstAddrName');
      // Interfaces, action, nat, log — skip si inchangé (utiliser le même fallback que l'export)
      if (patch.srcIntf !== null && patch.srcIntf !== (p._srcintf || '')) { p._srcintf = patch.srcIntf || undefined; changed = true; }
      if (patch.dstIntf !== null && patch.dstIntf !== (p._dstintf || '')) { p._dstintf = patch.dstIntf || undefined; changed = true; }
      if (patch.action  !== null && patch.action  !== (p._action || p.action || 'accept')) { p._action = patch.action; changed = true; }
      if (patch.nat     !== null && patch.nat     !== (p._nat ?? false)) { p._nat = patch.nat; changed = true; }
      if (patch.log     !== null && patch.log     !== (p._log   || 'all')) { p._log = patch.log; changed = true; }
      // Noms services : format "PORT/PROTO=Nom | label:SVC=Nom"
      if (patch.svcNames) {
        for (const entry of patch.svcNames.split('|')) {
          const eq = entry.indexOf('=');
          if (eq < 0) continue;
          const key  = entry.slice(0, eq).trim();
          const name = entry.slice(eq + 1).trim();
          if (!name) continue;
          const svc = (p.analysis?.services || []).find(s => {
            const k = s.isNamed ? `label:${s.label}` : `${s.port}/${s.proto}`;
            return k === key;
          });
          if (svc && !svc.found && name !== (svc.suggestedName || '')) { svc.suggestedName = name; changed = true; }
        }
      }
      if (changed) applied++;
    }

    renderDeployPolicies(filterDeployPolicies());
    alert(`✓ ${applied} policies mises à jour depuis l'Excel`);
  } catch (err) { alert('Erreur: ' + err.message); }
}

// ── F6: Export/Import session ──
async function exportSession() {
  try {
    const r = await fetch(`/api/export/workspace?session=${state.session}`);
    if (!r.ok) { const e = await r.json().catch(()=>({})); alert(e.error || 'Erreur export'); return; }
    const serverData = await r.json();
    const payload = {
      ...serverData,
      deployState: {
        fortiConfig:          deployState.fortiConfig,
        analyzed:             serializeAnalyzed(deployState.analyzed),
        baseAnalyzedPolicies: serializeAnalyzed(deployState.baseAnalyzedPolicies),
        selected:             [...deployState.selected],
        searchFilter:         deployState.searchFilter,
        interfaces:           deployState.interfaces,
        selectedSdwan:        deployState.selectedSdwan,
        generatedCli:         deployState.generatedCli,
        addrGroups:           deployState.addrGroups,
        warnings:             deployState.warnings,
        viewMode:             deployState.viewMode,
      },
    };
    // Compression gzip via l'API native (zéro dépendance)
    const jsonBytes  = new TextEncoder().encode(JSON.stringify(payload));
    const compressed = await new Response(
      new Blob([jsonBytes]).stream().pipeThrough(new CompressionStream('gzip'))
    ).blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(compressed);
    a.download = `fortiflow_${tsNow()}.ffws`;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (err) {
    alert('Erreur export: ' + err.message);
  }
}

function importSession(file) {
  const isFfws = file.name.endsWith('.ffws');
  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      let jsonText;
      if (isFfws) {
        // Décompression gzip via l'API native avant parsing
        jsonText = await new Response(
          new Blob([e.target.result]).stream().pipeThrough(new DecompressionStream('gzip'))
        ).text();
      } else {
        jsonText = e.target.result;
      }
      const data = JSON.parse(jsonText);

      if (data._ffws === 2) {
        // ── Nouveau format v2 : restore session serveur + deployState ──
        // Envoie les bytes gzip bruts si .ffws, sinon JSON texte
        const body   = isFfws ? e.target.result : jsonText;
        const ctype  = isFfws ? 'application/octet-stream' : 'application/json';
        const r = await fetch('/api/import/workspace', {
          method: 'POST',
          headers: { 'Content-Type': ctype },
          body,
        });
        if (!r.ok) { const err = await r.json().catch(()=>({})); alert(err.error || 'Erreur import'); return; }
        const { sessionId } = await r.json();
        state.session = sessionId;

        // Récupérer les stats depuis la session restaurée
        try {
          const sr = await fetch(`/api/stats?session=${sessionId}`);
          if (sr.ok) { const d = await sr.json(); state.stats = d.stats; state.meta = d.meta; }
        } catch {}

        // Restaurer le deployState si présent
        if (data.deployState) {
          const ds = data.deployState;
          deployState.fortiConfig          = ds.fortiConfig                                     || null;
          deployState.analyzed             = deserializeAnalyzed(ds.analyzed)                   || null;
          deployState.baseAnalyzedPolicies = deserializeAnalyzed(ds.baseAnalyzedPolicies || ds.analyzed) || null;
          deployState.selected             = new Set(ds.selected || []);
          deployState.searchFilter         = ds.searchFilter  || '';
          deployState.interfaces           = ds.interfaces    || null;
          deployState.selectedSdwan        = ds.selectedSdwan || null;
          deployState.generatedCli         = ds.generatedCli  || null;
          deployState.addrGroups           = ds.addrGroups    || null;
          deployState.warnings             = ds.warnings      || [];
          deployState.viewMode             = ds.viewMode      || 'interface-pair';
          if (deployState.analyzed?.length) {
            try {
              const recovery = await recoverInvalidSpecificServiceState(
                deployState.analyzed,
                'workspace-import-service-name-conflict',
              );
              if (recovery.applied.length) {
                deployState.generatedCli = null;
                alert(`Récupération services : ${recovery.applied.length} association(s) invalide(s) retirée(s). Sauvegarde : ${recovery.backupId}`);
              }
            } catch (recoveryError) {
              alert(`Récupération services annulée : ${recoveryError.message}`);
            }
          }
        }

        // Navigation : deploy si dispo, sinon dashboard
        if (data.deployState?.analyzed) {
          deployState.wizardStep = 4;
          navigateTo('deploy');
        } else if (data.fortiConfig) {
          deployState.wizardStep = 3;
          navigateTo('deploy');
        } else {
          navigateTo('dashboard');
        }

      } else if (data.version === 1 && data.deployState) {
        // ── Ancien format v1 (backward compat) ──
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
        deployState.viewMode      = ds.viewMode  || 'interface-pair';
        deploy();
      } else {
        alert('Fichier de session invalide');
      }
    } catch (err) { alert('Erreur lecture: ' + err.message); }
  };
  if (isFfws) reader.readAsArrayBuffer(file);
  else         reader.readAsText(file);
}

// ── F9: Merge diff modal ──
// Applique scope + stratégie à un jeu de policies et retourne le résultat fusionné
function computeMerge(original, scope, strategy) {
  const isInternet = p => p._isWan || p.dstType === 'public' || p.dstTarget === 'all';
  const clone = arr => arr.map(p => ({ ...p }));
  if (strategy === 'max') {
    return mergeAnalyzedPolicies(clone(original), scope);
  }
  // Pour service/policy : filtrer par scope puis fusionner uniquement le sous-ensemble
  let inScope, outScope;
  if (scope === 'all') {
    inScope = clone(original); outScope = [];
  } else if (scope === 'internet') {
    inScope = clone(original.filter(isInternet)); outScope = clone(original.filter(p => !isInternet(p)));
  } else {
    inScope = clone(original.filter(p => !isInternet(p))); outScope = clone(original.filter(isInternet));
  }
  const merged = strategy === 'service'      ? mergeByService(inScope)
               : strategy === 'destination'  ? mergeByDestination(inScope)
               :                               mergeByPolicyId(inScope);
  return [...merged, ...outScope].sort((a, b) => (b.sessions || 0) - (a.sessions || 0));
}

function showMergeDiff(scope, strategy) {
  const original = deployState._analyzedOriginal || deployState.analyzed;
  if (!original) return;
  const preview = computeMerge(original, scope, strategy);
  const label = `${scope === 'all' ? 'Tout' : scope === 'internet' ? 'Internet' : 'LAN'} · ${strategy === 'max' ? 'Par source' : strategy === 'service' ? 'Par service' : strategy === 'destination' ? 'Par destination' : 'Par interface'}`;

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
      <div style="font-size:14px;font-weight:600;margin-bottom:12px">Aperçu fusion : ${label}</div>
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
  modal.querySelector('#merge-confirm').addEventListener('click', () => { modal.remove(); applyMerge(scope, strategy); });
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
    // Multi-dst : collecter les subnets manquants (sauf si mode "all" activé sur policy WAN)
    const _moIsWan = p._isWan || p.dstType === 'public';
    if (p._isMultiDst && p._multiDstSubnets?.length && !(_moIsWan && p._dstUseAll === true)) {
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
          const suggested = cleanHostName(h, p._srcHostNames?.[h]) || `FF_HOST_${h.replace(/\./g, '_')}`;
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
          const suggested = cleanHostName(h, p._dstHostNames?.[h]) || `FF_HOST_${h.replace(/\./g, '_')}`;
          hosts.set(h, { ip: h, name: suggested, policyCount: 0 });
        }
        hosts.get(h).policyCount++;
      }
    }
    // Services manquants
    for (const svc of a.services || []) {
      if (!svc.found && !svc._isMerged && !isCompatibleServiceSelected(p, svc)) {
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

// ── Objects modal helpers ──────────────────────────────────────────────────────

function _objSvcKey(item) {
  return item.key || (item.port ? `${item.port}/${(item.proto||'tcp').toUpperCase()}` : `label:${item.label}`);
}

function _buildObjAddrRow(item, prefix) {
  const label = item.cidr || item.ip || item.key;
  const badge = item.policyCount > 0
    ? `<span class="obj-modal-badge">${item.policyCount} polic${item.policyCount > 1 ? 'ies' : 'y'}</span>` : '';
  return `<div class="obj-modal-row">
    <span class="obj-modal-key mono">${escHtml(label)}</span>${badge}
    <input class="deploy-name-input obj-modal-input" data-obj-prefix="${prefix}" data-obj-key="${escHtml(item.cidr || item.ip || item.key)}" value="${escHtml(item.name || '')}" placeholder="Nom FortiGate\u2026">
  </div>`;
}

function _buildObjSvcRow(item, selKeys) {
  const key   = _objSvcKey(item);
  const label = item.label || (item.port ? `${item.port}/${item.proto}` : item.key);
  const badge = item.policyCount > 0
    ? `<span class="obj-modal-badge">${item.policyCount} polic${item.policyCount > 1 ? 'ies' : 'y'}</span>` : '';
  const sel   = selKeys.has(key);
  return `<div class="obj-modal-row obj-svc-row${sel ? ' obj-svc-selected' : ''}" data-svc-key="${escHtml(key)}">
    <input type="checkbox" class="obj-svc-chk"${sel ? ' checked' : ''} style="flex-shrink:0;cursor:pointer">
    <span class="obj-modal-key mono">${escHtml(label)}</span>${badge}
    <input class="deploy-name-input obj-modal-input" data-obj-prefix="svc" data-obj-key="${escHtml(key)}" value="${escHtml(item.name || '')}" placeholder="Nom FortiGate\u2026" onclick="event.stopPropagation()">
  </div>`;
}

function _buildObjSvcMergeBar(services, selKeys, mergeMode, mergeName, mergeRange) {
  const sel = services.filter(s => selKeys.has(_objSvcKey(s)));
  if (sel.length < 2) return '';
  const protos = new Set(sel.map(s => (s.proto || 'tcp').toUpperCase()));
  if (protos.size > 1) {
    return `<div class="obj-svc-merge-bar" style="color:var(--warn)">\u26a0 Protocoles diff\u00e9rents (${[...protos].join(', ')}) \u2014 impossible de fusionner</div>`;
  }
  const proto = [...protos][0];
  const ports = sel.map(s => s.port).filter(Boolean).sort((a, b) => a - b);
  const rangeSuggestion = ports.length >= 2 ? `${ports[0]}-${ports[ports.length - 1]}` : '';
  const name = mergeName || `FF_SVC_${proto}_MULTI`;
  const mode = mergeMode || 'list';
  return `<div class="obj-svc-merge-bar">
    <span style="font-size:11px;color:var(--text2)">${sel.length} ports ${proto} s\u00e9lectionn\u00e9s</span>
    <input class="deploy-name-input obj-svc-merge-name" value="${escHtml(name)}" placeholder="FF_SVC_${escHtml(proto)}_MULTI" style="width:160px">
    <button class="btn-sm obj-svc-merge-type${mode==='list'?' btn-active':''}" data-mode="list">Ports individ.</button>
    <button class="btn-sm obj-svc-merge-type${mode==='range'?' btn-active':''}" data-mode="range">Range</button>
    ${mode === 'range'
      ? `<input class="deploy-name-input obj-svc-merge-range" value="${escHtml(mergeRange || rangeSuggestion)}" placeholder="${escHtml(rangeSuggestion || '80-90')}" style="width:100px">`
      : `<span style="font-size:10px;color:var(--text2)">${ports.join(', ')}</span>`}
    <button class="btn-sm btn-accent obj-svc-do-merge">Fusionner</button>
  </div>`;
}

function _buildObjSection(id, title, bodyHtml, collapsed) {
  if (!bodyHtml) return '';
  const arrow = collapsed ? '\u25b8' : '\u25be';
  return `<div class="obj-modal-section" data-section-id="${id}">
    <div class="obj-modal-section-title obj-section-toggle" data-section="${id}">
      <span class="obj-section-arrow">${arrow}</span> ${escHtml(title)}
    </div>
    <div class="obj-modal-section-body"${collapsed ? ' style="display:none"' : ''}>${bodyHtml}</div>
  </div>`;
}

function showObjectsModal() {
  const missing = collectMissingObjects();
  if (missing.total === 0) return;
  document.querySelector('.obj-modal-overlay')?.remove();

  // Modal state (closure)
  const state = { collapsed: new Set(), selSvcs: new Set(), mergeMode: 'list', mergeName: '', mergeRange: '' };

  function buildBody() {
    const addrHtml = missing.addresses.map(i => _buildObjAddrRow(i, 'addr')).join('');
    const hostHtml = missing.hosts.map(i => _buildObjAddrRow(i, 'host')).join('');
    const svcRows  = missing.services.map(i => _buildObjSvcRow(i, state.selSvcs)).join('');
    const mergeBar = _buildObjSvcMergeBar(missing.services, state.selSvcs, state.mergeMode, state.mergeName, state.mergeRange);
    return _buildObjSection('addr', `\u25c8 Adresses / Subnets (${missing.addresses.length})`, addrHtml, state.collapsed.has('addr'))
      + _buildObjSection('host', `\u25c9 H\u00f4tes /32 (${missing.hosts.length})`, hostHtml, state.collapsed.has('host'))
      + _buildObjSection('svc', `\u2699 Services (${missing.services.length})`, svcRows + mergeBar, state.collapsed.has('svc'));
  }

  const modal = document.createElement('div');
  modal.className = 'merge-modal-overlay obj-modal-overlay';
  modal.innerHTML = `<div class="merge-modal obj-modal-panel">
    <div class="obj-modal-header">
      <span>Objets \u00e0 nommer <span class="obj-modal-count">(${missing.total})</span></span>
      <button class="btn-sm" id="obj-modal-close">\u2715</button>
    </div>
    <div style="font-size:11px;color:var(--text2);margin-bottom:14px">Les noms seront appliqu\u00e9s \u00e0 toutes les policies concern\u00e9es.</div>
    <div id="obj-modal-body" style="max-height:62vh;overflow-y:auto;padding-right:6px">${buildBody()}</div>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px;border-top:1px solid var(--border);padding-top:12px">
      <button class="btn-sm" id="obj-modal-cancel">Annuler</button>
      <button class="btn-accent" id="obj-modal-apply">\u2713 Appliquer</button>
    </div>
  </div>`;

  document.body.appendChild(modal);
  const close = () => modal.remove();
  modal.querySelector('#obj-modal-close').addEventListener('click', close);
  modal.querySelector('#obj-modal-cancel').addEventListener('click', close);
  modal.addEventListener('click', e => { if (e.target === modal) close(); });

  function rerender() {
    // Snapshot current input values before re-render
    const vals = {};
    modal.querySelectorAll('.obj-modal-input').forEach(inp => { vals[inp.dataset.objKey] = inp.value; });
    const body = modal.querySelector('#obj-modal-body');
    body.innerHTML = buildBody();
    // Restore input values
    modal.querySelectorAll('.obj-modal-input').forEach(inp => {
      if (vals[inp.dataset.objKey] !== undefined) inp.value = vals[inp.dataset.objKey];
    });
  }

  // Event delegation
  modal.addEventListener('click', e => {
    // Collapse / expand section
    const toggle = e.target.closest('.obj-section-toggle');
    if (toggle) {
      const id = toggle.dataset.section;
      if (state.collapsed.has(id)) state.collapsed.delete(id); else state.collapsed.add(id);
      rerender(); return;
    }
    // Service row or checkbox click
    const svcRow = e.target.closest('.obj-svc-row');
    if (svcRow && !e.target.matches('.obj-modal-input')) {
      state.mergeName = modal.querySelector('.obj-svc-merge-name')?.value || state.mergeName;
      state.mergeRange = modal.querySelector('.obj-svc-merge-range')?.value || state.mergeRange;
      const key = svcRow.dataset.svcKey;
      if (state.selSvcs.has(key)) state.selSvcs.delete(key); else state.selSvcs.add(key);
      rerender(); return;
    }
    // Merge mode toggle
    const modeBtn = e.target.closest('.obj-svc-merge-type');
    if (modeBtn) {
      state.mergeName = modal.querySelector('.obj-svc-merge-name')?.value || state.mergeName;
      state.mergeRange = modal.querySelector('.obj-svc-merge-range')?.value || state.mergeRange;
      state.mergeMode = modeBtn.dataset.mode;
      rerender(); return;
    }
    // Do merge
    if (e.target.closest('.obj-svc-do-merge')) {
      const nameVal  = modal.querySelector('.obj-svc-merge-name')?.value.trim();
      const rangeVal = modal.querySelector('.obj-svc-merge-range')?.value.trim();
      const selItems = missing.services.filter(s => state.selSvcs.has(_objSvcKey(s)));
      if (selItems.length < 2) return;
      const proto = (selItems[0].proto || 'tcp').toUpperCase();
      const ports = selItems.map(s => s.port).filter(Boolean).sort((a, b) => a - b);
      const portRange = (state.mergeMode === 'range' && rangeVal) ? rangeVal : null;
      const svcName = nameVal || `FF_SVC_${proto}_MULTI`;
      applyGlobalSvcMerge(state.selSvcs, {
        label: svcName, found: false, name: null, source: null,
        suggestedName: svcName, isNamed: false, proto: proto.toLowerCase(),
        ...(portRange ? {} : { ports, port: ports[0] }),
        portRange: portRange || null,
        sourcePorts: ports,
        portHint: portRange ? `${proto}: ${portRange}` : `${proto}: ${ports.join(', ')}`,
        _isMerged: true,
      });
      // Remove merged keys from missing.services list
      missing.services = missing.services.filter(s => !state.selSvcs.has(_objSvcKey(s)));
      missing.services.push({ key: `label:${svcName}`, label: svcName, name: svcName, proto: proto.toLowerCase(), policyCount: selItems.reduce((a, s) => a + (s.policyCount || 0), 0) });
      state.selSvcs.clear();
      state.mergeName = '';
      state.mergeRange = '';
      rerender(); return;
    }
  });

  modal.querySelector('#obj-modal-apply').addEventListener('click', () => {
    const addrMap = {}, hostsMap = {}, svcMap = {};
    modal.querySelectorAll('.obj-modal-input').forEach(inp => {
      const { objPrefix: prefix, objKey: key } = inp.dataset;
      const val = inp.value.trim();
      if (!val) return;
      if (prefix === 'addr')      addrMap[key]  = val;
      else if (prefix === 'host') hostsMap[key] = val;
      else if (prefix === 'svc')  svcMap[key]   = val;
    });
    close();
    applyObjectNames(addrMap, hostsMap, svcMap);
  });
}

// Applique une fusion de services à toutes les policies concernées
function applyGlobalSvcMerge(selectedKeys, mergedSvc) {
  for (const p of deployState.analyzed) {
    const svcs = p.analysis?.services;
    if (!svcs) continue;
    const matching = svcs.filter(s => {
      const k = s.isNamed ? `label:${s.label}` : `${s.port}/${(s.proto||'tcp').toUpperCase()}`;
      return selectedKeys.has(k);
    });
    if (matching.length < 2) continue;
    const remaining = svcs.filter(s => {
      const k = s.isNamed ? `label:${s.label}` : `${s.port}/${(s.proto||'tcp').toUpperCase()}`;
      return !selectedKeys.has(k);
    });
    remaining.push({ ...mergedSvc });
    p.analysis.services = remaining;
  }
  renderDeployPolicies(filterDeployPolicies(), false);
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

// ─── Historique global de la liste de policies (undo/redo) ───────────────────
let _policyUndo = [];   // états passés
let _policyRedo = [];   // états futurs (après undo)
const POLICY_HISTORY_MAX = 10;

function _savePolicySnapshot() {
  if (!deployState.analyzed) return;
  const snap = {
    analyzed: deployState.analyzed.map(p => ({ ...p })),
    selected: new Set(deployState.selected),
    mergeSelected: new Set(deployState.mergeSelected),
  };
  if (_policyUndo.length >= POLICY_HISTORY_MAX) _policyUndo.shift();
  _policyUndo.push(snap);
  _policyRedo = [];  // une nouvelle action efface le redo
  _syncHistoryButtons();
}

// C4/M2: supprime des policies de deployState.analyzed (par indices) et réindexe
// selected + mergeSelected pour qu'ils restent alignés avec le tableau réduit.
// Sans ça, les index au-dessus des éléments supprimés pointent vers les mauvaises
// policies → config générée / fusion manuelle silencieusement erronées.
function _removeAnalyzedIndices(removeSet) {
  deployState.analyzed = deployState.analyzed.filter((_, i) => !removeSet.has(i));
  const removed = [...removeSet].sort((a, b) => a - b);
  const reindex = (set) => {
    const out = new Set();
    set.forEach(i => {
      if (removeSet.has(i)) return;
      const drop = removed.filter(r => r < i).length;
      out.add(i - drop);
    });
    return out;
  };
  deployState.selected     = reindex(deployState.selected);
  deployState.mergeSelected = reindex(deployState.mergeSelected);
}

function _syncHistoryButtons() {
  const btnUndo = el('btn-policy-undo');
  const btnRedo = el('btn-policy-redo');
  if (btnUndo) btnUndo.disabled = _policyUndo.length === 0;
  if (btnRedo) btnRedo.disabled = _policyRedo.length === 0;
}

function _policyUndoStep() {
  if (!_policyUndo.length) return;
  // Sauvegarder l'état actuel dans le redo
  if (deployState.analyzed) {
    _policyRedo.push({
      analyzed: deployState.analyzed.map(p => ({ ...p })),
      selected: new Set(deployState.selected),
    });
  }
  const snap = _policyUndo.pop();
  deployState.analyzed = snap.analyzed;
  deployState.selected = snap.selected;
  deployState.mergeSelected = new Set();
  _updateMergeSelectionBtn();
  _syncHistoryButtons();
  renderDeployPolicies(filterDeployPolicies(), false);
}

function _policyRedoStep() {
  if (!_policyRedo.length) return;
  if (deployState.analyzed) {
    if (_policyUndo.length >= POLICY_HISTORY_MAX) _policyUndo.shift();
    _policyUndo.push({
      analyzed: deployState.analyzed.map(p => ({ ...p })),
      selected: new Set(deployState.selected),
    });
  }
  const snap = _policyRedo.pop();
  deployState.analyzed = snap.analyzed;
  deployState.selected = snap.selected;
  deployState.mergeSelected = new Set();
  _updateMergeSelectionBtn();
  _syncHistoryButtons();
  renderDeployPolicies(filterDeployPolicies(), false);
}

const DRAWER_SNAPSHOT_KEYS = ['_srcAddrName','_dstAddrName','_policyName','_srcMode','_dstMode',
  '_use32Src','_use32Dst','_isMultiDst','dstTarget','dstTargets','_srcHostNames','_dstHostNames','_useSrcGroup','_useDstGroup',
  '_srcintf','_dstintf','_nat','_action','_log','_mergeMode','_mergedSvcName','_mergeRange','_serviceReuse','_resolvedServiceKeys',
  '_resolvedObjectKeys','_dismissedCompatibleSelection','_propagateServicePending','_propagatePending','_backendIssues','_backendIssueKind','_backendValidated'];

function _captureDrawerSnapshot(p) {
  const snap = {};
  const hasAnalysis = !!p.analysis;
  const hasAnalysisServices = hasAnalysis && Object.hasOwn(p.analysis, 'services');
  for (const k of DRAWER_SNAPSHOT_KEYS) {
    if (!(k in p)) continue;
    const v = p[k];
    snap[k] = k === '_propagateServicePending'
      ? JSON.parse(JSON.stringify(v))
      : Array.isArray(v)
      ? [...v]
      : (v && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Set) && !(v instanceof Map))
      ? { ...v } : v;
  }
  snap._selectedSvcKeys   = p._selectedSvcKeys   ? new Set(p._selectedSvcKeys)  : undefined;
  snap._hasAnalysis       = hasAnalysis;
  snap._hasAnalysisServices = hasAnalysisServices;
  snap._analysisServices  = hasAnalysisServices ? JSON.parse(JSON.stringify(p.analysis.services || [])) : undefined;
  snap._multiSrcSubnets   = p._multiSrcSubnets   ? JSON.parse(JSON.stringify(p._multiSrcSubnets)) : undefined;
  snap._multiDstSubnets   = p._multiDstSubnets   ? JSON.parse(JSON.stringify(p._multiDstSubnets)) : undefined;
  snap._excludedSrcHosts  = p._excludedSrcHosts  ? new Set(p._excludedSrcHosts) : undefined;
  snap._excludedDstHosts  = p._excludedDstHosts  ? new Set(p._excludedDstHosts) : undefined;
  return snap;
}

function _recordDrawerHistory(entries) {
  if (!entries?.length) return;
  if (_drawerHistory.length >= DRAWER_HISTORY_MAX) _drawerHistory.shift();
  _drawerHistory.push(entries.length === 1 ? entries[0] : { idx: _drawerIdx, entries });
  _syncDrawerUndoButton();
}

function _clearDrawerBackendState(p) {
  if (!p) return;
  delete p._backendIssues;
  delete p._backendIssueKind;
  delete p._backendValidated;
}

function _snapDrawerIndexes(indexes, clearIndexes = indexes) {
  const uniqueIndexes = [...new Set((indexes || []).filter(index => Number.isInteger(index) && index >= 0))];
  const indexesToClear = new Set((clearIndexes || []).filter(index => Number.isInteger(index) && index >= 0));
  const entries = uniqueIndexes.map(idx => {
    const policy = deployState.analyzed?.[idx];
    return policy ? { idx, snap: _captureDrawerSnapshot(policy) } : null;
  }).filter(Boolean);
  _recordDrawerHistory(entries);
  for (const { idx } of entries) {
    const p = deployState.analyzed[idx];
    if (indexesToClear.has(idx)) _clearDrawerBackendState(p);
  }
}

function _snapDrawer(p) {
  if (!p) return;
  const idx = Number.isInteger(_drawerIdx) ? _drawerIdx : deployState.analyzed?.indexOf(p);
  _snapDrawerIndexes([idx]);
}

function _restoreDrawerSnapshot(policy, snap) {
  if (!policy || !snap) return;
  for (const key of DRAWER_SNAPSHOT_KEYS) {
    if (key === '_propagateServicePending') {
      if (snap[key] === undefined) delete policy[key];
      else _setDrawerServicePropagationPending(policy, snap[key]);
    } else if (snap[key] === undefined) delete policy[key];
    else policy[key] = snap[key];
  }
  if (snap._hasAnalysis) {
    if (!policy.analysis) policy.analysis = {};
    if (snap._hasAnalysisServices) policy.analysis.services = snap._analysisServices;
    else delete policy.analysis.services;
  } else {
    delete policy.analysis;
  }
  if (snap._selectedSvcKeys !== undefined) policy._selectedSvcKeys = snap._selectedSvcKeys;
  else delete policy._selectedSvcKeys;
  if (snap._multiSrcSubnets !== undefined) policy._multiSrcSubnets = snap._multiSrcSubnets;
  else delete policy._multiSrcSubnets;
  if (snap._multiDstSubnets !== undefined) policy._multiDstSubnets = snap._multiDstSubnets;
  else delete policy._multiDstSubnets;
  if (snap._excludedSrcHosts !== undefined) policy._excludedSrcHosts = snap._excludedSrcHosts;
  else delete policy._excludedSrcHosts;
  if (snap._excludedDstHosts !== undefined) policy._excludedDstHosts = snap._excludedDstHosts;
  else delete policy._excludedDstHosts;
}

function _syncDrawerUndoButton() {
  const button = document.getElementById('drawer-undo');
  if (!button) return;
  button.disabled = _drawerIdx === null || _drawerHistory.length === 0;
}

function _undoDrawer() {
  if (_drawerIdx === null || !_drawerHistory.length) {
    _syncDrawerUndoButton();
    return false;
  }
  const last = _drawerHistory.pop();
  const entries = last.entries || [last];
  for (const entry of entries) {
    const policy = deployState.analyzed[entry.idx];
    _restoreDrawerSnapshot(policy, entry.snap);
    syncRowStatus(entry.idx);
  }
  populateDrawer(_drawerIdx);
  renderDeployPolicies(filterDeployPolicies(), false);
  _syncDrawerUndoButton();
  return true;
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
    <div class="drawer-header-actions" id="drawer-header-actions"></div>
    <button class="drawer-close" id="drawer-close" type="button" aria-label="Fermer le drawer" title="Fermer">&times;</button>
  </div>
  <div class="drawer-body" id="drawer-body"></div>`;
  document.body.appendChild(overlay);
  document.body.appendChild(drawer);
  overlay.addEventListener('click', closeDrawer);
  drawer.querySelector('#drawer-close').addEventListener('click', closeDrawer);

  // Ctrl+Z undo handler (once)
  if (!window._undoWired) {
    window._undoWired = true;
    document.addEventListener('keydown', e => {
      if (!(e.ctrlKey || e.metaKey) || (e.key || '').toLowerCase() !== 'z' || _drawerIdx === null) return;
      if (_undoDrawer()) e.preventDefault();
    });
  }

  // Delegated events inside drawer
  drawer.addEventListener('input', e => {
    const p = _drawerIdx !== null ? deployState.analyzed[_drawerIdx] : null;
    if (!p) return;
    _snapDrawer(p);
    if (e.target.matches('.drawer-src-name'))  { p._srcAddrName = e.target.value; syncAddrCell(_drawerIdx, 'src'); }
    if (e.target.matches('.drawer-dst-name'))  { p._dstAddrName = e.target.value; syncAddrCell(_drawerIdx, 'dst'); }
    if (e.target.matches('.drawer-policy-name')) p._policyName = e.target.value;
    if (e.target.matches('.drawer-host-input')) {
      const host = e.target.dataset.host;
      const type = e.target.dataset.type;
      if (type === 'src') { if (!p._srcHostNames) p._srcHostNames = {}; p._srcHostNames[host] = e.target.value; }
      else { if (!p._dstHostNames) p._dstHostNames = {}; p._dstHostNames[host] = e.target.value; }
      syncAddrCell(_drawerIdx, type);
    }
    if (e.target.matches('.svc-merge-name')) { p._mergedSvcName = e.target.value; return; }
    if (e.target.matches('.svc-merge-range')) { p._mergeRange = e.target.value; return; }
    if (e.target.matches('.drawer-svc-name')) {
      setPolicyServiceSuggestedName(p, e.target.dataset.svcKey, e.target.value);
      syncSvcCell(_drawerIdx);
    }
    if (e.target.matches('.drawer-multidst-name')) {
      const si = +e.target.dataset.si;
      if (p._multiDstSubnets?.[si]) p._multiDstSubnets[si].addrName = e.target.value;
      syncAddrCell(_drawerIdx, 'dst');
    }
    if (e.target.matches('.drawer-destination-cidr')) {
      const si = +e.target.dataset.si;
      const item = destinationScopeForElement(p, e.target);
      if (item) {
        item.subnet = e.target.value.trim();
        item.manual = true;
        item.addrName = '';
        item.addrFound = false;
        item.route = null;
        item.sources = [];
        const parsed = normalizeDestinationCidr(item.subnet);
        if (parsed) item.useSubnet = parsed.prefix !== 32;
        item.suggestedName = `FF_NET_${item.subnet.replace(/[./]/g, '_')}`;
        item._cidrError = destinationCidrIssue(item.subnet, item.hosts || []);
        e.target.dataset.subnetKey = item.subnet;
        const error = drawer.querySelector(`.drawer-destination-cidr-error[data-si="${si}"]`);
        if (error) error.textContent = item._cidrError;
        syncRowStatus(_drawerIdx);
      }
      return;
    }
    if (e.target.matches('.drawer-destination-aggregate-cidr')) {
      p._dstAggregateSubnet = e.target.value.trim();
      p._dstAggregateManual = true;
      p._dstAggregateError = destinationCidrIssue(p._dstAggregateSubnet, destinationObservedHosts(p));
      const error = drawer.querySelector('[data-aggregate-cidr-error="true"]');
      if (error) error.textContent = p._dstAggregateError;
      syncRowStatus(_drawerIdx);
      return;
    }
    if (e.target.matches('.drawer-multisrc-name')) {
      const si = +e.target.dataset.si;
      if (p._multiSrcSubnets?.[si]) {
        p._multiSrcSubnets[si].addrName = e.target.value;
        if (p.srcAddrNames && p.srcAddrNames[si] !== undefined) p.srcAddrNames[si] = e.target.value;
      }
      syncAddrCell(_drawerIdx, 'src');
    }
    if (e.target.matches('.drawer-grp-name')) {
      p._dstAddrName = e.target.value;
      syncAddrCell(_drawerIdx, 'dst');
    }
    if (e.target.matches('.drawer-src-grp-name')) {
      p._srcAddrName = e.target.value;
      syncAddrCell(_drawerIdx, 'src');
    }
    syncRowStatus(_drawerIdx);
  });
  drawer.addEventListener('click', e => {
    const p = _drawerIdx !== null ? deployState.analyzed[_drawerIdx] : null;
    if (!p) return;
    const undoButton = e.target.closest('.drawer-undo');
    if (undoButton) {
      e.stopPropagation();
      _undoDrawer();
      return;
    }
    const _snapAndShow = () => {
      _snapDrawer(p);
    };
    const _snapAndShowIndexes = (indexes, clearIndexes = [_drawerIdx]) => {
      _snapDrawerIndexes(indexes, clearIndexes);
    };
    const useSelectedCompatible = e.target.closest('.svc-use-compatible-selected');
    if (useSelectedCompatible) {
      const proto = String(useSelectedCompatible.dataset.proto || '').toUpperCase();
      const name = useSelectedCompatible.dataset.serviceName;
      const serviceKeys = String(useSelectedCompatible.dataset.ports || '').split(',')
        .filter(Boolean).map(port => `${proto}/${port}`);
      const propagationTargets = servicePropagationPlan(p, name, serviceKeys);
      _snapAndShowIndexes([_drawerIdx, ...propagationTargets.map(target => target.idx)], [_drawerIdx]);
      if (!p._serviceReuse) p._serviceReuse = {};
      serviceKeys.forEach(serviceKey => {
        p._serviceReuse[serviceKey] = name;
        markServiceDecisionResolved(p, serviceKey, `existing:${name}`);
      });
      _setDrawerServicePropagationPending(p, propagationTargets.length ? {
          serviceName: name,
          serviceKeys: [...serviceKeys],
          targets: propagationTargets.map(target => ({ idx: target.idx, keys: [...target.keys] })),
        } : null);
      delete p._dismissedCompatibleSelection;
      populateDrawer(_drawerIdx);
      syncRowStatus(_drawerIdx);
      renderDeployPolicies(filterDeployPolicies(), false);
      return;
    }
    const createNewSelected = e.target.closest('.svc-create-new-selected');
    if (createNewSelected) {
      _snapAndShow();
      p._dismissedCompatibleSelection = createNewSelected.dataset.selectionSignature;
      populateDrawer(_drawerIdx);
      return;
    }
    const useCompatible = e.target.closest('.drawer-use-compatible-service');
    if (useCompatible) {
      const serviceKeys = String(useCompatible.dataset.serviceKeys || useCompatible.dataset.serviceKey || '')
        .split(',').filter(Boolean);
      const serviceName = useCompatible.dataset.serviceName;
      const propagationTargets = servicePropagationPlan(p, serviceName, serviceKeys);
      _snapAndShowIndexes([_drawerIdx, ...propagationTargets.map(target => target.idx)], [_drawerIdx]);
      for (const serviceKey of serviceKeys) {
        markServiceDecisionResolved(
          p, serviceKey, `existing:${serviceName}`,
        );
      }
      _setDrawerServicePropagationPending(p, propagationTargets.length ? {
          serviceName,
          serviceKeys: [...serviceKeys],
          targets: propagationTargets.map(target => ({ idx: target.idx, keys: [...target.keys] })),
        } : null);
      populateDrawer(_drawerIdx);
      syncRowStatus(_drawerIdx);
      renderDeployPolicies(filterDeployPolicies(), false);
      return;
    }
    const createSpecific = e.target.closest('.drawer-create-specific-service');
    if (createSpecific) {
      _snapAndShow();
      const serviceKeys = String(createSpecific.dataset.serviceKeys || createSpecific.dataset.serviceKey || '')
        .split(',').filter(Boolean);
      const [proto, port] = serviceKeys[0]?.split('/') || [];
      const serviceIndex = (p.analysis?.services || []).findIndex(item =>
        serviceReuseKeys(item).some(key => serviceKeys.includes(key)));
      const service = p.analysis?.services?.[serviceIndex];
      const typedName = createSpecific.closest('.drawer-service-item')
        ?.querySelector('.drawer-svc-name')?.value.trim();
      if (serviceKeys.length === 1) {
        applySpecificServiceDecision(p, serviceKeys[0], typedName || `FF_SVC_${proto}_${port}`);
      } else if (service) {
        const next = cloneServiceDecision(service);
        next.suggestedName = typedName || `FF_SVC_${proto}_${port}`;
        if (['TCP', 'UDP'].includes(proto)
            && serviceKeys.every(key => key.startsWith(`${proto}/`))) {
          next.ports = serviceKeys.map(key => Number(key.split('/')[1]));
          next.sourcePorts = [...next.ports];
          next.proto = proto;
        }
        const services = [...p.analysis.services];
        services[serviceIndex] = next;
        p.analysis = { ...p.analysis, services };
        serviceKeys.forEach(serviceKey => markServiceDecisionResolved(p, serviceKey, 'specific'));
      }
      populateDrawer(_drawerIdx);
      syncRowStatus(_drawerIdx);
      renderDeployPolicies(filterDeployPolicies(), false);
      return;
    }
    if (e.target.closest('.drawer-services-toggle')) {
      p._servicesExpanded = !p._servicesExpanded;
      populateDrawer(_drawerIdx);
      return;
    }
    const hostsToggle = e.target.closest('.drawer-hosts-toggle');
    if (hostsToggle) {
      const key = hostsToggle.dataset.hostsType === 'src' ? '_srcHostsExpanded' : '_dstHostsExpanded';
      p[key] = !p[key];
      populateDrawer(_drawerIdx);
      return;
    }
    // Action toggle (accept / deny)
    if (e.target.matches('.drawer-action-btn')) {
      _snapAndShow();
      p._action = e.target.dataset.action;
      populateDrawer(_drawerIdx);
      renderDeployPolicies(filterDeployPolicies(), false);
      return;
    }
    // Select-all services toggle
    if (e.target.matches('.svc-sel-all')) {
      _snapAndShow();
      const _svcList = p.analysis?.services || [];
      const _getSvcPP = s => { const m = s.label?.match(/^(TCP|UDP)\/(\d+)$/i); return m ? { port: parseInt(m[2],10), proto: m[1].toUpperCase() } : { port: s.port, proto: (s.proto||'').toUpperCase() }; };
      const _selectable = _svcList.filter(s => {
        if (s.found || isServiceDecisionResolved(p, s)) return false;
        const m = s.label?.match(/^(TCP|UDP)\/\d+$/i);
        return m || (!s.isNamed && s.port);
      });
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
        ...(portRange ? {} : { ports, port: ports[0] }),
        portRange: portRange || null,
        sourcePorts: ports,
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
    const destinationModeBtn = e.target.closest('.drawer-destination-mode');
    if (destinationModeBtn) {
      _snapAndShow();
      if (setDestinationRepresentation(p, destinationModeBtn.dataset.mode)) {
        populateDrawer(_drawerIdx);
        syncAddrCell(_drawerIdx, 'dst');
        renderDeployPolicies(filterDeployPolicies(), false);
      }
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
    const dstAllBtn = e.target.closest('.drawer-dstall-btn');
    if (dstAllBtn) {
      _snapAndShow();
      p._dstUseAll = dstAllBtn.dataset.val === 'true';
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
        syncAddrCell(_drawerIdx, 'dst');
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
        syncAddrCell(_drawerIdx, 'src');
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
    // Addr propagation banner buttons
    if (e.target.closest('.addr-prop-yes')) {
      const ap = p._propagateAddrPending;
      if (ap) {
        for (let i = 0; i < (deployState.analyzed || []).length; i++) {
          if (i === _drawerIdx) continue;
          const op = deployState.analyzed[i];
          if (ap.isHost) {
            // Mode /32 : propagate host name
            const opHosts = ap.addrType === 'src' ? (op.srcHosts || []) : (op.dstHosts || []);
            const opFound = ap.addrType === 'src' ? new Set(op._srcHostsFound || []) : new Set(op._dstHostsFound || []);
            if (opHosts.includes(ap.hostIp) && !opFound.has(ap.hostIp)) {
              if (ap.addrType === 'src') { if (!op._srcHostNames) op._srcHostNames = {}; op._srcHostNames[ap.hostIp] = ap.newName; }
              else { if (!op._dstHostNames) op._dstHostNames = {}; op._dstHostNames[ap.hostIp] = ap.newName; }
              syncAddrCell(i, ap.addrType);
            }
          } else {
            // Mode /24 : propagate addr object name
            const field   = ap.addrType === 'src' ? '_srcAddrName' : '_dstAddrName';
            const opCidr  = ap.addrType === 'src' ? op.analysis?.srcAddr?.cidr  : op.analysis?.dstAddr?.cidr;
            const opFound = ap.addrType === 'src' ? op.analysis?.srcAddr?.found : op.analysis?.dstAddr?.found;
            if (opCidr === ap.cidr && !opFound) { op[field] = ap.newName; syncAddrCell(i, ap.addrType); }
          }
        }
        delete p._propagateAddrPending;
        populateDrawer(_drawerIdx);
      }
      return;
    }
    if (e.target.closest('.addr-prop-no')) {
      delete p._propagateAddrPending;
      populateDrawer(_drawerIdx);
      return;
    }
    if (e.target.closest('.svc-service-prop-yes')) {
      const pending = p._propagateServicePending;
      if (pending) {
        for (const target of pending.targets || []) {
          const op = deployState.analyzed[target.idx];
          if (!op) continue;
          const eligibleKeys = compatiblePolicyServiceKeys(op, pending.serviceName, target.keys);
          if (eligibleKeys.length) _clearDrawerBackendState(op);
          eligibleKeys.forEach(serviceKey => markServiceDecisionResolved(
            op, serviceKey, `existing:${pending.serviceName}`,
          ));
          syncRowStatus(target.idx);
        }
        _setDrawerServicePropagationPending(p, null);
        populateDrawer(_drawerIdx);
        syncRowStatus(_drawerIdx);
        renderDeployPolicies(filterDeployPolicies(), false);
      }
      return;
    }
    if (e.target.closest('.svc-service-prop-no')) {
      _setDrawerServicePropagationPending(p, null);
      populateDrawer(_drawerIdx);
      return;
    }
    // Propagation banner buttons
    if (e.target.closest('.svc-prop-yes')) {
      const pp = p._propagatePending;
      if (pp) {
        if (pp.targets?.length && pp.serviceKey) {
          const targetIndexes = pp.targets.map(target => target.idx);
          _snapDrawerIndexes(targetIndexes, targetIndexes);
          for (const target of pp.targets) {
            const op = deployState.analyzed[target.idx];
            if (op && applySpecificServiceDecision(op, target.serviceKey, pp.newName)) {
              syncRowStatus(target.idx);
            }
          }
        } else {
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
  drawer.addEventListener('keydown', e => {
    if (!['Enter', ' '].includes(e.key) || e.target.matches('.drawer-svc-name')) return;
    const serviceRow = e.target.closest('.svc-selectable');
    if (!serviceRow) return;
    e.preventDefault();
    serviceRow.click();
  });
  drawer.addEventListener('change', e => {
    const p = _drawerIdx !== null ? deployState.analyzed[_drawerIdx] : null;
    if (!p) return;
    _snapDrawer(p);
    if (e.target.matches('.drawer-srcintf')) { p._srcintf = e.target.value || undefined; renderDeployPolicies(filterDeployPolicies(), false); }
    if (e.target.matches('.drawer-dstintf')) { p._dstintf = e.target.value || undefined; renderDeployPolicies(filterDeployPolicies(), false); }
    if (e.target.matches('.drawer-nat')) {
      p._nat = e.target.checked;
      const natValue = e.target.closest('.drawer-inline-toggle')?.querySelector('.drawer-nat-value');
      if (natValue) natValue.textContent = p._nat ? 'Activé' : 'Désactivé';
    }
    if (e.target.matches('.drawer-log-sel')) { p._log = e.target.value; }
    if (e.target.matches('.drawer-sp-sel')) {
      if (!p._secProfiles) p._secProfiles = {};
      const spKey = e.target.dataset.sp;
      if (e.target.value) p._secProfiles[spKey] = e.target.value;
      else delete p._secProfiles[spKey];
    }
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
    const identity = canonicalMonoServiceIdentity(svc);
    if (identity) {
      applySpecificServiceDecision(p, identity.key, newName);
      const targets = specificServicePropagationPlan(p, identity.key);
      if (targets.length > 0) {
        p._propagatePending = {
          svcKey,
          serviceKey: identity.key,
          newName,
          port: identity.port,
          proto: identity.proto,
          label: null,
          portHint: svc.portHint || null,
          count: targets.length,
          targets,
        };
      } else {
        delete p._propagatePending;
      }
      populateDrawer(_drawerIdx);
      syncRowStatus(_drawerIdx);
      renderDeployPolicies(filterDeployPolicies(), false);
      return;
    }
    svc.suggestedName = newName;
    const decisionKeys = serviceReuseKeys(svc);
    decisionKeys.forEach(key => markServiceDecisionResolved(p, key, 'specific'));
    const decisionProtos = [...new Set(decisionKeys.map(key => key.split('/')[0]))];
    if (decisionKeys.length > 1 && decisionProtos.length === 1
        && ['TCP', 'UDP'].includes(decisionProtos[0])) {
      svc.proto = decisionProtos[0];
      svc.ports = decisionKeys.map(key => Number(key.split('/')[1])).sort((a, b) => a - b);
      svc.sourcePorts = [...svc.ports];
    }
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
    }
    populateDrawer(_drawerIdx);
    syncRowStatus(_drawerIdx);
    renderDeployPolicies(filterDeployPolicies(), false);
  });

  // Propagation check on addr name blur
  drawer.addEventListener('focusout', e => {
    const p = _drawerIdx !== null ? deployState.analyzed[_drawerIdx] : null;
    if (!p) return;
    if (e.target.matches('.drawer-destination-cidr')) {
      const si = +e.target.dataset.si;
      const item = destinationScopeForElement(p, e.target);
      if (!item) return;
      const issue = destinationCidrIssue(item.subnet, item.hosts || []);
      if (issue) {
        item._cidrError = issue;
        populateDrawer(_drawerIdx);
        return;
      }
      const parsed = normalizeDestinationCidr(item.subnet);
      item.subnet = parsed.cidr;
      item.useSubnet = parsed.prefix !== 32;
      item.manual = true;
      item.suggestedName = `FF_NET_${item.subnet.replace(/[./]/g, '_')}`;
      item._cidrError = '';
      deduplicateDestinationScopes(p);
      p._dstDetectedSubnets = p._multiDstSubnets.map(candidate => ({
        ...candidate, hosts: [...(candidate.hosts || [])],
      }));
      populateDrawer(_drawerIdx);
      syncAddrCell(_drawerIdx, 'dst');
      renderDeployPolicies(filterDeployPolicies(), false);
      return;
    }
    if (e.target.matches('.drawer-destination-aggregate-cidr')) {
      const issue = destinationCidrIssue(p._dstAggregateSubnet, destinationObservedHosts(p));
      if (issue) {
        p._dstAggregateError = issue;
        populateDrawer(_drawerIdx);
        return;
      }
      const parsed = normalizeDestinationCidr(p._dstAggregateSubnet);
      p._dstAggregateSubnet = parsed.cidr;
      p._dstAggregateManual = true;
      p._dstAggregateError = '';
      p.dstTarget = parsed.cidr;
      p.dstTargets = [parsed.cidr];
      p._dstAddrName = '';
      p._dstAggregateAddrName = '';
      populateDrawer(_drawerIdx);
      syncAddrCell(_drawerIdx, 'dst');
      renderDeployPolicies(filterDeployPolicies(), false);
      return;
    }
    const resolvedObjectKey = e.target.dataset.objectKey;
    const resolvedObjectName = typeof e.target.value === 'string' ? e.target.value.trim() : '';
    if (resolvedObjectKey && resolvedObjectName) {
      markDrawerObjectResolved(p, resolvedObjectKey, resolvedObjectName);
    }

    // Mode /24 subnet
    let addrType = null;
    if (e.target.matches('.drawer-src-name')) addrType = 'src';
    else if (e.target.matches('.drawer-dst-name')) addrType = 'dst';
    if (addrType) {
      const newName = e.target.value.trim();
      if (!newName) return;
      const cidr = addrType === 'src' ? p.analysis?.srcAddr?.cidr : p.analysis?.dstAddr?.cidr;
      if (!cidr) return;
      let count = 0;
      for (let i = 0; i < (deployState.analyzed || []).length; i++) {
        if (i === _drawerIdx) continue;
        const op = deployState.analyzed[i];
        const opCidr  = addrType === 'src' ? op.analysis?.srcAddr?.cidr  : op.analysis?.dstAddr?.cidr;
        const opFound = addrType === 'src' ? op.analysis?.srcAddr?.found : op.analysis?.dstAddr?.found;
        if (opCidr === cidr && !opFound) count++;
      }
      if (count > 0) {
        p._propagateAddrPending = { addrType, cidr, newName, count };
      }
      populateDrawer(_drawerIdx);
      syncRowStatus(_drawerIdx);
      renderDeployPolicies(filterDeployPolicies(), false);
      return;
    }

    // Mode /32 hosts
    if (e.target.matches('.drawer-host-input')) {
      const hostIp  = e.target.dataset.host;
      const hostAddrType = e.target.dataset.type; // 'src' or 'dst'
      const newName = e.target.value.trim();
      if (!newName || !hostIp) return;
      const hostFoundSet = hostAddrType === 'src'
        ? new Set(p._srcHostsFound || [])
        : new Set(p._dstHostsFound || []);
      if (hostFoundSet.has(hostIp)) return; // déjà en config, pas de propagation
      let count = 0;
      for (let i = 0; i < (deployState.analyzed || []).length; i++) {
        if (i === _drawerIdx) continue;
        const op = deployState.analyzed[i];
        const opHosts  = hostAddrType === 'src' ? (op.srcHosts || []) : (op.dstHosts || []);
        const opFound  = hostAddrType === 'src' ? new Set(op._srcHostsFound || []) : new Set(op._dstHostsFound || []);
        if (opHosts.includes(hostIp) && !opFound.has(hostIp)) count++;
      }
      if (count > 0) {
        p._propagateAddrPending = { addrType: hostAddrType, hostIp, newName, count, isHost: true };
      }
      populateDrawer(_drawerIdx);
      syncRowStatus(_drawerIdx);
      renderDeployPolicies(filterDeployPolicies(), false);
      return;
    }
    if (resolvedObjectKey && resolvedObjectName) {
      populateDrawer(_drawerIdx);
      syncRowStatus(_drawerIdx);
      renderDeployPolicies(filterDeployPolicies(), false);
    }
  });
}

function buildDrawerSecProfiles(p, idx) {
  const sp = deployState.availableProfiles;
  if (!sp || !(sp.antivirus?.length || sp.webfilter?.length || sp.ips?.length || sp.sslSsh?.length)) return '';
  const cur = p._secProfiles || {};
  const mkOpts = (list, cur) => `<option value="">— aucun —</option>` +
    (list || []).map(n => `<option value="${escHtml(n)}" ${cur === n ? 'selected' : ''}>${escHtml(n)}</option>`).join('');
  const row = (label, key, list) => !list?.length ? '' :
    `<div class="drawer-field"><span class="drawer-field-label">${label}</span><select class="drawer-input drawer-sp-sel" data-idx="${idx}" data-sp="${key}" style="font-size:10px">${mkOpts(list, cur[key])}</select></div>`;
  return `<details class="drawer-security-profiles" open>
    <summary>Security Profiles</summary>
    <div class="drawer-security-profiles-body">
      ${row('Antivirus', 'antivirus', sp.antivirus)}
      ${row('Web Filter', 'webfilter', sp.webfilter)}
      ${row('IPS', 'ips', sp.ips)}
      ${row('SSL Inspection', 'sslSsh', sp.sslSsh)}
    </div>
  </details>`;
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

// Nettoie un nom d'hôte stocké avec l'ancien format "IP=Nom" (corruption de l'import positionnel)
function cleanHostName(h, name) {
  if (!name) return name;
  const prefix = h + '=';
  return name.startsWith(prefix) ? name.slice(prefix.length) : name;
}

function markDrawerObjectResolved(policy, objectKey, name) {
  if (!objectKey || !name) return;
  if (!policy._resolvedObjectKeys) policy._resolvedObjectKeys = {};
  policy._resolvedObjectKeys[objectKey] = name;
}

function isDrawerObjectResolved(policy, objectKey) {
  return !!objectKey && !!policy?._resolvedObjectKeys?.[objectKey];
}

function drawerResolvedObjectHtml(name, title) {
  return `<span style="color:var(--success);font-size:10px" title="${escHtml(title || name)}">&#10003; ${escHtml(name)}${badgeHtml('config')}</span>`;
}

function drawerNamedObjectControl(policy, objectKey, name, found, inputHtml, title) {
  if (found || isDrawerObjectResolved(policy, objectKey)) {
    return drawerResolvedObjectHtml(name, title);
  }
  return inputHtml;
}

function drawerHostControl(policy, host, type) {
  const isSrc = type === 'src';
  const names = isSrc ? policy._srcHostNames : policy._dstHostNames;
  const found = new Set(isSrc ? (policy._srcHostsFound || []) : (policy._dstHostsFound || [])).has(host);
  const autoName = `FF_HOST_${host.replace(/\./g, '_')}`;
  const storedName = cleanHostName(host, names?.[host]);
  const objectKey = `host:${type}:${host}`;
  const displayName = storedName || autoName;
  if (found || isDrawerObjectResolved(policy, objectKey)) {
    return drawerResolvedObjectHtml(displayName, `${host}/32`);
  }
  return `<input class="drawer-host-input" data-object-key="${escHtml(objectKey)}" data-type="${type}" data-host="${escHtml(host)}" value="${escHtml(storedName && storedName !== autoName ? storedName : '')}" placeholder="${escHtml(displayName)}">`;
}

function serviceReuseKeys(svc) {
  if (Array.isArray(svc?.reuseKeys)) {
    return [...new Set(svc.reuseKeys.map(key => String(key).toUpperCase()).filter(Boolean))];
  }
  const icmp = svc?.label?.match(/^(ICMP6?)\/(\d+)\/(\d+)$/i);
  if (icmp) return [`${icmp[1].toUpperCase()}/${parseInt(icmp[2], 10)}/${parseInt(icmp[3], 10)}`];
  const notation = svc?.label?.match(/^(TCP|UDP)\/(\d+)$/i);
  const proto = notation ? notation[1] : svc?.proto;
  const port = notation ? parseInt(notation[2], 10) : svc?.port;
  if (!proto || !port) return [];
  return [`${String(proto).toUpperCase()}/${port}`];
}

function serviceReuseKey(svc) {
  return serviceReuseKeys(svc)[0] || '';
}

function isCompatibleServiceSelected(policy, svc) {
  const keys = serviceReuseKeys(svc);
  const matches = svc?.compatibleMatches || (svc?.compatibleMatch ? [svc.compatibleMatch] : []);
  return keys.length > 0 && matches.some(match =>
    keys.every(key => policy?._serviceReuse?.[key] === match.name));
}

function selectedCompatibleService(services) {
  if (!services || services.length < 2) return null;
  const keys = services.map(serviceReuseKey);
  const protos = new Set(keys.map(key => key.split('/')[0]).filter(Boolean));
  if (protos.size !== 1 || keys.some(key => !key)) return null;
  const candidateLists = services.map(service =>
    service.compatibleMatches || (service.compatibleMatch ? [service.compatibleMatch] : [])
  );
  const common = candidateLists[0].filter(candidate =>
    candidateLists.slice(1).every(list => list.some(match => match.name === candidate.name))
  );
  common.sort((a, b) => a.coverageCount - b.coverageCount || a.name.localeCompare(b.name));
  if (!common.length) return null;
  return {
    ...common[0],
    ports: keys.map(key => parseInt(key.split('/')[1], 10)).sort((a, b) => a - b),
    extraPortCount: Math.max(0, common[0].coverageCount - services.length),
  };
}

function isServiceDecisionResolved(policy, svc) {
  const keys = serviceReuseKeys(svc);
  return keys.length > 0 && keys.every(key => {
    const decision = policy?._resolvedServiceKeys?.[key];
    if (decision === 'specific') return true;
    if (decision?.startsWith('existing:')) {
      return policy?._serviceReuse?.[key] === decision.slice('existing:'.length);
    }
    return false;
  });
}

function clearSelectedServiceKey(policy, serviceKey) {
  const [proto, port] = String(serviceKey || '').split('/');
  if (proto && port) policy?._selectedSvcKeys?.delete(`${port}/${proto}`);
}

function markServiceDecisionResolved(policy, serviceKey, decision) {
  if (!serviceKey) return;
  if (!policy._resolvedServiceKeys) policy._resolvedServiceKeys = {};
  if (decision === 'specific' && policy._serviceReuse) {
    delete policy._serviceReuse[serviceKey];
  } else if (decision.startsWith('existing:')) {
    if (!policy._serviceReuse) policy._serviceReuse = {};
    policy._serviceReuse[serviceKey] = decision.slice('existing:'.length);
  }
  policy._resolvedServiceKeys[serviceKey] = decision;
  clearSelectedServiceKey(policy, serviceKey);
}

function normalizeServiceDecisionKey(rawKey) {
  const value = String(rawKey || '').trim().toUpperCase();
  let match = value.match(/^(TCP|UDP)\/(\d+)$/);
  if (match) return `${match[1]}/${Number(match[2])}`;
  match = value.match(/^(\d+)\/(TCP|UDP)$/);
  return match ? `${match[2]}/${Number(match[1])}` : value;
}

function canonicalMonoServiceIdentity(service) {
  const keys = serviceReuseKeys(service).map(normalizeServiceDecisionKey);
  if (keys.length !== 1) return null;
  const match = keys[0].match(/^(TCP|UDP)\/(\d+)$/);
  if (!match) return null;
  const port = Number(match[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { key: `${match[1]}/${port}`, proto: match[1], port };
}

function policyServiceIndexByCanonicalKey(policy, serviceKey) {
  const wanted = normalizeServiceDecisionKey(serviceKey);
  return (policy?.analysis?.services || []).findIndex(service =>
    canonicalMonoServiceIdentity(service)?.key === wanted);
}

function cloneServiceDecision(service) {
  return typeof structuredClone === 'function'
    ? structuredClone(service) : JSON.parse(JSON.stringify(service));
}

function setPolicyServiceSuggestedName(policy, serviceKey, serviceName) {
  const canonicalKey = normalizeServiceDecisionKey(serviceKey);
  const index = policyServiceIndexByCanonicalKey(policy, canonicalKey);
  if (index < 0) return false;
  const current = policy.analysis.services[index];
  if (current?.found) return false;
  const services = [...policy.analysis.services];
  services[index] = { ...cloneServiceDecision(current), suggestedName: String(serviceName ?? '') };
  policy.analysis = { ...policy.analysis, services };
  return true;
}

function applySpecificServiceDecision(policy, serviceKey, serviceName) {
  const canonicalKey = normalizeServiceDecisionKey(serviceKey);
  if (!serviceName) return false;
  if (!setPolicyServiceSuggestedName(policy, canonicalKey, serviceName)) return false;
  markServiceDecisionResolved(policy, canonicalKey, 'specific');
  return true;
}

function specificServicePropagationPlan(originPolicy, serviceKey) {
  const canonicalKey = normalizeServiceDecisionKey(serviceKey);
  if (!canonicalKey.match(/^(TCP|UDP)\/\d+$/)) return [];
  return (deployState.analyzed || []).flatMap((policy, idx) => {
    if (!policy || policy === originPolicy) return [];
    const serviceIndex = policyServiceIndexByCanonicalKey(policy, canonicalKey);
    if (serviceIndex < 0) return [];
    const service = policy.analysis.services[serviceIndex];
    if (service.found || policy._resolvedServiceKeys?.[canonicalKey] || policy._serviceReuse?.[canonicalKey]) return [];
    return [{ idx, serviceKey: canonicalKey }];
  });
}

function canonicalServiceKeyFromName(name) {
  const compact = String(name || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
  let match = compact.match(/^(TCP|UDP)(\d+)$/);
  if (!match) match = compact.match(/^FFSVC(TCP|UDP)(\d+)$/);
  if (match) return `${match[1]}/${Number(match[2])}`;
  match = compact.match(/^FFSVC(\d+)(TCP|UDP)$/);
  return match ? `${match[2]}/${Number(match[1])}` : null;
}

function defaultSpecificServiceName(identity) {
  return `FF_SVC_${identity.port}_${identity.proto}`;
}

function planInvalidSpecificServiceAssociations(policies) {
  const entries = [];
  for (let policyIndex = 0; policyIndex < (policies || []).length; policyIndex++) {
    const policy = policies[policyIndex];
    for (const service of policy?.analysis?.services || []) {
      if (service?.found || service?._isMerged) continue;
      const identity = canonicalMonoServiceIdentity(service);
      if (!identity) continue;
      const name = String(service.suggestedName || '').trim();
      if (!name) continue;
      const defaults = new Set([
        defaultSpecificServiceName(identity).toUpperCase(),
        `FF_SVC_${identity.proto}_${identity.port}`,
      ]);
      const decision = policy._resolvedServiceKeys?.[identity.key];
      if (decision !== 'specific' && defaults.has(name.toUpperCase())) continue;
      entries.push({ policyIndex, serviceKey: identity.key, identity, name, impliedKey: canonicalServiceKeyFromName(name) });
    }
  }
  const preferredNameByKey = new Map();
  for (const entry of entries) {
    if (entry.impliedKey === entry.serviceKey && !preferredNameByKey.has(entry.serviceKey)) {
      preferredNameByKey.set(entry.serviceKey, entry.name);
    }
  }
  const repairs = new Map();
  const markRepair = entry => repairs.set(`${entry.policyIndex}|${entry.serviceKey}`, {
    policyIndex: entry.policyIndex,
    serviceKey: entry.serviceKey,
    invalidName: entry.name,
    replacementName: preferredNameByKey.get(entry.serviceKey) || null,
  });
  const byName = new Map();
  for (const entry of entries) {
    const key = entry.name.toLowerCase();
    if (!byName.has(key)) byName.set(key, []);
    byName.get(key).push(entry);
  }
  const ambiguous = [];
  for (const group of byName.values()) {
    const definitions = new Set(group.map(entry => entry.serviceKey));
    if (definitions.size < 2) continue;
    const canonical = group.filter(entry => entry.impliedKey === entry.serviceKey);
    const canonicalKeys = new Set(canonical.map(entry => entry.serviceKey));
    if (canonicalKeys.size === 1) {
      group.filter(entry =>
        entry.name.toLowerCase() === 'tcp3268'
        && entry.serviceKey === 'TCP/8530'
        && canonicalKeys.has('TCP/3268')
      ).forEach(markRepair);
    } else {
      ambiguous.push({ name: group[0].name, serviceKeys: [...definitions].sort() });
    }
  }
  return { repairs: [...repairs.values()], ambiguous };
}

function applyInvalidSpecificServiceRecovery(policies, plan) {
  const applied = [];
  for (const repair of plan?.repairs || []) {
    const policy = policies?.[repair.policyIndex];
    const index = policyServiceIndexByCanonicalKey(policy, repair.serviceKey);
    if (!policy || index < 0) continue;
    const service = policy.analysis.services[index];
    const identity = canonicalMonoServiceIdentity(service);
    if (!identity) continue;
    const services = [...policy.analysis.services];
    const next = cloneServiceDecision(service);
    next.suggestedName = repair.replacementName || '';
    services[index] = next;
    policy.analysis = { ...policy.analysis, services };
    if (repair.replacementName) {
      markServiceDecisionResolved(policy, identity.key, 'specific');
    } else {
      if (policy._resolvedServiceKeys) {
        policy._resolvedServiceKeys = { ...policy._resolvedServiceKeys };
        delete policy._resolvedServiceKeys[identity.key];
        if (Object.keys(policy._resolvedServiceKeys).length === 0) delete policy._resolvedServiceKeys;
      }
      if (policy._serviceReuse) {
        policy._serviceReuse = { ...policy._serviceReuse };
        delete policy._serviceReuse[identity.key];
        if (Object.keys(policy._serviceReuse).length === 0) delete policy._serviceReuse;
      }
    }
    if (Array.isArray(policy._backendIssues)) {
      const remaining = policy._backendIssues.filter(issue => !String(issue).includes('SERVICE_NAME_CONFLICT'));
      if (remaining.length) policy._backendIssues = remaining;
      else {
        delete policy._backendIssues;
        delete policy._backendIssueKind;
        delete policy._backendValidated;
      }
    }
    applied.push(repair);
  }
  return { applied, ambiguous: plan?.ambiguous || [] };
}

function compatiblePolicyServiceKeys(policy, serviceName, requestedKeys) {
  const wanted = requestedKeys === undefined || requestedKeys === null ? null
    : requestedKeys instanceof Set
      ? requestedKeys : new Set((requestedKeys || []).map(key => String(key).toUpperCase()));
  const eligible = new Set();
  for (const service of policy?.analysis?.services || []) {
    if (service.found || isServiceDecisionResolved(policy, service)) continue;
    const matches = service.compatibleMatches || (service.compatibleMatch ? [service.compatibleMatch] : []);
    if (!matches.some(match => match?.name === serviceName)) continue;
    for (const key of serviceReuseKeys(service)) {
      if ((!wanted || wanted.has(key))
          && !policy?._resolvedServiceKeys?.[key]
          && !policy?._serviceReuse?.[key]) eligible.add(key);
    }
  }
  return [...eligible];
}

function servicePropagationPlan(originPolicy, serviceName, serviceKeys) {
  const requestedKeys = new Set((serviceKeys || []).map(key => String(key).toUpperCase()).filter(Boolean));
  if (!originPolicy || !serviceName || requestedKeys.size < 2) return [];
  return (deployState.analyzed || []).flatMap((policy, idx) => {
    if (!policy || policy === originPolicy) return [];
    const keys = compatiblePolicyServiceKeys(policy, serviceName);
    return keys.length ? [{ idx, keys }] : [];
  });
}

function _setDrawerServicePropagationPending(policy, pending) {
  if (!pending) {
    delete policy._propagateServicePending;
    return;
  }
  Object.defineProperty(policy, '_propagateServicePending', {
    configurable: true,
    enumerable: false,
    writable: true,
    value: pending,
  });
}

function serializePolicyServiceLabels(policy) {
  const services = policy?.analysis?.services || [];
  const labels = services
    .filter(service => !service?._isMerged)
    .map(service => service?.label)
    .filter(Boolean);
  const mergedSourceLabels = services.flatMap(service => {
    if (!service?._isMerged) return [];
    const proto = String(service.proto || '').toUpperCase();
    if (!['TCP', 'UDP'].includes(proto) || !Array.isArray(service.sourcePorts)) return [];
    return service.sourcePorts
      .map(Number)
      .filter(port => Number.isInteger(port) && port >= 1 && port <= 65535)
      .map(port => `${proto}/${port}`);
  });
  return [...new Set([...labels, ...mergedSourceLabels])];
}

function serializeMergedServiceDecisions(policy) {
  return (policy?.analysis?.services || []).filter(service => service?._isMerged).map(service => ({
    name: service.suggestedName,
    proto: service.proto,
    sourcePorts: [...(service.sourcePorts || [])],
    ...(Array.isArray(service.ports) ? { ports: [...service.ports] } : {}),
    ...(typeof service.portRange === 'string' ? { portRange: service.portRange } : {}),
  }));
}

function mergedServicePortLabel(svc) {
  const proto = String(svc?.proto || '').toUpperCase();
  const portSpec = svc?.portRange || (svc?.ports || []).join(',');
  return portSpec ? `${proto}/${portSpec}` : (svc?.portHint || svc?.label || proto);
}

function destinationRepresentationMode(policy) {
  if (['hosts', 'detected-subnets', 'aggregate'].includes(policy?._dstMode)) return policy._dstMode;
  return policy?._use32Dst ? 'hosts' : 'aggregate';
}

function destinationObservedHosts(policy) {
  const excluded = new Set(policy?._excludedDstHosts || []);
  return [...new Set((policy?.dstHosts || [])
    .filter(host => typeof host === 'string' && host && !excluded.has(host)))];
}

function normalizeDestinationCidr(cidr) {
  const match = String(cidr ?? '').trim().match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d{1,2})$/);
  if (!match) return null;
  const octets = match.slice(1, 5).map(Number);
  const prefix = Number(match[5]);
  if (octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255)
      || !Number.isInteger(prefix) || prefix < 1 || prefix > 32) return null;
  const ip = octets.join('.');
  const mask = prefix === 32 ? 0xFFFFFFFF : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  const networkInt = (ip2intFE(ip) & mask) >>> 0;
  return { cidr: `${int2ipFE(networkInt)}/${prefix}`, prefix, networkInt };
}

function destinationCidrIssue(cidr, hosts) {
  const parsed = normalizeDestinationCidr(cidr);
  if (!parsed) return 'CIDR invalide (0.0.0.0/0 interdit)';
  for (const host of hosts || []) {
    const hostParsed = normalizeDestinationCidr(`${host}/32`);
    if (!hostParsed || (((hostParsed.networkInt & (parsed.prefix === 32
      ? 0xFFFFFFFF : (0xFFFFFFFF << (32 - parsed.prefix)) >>> 0)) >>> 0) !== parsed.networkInt)) {
      return `IP observée ${host} hors du subnet`;
    }
  }
  return '';
}

function destinationDetectedForPolicy(policy) {
  const observed = destinationObservedHosts(policy);
  const observedSet = new Set(observed);
  const covered = new Set();
  const result = [];
  for (const candidate of (Array.isArray(policy?._dstDetectedSubnets) ? policy._dstDetectedSubnets : [])) {
    const candidateHosts = Array.isArray(candidate?.hosts) ? candidate.hosts : [];
    const hosts = [...new Set(candidateHosts
      .filter(host => observedSet.has(host) && !covered.has(host)))];
    if (hosts.length === 0) continue;
    hosts.forEach(host => covered.add(host));
    result.push({ ...candidate, hosts });
  }
  for (const host of observed) {
    if (covered.has(host)) continue;
    result.push({
      subnet: `${host}/32`, hosts: [host], useSubnet: false,
      addrName: '', addrFound: false, suggestedName: `FF_NET_${`${host}/32`.replace(/[./]/g, '_')}`,
      route: null, sources: [],
    });
  }
  return result;
}

function deduplicateDestinationScopes(policy) {
  const observed = new Set(destinationObservedHosts(policy));
  const assigned = new Set();
  const bySubnet = new Map();
  for (const candidate of policy?._multiDstSubnets || []) {
    const parsed = normalizeDestinationCidr(candidate?.subnet);
    const subnet = parsed?.cidr || String(candidate?.subnet || '').trim();
    if (!subnet) continue;
    const candidateHosts = Array.isArray(candidate?.hosts) ? candidate.hosts : [];
    const hosts = [...new Set(candidateHosts
      .filter(host => observed.has(host) && !assigned.has(host)))];
    if (!hosts.length) continue;
    hosts.forEach(host => assigned.add(host));
    if (!bySubnet.has(subnet)) {
      bySubnet.set(subnet, { ...candidate, subnet, hosts, useSubnet: parsed ? parsed.prefix !== 32 : candidate.useSubnet !== false });
      continue;
    }
    const merged = bySubnet.get(subnet);
    merged.hosts = [...new Set([...merged.hosts, ...hosts])].sort();
    if (!merged.addrFound && candidate.addrFound === true) {
      merged.addrFound = true;
      merged.addrName = candidate.addrName || merged.addrName;
    }
    merged.manual = merged.manual === true || candidate.manual === true;
  }
  policy._multiDstSubnets = [...bySubnet.values()];
  policy.dstTargets = policy._multiDstSubnets.map(candidate => candidate.subnet);
  policy.dstTarget = policy.dstTargets[0] || destinationAggregateSubnet(policy);
  return policy._multiDstSubnets;
}

function destinationScopeForElement(policy, element) {
  const scopes = policy?._multiDstSubnets || [];
  const index = Number(element?.dataset?.si);
  const indexed = Number.isInteger(index) ? scopes[index] : null;
  const key = element?.dataset?.subnetKey;
  if (indexed && (!key || indexed.subnet === key)) return indexed;
  return key ? scopes.find(scope => scope.subnet === key) : indexed;
}

function destinationAggregateSubnet(policy) {
  if (policy?._dstAggregateManual && policy._dstAggregateSubnet) return policy._dstAggregateSubnet;
  const hosts = destinationObservedHosts(policy);
  const computed = hosts.length > 0 ? cidrSupernet(hosts.map(host => `${host}/32`)) : '';
  return computed
    || policy?._dstAggregateSubnet
    || (policy?.dstTarget && policy.dstTarget !== 'all' ? policy.dstTarget : '')
    || policy?._dstDetectedSubnets?.[0]?.subnet
    || '';
}

function mergeDestinationDetectionCandidates(policies) {
  const bySubnet = new Map();
  for (const policy of policies || []) {
    const candidateSource = Array.isArray(policy?._dstDetectedSubnets)
      ? policy._dstDetectedSubnets
      : Array.isArray(policy?._multiDstSubnets) ? policy._multiDstSubnets : [];
    const observed = new Set((policy?.dstHosts || [])
      .filter(host => !policy?._excludedDstHosts?.has(host)));
    const covered = new Set();
    const candidates = candidateSource.flatMap(candidate => {
      const hosts = [...new Set((candidate?.hosts || [])
        .filter(host => observed.has(host) && !covered.has(host)))];
      if (!hosts.length) return [];
      hosts.forEach(host => covered.add(host));
      return [{ ...candidate, hosts }];
    });
    for (const candidate of candidates) {
      if (!candidate?.subnet) continue;
      if (!bySubnet.has(candidate.subnet)) {
        bySubnet.set(candidate.subnet, {
          ...candidate,
          hosts: [],
          addrName: candidate.addrName || '',
          addrFound: candidate.addrFound === true,
        });
      }
      const merged = bySubnet.get(candidate.subnet);
      merged.hosts = [...new Set([...merged.hosts, ...(candidate.hosts || [])])].sort();
      if (!merged.addrFound && candidate.addrFound === true) {
        merged.addrFound = true;
        merged.addrName = candidate.addrName || merged.addrName;
      }
      if (!merged.route && candidate.route) merged.route = candidate.route;
      if ((!merged.sources || merged.sources.length === 0) && candidate.sources) merged.sources = candidate.sources;
    }
  }
  return [...bySubnet.values()];
}

function destinationAggregateForPolicies(policies, fallback = '') {
  const targets = [...new Set((policies || []).map(policy => {
    if (policy?._dstAggregateManual && policy._dstAggregateSubnet) return policy._dstAggregateSubnet;
    const hosts = (policy?.dstHosts || []).filter(host => !policy?._excludedDstHosts?.has(host));
    return (hosts.length > 0 ? cidrSupernet(hosts.map(host => `${host}/32`)) : '')
      || policy?._dstAggregateSubnet || policy?.dstTarget;
  }).filter(target => target && target !== 'all'))];
  if (targets.length <= 1) return targets[0] || fallback;
  return cidrSupernet(targets) || fallback || targets[0];
}

function setDestinationRepresentation(policy, mode) {
  if (!policy || !['hosts', 'detected-subnets', 'aggregate'].includes(mode)) return false;
  const detected = destinationDetectedForPolicy(policy);
  if (mode === 'detected-subnets' && detected.length === 0) return false;
  const aggregate = destinationAggregateSubnet(policy);
  if (!policy._dstAggregateManual && aggregate) policy._dstAggregateSubnet = aggregate;
  policy._dstMode = mode;
  policy._dstAddrGrpFound = false;
  policy._useDstGroup = false;
  if (mode === 'hosts') {
    policy._use32Dst = true;
    policy._isMultiDst = false;
    delete policy._multiDstSubnets;
    if (aggregate) {
      policy.dstTarget = aggregate;
      policy.dstTargets = [aggregate];
    }
    policy._dstAddrName = '';
    return true;
  }
  if (mode === 'detected-subnets') {
    const scopes = detected.map(item => ({
      ...item,
      hosts: [...new Set(item.hosts || [])],
      useSubnet: item.subnet?.endsWith('/32') ? false : true,
      addrName: item.addrName || '',
      addrFound: item.addrFound === true,
    }));
    policy._use32Dst = false;
    policy._isMultiDst = scopes.length > 0;
    policy._multiDstSubnets = scopes;
    policy.dstTargets = scopes.map(item => item.subnet);
    policy.dstTarget = scopes[0]?.subnet || aggregate;
    policy._dstDetectedSubnets = scopes.map(item => ({ ...item, hosts: [...(item.hosts || [])] }));
    policy._dstAddrName = '';
    return true;
  }
  policy._use32Dst = false;
  policy._isMultiDst = false;
  delete policy._multiDstSubnets;
  if (aggregate) {
    policy.dstTarget = aggregate;
    policy.dstTargets = [aggregate];
  }
  policy._dstAddrName = policy._dstAggregateAddrName || '';
  return true;
}

function destinationProvenanceLabel(candidate) {
  if (candidate?.manual) return 'CIDR saisi manuellement';
  const route = candidate?.route;
  if (route) {
    const source = String(route.source || 'static').toLowerCase();
    const label = route.dst === '0.0.0.0/0'
      ? 'Route par défaut'
      : source === 'static' ? 'Route statique' : `Route ${source}`;
    return `${label} · ${route.device || route.gateway || '—'}`;
  }
  const iface = candidate?.sources?.find(source => source.type === 'interface');
  if (iface) return `Interface · ${iface.name}`;
  const object = candidate?.sources?.find(source => source.type === 'object');
  if (object) return `Objet FortiGate · ${object.name}`;
  return 'Aucune provenance réseau spécifique';
}

function syncHostCell(idx, type) {
  const p = deployState.analyzed[idx];
  if (!p) return;
  const field = type === 'src' ? '_srcAddrName' : '_dstAddrName';
  const cell = document.querySelector(`.inline-editable[data-idx="${idx}"][data-field="${field}"]`);
  if (!cell) return;
  if (type === 'src') {
    const hFoundSet = new Set(p._srcHostsFound || []);
    const hNames = (p.srcHosts || []).map(h => cleanHostName(h, p._srcHostNames?.[h]) || (hFoundSet.has(h) ? h : h));
    const allNamed = (p.srcHosts || []).every(h => hFoundSet.has(h) || !!(cleanHostName(h, p._srcHostNames?.[h])));
    const hDisplay = hNames.join(', ');
    cell.title = hDisplay;
    cell.innerHTML = escHtml(hDisplay) + (allNamed ? '' : ' ' + badgeHtml('auto'));
    cell.className = `inline-editable ${allNamed ? 'found' : 'missing'}`;
  } else {
    const dhFoundSet = new Set(p._dstHostsFound || []);
    const _autoHostName = h => `FF_HOST_${h.replace(/\./g, '_')}`;
    const _hostNameOk = (h, nm) => { const n = cleanHostName(h, nm?.[h]); return n && n !== _autoHostName(h); };
    const dhNames = (p.dstHosts || []).map(h => cleanHostName(h, p._dstHostNames?.[h]) || (dhFoundSet.has(h) ? h : h));
    const dhAllNamed = (p.dstHosts || []).every(h => dhFoundSet.has(h) || _hostNameOk(h, p._dstHostNames));
    const dhDisplay = dhNames.join(', ');
    cell.title = dhDisplay;
    cell.innerHTML = escHtml(dhDisplay) + (dhAllNamed ? '' : ' ' + badgeHtml('auto'));
    cell.className = `inline-editable ${dhAllNamed ? 'found' : 'missing'}`;
  }
  syncRowStatus(idx);
}

function _buildSvcCellHtml(p, limit = Infinity) {
  const svcList = p.analysis?.services || [];
  const stripPredef = n => (n || '').replace(/PREDEFINED$/i, '');
  const html = svcList.slice(0, limit).map(svc => {
    if (svc._isMerged) {
      const mergedName = svc.suggestedName || svc.label;
      const mergedPortLabel = mergedServicePortLabel(svc);
      return `<span class="match-ok" style="font-size:10px" title="${escHtml(mergedPortLabel)}">&#10003; ${escHtml(mergedName)}${badgeHtml('config')}</span>`;
    }
    const compatibleSelected = isCompatibleServiceSelected(p, svc);
    const reuseKey = serviceReuseKey(svc);
    const selectedReuseName = p._serviceReuse?.[reuseKey];
    const resolvedDecision = p._resolvedServiceKeys?.[reuseKey];
    if (svc.found || compatibleSelected) {
      const dispName = stripPredef(compatibleSelected ? selectedReuseName : svc.name);
      return `<span class="match-ok" style="font-size:10px" title="${escHtml(svc.portHint || stripPredef(svc.label) || dispName)}">&#10003; ${escHtml(dispName)}${badgeHtml('config')}</span>`;
    }
    if (resolvedDecision === 'specific') {
      const dispName = svc.suggestedName || svc.label || `FF_SVC_${svc.port}_${svc.proto}`;
      return `<span class="match-ok" style="font-size:10px" title="${escHtml(svc.portHint || dispName)}">&#10003; ${escHtml(dispName)}${badgeHtml('config')}</span>`;
    }
    const isPortNotation = /^(TCP|UDP)\/\d+$/i.test(svc.suggestedName || '');
    const autoLabel = svc.isNamed ? svc.label : `FF_SVC_${svc.port}_${svc.proto}`;
    const customName = svc.suggestedName && !isPortNotation && svc.suggestedName !== autoLabel ? svc.suggestedName : '';
    const displayName = customName || svc.label || (svc.port ? `${svc.port}/${svc.proto}` : '');
    if (customName) {
      return `<span class="match-ok" style="font-size:10px;color:var(--success)" title="${escHtml(svc.portHint || displayName)}">&#10003; ${escHtml(customName)}${badgeHtml('auto')}</span>`;
    }
    return `<span class="match-ok" style="font-size:10px;color:var(--warn)" title="${escHtml(svc.portHint || displayName)}">${displayName ? escHtml(displayName) + ' ' : ''}${badgeHtml('auto')}</span>`;
  }).join(' ');
  const more = svcList.length > limit ? `<span class="compact-more">+${svcList.length - limit} autres</span>` : '';
  return (html + (html && more ? ' ' : '') + more) || '<span style="color:var(--text2)">–</span>';
}

function syncSvcCell(idx) {
  const p = deployState.analyzed?.[idx];
  if (!p) return;
  const cell = document.querySelector(`.svc-cell[data-svc-idx="${idx}"]`);
  if (cell) cell.innerHTML = _buildSvcCellHtml(p, 3);
  syncRowStatus(idx);
}

function populateDrawer(idx) {
  const p = deployState.analyzed[idx];
  if (!p) return;
  const a = p.analysis || {};
  const pid0 = (p.policyIds || [])[0] || idx;
  const currentAction = (p._action || p.action || 'accept').toLowerCase();
  const title = document.getElementById('drawer-title');
  title.textContent = `Policy ${pid0}`;
  const headerActions = document.getElementById('drawer-header-actions');
  const drawerUndoDisabled = _drawerIdx === null || _drawerHistory.length === 0 ? ' disabled' : '';
  if (headerActions) headerActions.innerHTML = `<button class="btn-sm drawer-view-flows" type="button" onclick="filterFlowsByPolicy(${idx})">→ Voir les flux</button><button class="btn-sm drawer-undo" id="drawer-undo" type="button" aria-label="Annuler la dernière modification" title="Annuler la dernière modification"${drawerUndoDisabled}><span aria-hidden="true">Annuler</span> <kbd aria-hidden="true">Ctrl+Z</kbd></button>`;
  _syncDrawerUndoButton();

  const ifOpts = (deployState.ifaceOpts || []).map(o =>
    `<option value="${escHtml(o.value)}" ${(o.value === (p._srcintf || '')) ? 'selected' : ''}>${escHtml(o.label)}</option>`
  ).join('');
  const ifOptsDst = (deployState.ifaceOpts || []).map(o =>
    `<option value="${escHtml(o.value)}" ${(o.value === (p._dstintf || '')) ? 'selected' : ''}>${escHtml(o.label)}</option>`
  ).join('');
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
  // Addr propagation banner helper — doit être défini AVANT srcSection/dstSection
  const ap = p._propagateAddrPending;
  const _addrBanner = (forType) => {
    if (!ap || ap.addrType !== forType) return '';
    const label = ap.isHost ? ap.hostIp : ap.cidr;
    return `<div class="svc-propagate-banner">
      <span>${ap.count} autre${ap.count>1?'s':''} policy${ap.count>1?'s':''} ${ap.count>1?'ont':'a'} <code style="font-family:var(--mono)">${escHtml(label)}</code> en ${forType === 'src' ? 'source' : 'destination'} — Appliquer <strong>${escHtml(ap.newName)}</strong> à toutes ?</span>
      <button class="btn-sm btn-accent addr-prop-yes">Oui</button>
      <button class="btn-sm addr-prop-no">Non</button>
    </div>`;
  };

  let srcSection = '';
  if (p._multiSrcSubnets?.length) {
    // ── Multi-src : several source subnets ──
    const srcSubs = p._multiSrcSubnets;
    const srcSubRows = srcSubs.map((s, si) => {
      const isSubnet = s.useSubnet !== false;
      const objectKey = `multi-src:${si}`;
      const statusIcon = (s.addrFound || isDrawerObjectResolved(p, objectKey)) ? `<span style="color:var(--success)">&#10003;</span>` : `<span style="color:var(--warn)">+</span>`;
      const nameInput = `<input class="drawer-input drawer-multisrc-name" data-object-key="multi-src:${si}" data-si="${si}" value="${escHtml(inputVal(s.addrName, suggestAddrNameFE(s.subnet)))}" placeholder="${escHtml(s.addrName)}" style="flex:1;font-size:10px">`;
      let hostsHtml = '';
      if (!isSubnet && s.hosts?.length > 0) {
        const visibleSrcHosts = s.hosts.filter(h => !p._excludedSrcHosts?.has(h));
        const shownSrcHosts = p._srcHostsExpanded ? visibleSrcHosts : visibleSrcHosts.slice(0, 8);
        hostsHtml = `<div style="padding-left:16px;margin-top:2px;margin-bottom:6px">${shownSrcHosts.map(h => {
          const foundSet = new Set(p._srcHostsFound || []);
          const hostName = cleanHostName(h, (p._srcHostNames || {})[h]) || `FF_HOST_${h.replace(/\./g,'_')}`;
          const hostFound = foundSet.has(h);
          return `<div class="drawer-host-row">
            <span class="drawer-host-ip">${escHtml(h)}</span>
            ${drawerHostControl(p, h, 'src')}
            <button class="btn-del-item" data-del-type="src-host" data-host="${escHtml(h)}" title="Retirer cet hôte">✕</button>
          </div>`;
        }).join('')}${visibleSrcHosts.length > 8 ? `<button class="drawer-more-toggle drawer-hosts-toggle" data-hosts-type="src">${p._srcHostsExpanded ? 'Réduire' : `+ ${visibleSrcHosts.length - 8} autres`}</button>` : ''}</div>`;
      }
      return `<div class="drawer-multisrc-row" style="display:flex;align-items:center;gap:6px;padding:3px 0">
        <span class="drawer-multisrc-subnet" style="font-family:var(--mono);font-size:11px;min-width:120px">${escHtml(s.subnet)}</span>
        <button class="btn-sm drawer-multisrc-mode" data-si="${si}" style="font-size:9px;padding:2px 8px">${isSubnet ? `/${s.subnet.split('/')[1] || '24'}` : `/32 (${s.hosts?.length || 0}h)`}</button>
        ${isSubnet ? statusIcon : ''}
        ${isSubnet ? drawerNamedObjectControl(p, objectKey, s.addrName, s.addrFound, nameInput, s.subnet) : ''}
        <button class="btn-del-item" data-del-type="src-subnet" data-si="${si}" title="Retirer ce subnet">✕</button>
      </div>${hostsHtml}`;
    }).join('');
    srcSection = `<div class="drawer-section drawer-network-card drawer-source-card">
      <div class="drawer-section-title">Source · ${srcSubs.length} subnets</div>
      ${srcSubRows}
      <div class="drawer-toggle-row" style="margin-top:8px">
        <button class="drawer-toggle-btn drawer-grp-toggle ${p._useSrcGroup ? 'active' : ''}" data-type="src">Grouper (addrgrp)</button>
        ${p._useSrcGroup ? drawerNamedObjectControl(p, 'group:src', p._srcAddrName, p._srcAddrGrpFound, `<input class="drawer-input drawer-src-grp-name" data-object-key="group:src" value="${escHtml(p._srcAddrName || '')}" placeholder="${escHtml(suggestedSrcGrp)}" style="width:160px">`, srcSubs.map(s => s.subnet).join(', ')) : ''}
      </div>
      ${_addrBanner('src')}
      <div class="drawer-field drawer-interface-field"><span class="drawer-field-label">Interface</span><select class="drawer-input drawer-srcintf">${ifOpts}</select></div>
    </div>`;
  } else {
    // ── Single source subnet ──
    let srcHostsHtml = '';
    if (srcHosts.length > 0 && srcMode === 'hosts') {
      const visibleSrcHostsSingle = srcHosts.filter(h => !p._excludedSrcHosts?.has(h));
      const shownSrcHostsSingle = p._srcHostsExpanded ? visibleSrcHostsSingle : visibleSrcHostsSingle.slice(0, 8);
      srcHostsHtml = `<div class="drawer-host-list">${shownSrcHostsSingle.map(h => {
        const foundSet = new Set(p._srcHostsFound || []);
        const hostFound = foundSet.has(h);
        const name = cleanHostName(h, (p._srcHostNames || {})[h]) || `FF_HOST_${h.replace(/\./g,'_')}`;
        return `<div class="drawer-host-row">
          <span class="drawer-host-ip">${escHtml(h)}</span>
          ${drawerHostControl(p, h, 'src')}
          <button class="btn-del-item" data-del-type="src-host" data-host="${escHtml(h)}" title="Retirer cet hôte">✕</button>
        </div>`;
      }).join('')}${visibleSrcHostsSingle.length > 8 ? `<button class="drawer-more-toggle drawer-hosts-toggle" data-hosts-type="src">${p._srcHostsExpanded ? 'Réduire' : `+ ${visibleSrcHostsSingle.length - 8} autres`}</button>` : ''}</div>`;
      if (srcHosts.length > 1) {
        const srcGrpFound = p._srcAddrGrpFound;
        srcHostsHtml += `<div class="drawer-toggle-row" style="margin-top:4px">
          <button class="drawer-toggle-btn drawer-grp-toggle ${p._useSrcGroup ? 'active' : ''}" data-type="src">Grouper (addrgrp)</button>
          ${p._useSrcGroup ? drawerNamedObjectControl(p, 'group:src', p._srcAddrName, srcGrpFound, `<input class="drawer-input drawer-src-grp-name" data-object-key="group:src" value="${escHtml(p._srcAddrName || '')}" placeholder="${escHtml(suggestedSrcGrp)}" style="width:160px">`, srcHosts.map(h => h + '/32').join(', ')) : ''}
        </div>`;
      }
    }
    srcSection = `<div class="drawer-section drawer-network-card drawer-source-card">
      <div class="drawer-section-title">Source</div>
      <div class="drawer-field"><span class="drawer-field-label">Subnet</span><span class="drawer-field-value">${escHtml(p.srcSubnet || '')}</span></div>
      <div class="drawer-toggle-row">
        <span style="font-size:11px;color:var(--text2)">Mode :</span>
        <button class="drawer-toggle-btn drawer-mode-btn ${srcMode==='subnet'?'active':''}" data-type="src" data-mode="subnet">/${p.srcSubnet?.split('/')[1] || 'CIDR'} réseau</button>
        <button class="drawer-toggle-btn drawer-mode-btn ${srcMode==='hosts'?'active':''} ${srcHosts.length<1?'disabled':''}" data-type="src" data-mode="hosts">/32 hôtes (${srcHosts.length})</button>
      </div>
      ${srcMode === 'subnet' ? `<div class="drawer-field drawer-object-field">
        <span class="drawer-field-label">Objet addr</span>
        ${drawerNamedObjectControl(p, 'addr:src', srcAddrName, srcFound, `<input class="drawer-input drawer-src-name" data-object-key="addr:src" value="${escHtml(inputVal(srcAddrName, a.srcAddr?.suggestedName || suggestAddrNameFE(p.srcSubnet)))}" placeholder="${escHtml(srcAddrName || 'FF_...')}">${badgeHtml('auto')}`, a.srcAddr?.cidr || p.srcSubnet || '')}
      </div>` : ''}
      ${srcHostsHtml}
      ${_addrBanner('src')}
      <div class="drawer-field drawer-interface-field"><span class="drawer-field-label">Interface</span><select class="drawer-input drawer-srcintf">${ifOpts}</select></div>
    </div>`;
  }

  // Dst section — depends on multi-dst or single
  let dstSection = '';
  if (p.dstType === 'private' && p._dstDetectedSubnets?.length) {
    const detected = destinationDetectedForPolicy(p);
    const representationMode = destinationRepresentationMode(p);
    const aggregateTarget = destinationAggregateSubnet(p);
    const visibleDstHosts = destinationObservedHosts(p);
    const modeButton = (mode, label, disabled = false) => `<button type="button" class="drawer-toggle-btn drawer-destination-mode ${representationMode === mode ? 'active' : ''} ${disabled ? ' disabled' : ''}" data-mode="${mode}" aria-pressed="${representationMode === mode}"${disabled ? ' disabled' : ''}>${label}</button>`;
    const modeHtml = `<div class="drawer-destination-mode-group drawer-destination-modes" role="group" aria-label="Mode de destination">
      ${modeButton('hosts', `Hôtes /32 (${visibleDstHosts.length})`, visibleDstHosts.length === 0)}
      ${modeButton('detected-subnets', `Sous-réseaux détectés (${detected.length})`, detected.length === 0)}
      ${modeButton('aggregate', 'Réseau agrégé')}
    </div>`;
    const hostRows = visibleDstHosts.map(h => `<div class="drawer-host-row">
      <span class="drawer-host-ip">${escHtml(h)}</span>
      ${drawerHostControl(p, h, 'dst')}
      <button class="btn-del-item" data-del-type="dst-host" data-host="${escHtml(h)}" title="Retirer cet hôte">✕</button>
    </div>`).join('');
    const hostHtml = representationMode === 'hosts'
      ? `<div class="drawer-host-list">${hostRows}</div>` : '';
    const selectedDetected = p._multiDstSubnets?.length
      ? destinationDetectedForPolicy({ ...p, _dstDetectedSubnets: p._multiDstSubnets })
      : detected;
    const detectedHtml = representationMode === 'detected-subnets'
      ? `<div class="drawer-destination-detected-list">${selectedDetected.map((item, si) => {
        const isHost = item.useSubnet === false || item.subnet?.endsWith('/32');
        const objectKey = `multi-dst:${si}`;
        const suggestedName = item.suggestedName || `FF_NET_${(item.subnet || '').replace(/[./]/g, '_')}`;
        const nameInput = `<input class="drawer-input drawer-multidst-name" data-object-key="${objectKey}" data-si="${si}" value="${escHtml(inputVal(item.addrName, suggestedName))}" placeholder="${escHtml(suggestedName)}" style="flex:1;font-size:10px">`;
        const objectHtml = isHost ? '' : drawerNamedObjectControl(p, objectKey, item.addrName, item.addrFound, nameInput, item.subnet);
        const hosts = (item.hosts || []).map(host => escHtml(host)).join(', ');
        return `<div class="drawer-destination-detected-row">
          <div class="drawer-destination-detected-main">
            <input class="drawer-input drawer-destination-cidr" data-si="${si}" value="${escHtml(item.subnet || '')}" aria-label="CIDR destination ${escHtml(String(si + 1))}" style="max-width:150px;font-size:10px">
            ${objectHtml}
          </div>
          <div class="drawer-destination-provenance">${escHtml(destinationProvenanceLabel(item))}</div>
          ${hosts ? `<div class="drawer-destination-observed">IPs observées : <span class="mono">${hosts}</span></div>` : ''}
          ${isHost && hosts ? `<div class="drawer-host-list">${(item.hosts || []).map(host => `<div class="drawer-host-row"><span class="drawer-host-ip">${escHtml(host)}</span>${drawerHostControl(p, host, 'dst')}</div>`).join('')}</div>` : ''}
          <div class="drawer-destination-cidr-error" data-si="${si}">${escHtml(item._cidrError || '')}</div>
        </div>`;
      }).join('')}</div>` : '';
    const aggregateAddressMatch = a.dstAddr?.found && a.dstAddr.cidr === aggregateTarget;
    const aggregateName = p._dstAddrName || (aggregateAddressMatch ? a.dstAddr.name : '') || '';
    const aggregateSuggestedName = `FF_NET_${(aggregateTarget || '').replace(/[./]/g, '_')}`;
    const aggregateHtml = representationMode === 'aggregate'
      ? `<div class="drawer-field"><span class="drawer-field-label">CIDR</span><input class="drawer-input drawer-destination-aggregate-cidr" value="${escHtml(aggregateTarget || '')}" aria-label="CIDR réseau agrégé"><span class="drawer-destination-cidr-error" data-aggregate-cidr-error="true">${escHtml(p._dstAggregateError || '')}</span></div>
        <div class="drawer-field drawer-object-field"><span class="drawer-field-label">Objet addr</span>
          ${drawerNamedObjectControl(p, 'addr:dst', aggregateName, aggregateAddressMatch, `<input class="drawer-input drawer-dst-name" data-object-key="addr:dst" value="${escHtml(inputVal(aggregateName, aggregateSuggestedName))}" placeholder="${escHtml(aggregateName || aggregateSuggestedName)}">${badgeHtml('auto')}`, aggregateTarget)}
        </div>` : '';
    dstSection = `<div class="drawer-section drawer-network-card drawer-destination-card">
      <div class="drawer-section-title">Destination · ${visibleDstHosts.length} hôtes</div>
      ${modeHtml}
      ${hostHtml}
      ${detectedHtml}
      ${aggregateHtml}
      ${_addrBanner('dst')}
      <div class="drawer-field drawer-interface-field"><span class="drawer-field-label">Interface</span><select class="drawer-input drawer-dstintf">${ifOptsDst}</select></div>
    </div>`;
  } else if (p._isMultiDst && p._multiDstSubnets?.length) {
    const subs = p._multiDstSubnets;
    const subRows = subs.map((s, si) => {
      const isSubnet = s.useSubnet !== false;
      const objectKey = `multi-dst:${si}`;
      const statusIcon = (s.addrFound || isDrawerObjectResolved(p, objectKey)) ? `<span style="color:var(--success)">&#10003;</span>` : `<span style="color:var(--warn)">+</span>`;
      const nameInput = `<input class="drawer-input drawer-multidst-name" data-object-key="multi-dst:${si}" data-si="${si}" value="${escHtml(inputVal(s.addrName, suggestAddrNameFE(s.subnet)))}" placeholder="${escHtml(s.addrName)}" style="flex:1;font-size:10px">`;
      let hostsHtml = '';
      if (!isSubnet && s.hosts?.length > 0) {
        const visibleDstHosts = s.hosts.filter(h => !p._excludedDstHosts?.has(h));
        const shownDstHosts = p._dstHostsExpanded ? visibleDstHosts : visibleDstHosts.slice(0, 8);
        hostsHtml = `<div style="padding-left:16px;margin-top:2px;margin-bottom:6px">${shownDstHosts.map(h => {
          const foundSet = new Set(p._dstHostsFound || []);
          const hostName = cleanHostName(h, (p._dstHostNames || {})[h]) || `FF_HOST_${h.replace(/\./g,'_')}`;
          const hostFound = foundSet.has(h);
          return `<div class="drawer-host-row">
            <span class="drawer-host-ip">${escHtml(h)}</span>
            ${drawerHostControl(p, h, 'dst')}
            <button class="btn-del-item" data-del-type="dst-host" data-host="${escHtml(h)}" title="Retirer cet hôte">✕</button>
          </div>`;
        }).join('')}${visibleDstHosts.length > 8 ? `<button class="drawer-more-toggle drawer-hosts-toggle" data-hosts-type="dst">${p._dstHostsExpanded ? 'Réduire' : `+ ${visibleDstHosts.length - 8} autres`}</button>` : ''}</div>`;
      }
      return `<div class="drawer-multidst-row">
        <span class="drawer-multidst-subnet">${escHtml(s.subnet)}</span>
        <button class="btn-sm drawer-multidst-mode" data-si="${si}" style="font-size:9px;padding:2px 8px">${isSubnet ? `/${s.subnet.split('/')[1] || '24'}` : `/32 (${s.hosts?.length || 0}h)`}</button>
        ${isSubnet ? statusIcon : ''}
        ${isSubnet ? drawerNamedObjectControl(p, objectKey, s.addrName, s.addrFound, nameInput, s.subnet) : ''}
        <button class="btn-del-item" data-del-type="dst-subnet" data-si="${si}" title="Retirer ce subnet">✕</button>
      </div>${hostsHtml}`;
    }).join('');
    const isMultiDstWan = p._isWan || p.dstTypeSummary === 'public' || subs.some(s => s.subnet === 'all' || (p.dstTypes || {})[s.subnet] === 'public');
    const dstUseAllMulti = p._dstUseAll === true;
    dstSection = `<div class="drawer-section drawer-network-card drawer-destination-card">
      <div class="drawer-section-title">Destination · ${subs.length} scopes</div>
      ${isMultiDstWan ? `<div class="drawer-toggle-row" style="margin-bottom:8px">
        <span style="font-size:11px;color:var(--text2)">Mode :</span>
        <button class="drawer-toggle-btn drawer-dstall-btn ${!dstUseAllMulti ? 'active' : ''}" data-val="false">IPs spécifiques (${subs.length})</button>
        <button class="drawer-toggle-btn drawer-dstall-btn ${dstUseAllMulti ? 'active' : ''}" data-val="true">all</button>
      </div>` : ''}
      ${isMultiDstWan && dstUseAllMulti ? `<div class="drawer-field drawer-object-field">
        <span class="drawer-field-label">Objet addr</span>
        <span class="drawer-field-value" style="color:var(--success)">&#10003; all${badgeHtml('config')}</span>
      </div>` : `${subRows}
      <div class="drawer-toggle-row" style="margin-top:8px">
        <button class="drawer-toggle-btn drawer-grp-toggle ${p._useDstGroup ? 'active' : ''}" data-type="dst">Grouper (addrgrp)</button>
        ${p._useDstGroup ? drawerNamedObjectControl(p, 'group:dst', p._dstAddrName, p._dstAddrGrpFound, `<input class="drawer-input drawer-grp-name" data-object-key="group:dst" value="${escHtml(p._dstAddrName || '')}" placeholder="${escHtml(suggestedDstGrp)}" style="width:160px">`, subs.map(s => s.subnet).join(', ')) : ''}
      </div>`}
      ${_addrBanner('dst')}
      <div class="drawer-field drawer-interface-field"><span class="drawer-field-label">Interface</span><select class="drawer-input drawer-dstintf">${ifOptsDst}</select></div>
    </div>`;
  } else {
    const dstAddrName = p._dstAddrName || a.dstAddr?.name || '';
    const dstFound = a.dstAddr?.found;
    const isWan = p._isWan || p.dstType === 'public';
    const dstUseAll = p._dstUseAll !== undefined ? p._dstUseAll : isWan;
    const privateDetected = p.dstType === 'private' && p._dstDetectedSubnets?.length
      ? destinationDetectedForPolicy(p) : [];
    const privateRepresentation = p.dstType === 'private'
      ? (p._dstMode === 'subnet' ? 'aggregate' : destinationRepresentationMode(p)) : '';
    const privateModeButton = (mode, label, disabled = false) => `<button type="button" class="drawer-toggle-btn drawer-destination-mode ${privateRepresentation === mode ? 'active' : ''} ${disabled ? ' disabled' : ''}" data-mode="${mode}" aria-pressed="${privateRepresentation === mode}"${disabled ? ' disabled' : ''}>${label}</button>`;
    const privateModeHtml = p.dstType === 'private' ? `<div class="drawer-destination-mode-group drawer-destination-modes" role="group" aria-label="Mode de destination">
      ${privateModeButton('hosts', `Hôtes /32 (${destinationObservedHosts(p).length})`, destinationObservedHosts(p).length === 0)}
      ${privateModeButton('detected-subnets', `Sous-réseaux détectés (${privateDetected.length})`, privateDetected.length === 0)}
      ${privateModeButton('aggregate', 'Réseau agrégé')}
    </div>` : '';
    const showPrivateAggregate = p.dstType === 'private'
      && (privateRepresentation === 'aggregate' || dstMode === 'subnet');
    let dstHostsHtml = '';
    if (dstHosts.length > 0 && (dstMode === 'hosts' || (isWan && !dstUseAll))) {
      const dstFoundSet = new Set(p._dstHostsFound || []);
      const visibleDstHostsSingle = dstHosts.filter(h => !p._excludedDstHosts?.has(h));
      const shownDstHostsSingle = p._dstHostsExpanded ? visibleDstHostsSingle : visibleDstHostsSingle.slice(0, 8);
      dstHostsHtml = `<div class="drawer-host-list">${shownDstHostsSingle.map(h => {
        const name = cleanHostName(h, (p._dstHostNames || {})[h]) || `FF_HOST_${h.replace(/\./g,'_')}`;
        const hostFound = dstFoundSet.has(h);
        return `<div class="drawer-host-row">
          <span class="drawer-host-ip">${escHtml(h)}</span>
          ${drawerHostControl(p, h, 'dst')}
          <button class="btn-del-item" data-del-type="dst-host" data-host="${escHtml(h)}" title="Retirer cet hôte">✕</button>
        </div>`;
      }).join('')}${visibleDstHostsSingle.length > 8 ? `<button class="drawer-more-toggle drawer-hosts-toggle" data-hosts-type="dst">${p._dstHostsExpanded ? 'Réduire' : `+ ${visibleDstHostsSingle.length - 8} autres`}</button>` : ''}</div>`;
    }
    // WAN + IPs spécifiques + pas de dstHosts : montrer dstTarget comme objet à nommer
    let dstWanSpecificHtml = '';
    if (isWan && !dstUseAll && dstHosts.length === 0 && p.dstTarget && p.dstTarget !== 'all') {
      const ip = p.dstTarget;
      const autoName = `FF_HOST_${ip.replace(/[\./]/g,'_')}`;
      const customName = p._dstAddrName || '';
      const dstTargetFound = dstFound && dstAddrName !== 'all';
      const dstInput = `<input class="drawer-input drawer-dst-name" data-object-key="addr:dst" value="${escHtml(inputVal(customName, autoName))}" placeholder="${escHtml(autoName)}">${badgeHtml('auto')}`;
      dstWanSpecificHtml = `<div class="drawer-field drawer-object-field">
        <span class="drawer-field-label">Objet addr</span>
        ${drawerNamedObjectControl(p, 'addr:dst', dstAddrName || customName, dstTargetFound, dstInput, ip)}
      </div>`;
    }
    dstSection = `<div class="drawer-section drawer-network-card drawer-destination-card">
      <div class="drawer-section-title">Destination · ${destinationObservedHosts(p).length} hôtes</div>
      <div class="drawer-field">
        <span class="drawer-field-label">Target</span>
        <span class="drawer-field-value">${escHtml(p.dstTarget || '—')}</span>
      </div>
      ${isWan ? `<div class="drawer-toggle-row">
        <span style="font-size:11px;color:var(--text2)">Mode :</span>
        <button class="drawer-toggle-btn drawer-dstall-btn ${dstUseAll ? 'active' : ''}" data-val="true">all</button>
        <button class="drawer-toggle-btn drawer-dstall-btn ${!dstUseAll ? 'active' : ''}" data-val="false">IPs spécifiques${dstHosts.length > 0 ? ` (${dstHosts.length})` : ''}</button>
      </div>
      ${dstUseAll ? `<div class="drawer-field drawer-object-field">
        <span class="drawer-field-label">Objet addr</span>
        <span class="drawer-field-value" style="color:var(--success)">&#10003; all${badgeHtml('config')}</span>
      </div>` : dstWanSpecificHtml}
      ` : `${privateModeHtml}
      ${showPrivateAggregate ? `<div class="drawer-field drawer-object-field">
        <span class="drawer-field-label">Objet addr</span>
        ${drawerNamedObjectControl(p, 'addr:dst', dstAddrName, dstFound, `<input class="drawer-input drawer-dst-name" data-object-key="addr:dst" value="${escHtml(inputVal(dstAddrName, a.dstAddr?.suggestedName || suggestAddrNameFE(p.dstTarget)))}" placeholder="${escHtml(dstAddrName || 'FF_...')}">${badgeHtml('auto')}`, a.dstAddr?.cidr || p.dstTarget || '')}
      </div>` : ''}
      `}
      ${dstHostsHtml}
      ${_addrBanner('dst')}
      <div class="drawer-field drawer-interface-field"><span class="drawer-field-label">Interface</span><select class="drawer-input drawer-dstintf">${ifOptsDst}</select></div>
    </div>`;
  }


  // Services
  const svcList = a.services || [];
  if (!p._selectedSvcKeys) p._selectedSvcKeys = new Set();
  const selKeys = p._selectedSvcKeys;
  // Compute merge bar state
  const getSvcPortProto = s => { const m = s.label?.match(/^(TCP|UDP)\/(\d+)$/i); return m ? { port: parseInt(m[2],10), proto: m[1].toUpperCase() } : { port: s.port, proto: (s.proto||'').toUpperCase() }; };
  const selectableSvcs = svcList.filter(s => {
    if (s.found || isServiceDecisionResolved(p, s)) return false;
    const m = s.label?.match(/^(TCP|UDP)\/\d+$/i);
    return m || (!s.isNamed && s.port);
  });
  const selectedSvcs = selectableSvcs.filter(s => { const { port, proto } = getSvcPortProto(s); return selKeys.has(`${port}/${proto}`); });
  const canMerge = selectedSvcs.length >= 2 && new Set(selectedSvcs.map(s => getSvcPortProto(s).proto)).size === 1;
  const selectionSignature = selectedSvcs.map(serviceReuseKey).sort().join('|');
  const commonCompatibleService = canMerge ? selectedCompatibleService(selectedSvcs) : null;
  const compatibleSelectionDismissed = !!selectionSignature
    && p._dismissedCompatibleSelection === selectionSignature;
  const showGlobalCompatibleDecision = !!commonCompatibleService && !compatibleSelectionDismissed;
  const globalCompatibleSelected = !!commonCompatibleService
    && commonCompatibleService.ports.every(port => p._serviceReuse?.[`${getSvcPortProto(selectedSvcs[0]).proto}/${port}`] === commonCompatibleService.name);
  const selectedGlobalServiceKeys = new Set(selectedSvcs.map(serviceReuseKey));
  const mergeProto = canMerge ? getSvcPortProto(selectedSvcs[0]).proto : '';
  const mergePorts = canMerge ? selectedSvcs.map(s => getSvcPortProto(s).port).sort((a, b) => a - b) : [];
  const mergeRangeSuggestion = canMerge ? `${mergePorts[0]}-${mergePorts[mergePorts.length - 1]}` : '';
  const mergeName = p._mergedSvcName || (canMerge ? `FF_SVC_${mergeProto}_MULTI` : '');
  const mergeMode = p._mergeMode || 'list';
  const mergeBar = canMerge && !showGlobalCompatibleDecision ? `
    <div class="svc-merge-bar" style="background:var(--bg3);border-radius:6px;padding:8px;margin-top:8px;display:flex;flex-wrap:wrap;gap:6px;align-items:center">
      <span style="font-size:11px;color:var(--text2)">${selectedSvcs.length} ports ${mergeProto} sélectionnés</span>
      <input class="drawer-input svc-merge-name" value="${escHtml(mergeName)}" placeholder="FF_SVC_${mergeProto}_MULTI" style="width:160px;font-size:11px">
      <button class="btn-sm svc-merge-type ${mergeMode==='list'?'active':''}" data-mode="list" style="font-size:10px">Ports individ.</button>
      <button class="btn-sm svc-merge-type ${mergeMode==='range'?'active':''}" data-mode="range" style="font-size:10px">Range</button>
      ${mergeMode === 'range' ? `<input class="drawer-input svc-merge-range" value="${escHtml(p._mergeRange || mergeRangeSuggestion)}" placeholder="${mergeRangeSuggestion}" style="width:100px;font-size:11px">` : `<span style="font-size:10px;color:var(--text2)">${mergePorts.join(', ')}</span>`}
      <button class="btn-sm btn-accent svc-do-merge" style="font-size:10px">Fusionner</button>
    </div>` : '';
  const compatiblePortSpec = String(commonCompatibleService?.portSpec || '').replace(/(\d)-(\d)/g, '$1–$2');
  const selectedPortLabels = commonCompatibleService?.ports?.map(port => `${mergeProto}/${port}`) || [];
  const selectedPortSummary = selectedPortLabels.length > 3
    ? `${selectedPortLabels.slice(0, 3).join(', ')}… +${fmtNum(selectedPortLabels.length - 3)} autres`
    : selectedPortLabels.join(', ');
  const selectedPortTitle = selectedPortLabels.join(', ');
  const compatibleSelectionHtml = showGlobalCompatibleDecision ? `
    <div class="svc-selected-compatible" title="${escHtml(`${commonCompatibleService.portSpec} · Ports sélectionnés : ${selectedPortTitle}`)}">
      <div class="svc-selected-compatible-copy">
        <strong aria-label="${escHtml(commonCompatibleService.name)} couvre les ports sélectionnés">${escHtml(commonCompatibleService.name)} couvre les ports sélectionnés</strong>
        <small title="${escHtml(selectedPortTitle)}">${escHtml(compatiblePortSpec)} · Ports sélectionnés : ${escHtml(selectedPortSummary)} · +${fmtNum(commonCompatibleService.extraPortCount)} ports supplémentaires</small>
      </div>
      <div>
        <button class="btn-sm btn-accent svc-use-compatible-selected ${globalCompatibleSelected ? 'btn-active' : ''}" data-proto="${mergeProto}" data-ports="${commonCompatibleService.ports.join(',')}" data-service-name="${escHtml(commonCompatibleService.name)}" aria-label="Utiliser ${escHtml(commonCompatibleService.name)}">${globalCompatibleSelected ? '✓ Service utilisé' : `Utiliser ${escHtml(commonCompatibleService.name)}`}</button>
        <button class="btn-sm svc-create-new-selected" data-selection-signature="${escHtml(selectionSignature)}">Créer un nouveau service</button>
      </div>
    </div>` : '';
  const stripPd = n => (n || '').replace(/PREDEFINED$/i, '');
  const resolvedExistingGroups = new Map();
  const resolvedExistingKeys = new Set();
  for (const service of svcList) {
    const keys = serviceReuseKeys(service);
    if (keys.length === 0) continue;
    const decisions = keys.map(key => p._resolvedServiceKeys?.[key]);
    if (!decisions.every(decision => decision?.startsWith('existing:'))) continue;
    const serviceName = decisions[0].slice('existing:'.length);
    if (!decisions.every(decision => decision === `existing:${serviceName}`)
        || !keys.every(key => p._serviceReuse?.[key] === serviceName)) continue;
    if (!resolvedExistingGroups.has(serviceName)) resolvedExistingGroups.set(serviceName, []);
    resolvedExistingGroups.get(serviceName).push(service);
    keys.forEach(key => resolvedExistingKeys.add(key));
  }
  const resolvedExistingHtml = [...resolvedExistingGroups].map(([serviceName, services]) => `
    <div class="drawer-field" title="${escHtml(services.map(service => service.label).join(', '))}">
      <span class="drawer-field-label">Ports couverts</span>
      <span class="drawer-field-value" style="color:var(--success)">&#10003; ${escHtml(serviceName)}${badgeHtml('config')}</span>
    </div>`).join('');
  const servicesWithoutResolvedExisting = svcList.filter(service => {
    const keys = serviceReuseKeys(service);
    return keys.length === 0 || !keys.every(key => resolvedExistingKeys.has(key));
  });
  const visibleSvcList = showGlobalCompatibleDecision
    ? servicesWithoutResolvedExisting.filter(service =>
      !serviceReuseKeys(service).some(key => selectedGlobalServiceKeys.has(key)))
    : servicesWithoutResolvedExisting;
  const displayServiceCount = visibleSvcList.length + resolvedExistingGroups.size + (showGlobalCompatibleDecision ? 1 : 0);
  const renderService = svc => {
    if (svc._isMerged) {
      const mergedName = svc.suggestedName || svc.label;
      const mergedPortLabel = svc.portRange
        ? `${String(svc.proto || '').toUpperCase()}/${svc.portRange}`
        : mergedServicePortLabel(svc);
      const rawKey = svc.label || mergedName;
      return `<div class="drawer-field drawer-service-row" title="${escHtml(svc.portHint || mergedPortLabel)}"><span class="drawer-field-label">${escHtml(mergedPortLabel)}</span><span class="drawer-field-value" style="color:var(--success)">&#10003; ${escHtml(mergedName)}${badgeHtml('config')}</span><button class="btn-del-item" type="button" data-del-type="svc" data-svc-key="${escHtml(rawKey)}" aria-label="Retirer ${escHtml(mergedPortLabel)}" title="Retirer ce service de la policy">✕</button></div>`;
    }
    if (svc.found) {
      const dispLabel = stripPd(svc.label || svc.name);
      const dispName  = stripPd(svc.name);
      const rawKey    = svc.label || svc.name; // keep raw for data-svc-key (CLI needs full name)
      return `<div class="drawer-field drawer-service-row" title="${escHtml(svc.portHint || '')}"><span class="drawer-field-label">${escHtml(dispLabel)}</span><span class="drawer-field-value" style="color:var(--success)">&#10003; ${escHtml(dispName)}${badgeHtml(svc.source === 'predefined' ? 'predefined' : 'config')}</span><button class="btn-del-item" type="button" data-del-type="svc" data-svc-key="${escHtml(rawKey)}" aria-label="Retirer ${escHtml(dispLabel)}" title="Retirer ce service de la policy">✕</button></div>`;
    }
    // Detect port-notation labels like "UDP/11436" from FortiGate logs
    const _pnm = svc.label?.match(/^(TCP|UDP)\/(\d+)$/i);
    const _icmp = svc.label?.match(/^(ICMP6?)\/(\d+)\/(\d+)$/i);
    const svcProto = _pnm ? _pnm[1].toUpperCase() : (svc.proto || '').toUpperCase();
    const svcPort  = _pnm ? parseInt(_pnm[2], 10) : svc.port;
    const reuseKeys = serviceReuseKeys(svc);
    const observedServiceLabel = _icmp
      ? `${_icmp[1].toUpperCase()}/${parseInt(_icmp[2], 10)}/${parseInt(_icmp[3], 10)}`
      : reuseKeys.length > 1 ? reuseKeys.join(', ') : `${svcProto}/${svcPort}`;
    const svcKey = _pnm ? `${svcPort}/${svcProto}` : (svc.isNamed ? `label:${svc.label}` : `${svc.port}/${svc.proto}`);
    const reuseKey = serviceReuseKey(svc);
    const compatibleMatch = svc.compatibleMatch;
    const usingCompatible = isCompatibleServiceSelected(p, svc);
    const serviceDecisionResolved = isServiceDecisionResolved(p, svc);
    const serviceDecision = reuseKey ? p._resolvedServiceKeys?.[reuseKey] : null;
    const isSelectable = !serviceDecisionResolved && !usingCompatible && !svc.found && (_pnm || (!svc.isNamed && svc.port));
    const isSelected = selKeys.has(svcKey);
    const legacySvcAutoName = _pnm ? `FF_SVC_${svcPort}_${svcProto}` : null;
    const svcAutoName = _pnm ? `FF_SVC_${svcProto}_${svcPort}` : (svc.isNamed ? svc.label : `FF_SVC_${svc.port}_${svc.proto}`);
    const hasCustomSuggestedName = svc.suggestedName
      && svc.suggestedName !== svcAutoName
      && svc.suggestedName !== legacySvcAutoName;
    const svcDefaultName = hasCustomSuggestedName ? svc.suggestedName : svcAutoName;
    const svcInputValue = hasCustomSuggestedName ? svc.suggestedName : '';
    // Show inline port hint only when it's precise (predefined/custom/port-notation resolved)
    // — never when it's the raw multi-port "observé" fallback (misleading for named services)
    const precisHint = svc.portHint && !svc.portHint.includes('observé');
    const hintTitle = svc.portHint || '(nom issu des logs FortiGate — port/protocol non résolu dans la config chargée)';
    const hintText = precisHint
      ? `<span style="font-size:9px;color:var(--text2);margin-left:4px" title="${escHtml(hintTitle)}">${escHtml(svc.portHint)}</span>`
      : '';
    if (serviceDecision === 'specific') {
      const finalName = svc.suggestedName || svcAutoName;
      return `<div class="drawer-field drawer-service-row" title="${escHtml(observedServiceLabel)}"><span class="drawer-field-label">${escHtml(svc.label || observedServiceLabel)}</span><span class="drawer-field-value" style="color:var(--success)">&#10003; ${escHtml(finalName)}${badgeHtml('config')}</span><button class="btn-del-item" type="button" data-del-type="svc" data-svc-key="${escHtml(svcKey)}" aria-label="Retirer ${escHtml(svc.label || observedServiceLabel)}" title="Retirer ce service de la policy">✕</button></div>`;
    }
    const compatibilityHtml = compatibleMatch && !serviceDecisionResolved && !commonCompatibleService ? `<div class="drawer-service-compatibility-line ${usingCompatible ? 'is-selected' : ''}" title="${escHtml(compatibleMatch.portSpec)}" aria-label="Service observé · Service compatible · Extension possible">
      <span class="drawer-service-compatibility-text"><strong class="mono">${escHtml(observedServiceLabel)}</strong> observé → <strong>${escHtml(compatibleMatch.name)}</strong> compatible · <strong>${fmtNum(compatibleMatch.extraPortCount)} ports</strong></span>
      <span class="drawer-service-compatibility-spec mono">${escHtml(compatibleMatch.portSpec)}</span>
      <div class="drawer-service-compatibility-actions">
        <button class="btn-sm drawer-use-compatible-service ${usingCompatible ? 'btn-active' : ''}" data-service-key="${escHtml(reuseKey)}" data-service-keys="${escHtml(reuseKeys.join(','))}" data-service-name="${escHtml(compatibleMatch.name)}">${usingCompatible ? '✓ Service utilisé' : 'Utiliser ce service'}</button>
        ${_icmp ? '' : `<button class="btn-sm drawer-create-specific-service ${usingCompatible ? '' : 'btn-active'}" data-service-key="${escHtml(reuseKey)}" data-service-keys="${escHtml(reuseKeys.join(','))}">Créer un service spécifique</button>`}
      </div>
    </div>` : '';
    return `<div class="drawer-service-item${compatibilityHtml ? ' drawer-service-item-with-compatibility' : ''}">
      <div class="drawer-field drawer-service-row${isSelectable ? ' svc-selectable' : ''}" data-svc-key="${escHtml(svcKey)}"${isSelectable ? ` role="button" tabindex="0" aria-pressed="${isSelected}"` : ''} style="cursor:${isSelectable?'pointer':'default'};${isSelected ? 'background:rgba(99,179,237,0.10);border-radius:4px;outline:1px solid var(--accent);' : ''}">
        <span class="drawer-field-label" title="${escHtml(hintTitle)}">${escHtml(svc.label || `${svc.port}/${svc.proto}`)}</span>
        ${svc.isNamed && !_pnm ? hintText : ''}
        <input class="drawer-input drawer-svc-name" data-svc-key="${escHtml(svcKey)}" value="${escHtml(svcInputValue)}" placeholder="${escHtml(svcDefaultName)}" onclick="event.stopPropagation()" ${usingCompatible || _icmp ? 'disabled' : ''}>${badgeHtml('auto')}
        <button class="btn-del-item" type="button" data-del-type="svc" data-svc-key="${escHtml(svcKey)}" aria-label="Retirer ${escHtml(svc.label || observedServiceLabel)}" title="Retirer ce service de la policy">✕</button>
      </div>
      ${compatibilityHtml}
    </div>`;
  };
  const resolvedVisibleServices = visibleSvcList.filter(svc =>
    svc._isMerged || svc.found || isServiceDecisionResolved(p, svc));
  const pendingVisibleServices = visibleSvcList.filter(svc =>
    !(svc._isMerged || svc.found || isServiceDecisionResolved(p, svc)));
  const resolvedServiceEntries = resolvedExistingHtml
    + resolvedVisibleServices.map(renderService).join('');
  const pendingServiceEntries = pendingVisibleServices.map(renderService).join('');
  const configuredServiceCount = resolvedExistingGroups.size + resolvedVisibleServices.length;
  const pendingServiceCount = pendingVisibleServices.length + (showGlobalCompatibleDecision ? 1 : 0);
  // Propagation banner (shown after blur on svc name when other policies have same port/proto)
  const pp = p._propagatePending;
  const propagateBanner = pp ? `<div class="svc-propagate-banner">
    <span>${pp.count} autre${pp.count>1?'s':''} policy${pp.count>1?'s':''} ${pp.count>1?'ont':'a'} <code style="font-family:var(--mono)">${escHtml(pp.label || `${pp.proto}/${pp.port}`)}</code>${pp.portHint ? ` <span style="font-size:9px;color:var(--text2)">(${escHtml(pp.portHint)})</span>` : ''} — Appliquer <strong>${escHtml(pp.newName)}</strong> à toutes ?</span>
    <button class="btn-sm btn-accent svc-prop-yes">Oui</button>
    <button class="btn-sm svc-prop-no">Non</button>
  </div>` : '';
  const servicePropagation = p._propagateServicePending;
  const servicePropagationBanner = servicePropagation?.targets?.length ? `<div class="svc-propagate-banner drawer-service-propagate-banner">
    <span>${servicePropagation.targets.length} autre${servicePropagation.targets.length > 1 ? 's' : ''} polic${servicePropagation.targets.length > 1 ? 'ies' : 'y'} contien${servicePropagation.targets.length > 1 ? 'nent' : 't'} des ports couverts par <strong>${escHtml(servicePropagation.serviceName)}</strong>. Appliquer ce service aux policies concernées&nbsp;?</span>
    <button class="btn-sm btn-accent svc-prop-yes svc-service-prop-yes">Oui</button>
    <button class="btn-sm svc-prop-no svc-service-prop-no">Non</button>
  </div>` : '';

  const body = document.getElementById('drawer-body');
  body.innerHTML = `
    <div class="drawer-section drawer-general-summary">
      <div class="drawer-section-title">Général</div>
      <div class="drawer-general-lines">
        <div class="drawer-general-line"><span>Direction</span><strong class="dir-badge ${p._isWan ? 'wan' : 'lan'}">${p._isWan ? 'WAN' : 'LAN'}</strong></div>
        <div class="drawer-general-line"><span>Sessions</span><strong>${fmtNum(p.sessions || 0)}</strong></div>
        <div class="drawer-general-line drawer-general-action"><span>Action</span><div class="drawer-action-group" role="group" aria-label="Action de la policy">
          <button type="button" class="btn-sm drawer-action-btn accept ${currentAction === 'accept' ? 'active' : ''}" data-action="accept" aria-pressed="${currentAction === 'accept'}">✓ ACCEPT</button>
          <button type="button" class="btn-sm drawer-action-btn deny ${currentAction === 'deny' ? 'active' : ''}" data-action="deny" aria-pressed="${currentAction === 'deny'}">✕ DENY</button>
        </div></div>
        <div class="drawer-general-line"><span>Policy ID</span><strong>${pid0}</strong></div>
        <div class="drawer-general-line drawer-general-control"><span>Log</span><select class="drawer-input drawer-inline-select drawer-log-sel" aria-label="Journalisation"><option value="all" ${(p._log||'all')==='all'?'selected':''}>all</option><option value="utm" ${p._log==='utm'?'selected':''}>utm</option><option value="disable" ${p._log==='disable'?'selected':''}>disable</option></select></div>
        <div class="drawer-general-line drawer-general-control"><span>NAT</span><label class="drawer-inline-toggle"><input type="checkbox" class="drawer-nat" ${p._nat ? 'checked' : ''}><span class="drawer-nat-value">${p._nat ? 'Activé' : 'Désactivé'}</span></label></div>
        <div class="drawer-general-line drawer-general-name"><span>Nom</span><input class="drawer-input drawer-inline-input drawer-policy-name" value="${escHtml(p._policyName || '')}" placeholder="FF_POLICY_..." title="Nom complet de la policy"></div>
      </div>
    </div>
    <div class="drawer-network-grid">
      ${srcSection}
      ${dstSection}
    </div>
    ${svcList.length ? `<div class="drawer-section drawer-services-section">
      <div class="drawer-section-title">Services (${displayServiceCount})${!showGlobalCompatibleDecision && selectableSvcs.length > 1 ? `<label style="font-size:10px;color:var(--text2);font-weight:400;margin-left:8px;display:inline-flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" class="svc-sel-all" ${selectedSvcs.length === selectableSvcs.length ? 'checked':''} style="cursor:pointer;margin:0"> Tout sélectionner</label>` : ''}</div>
      ${resolvedServiceEntries ? `<div class="drawer-services-group drawer-services-configured"><div class="drawer-services-subtitle">Configurés <span>(${configuredServiceCount})</span></div><div class="drawer-services-grid">${resolvedServiceEntries}</div></div>` : ''}
      ${(pendingServiceEntries || compatibleSelectionHtml) ? `<div class="drawer-services-group drawer-services-pending"><div class="drawer-services-subtitle">À traiter <span>(${pendingServiceCount})</span></div>${compatibleSelectionHtml}${pendingServiceEntries ? `<div class="drawer-services-grid">${pendingServiceEntries}</div>` : ''}</div>` : ''}
      ${servicePropagationBanner}${mergeBar}${propagateBanner}
    </div>` : ''}
    ${buildDrawerSecProfiles(p, idx)}
  `;
}

// ═══════════════════════════════════════════════════════════════
// View: Analyse (wrapper — sub-tabs: Flux, Matrice, Groupes, Ports)
// ═══════════════════════════════════════════════════════════════

async function analyse() {
  let sub = state.subView.analyse;
  if (sub === 'groups') sub = state.subView.analyse = 'flows';
  const pills = [
    { key: 'flows',  label: 'Flux',    icon: '≡' },
    { key: 'matrix', label: 'Matrice', icon: '⊞' },
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
          <div style="margin-left:auto;display:flex;gap:8px;align-items:center;font-size:12px;font-weight:400">
            <div class="dropdown-wrap" id="deploy-options-wrap">
              <button class="btn-sm dropdown-trigger">Options ▾</button>
              <div class="dropdown-menu deploy-options-menu">
                <label class="deploy-option-row"><span>NAT WAN</span><input type="checkbox" id="opt-nat"></label>
                <label class="deploy-option-row"><span>Action</span><select id="opt-action" class="deploy-select"><option value="accept">accept</option><option value="deny">deny</option></select></label>
                <label class="deploy-option-row"><span>Logs</span><select id="opt-log" class="deploy-select"><option value="all">log all</option><option value="utm">log utm</option><option value="disable">log disable</option></select></label>
              </div>
            </div>
            <button class="btn-accent" id="btn-analyze">⚡ Analyser les policies</button>
          </div>
        </div>
        <div id="deploy-hps-warn" style="display:none;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.35);border-radius:6px;padding:5px 12px;font-size:12px;color:var(--danger,#ef4444);margin-bottom:4px"></div>
        <div class="deploy-toolbar" id="deploy-merge-bar" style="display:none">
          <span id="deploy-merge-info" style="font-size:11px;color:var(--text2)"></span>
          <div class="dropdown-wrap" id="merge-dropdown-wrap">
            <button class="btn-sm dropdown-trigger">⚡ Fusion ▾</button>
            <div class="dropdown-menu" style="min-width:210px;padding:10px 12px">
              <div style="font-size:10px;font-weight:700;color:var(--text2);margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px">Périmètre</div>
              <div style="display:flex;gap:4px;margin-bottom:10px">
                <button class="btn-sm merge-scope-btn ${deployState.mergeScope==='all'?'btn-accent':''}" data-scope="all">Tout</button>
                <button class="btn-sm merge-scope-btn ${deployState.mergeScope==='internet'?'btn-accent':''}" data-scope="internet">Internet</button>
                <button class="btn-sm merge-scope-btn ${deployState.mergeScope==='lan'?'btn-accent':''}" data-scope="lan">LAN</button>
              </div>
              <div style="font-size:10px;font-weight:700;color:var(--text2);margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px">Stratégie</div>
              <div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:6px">
                <button class="btn-sm merge-strategy-btn ${deployState.mergeStrategy==='service'?'btn-accent':''}" data-strategy="service">Par service</button>
                <button class="btn-sm merge-strategy-btn ${deployState.mergeStrategy==='max'?'btn-accent':''}" data-strategy="max">Par source</button>
                <button class="btn-sm merge-strategy-btn ${deployState.mergeStrategy==='destination'?'btn-accent':''}" data-strategy="destination">Par destination</button>
                <button class="btn-sm merge-strategy-btn ${deployState.mergeStrategy==='policy'?'btn-accent':''}" data-strategy="policy">Par interface</button>
              </div>
              <div class="merge-strategy-hint">${{
                service:     '↳ Le plus granulaire : même services + interfaces → règles multi-src/dst précises. Idéal pour construire des policies propres.',
                max:         '↳ Même flux src→dst → une règle par source. Bon compromis granularité / volume.',
                destination: '↳ Même destination + interfaces → fusionne les sources. Réduit bien sans trop élargir les règles.',
                policy:      '↳ ⚠️ Le plus réducteur : regroupe par policy d\'origine. Peut recréer des règles très larges si la policy de départ était permissive.',
              }[deployState.mergeStrategy] || ''}</div>
              <button class="btn-sm btn-accent" style="width:100%;margin-bottom:8px" data-merge="apply">▶ Appliquer</button>
              <div class="dropdown-sep" style="margin:4px -4px"></div>
              <div class="dropdown-item" data-merge="selection">⚡ Fusionner la sélection</div>
              <div class="dropdown-sep"></div>
              <div class="dropdown-item" data-merge="reset">↺ Réinitialiser</div>
            </div>
          </div>
          <div class="dropdown-wrap" id="detail-dropdown-wrap">
            <button class="btn-sm dropdown-trigger ${deployState.bruteMode !== 'off' ? 'btn-active' : ''}" id="btn-brute-mode">${{ off: 'Détailler ▾', service: 'Services ✓', host: 'IP à IP ✓', 'src-agg-dst-detail': 'Réseau → Serveur ✓' }[deployState.bruteMode] || 'Détailler ▾'}</button>
            <div class="dropdown-menu" style="min-width:270px;padding:10px 12px">
              <div style="font-size:10px;font-weight:700;color:var(--text2);margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px">Mode de détail</div>
              <div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:6px">
                <button class="btn-sm detail-mode-btn ${deployState.bruteMode==='service'?'btn-accent':''}" data-detail-mode="service">Services</button>
                <button class="btn-sm detail-mode-btn ${deployState.bruteMode==='host'?'btn-accent':''}" data-detail-mode="host">IP à IP</button>
                <button class="btn-sm detail-mode-btn ${deployState.bruteMode==='src-agg-dst-detail'?'btn-accent':''}" data-detail-mode="src-agg-dst-detail">Réseau → Serveur</button>
              </div>
              <div class="detail-mode-hint">${{
                service:              '↳ 1 policy par service — sources et destinations restent groupées. Vue propre par protocole.',
                host:                 '↳ 1:1 complet : 1 policy par hôte src /32 × hôte dst /32 × service. Maximum de granularité.',
                'src-agg-dst-detail': '↳ Hybride : sources en réseau CIDR, destinations en IP /32. Idéal pour flux utilisateurs → serveurs (WSUS, DC, VEEAM…).',
              }[deployState.bruteMode] || ''}</div>
              <button class="btn-sm btn-accent" style="width:100%;margin-bottom:8px" data-detail-action="apply">▶ Appliquer</button>
              <div class="dropdown-sep" style="margin:4px -4px"></div>
              <div class="dropdown-item" data-detail-action="reset">↺ Désactiver le détail</div>
            </div>
          </div>
          <div class="dropdown-wrap" id="analyse-dropdown">
            <button class="btn-sm dropdown-trigger ${deployState.riskPanelOpen ? 'btn-accent' : ''}" id="btn-analyse-menu">Analyse ▾</button>
            <div class="dropdown-menu" style="min-width:160px">
              <div class="dropdown-item" id="btn-risk-toggle">⚠ Risques</div>
              <div class="dropdown-item" id="btn-risk-ports">⚙ Ports à risque</div>
            </div>
          </div>
          <button class="btn-sm btn-accent" id="btn-merge-selection" style="display:none" title="Fusionner les policies sélectionnées en une seule">⚡ Fusionner la sélection (<span id="merge-sel-count">0</span>)</button>
          <span class="toolbar-sep"></span>
          <span class="history-btn-group" title="Historique des modifications (10 max)">
            <button class="btn-sm btn-history" id="btn-policy-undo" disabled title="Annuler la dernière modification">‹</button>
            <button class="btn-sm btn-history" id="btn-policy-redo" disabled title="Rétablir">›</button>
          </span>
          <span style="margin-left:auto"></span>
          <input type="text" id="deploy-search" class="deploy-search-input" placeholder="Rechercher (IP, subnet, service, srcintf:X, dstintf:Y...)" value="${escHtml(deployState.searchFilter || '')}" title="Filtrer par texte libre. Syntaxe spéciale : srcintf:NOM ou dstintf:NOM pour filtrer par interface exacte">
        </div>
        <div class="missing-bar" id="deploy-missing-bar" style="display:none;cursor:pointer" onclick="showObjectsModal()" title="Cliquer pour nommer les objets manquants">
          <span id="deploy-missing-text"></span>
          <span style="margin-left:auto;font-size:10px;opacity:0.7">→ Cliquer pour nommer</span>
        </div>
        <div class="missing-bar" id="no-rcvd-bar" style="display:none">
          <span id="no-rcvd-bar-text" style="flex:1"></span>
          <button id="no-rcvd-toggle" class="missing-bar-btn"></button>
        </div>
<div class="deploy-legend" id="deploy-legend" style="display:none">
          <div class="deploy-legend-item"><span class="deploy-legend-dot found"></span> Objet existant</div>
          <div class="deploy-legend-item"><span class="deploy-legend-dot missing"></span> A créer</div>
          <div class="deploy-legend-item"><span class="deploy-legend-dot auto"></span> Auto-détecté</div>
          <span style="margin-left:auto;font-size:10px;color:var(--text2)">Cliquez sur une ligne pour la personnaliser</span>
        </div>
        <div id="deploy-risk-panel" style="display:none;padding:0 4px 12px"></div>
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
              <button class="btn-sm" id="btn-export-policies-xlsx" title="Exporter les policies en Excel">📊 Export Excel</button>
              <label class="btn-sm" style="cursor:pointer" title="Importer les modifications depuis un fichier Excel">📥 Import Excel<input type="file" id="btn-import-policies-xlsx" accept=".xlsx,.xls" style="display:none"></label>
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

  // VDOM selector
  el('vdom-selector')?.addEventListener('change', async (e) => {
    const vdom = e.target.value;
    try {
      const r = await fetch(`/api/deploy/config-vdom?session=${state.session}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vdom }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
      deployState.fortiConfig = data;
      const ir = await fetch(`/api/deploy/interfaces?session=${state.session}`);
      if (ir.ok) deployState.interfaces = await ir.json();
      deploy();
    } catch (err) {
      alert('Erreur changement VDOM : ' + err.message);
    }
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

    // Merge scope toggle
    const scopeBtn = e.target.closest('.merge-scope-btn');
    if (scopeBtn) {
      e.stopImmediatePropagation(); // empêche la fermeture du dropdown
      deployState.mergeScope = scopeBtn.dataset.scope;
      document.querySelectorAll('.merge-scope-btn').forEach(b => b.classList.toggle('btn-accent', b.dataset.scope === deployState.mergeScope));
      return;
    }
    // Merge strategy toggle
    const strategyBtn = e.target.closest('.merge-strategy-btn');
    if (strategyBtn) {
      e.stopImmediatePropagation(); // empêche la fermeture du dropdown
      deployState.mergeStrategy = strategyBtn.dataset.strategy;
      document.querySelectorAll('.merge-strategy-btn').forEach(b => b.classList.toggle('btn-accent', b.dataset.strategy === deployState.mergeStrategy));
      const hintEl = document.querySelector('.merge-strategy-hint');
      if (hintEl) hintEl.textContent = {
        service:     '↳ Le plus granulaire : même services + interfaces → règles multi-src/dst précises. Idéal pour construire des policies propres.',
        max:         '↳ Même flux src→dst → une règle par source. Bon compromis granularité / volume.',
        destination: '↳ Même destination + interfaces → fusionne les sources. Réduit bien sans trop élargir les règles.',
        policy:      '↳ ⚠️ Le plus réducteur : regroupe par policy d\'origine. Peut recréer des règles très larges si la policy de départ était permissive.',
      }[deployState.mergeStrategy] || '';
      return;
    }
    // Merge action from dropdown
    const mergeItem = e.target.closest('[data-merge]');
    if (mergeItem) {
      const mode = mergeItem.dataset.merge;
      document.querySelectorAll('.dropdown-wrap.open').forEach(w => w.classList.remove('open'));
      if (mode === 'reset') applyMerge('reset');
      else if (mode === 'selection') mergeSelectedDeployPolicies();
      else if (mode === 'apply') showMergeDiff(deployState.mergeScope, deployState.mergeStrategy);
      return;
    }


    if (e.target.id === 'btn-risk-ports') {
      document.querySelectorAll('.dropdown-wrap.open').forEach(w => w.classList.remove('open'));
      showRiskPortsModal();
      return;
    }

    if (e.target.id === 'btn-risk-toggle') {
      document.querySelectorAll('.dropdown-wrap.open').forEach(w => w.classList.remove('open'));
      deployState.riskPanelOpen = !deployState.riskPanelOpen;
      const panel = el('deploy-risk-panel');
      const body  = el('deploy-policy-body');
      panel.style.display = deployState.riskPanelOpen ? '' : 'none';
      body.style.display  = deployState.riskPanelOpen ? 'none' : '';
      el('btn-analyse-menu')?.classList.toggle('btn-accent', deployState.riskPanelOpen);
      if (deployState.riskPanelOpen) loadRiskPanel();
      return;
    }

    // Detail mode selection (dropdown — mode sélectionné sans appliquer)
    const detailModeBtn = e.target.closest('.detail-mode-btn');
    if (detailModeBtn) {
      e.stopImmediatePropagation();
      deployState.bruteMode = detailModeBtn.dataset.detailMode;
      document.querySelectorAll('.detail-mode-btn').forEach(b => b.classList.toggle('btn-accent', b.dataset.detailMode === deployState.bruteMode));
      const hintEl = document.querySelector('.detail-mode-hint');
      if (hintEl) hintEl.textContent = {
        service:              '↳ 1 policy par service — sources et destinations restent groupées. Vue propre par protocole.',
        host:                 '↳ 1:1 complet : 1 policy par hôte src /32 × hôte dst /32 × service. Maximum de granularité.',
        'src-agg-dst-detail': '↳ Hybride : sources en réseau CIDR, destinations en IP /32. Idéal pour flux utilisateurs → serveurs (WSUS, DC, VEEAM…).',
      }[deployState.bruteMode] || '';
      return;
    }

    // Detail action (appliquer / réinitialiser)
    const detailAction = e.target.closest('[data-detail-action]');
    if (detailAction) {
      const action = detailAction.dataset.detailAction;
      document.querySelectorAll('.dropdown-wrap.open').forEach(w => w.classList.remove('open'));
      if (action === 'reset') deployState.bruteMode = 'off';
      _applyDetailMode();
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

  // Toggle "sans réponse" (rcvdBytes=0) — wired once
  if (!window._noRcvdToggleWired) {
    window._noRcvdToggleWired = true;
    document.addEventListener('click', e => {
      if (!e.target.closest('#no-rcvd-toggle')) return;
      deployState.hideNoRcvd = !deployState.hideNoRcvd;
      updateNoRcvdToggleBtn();
      renderDeployPolicies(filterDeployPolicies(), false);
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

  // Export/Import policies Excel
  el('btn-export-policies-xlsx')?.addEventListener('click', exportPoliciesExcel);
  el('btn-import-policies-xlsx')?.addEventListener('change', e => {
    const f = e.target.files[0];
    if (f) { importPoliciesExcel(f); e.target.value = ''; }
  });

  // Export/Import session
  // (missing objects bar is now info-only — no modal, edit via drawer)

  // Applique le bruteMode courant (appelé par le dropdown Détailler → Appliquer / Réinitialiser)
  function _applyDetailMode() {
    const labels = { 'off': 'Détailler ▾', 'service': 'Services ✓', 'host': 'IP à IP ✓', 'src-agg-dst-detail': 'Réseau → Serveur ✓' };
    const btn = el('btn-brute-mode');
    if (btn) {
      btn.textContent = labels[deployState.bruteMode] || 'Détailler ▾';
      btn.classList.toggle('btn-active', deployState.bruteMode !== 'off');
    }
    // M3: _detailOriginal est dédié au détail, distinct de _analyzedOriginal (base de fusion).
    // On capture la base UNIQUEMENT à la transition off→actif → le détail s'applique sur
    // l'état courant (fusionné inclus) et non sur un snapshot pré-fusion partagé.
    const hpsAvailable = deployState.hostPairServices && Object.keys(deployState.hostPairServices).length > 0;
    const warn = el('deploy-hps-warn');
    if (!hpsAvailable && deployState.bruteMode !== 'off') {
      // Sans l'index de flows bruts, les modes de détail /32 produiraient des associations fictives
      if (warn) {
        warn.textContent = '⚠ Index de flows absent — résultats potentiellement imprécis. Relancez l\'analyse pour des données exactes.';
        warn.style.display = '';
      }
    } else if (warn) {
      warn.style.display = 'none';
    }
    if (deployState.bruteMode === 'off') {
      // Retour à la base : restaurer le snapshot pré-détail et le libérer
      if (deployState._detailOriginal) {
        deployState.analyzed = deployState._detailOriginal.map(p => ({ ...p }));
        deployState._detailOriginal = null;
      }
    } else {
      if (!deployState._detailOriginal && deployState.analyzed) {
        deployState._detailOriginal = deployState.analyzed.map(p => ({ ...p }));
      }
      const orig = deployState._detailOriginal || [];
      if (deployState.bruteMode === 'service') {
        deployState.analyzed = splitPoliciesByService(orig, deployState.baseAnalyzedPolicies, deployState.hostPairServices);
      } else if (deployState.bruteMode === 'host') {
        deployState.analyzed = splitPoliciesByHostAndService(orig, deployState.baseAnalyzedPolicies, deployState.hostPairServices);
      } else if (deployState.bruteMode === 'src-agg-dst-detail') {
        deployState.analyzed = splitPoliciesBySrcAggDstDetail(orig, deployState.baseAnalyzedPolicies, deployState.hostPairServices);
      }
    }
    deployState.selected = defaultSelectedSet(deployState.analyzed || []);
    deployState.mergeSelected = new Set();
    deployState._noRcvdCount = undefined;
    _updateMergeSelectionBtn();
    renderDeployPolicies(filterDeployPolicies(), false);
  }

  // Merge selection button
  el('btn-merge-selection')?.addEventListener('click', () => {
    mergeSelectedDeployPolicies();
  });

  // Undo / Redo
  el('btn-policy-undo')?.addEventListener('click', _policyUndoStep);
  el('btn-policy-redo')?.addEventListener('click', _policyRedoStep);

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
    ${cfg.vdomList?.length > 1
      ? `<div class="conf-stat" style="flex-direction:row;align-items:center;gap:6px;padding:4px 8px">
           <select id="vdom-selector" style="font-size:12px;padding:2px 4px;border-radius:4px;border:1px solid var(--border);background:var(--bg2);color:var(--text);cursor:pointer">
             ${cfg.vdomList.map(v => `<option value="${v}"${v === cfg.selectedVdom ? ' selected' : ''}>${v}</option>`).join('')}
           </select>
           <span class="conf-stat-lbl" style="margin:0">VDOM</span>
         </div>`
      : cfg.vdom
        ? `<div class="conf-stat" title="VDOM actif : ${cfg.selectedVdom || ''}"><span class="conf-stat-val">${cfg.selectedVdom || 'root'}</span><span class="conf-stat-lbl">VDOM</span></div>`
        : ''}
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

// ─── Brute /32 modes ──────────────────────────────────────────────────────────
// Mode 'service' : 1 policy par service (sources groupées)
// Mode 'host'    : 1 policy par source /32 × service (vrai 1:1)

function splitPoliciesByService(analyzedPolicies, baseAnalyzed, hostPairServices) {
  const result = [];
  const forceHosts = { _use32Src: true, _use32Dst: true, _srcMode: 'hosts', _dstMode: 'hosts' };
  const subnetIdx = baseAnalyzed && baseAnalyzed.length ? _buildSubnetServiceIndex(baseAnalyzed) : null;

  for (const p of analyzedPolicies) {
    // Union des services réels pour toutes les paires (srcHost, dstHost) de cette policy
    const srcHosts = p.srcHosts || [];
    const dstHosts = p.dstHosts || [];
    let services;
    if (srcHosts.length > 0 && dstHosts.length > 0) {
      const svcMap = new Map();
      for (const src of srcHosts) {
        for (const dst of dstHosts) {
          for (const svc of _getServicesForPair(src, dst, p, hostPairServices, subnetIdx)) {
            svcMap.set(svc.label || svc.name, svc);
          }
        }
      }
      if (svcMap.size > 0) services = [...svcMap.values()];
    }
    if (!services) services = p.analysis?.services || [];

    if (services.length <= 1) {
      result.push({ ...p, ...forceHosts, analysis: services.length === 1 ? { ...p.analysis, services } : p.analysis });
    } else {
      for (const svc of services) {
        // Filtre srcHosts ET dstHosts aux seuls hôtes ayant réellement utilisé ce service.
        let svcSrcHosts = srcHosts;
        let svcDstHosts = dstHosts;
        if (hostPairServices && srcHosts.length > 0 && dstHosts.length > 0) {
          const svcName = (svc.label || svc.name || '').toUpperCase();
          const filteredSrc = srcHosts.filter(src =>
            dstHosts.some(dst => {
              const flowSvcs = hostPairServices[src + '|' + dst];
              return flowSvcs && flowSvcs.some(s => s.toUpperCase() === svcName);
            })
          );
          const filteredDst = dstHosts.filter(dst =>
            srcHosts.some(src => {
              const flowSvcs = hostPairServices[src + '|' + dst];
              return flowSvcs && flowSvcs.some(s => s.toUpperCase() === svcName);
            })
          );
          if (filteredSrc.length > 0) svcSrcHosts = filteredSrc;
          if (filteredDst.length > 0) svcDstHosts = filteredDst;
        }
        result.push({
          ...p,
          ...forceHosts,
          srcHosts:    svcSrcHosts,
          dstHosts:    svcDstHosts,
          serviceDesc: svc.label || svc.name || '',
          analysis:    { ...p.analysis, services: [svc] },
        });
      }
    }
  }
  return result;
}

// Retourne les services réels pour une paire (srcHost, dstHost) spécifique.
// Priorité 1 : hostPairServices (index exact par IP depuis les flows bruts)
// Priorité 2 : index subnet depuis baseAnalyzed (pré-fusion, moins précis)
// Fallback   : services de la policy courante (comportement d'origine)
function _getServicesForPair(srcHost, dstHost, p, hostPairServices, subnetIdx) {
  // Niveau 1 : flows bruts — service exactement observé pour cette paire IP
  if (hostPairServices && srcHost && dstHost) {
    const flowSvcs = hostPairServices[srcHost + '|' + dstHost];
    if (flowSvcs && flowSvcs.length > 0) {
      const flowSvcSet = new Set(flowSvcs.map(s => s.toUpperCase()));
      // Filtre les objets service complets de la policy (conserve les métadonnées : found, suggestedName, port…)
      const filtered = (p.analysis?.services || []).filter(s =>
        flowSvcSet.has((s.label || s.name || '').toUpperCase())
      );
      if (filtered.length > 0) return filtered;
    }
  }
  // Niveau 2 : index subnet pré-fusion
  if (subnetIdx && srcHost && dstHost) {
    const pairMap = subnetIdx.get(srcHost + '|' + dstHost);
    if (pairMap && pairMap.size > 0) return [...pairMap.values()];
  }
  // Fallback
  return p.analysis?.services || [];
}

// Construit un index subnet srcHost→dstHost→services[] depuis les policies brutes (pré-fusion)
// Utilisé comme fallback quand les flows bruts ne sont pas disponibles
function _buildSubnetServiceIndex(baseAnalyzed) {
  const idx = new Map(); // "srcHost|dstHost" → Map<svcName, svc>
  for (const p of (baseAnalyzed || [])) {
    const srcHosts = p.srcHosts || [];
    const dstHosts = p.dstHosts || [];
    const services = p.analysis?.services || [];
    for (const src of srcHosts) {
      for (const dst of dstHosts) {
        const key = src + '|' + dst;
        if (!idx.has(key)) idx.set(key, new Map());
        const svcMap = idx.get(key);
        for (const svc of services) {
          svcMap.set(svc.name || svc.label, svc);
        }
      }
    }
  }
  return idx;
}

function splitPoliciesByHostAndService(analyzedPolicies, baseAnalyzed, hostPairServices) {
  const result = [];
  const forceHosts = { _use32Src: true, _use32Dst: true, _srcMode: 'hosts', _dstMode: 'hosts' };
  const subnetIdx = baseAnalyzed && baseAnalyzed.length ? _buildSubnetServiceIndex(baseAnalyzed) : null;

  for (const p of analyzedPolicies) {
    const srcHosts = p.srcHosts || [];
    const dstHosts = p.dstHosts || [];
    const srcList  = srcHosts.length > 0 ? srcHosts : [null];
    const dstList  = dstHosts.length > 0 ? dstHosts : [null];

    const noRcvdSrcSet = new Set(p.noRcvdSrcHosts || []);

    for (const srcHost of srcList) {
      const hostNoRcvd = srcHost ? (noRcvdSrcSet.has(srcHost) ? 1 : 0) : (p.noRcvdFlows || 0);
      for (const dstHost of dstList) {
        // Si l'index exact est disponible, ignorer les paires non observées dans les flows bruts
        // (artefacts du produit cartésien après fusion — ne correspondent à aucun trafic réel)
        if (hostPairServices && srcHost && dstHost && !hostPairServices[srcHost + '|' + dstHost]) continue;
        const svcs = _getServicesForPair(srcHost, dstHost, p, hostPairServices, subnetIdx);
        const svcList = svcs.length > 0 ? svcs : [null];

        const splitCount  = srcList.length * dstList.length * svcList.length;
        const sessionsPer = Math.max(1, Math.round((p.sessions || 0) / splitCount));

        for (const svc of svcList) {
          result.push({
            ...p,
            ...forceHosts,
            srcSubnet:    srcHost ? srcHost + '/32' : p.srcSubnet,
            srcHosts:     srcHost ? [srcHost] : (p.srcHosts || []),
            dstTarget:    dstHost ? dstHost + '/32' : p.dstTarget,
            dstHosts:     dstHost ? [dstHost] : (p.dstHosts || []),
            serviceDesc:  svc ? (svc.label || svc.name || '') : p.serviceDesc,
            analysis:     svc ? { ...p.analysis, services: [svc] } : p.analysis,
            noRcvdFlows:  hostNoRcvd,
            sessions:     sessionsPer,
          });
        }
      }
    }
  }
  return result;
}

// Mode 'src-agg-dst-detail' : source agrégée en subnet /24, destination détaillée par IP /32
// Cas d'usage : flux utilisateurs (mêmes droits → subnet) vers serveurs (distincts → IP individuelle)
// srcHosts est filtré aux seuls hôtes ayant réellement communiqué avec dstHost+service
// → si l'utilisateur bascule en /32, seuls ces hôtes apparaissent
function splitPoliciesBySrcAggDstDetail(analyzedPolicies, baseAnalyzed, hostPairServices) {
  const result = [];
  const subnetIdx = baseAnalyzed && baseAnalyzed.length ? _buildSubnetServiceIndex(baseAnalyzed) : null;

  for (const p of analyzedPolicies) {
    const srcHosts = p.srcHosts || [];
    const dstHosts = p.dstHosts || [];
    const dstList  = dstHosts.length > 0 ? dstHosts : [null];

    for (const dstHost of dstList) {
      // Hôtes sources ayant réellement du trafic vers cette destination
      let realSrcHosts = srcHosts;
      if (hostPairServices && dstHost && srcHosts.length > 0) {
        realSrcHosts = srcHosts.filter(src => hostPairServices[src + '|' + dstHost]);
        if (realSrcHosts.length === 0) continue;
      }

      // Agrège les services de toutes les paires réelles (srcHost → dstHost)
      const svcMap = new Map();
      if (realSrcHosts.length > 0 && dstHost) {
        for (const src of realSrcHosts) {
          for (const svc of _getServicesForPair(src, dstHost, p, hostPairServices, subnetIdx)) {
            svcMap.set(svc.label || svc.name, svc);
          }
        }
      }
      const svcs = svcMap.size > 0 ? [...svcMap.values()] : (p.analysis?.services || [null]);
      const svcList = svcs.length > 0 ? svcs : [null];

      const splitCount  = dstList.length * svcList.length;
      const sessionsPer = Math.max(1, Math.round((p.sessions || 0) / splitCount));

      for (const svc of svcList) {
        // Pour ce service précis, ne garder que les hôtes sources qui l'ont réellement utilisé
        let svcSrcHosts = realSrcHosts;
        if (svc && hostPairServices && dstHost && realSrcHosts.length > 0) {
          const svcName = (svc.label || svc.name || '').toUpperCase();
          const filtered = realSrcHosts.filter(src => {
            const flowSvcs = hostPairServices[src + '|' + dstHost];
            return flowSvcs && flowSvcs.some(s => s.toUpperCase() === svcName);
          });
          if (filtered.length > 0) svcSrcHosts = filtered;
        }

        result.push({
          ...p,
          _use32Src: false,
          _use32Dst: true,
          _srcMode: 'subnet',
          _dstMode: 'hosts',
          srcHosts:    svcSrcHosts,
          dstTarget:   dstHost ? dstHost + '/32' : p.dstTarget,
          dstHosts:    dstHost ? [dstHost] : (p.dstHosts || []),
          serviceDesc: svc ? (svc.label || svc.name || '') : p.serviceDesc,
          analysis:    svc ? { ...p.analysis, services: [svc] } : p.analysis,
          sessions:    sessionsPer,
        });
      }
    }
  }
  return result;
}

// ─── Merge sélection manuelle ─────────────────────────────────────────────────

function _updateMergeSelectionBtn() {
  const btn = el('btn-merge-selection');
  const countEl = el('merge-sel-count');
  const n = deployState.mergeSelected.size;
  if (btn) btn.style.display = n >= 2 ? '' : 'none';
  if (countEl) countEl.textContent = n;
}

// ─── Services inconnus ────────────────────────────────────────────────────────


function _isUnqualifiedSvc(svc) {
  if (svc.found) return false;
  const autoLabel      = svc.isNamed ? svc.label : `FF_SVC_${svc.port}_${svc.proto}`;
  const isPortNotation = /^(TCP|UDP)\/\d+$/i.test(svc.suggestedName || '');
  const customName     = svc.suggestedName && !isPortNotation && svc.suggestedName !== autoLabel
    ? svc.suggestedName : '';
  return !customName;
}

function _collectUnqualifiedSvcs(policies) {
  const portMap = new Map();
  for (const p of (policies || [])) {
    for (const svc of (p.analysis?.services || [])) {
      if (!_isUnqualifiedSvc(svc)) continue;
      const key = svc.isNamed
        ? `label:${svc.label}`
        : `${svc.port}/${(svc.proto || 'tcp').toUpperCase()}`;
      if (!portMap.has(key)) {
        portMap.set(key, { key, port: svc.port, proto: svc.proto, label: svc.label, isNamed: svc.isNamed, count: 0 });
      }
      portMap.get(key).count++;
    }
  }
  return portMap;
}



function mergeSelectedDeployPolicies() {
  const sel = [...deployState.mergeSelected];
  if (sel.length < 2) {
    alert('S\u00e9lectionnez au moins 2 policies pour fusionner.');
    return;
  }
  const toMerge  = sel.map(i => deployState.analyzed[i]).filter(Boolean);
  if (new Set(toMerge.map(policyDecisionKey)).size > 1) {
    alert('Impossible de fusionner des policies avec des actions ou options différentes.');
    return;
  }
  const manualWan = toMerge.some(policy => policy.dstType === 'public' || policy._isWan);
  if (manualWan && new Set(toMerge.map(serviceSetKey)).size > 1) {
    alert('Impossible de fusionner vers Internet des policies avec des services différents.');
    return;
  }
  _savePolicySnapshot();
  const base     = toMerge[0];
  const allSvcs  = mergeServices(toMerge);
  const sessions = toMerge.reduce((s, p) => s + (p.sessions || 0), 0);
  const policyIds = [...new Set(toMerge.flatMap(p => p.policyIds || []))].sort((a, b) => +a - +b);
  let allSrcHosts = [...new Set(toMerge.flatMap(p => p.srcHosts || []))];
  let allDstHosts = [...new Set(toMerge.flatMap(p => (p.dstHosts || []).filter(host => !p._excludedDstHosts?.has(host))))];
  const mergedDetectedDstSubnets = mergeDestinationDetectionCandidates(toMerge);
  const mergedAggregateDst = destinationAggregateForPolicies(toMerge, base._dstAggregateSubnet || base.dstTarget);

  // Re-filtrer via hostPairServices pour éliminer les combinaisons src×dst fictives
  // (croisements entre policies d'origines différentes qui n'ont jamais eu lieu)
  const _hpsManual = deployState.hostPairServices;
  if (_hpsManual && Object.keys(_hpsManual).length > 0 && allSrcHosts.length > 0 && allDstHosts.length > 0) {
    const svcNames = new Set(allSvcs.map(s => (s.label || s.name || '').toUpperCase()));
    const fSrc = allSrcHosts.filter(src =>
      allDstHosts.some(dst => {
        const svcs = _hpsManual[src + '|' + dst];
        return svcs && (svcNames.size === 0 || svcs.some(s => svcNames.has(s.toUpperCase())));
      })
    );
    const fDst = allDstHosts.filter(dst =>
      allSrcHosts.some(src => {
        const svcs = _hpsManual[src + '|' + dst];
        return svcs && (svcNames.size === 0 || svcs.some(s => svcNames.has(s.toUpperCase())));
      })
    );
    if (fSrc.length > 0) allSrcHosts = fSrc;
    if (fDst.length > 0) allDstHosts = fDst;
  }

  const srcSubnets = [...new Set(toMerge.flatMap(policy =>
    policy._multiSrcSubnets?.map(item => item.subnet) || policy.srcSubnets || [policy.srcSubnet]).filter(Boolean))].sort();
  const multiSrcSubnets = srcSubnets.length > 1 ? srcSubnets.map(subnet => {
    const entries = toMerge.flatMap(policy => {
      if (policy._multiSrcSubnets?.length) return policy._multiSrcSubnets.filter(item => item.subnet === subnet);
      if (policy.srcSubnet !== subnet) return [];
      return [{
        subnet,
        hosts: policy.srcHosts || [],
        useSubnet: policy._use32Src !== true && policy._srcMode !== 'hosts',
        addrName: policy._srcAddrName || policy.analysis?.srcAddr?.name || '',
        addrFound: !!policy.analysis?.srcAddr?.found,
      }];
    });
    const hosts = [...new Set(entries.flatMap(item => item.hosts || []))].sort();
    return {
      subnet,
      hosts,
      useSubnet: entries.every(item => item.useSubnet !== false),
      addrName: entries.find(item => item.addrFound)?.addrName || '',
      addrFound: entries.some(item => item.addrFound),
    };
  }) : undefined;

  const merged = {
    ...base,
    srcSubnet:   srcSubnets[0] || base.srcSubnet,
    srcSubnets:  srcSubnets.length ? srcSubnets : (base.srcSubnets || [base.srcSubnet]),
    _multiSrcSubnets: multiSrcSubnets,
    _dstDetectedSubnets: mergedDetectedDstSubnets.length ? mergedDetectedDstSubnets : base._dstDetectedSubnets,
    _dstAggregateSubnet: mergedAggregateDst,
    _dstAggregateAddrName: mergedAggregateDst === (base._dstAggregateSubnet || base.dstTarget)
      ? (base._dstAggregateAddrName || '') : '',
    _use32Src:   srcSubnets.length > 1 ? false : base._use32Src,
    srcHosts:    allSrcHosts,
    dstHosts:    allDstHosts,
    sessions,
    serviceDesc: allSvcs.map(s => s.label || s.name || '').join(', '),
    policyIds,
    _mergedCount: toMerge.length,
    _mergedFrom: toMerge.map(policy => ({
      srcSubnet: policy.srcSubnet,
      dstTarget: policy.dstTarget,
      action: policy._action || policy.action || 'accept',
      analysis: { services: policy.analysis?.services || [] },
    })),
    _policyName: '',
    analysis: {
      ...base.analysis,
      services: allSvcs,
      needsWork: !(base.analysis?.srcAddr?.found) || !(base.analysis?.dstAddr?.found) || allSvcs.some(s => !s.found),
    },
  };
  const finalizedMerged = normalizeInternetMerge(syncMergedServiceMetadata(merged));

  const selSet  = new Set(sel);
  const newList = deployState.analyzed.filter((_, i) => !selSet.has(i));
  newList.push(finalizedMerged);
  // Trier par sessions décroissantes pour que la fusionnée remonte à sa place naturelle
  newList.sort((a, b) => (b.sessions || 0) - (a.sessions || 0));
  newList.forEach((p, i) => { p._listIdx = i; });
  deployState.analyzed = newList;
  deployState.selected = defaultSelectedSet(newList);
  deployState.mergeSelected = new Set();

  // Trouver l'index de la policy fusionnée pour y naviguer
  const mergedIdx = newList.indexOf(finalizedMerged);
  const pageSize  = deployState.pageSize;
  if (mergedIdx >= 0) {
    deployState.page = Math.floor(mergedIdx / pageSize) + 1;
    deployState._highlightIdx = mergedIdx;
  }

  const info = el('deploy-merge-info');
  if (info) {
    const txt = info.innerHTML || '';
    info.innerHTML = txt.replace(/^\d+/, String(newList.length));
  }
  _updateMergeSelectionBtn();
  renderDeployPolicies(filterDeployPolicies(), false);
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
      const src = p._srcintf || p.analysis?.srcIface || '';
      const dst = p._dstintf || p.analysis?.dstIface || '';
      const k = `${p.srcSubnet}|${src}|${dst}|${policyDecisionKey(p)}|${serviceSetKey(p)}`;
      if (!internetGroups.has(k)) internetGroups.set(k, []);
      internetGroups.get(k).push(p);
    } else if (!isPublic && lan) {
      const src = p._srcintf || p.analysis?.srcIface || '';
      const dst = p._dstintf || p.analysis?.dstIface || '';
      const k = `${p.srcSubnet}|${p.dstTarget}|${src}|${dst}|${policyDecisionKey(p)}`;
      if (!lanGroups.has(k)) lanGroups.set(k, []);
      lanGroups.get(k).push(p);
    }
    // else: filtered out (not shown)
  }

  // Build merged internet policies (one per srcSubnet → dst=all)
  for (const [srcSubnet, group] of internetGroups) {
    if (group.length === 1) { merged.push({ ...group[0] }); continue; }
    const base = group[0];
    const allServices   = mergeServices(group);
    const totalSessions = group.reduce((s, p) => s + (p.sessions || 0), 0);
    const allPolicyIds  = [...new Set(group.flatMap(p => p.policyIds || []))].sort((a, b) => Number(a) - Number(b));
    const allSrcHosts   = [...new Set(group.flatMap(p => p.srcHosts || []))];
    const allDstHosts   = [...new Set(group.flatMap(p => (p.dstHosts || []).filter(host => !p._excludedDstHosts?.has(host))))];  // M5: agréger tout le groupe, pas seulement base
    merged.push({
      ...base,
      srcHosts:     allSrcHosts,
      dstHosts:     allDstHosts,
      dstTarget:    'all',
      dstType:      'public',
      sessions:     totalSessions,
      serviceDesc:  allServices.map(s => s.label).join(', '),
      policyIds:    allPolicyIds,
      _mergedCount: group.length,
      _mergedFrom:  group.map(p => ({ srcSubnet: p.srcSubnet, dstTarget: p.dstTarget, action: p._action || p.action || 'accept', analysis: { services: p.analysis?.services } })),
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
    const allSrcHosts   = [...new Set(group.flatMap(p => p.srcHosts || []))];
    const allDstHosts   = [...new Set(group.flatMap(p => (p.dstHosts || []).filter(host => !p._excludedDstHosts?.has(host))))];
    merged.push({
      ...base,
      srcHosts:     allSrcHosts,
      dstHosts:     allDstHosts,
      sessions:     totalSessions,
      serviceDesc:  allServices.map(s => s.label).join(', '),
      policyIds:    allPolicyIds,
      _mergedCount: group.length,
      _mergedFrom:  group.map(p => ({ srcSubnet: p.srcSubnet, dstTarget: p.dstTarget, action: p._action || p.action || 'accept', analysis: { services: p.analysis?.services } })),
      analysis: {
        ...base.analysis,
        services:  allServices,
        needsWork: !(base.analysis?.srcAddr?.found) || !(base.analysis?.dstAddr?.found) || allServices.some(s => !s.found),
      },
    });
  }

  return merged.map(syncMergedServiceMetadata).map(normalizeInternetMerge);
}

function mergeServices(group) {
  // C3: dédupliquer par clé canonique (même convention que L2342/L2598), pas par label seul.
  // Deux services de label identique mais ports/protos différents — ou tous les services sans label
  // (label undefined) — ne doivent pas s'écraser mutuellement.
  const seen = new Map();
  for (const p of group) {
    for (const svc of (p.analysis?.services || [])) {
      const technical = serviceReuseKeys(svc).sort().join('+');
      const key = `${svc.label || svc.name || ''}|${technical || `${svc.port || ''}/${svc.proto || ''}`}`;
      if (!seen.has(key)) seen.set(key, svc);
    }
  }
  return [...seen.values()];
}

function syncMergedServiceMetadata(policy) {
  const services = policy.analysis?.services || [];
  const technicalKeys = [...new Set(services.flatMap(serviceReuseKeys))].sort();
  return {
    ...policy,
    services: services.map(service => service.label || service.name || '').filter(Boolean),
    ports: [...new Set(technicalKeys
      .filter(key => /^(TCP|UDP)\/\d+$/.test(key))
      .map(key => Number(key.split('/')[1])))].sort((a, b) => a - b),
    protos: [...new Set(technicalKeys.map(key => key.split('/')[0]))].sort(),
    serviceDesc: services.map(service => service.label || service.name || '').filter(Boolean).join(', '),
  };
}

function policyDecisionKey(policy) {
  const profiles = policy._secProfiles || policy.securityProfiles || {};
  const normalizedProfiles = Object.keys(profiles).sort()
    .map(key => `${key}:${profiles[key]}`).join(',');
  return [
    policy._srcintf || policy.srcintf || policy.analysis?.srcIface || '',
    policy._dstintf || policy.dstintf || policy.analysis?.dstIface || '',
    policy.dstType === 'public' || policy._isWan ? 'wan' : 'lan',
    policy._action || policy.action || 'accept',
    policy._log || policy.log || 'all',
    policy._nat ?? policy.nat ?? false,
    policy._disabled || policy.disabled || false,
    normalizedProfiles,
  ].join('|');
}

// Met à jour la barre "destination silencieuse" et son bouton toggle
function updateNoRcvdToggleBtn() {
  const btn     = document.getElementById('no-rcvd-toggle');
  const barText = document.getElementById('no-rcvd-bar-text');
  const count   = deployState._noRcvdCount || 0;
  if (barText) {
    barText.textContent = `⚠ ${count} police${count > 1 ? 's' : ''} avec destination silencieuse`
      + ` (≥80% flows sans réponse) — port fermé ou hôte injoignable`;
  }
  if (btn) {
    btn.textContent = deployState.hideNoRcvd ? 'Afficher' : 'Masquer';
  }
}

// Une policy est un scan probable si ≥80% de ses flows n'ont reçu aucune réponse
function isScanPolicy(p) {
  const noRcvd = p.noRcvdFlows || 0;
  const total  = p.sessions || 0;
  return noRcvd > 0 && total > 0 && (noRcvd / total) >= 0.8;
}

// Retourne un Set d'indices pour toutes les policies non-scan (sélection initiale par défaut)
function defaultSelectedSet(arr) {
  return new Set(arr.reduce((acc, p, i) => { if (!isScanPolicy(p)) acc.push(i); return acc; }, []));
}

function filterDeployPolicies() {
  const q = (deployState.searchFilter || '').toLowerCase().trim();
  let result = deployState.analyzed || [];

  // Masquer les policies dont ≥80% des flows sont sans réponse (scan probable)
  if (deployState.hideNoRcvd) {
    result = result.filter(p => !isScanPolicy(p));
  }

  if (q) {
    // Syntaxe spéciale : srcintf:X, dstintf:X (filtres exacts sur l'interface)
    const srcIntfFilter = (q.match(/\bsrcintf:(\S+)/) || [])[1] || null;
    const dstIntfFilter = (q.match(/\bdstintf:(\S+)/) || [])[1] || null;
    const plainQ = q.replace(/\b(?:src|dst)intf:\S+/g, '').trim();
    const terms = plainQ ? plainQ.split(/\s+/) : [];

    result = result.filter(p => {
      if (srcIntfFilter && (p._srcintf || '').toLowerCase() !== srcIntfFilter) return false;
      if (dstIntfFilter && (p._dstintf || '').toLowerCase() !== dstIntfFilter) return false;
      if (!terms.length) return true;
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
      return terms.every(t => {
        // Pour les termes de type IP (ex: 10.1.6.19), éviter de matcher 10.1.6.192
        if (/^\d+(\.\d+)+$/.test(t)) {
          const escaped = t.replace(/\./g, '\\.');
          return new RegExp(escaped + '(?!\\d)').test(haystack);
        }
        return haystack.includes(t);
      });
    });
  }

  // Tri par colonne
  const { sortCol, sortDir } = deployState;
  if (sortCol) {
    const getVal = (p) => {
      switch (sortCol) {
        case 'sessions':  return p.sessions || 0;
        case 'dir':       return p._isWan ? 1 : 0;
        case 'source':    return (p.srcSubnet || p.srcSubnets?.[0] || '').toLowerCase();
        case 'srcAddr':   return (p._srcAddrName || '').toLowerCase();
        case 'srcIntf':   return (p._srcintf || '').toLowerCase();
        case 'dst':       return (p.dstTarget || '').toLowerCase();
        case 'dstAddr':   return (p._dstAddrName || '').toLowerCase();
        case 'dstIntf':   return (p._dstintf || '').toLowerCase();
        case 'services':  return (p.serviceDesc || '').toLowerCase();
        default:          return 0;
      }
    };
    result = [...result].sort((a, b) => {
      const va = getVal(a), vb = getVal(b);
      if (va < vb) return sortDir === 'asc' ? -1 : 1;
      if (va > vb) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
  }

  return result;
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
    modeBadge = ` <span class="dst-count-badge" title="${dstHosts.length} h\u00f4tes">${dstHosts.length}h</span>`;
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
    .map(s => {
      const technical = serviceReuseKeys(s).sort().join('+');
      return `${s.label || s.name || ''}|${technical || `${s.port || ''}/${s.proto || ''}`}`;
    })
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
      dstHosts: [...new Set(members.flatMap(m => (m.dstHosts || []).filter(host => !m._excludedDstHosts?.has(host))))].sort(),
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
    const key = `${ids[0]}|${policyDecisionKey(p)}`;
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
      const ik  = `${p.srcSubnet}|${src}|${dst}|${serviceSetKey(p)}`;
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
          const hosts      = [...new Set(subnetPols.flatMap(p => (p.dstHosts || []).filter(host => !p._excludedDstHosts?.has(host))))].sort();
          const dstAddr    = subnetPols.find(p => p.analysis?.dstAddr?.found)?.analysis?.dstAddr
                          || subnetPols[0]?.analysis?.dstAddr;
          return { subnet, hosts, useSubnet: hosts.length === 0 || hosts.length >= DST_SUBNET_THRESHOLD,
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
        const allDstHosts = [...new Set(ifGroup.flatMap(p => (p.dstHosts || []).filter(host => !p._excludedDstHosts?.has(host))))].sort();
        const mergedDetectedDstSubnets = mergeDestinationDetectionCandidates(ifGroup);
        const mergedAggregateDst = destinationAggregateForPolicies(ifGroup, base._dstAggregateSubnet || base.dstTarget);
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
          _dstDetectedSubnets: mergedDetectedDstSubnets.length ? mergedDetectedDstSubnets : base._dstDetectedSubnets,
          _dstAggregateSubnet: mergedAggregateDst,
          _dstAggregateAddrName: mergedAggregateDst === (base._dstAggregateSubnet || base.dstTarget)
            ? (base._dstAggregateAddrName || '') : '',
          _multiDstSubnets: dstSubnets, _isMultiDst: true,
          dstType: base.dstType, sessions: totalSessions,
          serviceDesc: allServices.map(s => s.label).join(', '),
          policyIds: allPolicyIds, srcHosts: allSrcHosts, dstHosts: allDstHosts,
          _use32Src: allSrcHosts.length >= 1 && allSrcHosts.length <= AUTO32_THRESHOLD,
          _use32Dst: false, _mergedCount: ifGroup.length, _isWan: isWan,
          _nat: base._nat ?? base.nat ?? isWan,
          _srcAddrName: base._srcAddrName || '',
          _dstAddrName: existingDstGrp1 || base._dstAddrName || '',
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
      const destinationKey = p.dstType === 'public' || p.dstTarget === 'all' || p._isWan
        ? '__wan__' : (p.dstTarget || '');
      const sk = `${serviceSetKey(p)}||${destinationKey}`;
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
      // M6: l'early-out qui splittait ici les destinations diverses en policies séparées
      // rendait le bloc multi-dst plus bas (même condition) inatteignable (dead code).
      // Supprimé : on laisse le flux atteindre la construction _multiDstSubnets correcte.
      const allDstIPs   = [...new Set(subGroup.flatMap(p => p.dstIPs || (p.dstType === 'public' ? [p.dstTarget] : [])).filter(t => t && t !== 'all'))];
      const allSrcHosts = [...new Set(subGroup.flatMap(p => p.srcHosts || []))].sort();
      const allDstHosts = [...new Set(subGroup.flatMap(p => (p.dstHosts || []).filter(host => !p._excludedDstHosts?.has(host))))].sort();
      const mergedDetectedDstSubnets = mergeDestinationDetectionCandidates(subGroup);
      const mergedAggregateDst = destinationAggregateForPolicies(subGroup, base._dstAggregateSubnet || base.dstTarget);
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
            subnet, hosts, useSubnet: hosts.length === 0 || hosts.length >= 5,
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
          const hosts      = [...new Set(subnetPols.flatMap(p => (p.dstHosts || []).filter(host => !p._excludedDstHosts?.has(host))))].sort();
          const dstAddr    = subnetPols.find(p => p.analysis?.dstAddr?.found)?.analysis?.dstAddr
                          || subnetPols[0]?.analysis?.dstAddr;
          return {
            subnet,
            hosts,
            useSubnet: hosts.length === 0 || hosts.length >= DST_SUBNET_THRESHOLD,
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
          _dstDetectedSubnets: mergedDetectedDstSubnets.length ? mergedDetectedDstSubnets : base._dstDetectedSubnets,
          _dstAggregateSubnet: mergedAggregateDst,
          _dstAggregateAddrName: mergedAggregateDst === (base._dstAggregateSubnet || base.dstTarget)
            ? (base._dstAggregateAddrName || '') : '',
          _multiDstSubnets: dstSubnets,
          _isMultiDst:      true,
          dstType:          base.dstType,
          sessions:         totalSessions,
          serviceDesc:      allServices.map(s => s.label).join(', '),
          policyIds:        allPolicyIds,
          srcHosts:         allSrcHosts,
          dstHosts:         allDstHosts,
          _use32Src:        !multiSrc && allSrcHosts.length >= 1 && allSrcHosts.length <= AUTO32_THRESHOLD,
          _use32Dst:        false,
          _mergedCount:     subGroup.length,
          _isWan:           false,
          _nat:             base._nat ?? base.nat ?? false,
          _srcAddrName:     existingGrp || base._srcAddrName || '',
          _srcAddrGrpFound: !!existingGrp,
          _useSrcGroup:     !!existingGrp,
          _dstAddrName:     existingDstGrp || base._dstAddrName || '',
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
        _dstDetectedSubnets: mergeDestinationDetectionCandidates(subGroup),
        _dstAggregateSubnet: mergedAggregateDst,
        _dstAggregateAddrName: mergedAggregateDst === (base._dstAggregateSubnet || base.dstTarget)
          ? (base._dstAggregateAddrName || '') : '',
        dstType:      isWan ? 'public' : base.dstType,
        sessions:     totalSessions,
        serviceDesc:  allServices.map(s => s.label).join(', '),
        policyIds:    allPolicyIds,
        dstIPs:       allDstIPs,
        _dstIPs:      allDstIPs,
        srcHosts:     allSrcHosts,
        dstHosts:     allDstHosts,
        _use32Src:    !multiSrc && allSrcHosts.length >= 1 && allSrcHosts.length <= AUTO32_THRESHOLD,
        _use32Dst:    !isWan && allDstHosts.length >= 1 && allDstHosts.length <= AUTO32_THRESHOLD,
        _mergedCount: subGroup.length,
        _isWan:       isWan,
        _nat:         base._nat ?? base.nat ?? isWan,
        _srcAddrName: existingGrp || base._srcAddrName || '',
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

  return merged.map(syncMergedServiceMetadata).map(normalizeInternetMerge);
}

// ── Analyse de risques ──
function renderRiskPanel(data) {
  const LEVEL_BADGE = {
    critical: `<span style="background:#c0392b;color:#fff;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700">CRITIQUE</span>`,
    high:     `<span style="background:#e67e22;color:#fff;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700">ÉLEVÉ</span>`,
    medium:   `<span style="background:#f1c40f;color:#222;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700">MOYEN</span>`,
  };
  const sectionStyle = `background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:10px;overflow:hidden`;
  const headerStyle  = `padding:8px 12px;font-weight:600;font-size:12px;cursor:pointer;display:flex;align-items:center;gap:6px;user-select:none;border-bottom:1px solid var(--border)`;
  const bodyStyle    = `padding:8px 12px`;
  const thStyle      = `text-align:left;padding:4px 8px;font-size:10px;font-weight:600;color:var(--text2);border-bottom:1px solid var(--border)`;
  const tdStyle      = `padding:4px 8px;font-size:11px;border-bottom:1px solid var(--border)`;
  const tableStyle   = `width:100%;border-collapse:collapse`;
  let html = '';

  const rp = data.riskPolicies || [];
  let s1Body = '';
  if (rp.length === 0) {
    s1Body = `<div style="color:var(--success,#27ae60);padding:8px 0">Aucun flux à risque détecté ✓</div>`;
  } else {
    s1Body = `<table style="${tableStyle}"><thead><tr>
      <th style="${thStyle}">Src subnet</th><th style="${thStyle}">Destination</th>
      <th style="${thStyle}">Ports à risque</th><th style="${thStyle}">Niveau</th><th style="${thStyle}">Sessions</th>
    </tr></thead><tbody>`;
    for (const row of rp) {
      const portsDesc = row.ports.map(p => `${escHtml(String(p.port))} (${escHtml(p.label)})`).join('<br>');
      s1Body += `<tr>
        <td style="${tdStyle}">${escHtml(row.srcSubnet||'')}</td>
        <td style="${tdStyle}">${escHtml(row.dstTarget||'')} <span style="font-size:10px;color:var(--text2)">${escHtml(row.dstType||'')}</span></td>
        <td style="${tdStyle}">${portsDesc}</td>
        <td style="${tdStyle}">${LEVEL_BADGE[row.level]||escHtml(row.level)}</td>
        <td style="${tdStyle}">${escHtml(String(row.sessions))}</td>
      </tr>`;
    }
    s1Body += `</tbody></table>`;
  }
  html += `<div style="${sectionStyle}">
    <div class="risk-section-header" style="${headerStyle}"><span class="risk-chevron">⌄</span><span>⚠ ${rp.length} flux à risque</span></div>
    <div style="${bodyStyle}">${s1Body}</div></div>`;


  if (data.hasFortiConfig) {
    const shadows = data.shadows;
    const cleanJoin = (arr) => (arr||[]).filter(v => v && String(v).trim()).join(', ');
    const wrapStyle = 'word-break:break-word;white-space:normal;';
    const renderPermTable = (list) => {
      if (list.length === 0) return `<div style="color:var(--text2);font-size:11px;padding:4px 0">Aucune</div>`;
      let t = `<table style="${tableStyle}table-layout:fixed;width:100%"><thead><tr>
        <th style="${thStyle};width:40px">ID</th>
        <th style="${thStyle};width:8%">Nom</th>
        <th style="${thStyle};width:10%">Src intf</th>
        <th style="${thStyle};width:22%">Src addr</th>
        <th style="${thStyle};width:10%">Dst intf</th>
        <th style="${thStyle};width:22%">Dst addr</th>
        <th style="${thStyle};width:10%">Service</th>
        <th style="${thStyle}">Raison</th>
      </tr></thead><tbody>`;
      for (const sh of list) {
        const srcAddr = cleanJoin(sh.srcaddr);
        const dstAddr = cleanJoin(sh.dstaddr);
        const svc     = cleanJoin(sh.service);
        t += `<tr>
          <td style="${tdStyle}">${escHtml(String(sh.id))}</td>
          <td style="${tdStyle}${wrapStyle}">${escHtml(sh.name)}</td>
          <td style="${tdStyle}${wrapStyle}font-family:var(--mono);font-size:10px">${escHtml(cleanJoin(sh.srcintf))}</td>
          <td style="${tdStyle}${wrapStyle}">${escHtml(srcAddr)}</td>
          <td style="${tdStyle}${wrapStyle}font-family:var(--mono);font-size:10px">${escHtml(cleanJoin(sh.dstintf))}</td>
          <td style="${tdStyle}${wrapStyle}">${escHtml(dstAddr)}</td>
          <td style="${tdStyle}${wrapStyle}">${escHtml(svc)}</td>
          <td style="${tdStyle};color:var(--warn,#f39c12)">${escHtml(sh.reason)}</td>
        </tr>`;
      }
      t += `</tbody></table>`;
      return t;
    };

    let s3Body = '';
    if (!shadows) {
      s3Body = `<div style="color:var(--text2);padding:8px 0">Chargez une config FortiGate pour activer cette analyse</div>`;
    } else if (shadows.length === 0) {
      s3Body = `<div style="color:var(--success,#27ae60);padding:8px 0">Aucune policy trop permissive détectée ✓</div>`;
    } else {
      const dirs = [
        { key: 'lan-wan', label: '🌐 LAN → WAN' },
        { key: 'wan-lan', label: '⬇ WAN → LAN' },
        { key: 'lan-lan', label: '🔁 LAN → LAN' },
      ];
      for (const d of dirs) {
        const list = shadows.filter(sh => sh.direction === d.key);
        if (list.length === 0) continue;
        s3Body += `<div style="margin-bottom:14px">
          <div style="font-size:11px;font-weight:600;color:var(--text2);margin-bottom:4px;padding:2px 0;border-bottom:1px solid var(--border)">${d.label} (${list.length})</div>
          ${renderPermTable(list)}
        </div>`;
      }
    }
    html += `<div style="${sectionStyle}">
      <div class="risk-section-header" style="${headerStyle}"><span class="risk-chevron">⌄</span><span>⚠ Policies trop permissives (${shadows?shadows.length:0})</span></div>
      <div style="${bodyStyle}">${s3Body}</div></div>`;
  }

  return html;
}

async function loadRiskPanel() {
  const panel = el('deploy-risk-panel');
  panel.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text2)">Chargement…</div>';
  try {
    const data = await api('/api/risk-analysis');
    panel.innerHTML = renderRiskPanel(data);
    panel.querySelectorAll('.risk-section-header').forEach(h => {
      h.addEventListener('click', () => {
        const body = h.nextElementSibling;
        const isOpen = body.style.display !== 'none';
        body.style.display = isOpen ? 'none' : '';
        h.querySelector('.risk-chevron').textContent = isOpen ? '›' : '⌄';
      });
    });
  } catch(e) {
    panel.innerHTML = `<div style="padding:20px;color:var(--error)">Erreur : ${escHtml(e.message)}</div>`;
  }
}

// ── Configuration des ports à risque ──
// Note: All dynamic values inserted into HTML strings below are escaped via escHtml()
// before insertion, following the same XSS-prevention pattern used throughout app.js.
function buildRiskPortsModalHtml(cfg) {
  const inputStyle = 'background:var(--bg3);color:var(--text);border:1px solid var(--border);border-radius:3px;padding:2px 5px';
  const SECTIONS = [
    { key: 'always_critical', label: '🔴 Toujours CRITIQUE',                color: '#c0392b' },
    { key: 'always_high',     label: '🟠 Toujours ÉLEVÉ',                   color: '#e67e22' },
    { key: 'critical_if_wan', label: '🔴/🟡 CRITIQUE si WAN, MOYEN si LAN', color: '#c0392b' },
    { key: 'high_if_wan',     label: '🟠/🟡 ÉLEVÉ si WAN, MOYEN si LAN',   color: '#e67e22' },
  ];
  let sectionsHtml = '';
  for (const sec of SECTIONS) {
    const ports = cfg[sec.key] || {};
    let rows = '';
    for (const [port, label] of Object.entries(ports)) {
      // escHtml() applied to all dynamic values (port number and label from saved config)
      rows += `<tr>`
        + `<td style="padding:3px 5px"><input class="rp-port" type="number" min="1" max="65535"`
        + ` value="${escHtml(String(port))}" style="${inputStyle};width:64px;font-family:var(--mono);font-size:11px"></td>`
        + `<td style="padding:3px 5px"><input class="rp-label" type="text"`
        + ` value="${escHtml(String(label))}" style="${inputStyle};width:260px;font-size:11px"></td>`
        + `<td style="padding:3px 5px"><button class="rp-del btn-sm" style="padding:1px 5px;font-size:10px;color:var(--error,#e74c3c)">✕</button></td>`
        + `</tr>`;
    }
    sectionsHtml += `<div class="rp-section" data-section="${escHtml(sec.key)}" style="margin-bottom:18px">`
      + `<div style="font-size:11px;font-weight:700;color:${sec.color};margin-bottom:6px;border-bottom:1px solid var(--border);padding-bottom:4px">${sec.label}</div>`
      + `<table style="border-collapse:collapse;width:100%"><thead><tr>`
      + `<th style="text-align:left;padding:2px 5px;font-size:10px;color:var(--text2);width:80px">Port</th>`
      + `<th style="text-align:left;padding:2px 5px;font-size:10px;color:var(--text2)">Description</th>`
      + `<th style="width:28px"></th></tr></thead>`
      + `<tbody class="rp-tbody">${rows}</tbody></table>`
      + `<button class="rp-add btn-sm" data-section="${escHtml(sec.key)}" style="margin-top:6px;font-size:11px">+ Ajouter</button>`
      + `</div>`;
  }
  return `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:20px;width:540px;max-height:88vh;overflow-y:auto">`
    + `<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">`
    + `<span style="font-weight:700;font-size:13px">⚙ Ports à risque</span>`
    + `<button id="rp-close" class="btn-sm">✕</button></div>`
    + `<div style="font-size:11px;color:var(--text2);margin-bottom:16px;line-height:1.5">`
    + `Classification des ports pour l'analyse de risques.<br>`
    + `Les ports conditionnels sont évalués selon la nature de la destination (WAN/public vs LAN/privé).</div>`
    + sectionsHtml
    + `<div style="display:flex;gap:8px;padding-top:12px;border-top:1px solid var(--border)">`
    + `<button id="rp-save" class="btn-sm btn-accent" style="font-size:12px">💾 Sauvegarder et relancer</button>`
    + `<button id="rp-reset" class="btn-sm" style="font-size:12px;opacity:0.7">↺ Réinitialiser aux défauts</button>`
    + `</div></div>`;
}

async function showRiskPortsModal() {
  const existing = document.getElementById('risk-ports-modal-overlay');
  if (existing) { existing.remove(); return; }

  const overlay = document.createElement('div');
  overlay.id = 'risk-ports-modal-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:9999;display:flex;align-items:center;justify-content:center';
  document.body.appendChild(overlay);

  const inputStyle = 'background:var(--bg3);color:var(--text);border:1px solid var(--border);border-radius:3px;padding:2px 5px';

  function setLoading() {
    const d = document.createElement('div');
    d.style.cssText = 'padding:30px;color:var(--text2);font-size:12px';
    d.textContent = 'Chargement…';
    overlay.replaceChildren(d);
  }

  function setError(msg) {
    const wrap = document.createElement('div');
    wrap.style.cssText = 'background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:24px;font-size:12px';
    const p = document.createElement('p');
    p.style.color = 'var(--error,#e74c3c)';
    p.textContent = 'Erreur : ' + msg;
    const btn = document.createElement('button');
    btn.className = 'btn-sm'; btn.textContent = 'Fermer'; btn.style.marginTop = '12px';
    btn.addEventListener('click', () => overlay.remove());
    wrap.appendChild(p); wrap.appendChild(btn);
    overlay.replaceChildren(wrap);
  }

  function collectConfig() {
    const result = { always_critical: {}, always_high: {}, critical_if_wan: {}, high_if_wan: {} };
    overlay.querySelectorAll('.rp-section').forEach(sec => {
      const key = sec.dataset.section;
      sec.querySelectorAll('.rp-tbody tr').forEach(row => {
        const port  = parseInt(row.querySelector('.rp-port')?.value?.trim(), 10);
        const label = row.querySelector('.rp-label')?.value?.trim();
        if (!isNaN(port) && port > 0 && label) result[key][port] = label;
      });
    });
    return result;
  }

  function addNewRow(tbody) {
    const tr = document.createElement('tr');
    const tdPort = document.createElement('td'); tdPort.style.padding = '3px 5px';
    const inPort = document.createElement('input');
    inPort.className = 'rp-port'; inPort.type = 'number'; inPort.min = '1'; inPort.max = '65535';
    inPort.placeholder = 'Port'; inPort.style.cssText = inputStyle + ';width:64px;font-family:var(--mono);font-size:11px';
    tdPort.appendChild(inPort);
    const tdLabel = document.createElement('td'); tdLabel.style.padding = '3px 5px';
    const inLabel = document.createElement('input');
    inLabel.className = 'rp-label'; inLabel.type = 'text'; inLabel.placeholder = 'Description';
    inLabel.style.cssText = inputStyle + ';width:260px;font-size:11px';
    tdLabel.appendChild(inLabel);
    const tdDel = document.createElement('td'); tdDel.style.padding = '3px 5px';
    const btnDel = document.createElement('button');
    btnDel.className = 'rp-del btn-sm'; btnDel.textContent = '✕';
    btnDel.style.cssText = 'padding:1px 5px;font-size:10px;color:var(--error,#e74c3c)';
    tdDel.appendChild(btnDel);
    tr.appendChild(tdPort); tr.appendChild(tdLabel); tr.appendChild(tdDel);
    tbody.appendChild(tr);
    inPort.focus();
  }

  async function loadAndRender(url, method) {
    setLoading();
    try {
      const r = await fetch(url, { method: method || 'GET' });
      if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.error || r.statusText); }
      const cfg = await r.json();
      // buildRiskPortsModalHtml escapes all cfg values with escHtml() before HTML insertion
      const modalWrap = document.createElement('div');
      modalWrap.style.cssText = 'display:contents';
      modalWrap.innerHTML = buildRiskPortsModalHtml(cfg);
      overlay.replaceChildren(modalWrap.firstElementChild);
      bindModalEvents();
    } catch (e) {
      setError(e.message);
    }
  }

  function bindModalEvents() {
    overlay.addEventListener('click', async e => {
      if (e.target === overlay)                    { overlay.remove(); return; }
      if (e.target.id === 'rp-close')              { overlay.remove(); return; }
      if (e.target.classList.contains('rp-del'))   { e.target.closest('tr').remove(); return; }
      if (e.target.classList.contains('rp-add'))   {
        const sec = e.target.closest('.rp-section');
        addNewRow(sec.querySelector('.rp-tbody'));
        return;
      }
      if (e.target.id === 'rp-reset') {
        if (!confirm('Réinitialiser aux ports par défaut ? Vos modifications seront perdues.')) return;
        await loadAndRender('/api/risk-ports', 'DELETE');
        return;
      }
      if (e.target.id === 'rp-save') {
        const cfg = collectConfig();
        const btn = e.target;
        btn.disabled = true; btn.textContent = 'Sauvegarde…';
        try {
          const r = await fetch('/api/risk-ports', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(cfg),
          });
          if (!r.ok) { const err = await r.json().catch(() => ({})); throw new Error(err.error || r.statusText); }
          overlay.remove();
          if (deployState.riskPanelOpen) loadRiskPanel();
        } catch (err) {
          btn.textContent = 'Erreur : ' + err.message;
          btn.disabled = false;
        }
      }
    });
  }

  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
  await loadAndRender('/api/risk-ports', 'GET');
}

function normalizeInternetMerge(policy) {
  const isInternet = policy.dstType === 'public' || policy.dstTarget === 'all' || policy._isWan;
  if (!isInternet) return policy;
  const explicitlyAll = policy.dstTarget === 'all' || policy._dstUseAll === true;
  const merged = (policy._mergedCount || 0) > 1
    || (Array.isArray(policy._mergedFrom) && policy._mergedFrom.length > 1);
  if (!explicitlyAll && !merged) return policy;
  const multiSrc = Array.isArray(policy._multiSrcSubnets) && policy._multiSrcSubnets.length > 1
    ? policy._multiSrcSubnets : undefined;
  const singleSrc = Array.isArray(policy._multiSrcSubnets) && policy._multiSrcSubnets.length === 1
    ? policy._multiSrcSubnets[0] : null;
  return {
    ...policy,
    srcHosts: singleSrc ? [...(singleSrc.hosts || [])] : (policy.srcHosts || []),
    _multiSrcSubnets: multiSrc,
    _use32Src: multiSrc ? false : (singleSrc ? singleSrc.useSubnet === false : policy._use32Src === true),
    _srcMode: multiSrc ? undefined : policy._srcMode,
    dstTarget: 'all',
    dstTargets: ['all'],
    dstType: 'public',
    dstHosts: [],
    _isWan: true,
    _dstUseAll: true,
    _isMultiDst: false,
    _multiDstSubnets: undefined,
    _use32Dst: false,
    _dstMode: undefined,
    _dstAddrName: 'all',
    _dstAddrGrpFound: false,
    _useDstGroup: false,
    analysis: {
      ...policy.analysis,
      dstAddr: { found: true, name: 'all', cidr: 'all', source: 'builtin' },
    },
  };
}

// ── Fusion par service : policies partageant le même ensemble de services
//    ET la même paire d'interfaces sont regroupées en une seule règle multi-src/multi-dst.
function mergeByService(policies) {
  const groups = new Map(); // serviceKey||srcintf||dstintf||destination → [policies]

  for (const p of policies) {
    const svcKey = serviceSetKey(p);
    const src    = p._srcintf || p.analysis?.srcIface || '';
    const dst    = p._dstintf || p.analysis?.dstIface || '';
    const destinationKey = p.dstType === 'public' || p.dstTarget === 'all' || p._isWan
      ? '__wan__' : (p.dstTarget || '');
    const key    = `${svcKey}||${src}||${dst}||${destinationKey}||${policyDecisionKey(p)}`;
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
    const allDstHosts = [...new Set(group.flatMap(p => (p.dstHosts || []).filter(host => !p._excludedDstHosts?.has(host))))].sort();

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
        return { subnet, hosts, useSubnet: hosts.length === 0 || hosts.length >= 5,
          addrName: srcAddr?.found ? srcAddr.name : '', addrFound: !!(srcAddr?.found) };
      });
    }

    // Build _multiDstSubnets
    const DST_SUBNET_THRESHOLD = 5;
    let multiDstSubnets = null;
    if (multiDst) {
      multiDstSubnets = dstTargets.map(subnet => {
        const subnetPols = group.filter(p => p.dstTarget === subnet);
        const hosts      = [...new Set(subnetPols.flatMap(p => (p.dstHosts || []).filter(host => !p._excludedDstHosts?.has(host))))].sort();
        const dstAddr    = subnetPols.find(p => p.analysis?.dstAddr?.found)?.analysis?.dstAddr
                         || subnetPols[0]?.analysis?.dstAddr;
        return { subnet, hosts, useSubnet: hosts.length === 0 || hosts.length >= DST_SUBNET_THRESHOLD,
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
      _multiDstSubnets: multiDst ? multiDstSubnets : undefined,
      _multiSrcSubnets: multiSrcSubnets,
      sessions:         totalSessions,
      serviceDesc:      allServices.map(s => s.label).join(', '),
      policyIds:        allPolicyIds,
      srcHosts:         allSrcHosts,
      dstHosts:         allDstHosts,
      _use32Src:        !multiSrc && allSrcHosts.length >= 1 && allSrcHosts.length <= AUTO32_THRESHOLD,
      _use32Dst:        !multiDst && !isWan && allDstHosts.length >= 1 && allDstHosts.length <= AUTO32_THRESHOLD,
      _isWan:           isWan,
      _nat:             base._nat ?? base.nat ?? isWan,
      _mergedCount:     group.length,
      _isSvcMerge:      true,
      _mergedFrom:      group.map(p => ({ srcSubnet: p.srcSubnet, dstTarget: p.dstTarget, action: p._action || p.action || 'accept', analysis: { services: p.analysis?.services } })),
      _srcAddrName:     existingSrcGrp || base._srcAddrName || '',
      _srcAddrGrpFound: !!existingSrcGrp,
      _useSrcGroup:     !!existingSrcGrp,
      _dstAddrName:     isWan ? 'all' : (existingDstGrp || base._dstAddrName || ''),
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

  return merged.map(syncMergedServiceMetadata).map(normalizeInternetMerge);
}

// Regroupe par même destination + même interfaces → multi-source rules
function mergeByDestination(policies) {
  const groups = new Map(); // dstTarget||srcintf||dstintf||serviceSet → [policies]

  for (const p of policies) {
    const dst    = p.dstTarget || '';
    const src    = p._srcintf || p.analysis?.srcIface || '';
    const dstI   = p._dstintf || p.analysis?.dstIface || '';
    const isWan  = p.dstType === 'public' || p.dstTarget === 'all' || p._isWan;
    const key    = `${isWan ? '__wan__' : dst}||${src}||${dstI}||${serviceSetKey(p)}||${policyDecisionKey(p)}`;
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
    const multiSrc   = srcSubnets.length > 1;

    const allSrcHosts = [...new Set(group.flatMap(p => p.srcHosts || []))].sort();
    const allDstHosts = [...new Set(group.flatMap(p => (p.dstHosts || []).filter(host => !p._excludedDstHosts?.has(host))))].sort();

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

    let multiSrcSubnets = null;
    if (multiSrc) {
      multiSrcSubnets = srcSubnets.map(subnet => {
        const subnetPols = group.filter(p => p.srcSubnet === subnet);
        const hosts      = [...new Set(subnetPols.flatMap(p => p.srcHosts || []))].sort();
        const srcAddr    = subnetPols.find(p => p.analysis?.srcAddr?.found)?.analysis?.srcAddr
                         || subnetPols[0]?.analysis?.srcAddr;
        return { subnet, hosts, useSubnet: hosts.length === 0 || hosts.length >= 5,
          addrName: srcAddr?.found ? srcAddr.name : '', addrFound: !!(srcAddr?.found) };
      });
    }

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

    merged.push({
      ...base,
      srcSubnet:        srcSubnets[0],
      srcSubnets,
      dstType:          isWan ? 'public' : base.dstType,
      _isMultiDst:      false,
      _multiDstSubnets: undefined,
      _multiSrcSubnets: multiSrcSubnets,
      sessions:         totalSessions,
      serviceDesc:      allServices.map(s => s.label).join(', '),
      policyIds:        allPolicyIds,
      srcHosts:         allSrcHosts,
      dstHosts:         allDstHosts,
      _use32Src:        !multiSrc && allSrcHosts.length >= 1 && allSrcHosts.length <= AUTO32_THRESHOLD,
      _use32Dst:        !isWan && allDstHosts.length >= 1 && allDstHosts.length <= AUTO32_THRESHOLD,
      _isWan:           isWan,
      _nat:             base._nat ?? base.nat ?? isWan,
      _mergedCount:     group.length,
      _isDstMerge:      true,
      _mergedFrom:      group.map(p => ({ srcSubnet: p.srcSubnet, dstTarget: p.dstTarget, action: p._action || p.action || 'accept', analysis: { services: p.analysis?.services } })),
      _srcAddrName:     existingSrcGrp || base._srcAddrName || '',
      _srcAddrGrpFound: !!existingSrcGrp,
      _useSrcGroup:     !!existingSrcGrp,
      _dstAddrName:     isWan ? 'all' : (base._dstAddrName || (base.analysis?.dstAddr?.found ? base.analysis.dstAddr.name : '')),
      _dstAddrGrpFound: !isWan && !!(base.analysis?.dstAddr?.found),
      _useDstGroup:     !isWan && !!(base.analysis?.dstAddr?.found),
      _policyName:      '',
      _srcHostNames:    Object.keys(mergedSrcHostNames).length ? mergedSrcHostNames : undefined,
      _dstHostNames:    Object.keys(mergedDstHostNames).length ? mergedDstHostNames : undefined,
      _srcHostsFound:   mergedSrcHF.size ? [...mergedSrcHF] : undefined,
      _dstHostsFound:   mergedDstHF.size ? [...mergedDstHF] : undefined,
      srcAddrNames:     existingSrcGrp ? null : (multiSrc ? srcSubnets.map(s => `FF_${escSlug(s)}`) : null),
      analysis: {
        ...base.analysis,
        services:  allServices,
        needsWork: allServices.some(s => !s.found),
      },
    });
  }

  return merged.map(syncMergedServiceMetadata).map(normalizeInternetMerge);
}

function applyMerge(scope, strategy) {
  const mode = scope; // compat interne (reset utilise le 1er arg)
  if (!deployState.analyzed) return;
  if (mode !== 'reset' && mode !== 'selection') _savePolicySnapshot();
  if (mode === 'reset') {
    // Source de vérité pour le reset : _analyzedOriginal (avant dernière fusion)
    // ou baseAnalyzedPolicies (snapshot de l'analyse initiale, survit aux workspaces)
    const resetSource = deployState._analyzedOriginal || deployState.baseAnalyzedPolicies;
    if (!resetSource) return; // rien à réinitialiser

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
    deployState.analyzed = resetSource.map(p => {
      const edit = edits.get(`${p.srcSubnet}|${p.dstTarget}`);
      return edit ? { ...p, ...edit } : { ...p };
    });
    deployState._analyzedOriginal = null;
  } else {
    // Save original on first merge
    if (!deployState._analyzedOriginal) {
      deployState._analyzedOriginal = deployState.analyzed.map(p => ({ ...p }));
    }
    // Always merge from original
    if (mode === 'selection') {
      mergeSelectedDeployPolicies();
      return;
    } else {
      deployState.analyzed = computeMerge(deployState._analyzedOriginal, scope, strategy || 'max');
    }
  }

  // M3: la fusion/reset remplace analyzed → toute granularité de détail devient caduque.
  // On repasse en mode base pour éviter un _detailOriginal pointant vers un état remplacé.
  deployState.bruteMode = 'off';
  deployState._detailOriginal = null;
  const _bm = el('btn-brute-mode');
  if (_bm) { _bm.textContent = 'Détailler ▾'; _bm.classList.remove('btn-active'); }
  document.querySelectorAll('.detail-mode-btn').forEach(b => b.classList.remove('btn-accent'));

  // Reset selection (hors scan policies)
  deployState.selected = defaultSelectedSet(deployState.analyzed);
  renderDeployPolicies(filterDeployPolicies());

  const info = el('deploy-merge-info');
  if (info) {
    const orig = deployState._analyzedOriginal?.length || deployState.analyzed.length;
    const cur  = deployState.analyzed.length;
    // Conserver le bouton scan potentiels s'il existe, puis remettre le texte
    const existingBtn = info.querySelector('#no-rcvd-toggle');
    info.textContent = mode === 'reset'
      ? `${cur} policies (original)`
      : `${cur} policies (économie : ${orig - cur})`;
    if (existingBtn) info.appendChild(existingBtn);
  }
  syncNoRcvdInfoBtn();
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
    const polData = await api('/api/policies?include_no_rcvd=1');
    rawPolicies = polData.policies || polData;
    // Append pending denied flows if any
    if (deployState._pendingDenied && deployState._pendingDenied.length > 0) {
      rawPolicies = rawPolicies.concat(deployState._pendingDenied);
      deployState._pendingDenied = null;
    }
    setLoadingText(`${rawPolicies.length} policies récupérées — analyse en cours…`);
    setLoadingPct(30);
  } catch (err) { resetAnalyzeBtn(); alert(err.message); return; }
  if (!rawPolicies || rawPolicies.length === 0) {
    resetAnalyzeBtn();
    alert('Aucune policy à analyser. Vérifiez que le fichier de trafic est bien chargé (étape 1).');
    if (body) body.innerHTML = '<div class="empty-state" style="padding:24px">Aucune policy disponible. Chargez un fichier de trafic en étape 1.</div>';
    return;
  }

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

    const r = await fetch(`/api/deploy/analyze?session=${state.session}`, {
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
    deployState.addrGroups      = respData.addrGroups      || {};
    deployState.warnings        = respData.warnings        || [];
    deployState.resolvedHosts   = respData.resolvedHosts   || {};
    deployState.hostPairServices = respData.hostPairServices || {};
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
    const aggregateHosts = p.dstHosts || [];
    const aggregateComputed = aggregateHosts.length > 0
      ? cidrSupernet(aggregateHosts.map(host => `${host}/32`)) : '';
    const aggregateSubnet = p._dstAggregateManual && p._dstAggregateSubnet
      ? p._dstAggregateSubnet : (aggregateComputed || p._dstAggregateSubnet || p.dstTarget || '');
    const aggregateAddressMatch = p.analysis?.dstAddr?.found && p.analysis.dstAddr.cidr === aggregateSubnet;
    return {
      ...p,
      srcAddrExists: p.analysis?.srcAddr?.found ?? false,
      dstAddrExists: p.analysis?.dstAddr?.found ?? false,
      _srcintf:          resolveZone(rawSrcIntf),
      _srcIfaceSource:   p.analysis?.srcIfaceSource || 'auto',
      _dstintf:          resolveZone(rawDstIntf),
      _dstIfaceSource:   p.analysis?.dstIfaceSource || 'auto',
      _dstAggregateSubnet: aggregateSubnet,
      _dstAggregateManual: p._dstAggregateManual === true,
      _dstAggregateAddrName: p._dstAggregateAddrName
        || (aggregateAddressMatch ? p.analysis?.dstAddr?.name || '' : ''),
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

  // Tri par volume de sessions décroissant (policies les plus actives en premier)
  analyzed.sort((a, b) => (b.sessions || 0) - (a.sessions || 0));

  // ── Normalisation srcHosts + dstHosts ─────────────────────────────────────────
  // Filtre srcHosts ET dstHosts de chaque policy aux seuls hôtes ayant réellement
  // participé aux services de cette policy, selon les flows bruts (hostPairServices).
  // Garantit que tous les modes de fusion et de détail travaillent sur des données propres.
  const _hps = deployState.hostPairServices;
  if (_hps && Object.keys(_hps).length > 0) {
    analyzed = analyzed.map(p => {
      const srcHosts = p.srcHosts || [];
      const dstHosts = p.dstHosts || [];
      if (srcHosts.length === 0 || dstHosts.length === 0) return p;
      const svcNames = new Set((p.analysis?.services || []).map(s => (s.label || s.name || '').toUpperCase()));
      if (svcNames.size === 0) return p;
      const filteredSrc = srcHosts.filter(src =>
        dstHosts.some(dst => {
          const flowSvcs = _hps[src + '|' + dst];
          return flowSvcs && flowSvcs.some(s => svcNames.has(s.toUpperCase()));
        })
      );
      const filteredDst = dstHosts.filter(dst =>
        srcHosts.some(src => {
          const flowSvcs = _hps[src + '|' + dst];
          return flowSvcs && flowSvcs.some(s => svcNames.has(s.toUpperCase()));
        })
      );
      const newP = { ...p };
      if (filteredSrc.length > 0) newP.srcHosts = filteredSrc;
      if (filteredDst.length > 0) newP.dstHosts = filteredDst;
      // Si aucune paire trouvée dans hostPairServices, signaler pour affichage UI
      if (filteredSrc.length === 0 && filteredDst.length === 0) newP._hpsUnverified = true;
      return newP;
    });
  }

  // Auto /32 : peu d'hôtes réels = utiliser les /32 par défaut (≤ AUTO32_THRESHOLD hôtes)
  for (const p of analyzed) {
    if ((p.srcHosts || []).length >= 1 && (p.srcHosts || []).length <= AUTO32_THRESHOLD) p._use32Src = true;
    if ((p.dstHosts || []).length >= 1 && (p.dstHosts || []).length <= AUTO32_THRESHOLD) p._use32Dst = true;
    if (p._dstDetectedSubnets?.length) {
      if (!p._dstAggregateManual) p._dstAggregateSubnet = destinationAggregateSubnet(p);
      // Une destination issue de plusieurs réseaux reste volontairement en /32
      // tant que l'ingénieur n'a pas choisi le mode détecté ou agrégé.
      p._use32Dst = true;
    }
    // Initialize per-policy mode from _use32 flags
    p._srcMode = p._use32Src ? 'hosts' : 'subnet';
    p._dstMode = p._dstDetectedSubnets?.length ? 'hosts' : (p._use32Dst ? 'hosts' : 'subnet');
    // Auto "all" : si destination WAN avec beaucoup d'hôtes ou sous-réseaux → mode all par défaut
    const _isWanP = p._isWan || p.dstType === 'public';
    if (_isWanP && p._dstUseAll === undefined) {
      const dstCount = p._isMultiDst ? (p._multiDstSubnets?.length || 0) : (p.dstHosts?.length || 0);
      if (dstCount > 10) p._dstUseAll = true;
    }
  }

  deployState.analyzed              = analyzed;
  deployState._analyzedOriginal     = null;
  deployState._detailOriginal       = null;  // M3: base de détail, réinitialisée à chaque analyse
  deployState.baseAnalyzedPolicies  = analyzed.map(p => ({ ...p })); // snapshot for reset
  deployState.generatedCli          = null;
  deployState.selected              = defaultSelectedSet(analyzed);
  _drawerHistory = [];  // clear undo history from previous session
  _policyUndo = [];
  _policyRedo = [];

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

  const noRcvdCount = analyzed.filter(isScanPolicy).length;
  deployState._noRcvdCount = noRcvdCount;
  if (info) {
    info.innerHTML = analyzed.length + ' policies' + deniedNote + ' · ';
  }
  syncNoRcvdInfoBtn();

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
      deployState.availableProfiles = sp;
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
function _buildSrcAddrCell(p, idx) {
  if (p.srcSubnets && p.srcSubnets.length > 1) {
    if (p._useSrcGroup) {
      const srcGrpDisplay = p._srcAddrName || `FF_POLICY_${(p.policyIds||[])[0] || idx}_SRC`;
      return p._srcAddrGrpFound
        ? `<span class="inline-editable found" data-idx="${idx}" data-field="_srcAddrName">${escHtml(p._srcAddrName)}</span>`
        : `<span class="inline-editable missing" data-idx="${idx}" data-field="_srcAddrName">${escHtml(srcGrpDisplay)} ${badgeHtml('auto')}</span>`;
    }
    const subs = p._multiSrcSubnets || [];
    const srcFoundSet = new Set(p._srcHostsFound || []);
    const _autoHostName = h => `FF_HOST_${h.replace(/\./g, '_')}`;
    const _hostNameOk = (h) => { const n = cleanHostName(h, p._srcHostNames?.[h]); return n && n !== _autoHostName(h); };
    const allDone = subs.every(s => {
      if (s.useSubnet !== false) return s.addrFound || !!s.addrName;
      return (s.hosts || []).every(h => srcFoundSet.has(h) || _hostNameOk(h));
    });
    const names = subs.map(s => {
      if (s.useSubnet !== false) return s.addrName || s.subnet;
      return (s.hosts || []).map(h => cleanHostName(h, p._srcHostNames?.[h]) || h).join(', ');
    }).join(', ');
    return allDone
      ? `<span class="inline-editable found" data-idx="${idx}" data-field="_srcAddrName" title="${escHtml(names)}">${escHtml(names)}</span>`
      : `<span class="inline-editable missing" data-idx="${idx}" data-field="_srcAddrName" title="${escHtml(names)}">${escHtml(names)} ${badgeHtml('auto')}</span>`;
  }
  if ((p._srcMode === 'hosts' || p._use32Src) && p.srcHosts?.length) {
    const hFoundSet = new Set(p._srcHostsFound || []);
    const _autoHostName = h => `FF_HOST_${h.replace(/\./g, '_')}`;
    const _hostNameOk = (h) => { const n = cleanHostName(h, p._srcHostNames?.[h]); return n && n !== _autoHostName(h); };
    const hNames = p.srcHosts.map(h => cleanHostName(h, p._srcHostNames?.[h]) || h);
    const allNamed = p.srcHosts.every(h => hFoundSet.has(h) || _hostNameOk(h));
    const hDisplay = hNames.join(', ');
    return allNamed
      ? `<span class="inline-editable found" data-idx="${idx}" data-field="_srcAddrName" title="${escHtml(hDisplay)}">${escHtml(hDisplay)}</span>`
      : `<span class="inline-editable missing" data-idx="${idx}" data-field="_srcAddrName" title="${escHtml(hDisplay)}">${escHtml(hDisplay)} ${badgeHtml('auto')}</span>`;
  }
  return addrCell(p.analysis?.srcAddr, p._srcAddrName, idx, '_srcAddrName');
}

function _buildDstAddrCell(p, idx) {
  // Mode "all" explicite — uniquement pour les policies WAN/internet
  const _cellIsWan = p._isWan || p.dstType === 'public';
  if (_cellIsWan && p._dstUseAll === true) {
    return `<span class="inline-editable found" data-idx="${idx}" data-field="_dstAddrName">all ${badgeHtml('config')}</span>`;
  }
  if (p._isMultiDst && p._multiDstSubnets?.length) {
    if (p._useDstGroup) {
      const dstGrpDisplay = p._dstAddrName || `GRP_${(p.policyIds||[])[0] || idx}_DST`;
      return p._dstAddrGrpFound
        ? `<span class="inline-editable found" data-idx="${idx}" data-field="_dstAddrName">${escHtml(p._dstAddrName)}</span>`
        : `<span class="inline-editable missing" data-idx="${idx}" data-field="_dstAddrName">${escHtml(dstGrpDisplay)} ${badgeHtml('auto')}</span>`;
    }
    const subs = p._multiDstSubnets;
    const dstFoundSet = new Set(p._dstHostsFound || []);
    const _autoHostName = h => `FF_HOST_${h.replace(/\./g, '_')}`;
    const _hostNameOk = (h) => { const n = cleanHostName(h, p._dstHostNames?.[h]); return n && n !== _autoHostName(h); };
    const allDone = subs.every(s => {
      if (s.useSubnet !== false) return s.addrFound || !!s.addrName;
      return (s.hosts || []).every(h => dstFoundSet.has(h) || _hostNameOk(h));
    });
    const names = subs.map(s => {
      if (s.useSubnet !== false) return s.addrName || s.subnet;
      return (s.hosts || []).map(h => cleanHostName(h, p._dstHostNames?.[h]) || h).filter(Boolean).join(', ');
    }).filter(Boolean).join(', ');
    return allDone
      ? `<span class="inline-editable found" data-idx="${idx}" data-field="_dstAddrName" title="${escHtml(names)}">${escHtml(names)}</span>`
      : `<span class="inline-editable missing" data-idx="${idx}" data-field="_dstAddrName" title="${escHtml(names)}">${escHtml(names)} ${badgeHtml('auto')}</span>`;
  }
  // WAN + IPs spécifiques
  const isWan = p._isWan || p.dstType === 'public';
  if (isWan && p._dstUseAll === false && p.dstHosts?.length > 0) {
    const dhFoundSet = new Set(p._dstHostsFound || []);
    const _autoHostName = h => `FF_HOST_${h.replace(/\./g, '_')}`;
    const _hostNameOk = (h) => { const n = cleanHostName(h, p._dstHostNames?.[h]); return n && n !== _autoHostName(h); };
    const dhNames = p.dstHosts.map(h => cleanHostName(h, p._dstHostNames?.[h]) || h);
    const dhAllNamed = p.dstHosts.every(h => dhFoundSet.has(h) || _hostNameOk(h));
    const dhDisplay = dhNames.join(', ');
    return dhAllNamed
      ? `<span class="inline-editable found" data-idx="${idx}" data-field="_dstAddrName" title="${escHtml(dhDisplay)}">${escHtml(dhDisplay)}</span>`
      : `<span class="inline-editable missing" data-idx="${idx}" data-field="_dstAddrName" title="${escHtml(dhDisplay)}">${escHtml(dhDisplay)} ${badgeHtml('auto')}</span>`;
  }
  if (isWan && p._dstUseAll === false && p.dstTarget && p.dstTarget !== 'all') {
    const ip = p.dstTarget;
    const autoName = `FF_HOST_${ip.replace(/[\./]/g,'_')}`;
    const name = p._dstAddrName || autoName;
    return `<span class="inline-editable found" data-idx="${idx}" data-field="_dstAddrName">${escHtml(name)} ${badgeHtml('auto')}</span>`;
  }
  const _dstModeResolved = p._dstMode || (p._use32Dst ? 'hosts' : 'subnet');
  if (_dstModeResolved === 'hosts' && (p.dstHosts || []).length > 0) {
    const dhFoundSet = new Set(p._dstHostsFound || []);
    const _autoHostName = h => `FF_HOST_${h.replace(/\./g, '_')}`;
    const _hostNameOk = (h) => { const n = cleanHostName(h, p._dstHostNames?.[h]); return n && n !== _autoHostName(h); };
    const dhNames = p.dstHosts.map(h => cleanHostName(h, p._dstHostNames?.[h]) || h);
    const dhAllNamed = p.dstHosts.every(h => dhFoundSet.has(h) || _hostNameOk(h));
    const dhDisplay = dhNames.join(', ');
    return dhAllNamed
      ? `<span class="inline-editable found" data-idx="${idx}" data-field="_dstAddrName" title="${escHtml(dhDisplay)}">${escHtml(dhDisplay)}</span>`
      : `<span class="inline-editable missing" data-idx="${idx}" data-field="_dstAddrName" title="${escHtml(dhDisplay)}">${escHtml(dhDisplay)} ${badgeHtml('auto')}</span>`;
  }
  return addrCell(p.analysis?.dstAddr, p._dstAddrName, idx, '_dstAddrName');
}

function syncAddrCell(idx, type) {
  const p = deployState.analyzed?.[idx];
  if (!p) return;
  const field = type === 'src' ? '_srcAddrName' : '_dstAddrName';
  const cell = document.querySelector(`.inline-editable[data-idx="${idx}"][data-field="${field}"]`);
  if (!cell) return;
  const html = type === 'src' ? _buildSrcAddrCell(p, idx) : _buildDstAddrCell(p, idx);
  cell.outerHTML = html;
  syncRowStatus(idx);
}

function objectStatusTag(addrAnalysis, currentName) {
  if (!addrAnalysis?.found) {
    return currentName
      ? '<span class="object-status-tag create">À CRÉER</span>'
      : '<span class="object-status-tag auto">AUTO</span>';
  }
  const prefix = parseInt(String(addrAnalysis.cidr || '').split('/')[1], 10);
  const source = String(addrAnalysis.source || '').replace('config-range', 'config');
  if (source === 'config' && Number.isInteger(prefix) && prefix <= 16) {
    return `<span class="object-status-tag broad" title="Objet existant à périmètre large">LARGE /${prefix}</span>`;
  }
  return source === 'config'
    ? '<span class="object-status-tag exact">EXACT</span>'
    : '<span class="object-status-tag auto">AUTO</span>';
}

function addrCell(addrAnalysis, currentName, idx, field) {
  if (!addrAnalysis?.found) {
    const displayName = currentName || addrAnalysis?.suggestedName || '';
    // Si l'utilisateur a tapé un nom custom → neutre (sera créé), sinon orange (action requise)
    if (currentName) {
      return `<span class="inline-editable found" data-idx="${idx}" data-field="${field}" title="Cliquer pour modifier"><span class="object-name">${escHtml(currentName)}</span>${objectStatusTag(addrAnalysis, currentName)}</span>`;
    }
    return `<span class="inline-editable missing" data-idx="${idx}" data-field="${field}" title="Cliquer pour modifier"><span class="object-name">${displayName ? escHtml(displayName) : '—'}</span>${objectStatusTag(addrAnalysis, currentName)}</span>`;
  }
  const matches = addrAnalysis.allMatches || [{ name: addrAnalysis.name, source: addrAnalysis.source }];
  const cidrTip = addrAnalysis.cidr ? ` (${addrAnalysis.cidr})` : '';
  const badge = objectStatusTag(addrAnalysis, currentName);
  if (matches.length === 1) {
    return `<span class="inline-editable found" data-idx="${idx}" data-field="${field}" title="${escHtml(matches[0].name + cidrTip)}"><span class="object-name">${escHtml(matches[0].name)}</span>${badge}</span>`;
  }
  return `<span class="inline-editable found" data-idx="${idx}" data-field="${field}" title="${escHtml(matches.length + ' objets correspondent' + cidrTip)}"><span class="object-name">${escHtml(matches[0].name)}</span>${badge}</span>`;
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

function policyMissingMandatoryFields(p) {
  const a = p?.analysis || {};
  const missing = [];
  const add = field => { if (!missing.includes(field)) missing.push(field); };
  const hostNameOk = (host, names) => {
    const name = String(names?.[host] || '').trim();
    return name && name !== `FF_HOST_${host.replace(/\./g, '_')}`;
  };
  const checkHosts = (hosts, foundHosts, names, field) => {
    const found = new Set(foundHosts || []);
    if ((hosts || []).some(host => !found.has(host) && !hostNameOk(host, names))) add(field);
  };

  if (!p?._srcintf) add('interface source');
  if (!p?._dstintf) add('interface destination');

  if (p._multiSrcSubnets?.length) {
    for (const scope of p._multiSrcSubnets) {
      if (scope.useSubnet !== false) {
        if (!scope.addrFound && !scope.addrName) add('source');
      } else {
        checkHosts(scope.hosts, p._srcHostsFound, p._srcHostNames, 'source');
      }
    }
  } else {
    const srcMode = p._srcMode || (p._use32Src ? 'hosts' : 'subnet');
    if (srcMode === 'hosts' && p.srcHosts?.length) {
      checkHosts(p.srcHosts, p._srcHostsFound, p._srcHostNames, 'source');
    } else if (!a.srcAddr?.found && !p._srcAddrName) {
      add('source');
    }
  }
  if (p._useSrcGroup && !p._srcAddrGrpFound && !p._srcAddrName) add('source');

  const isWan = p._isWan || p.dstType === 'public';
  const usesAll = isWan && p._dstUseAll === true;
  if (!usesAll) {
    if (p._isMultiDst && p._multiDstSubnets?.length) {
      for (const scope of p._multiDstSubnets) {
        if (scope.useSubnet !== false) {
          if (!scope.addrFound && !scope.addrName) add('destination');
        } else {
          checkHosts(scope.hosts, p._dstHostsFound, p._dstHostNames, 'destination');
        }
      }
    } else {
      const dstMode = p._dstMode || (p._use32Dst ? 'hosts' : 'subnet');
      const isWanSpecific = isWan && p._dstUseAll === false;
      if ((dstMode === 'hosts' || isWanSpecific) && p.dstHosts?.length) {
        checkHosts(p.dstHosts, p._dstHostsFound, p._dstHostNames, 'destination');
      } else if (!isWanSpecific && p.dstType !== 'public'
          && !a.dstAddr?.found && !p._dstAddrName) {
        add('destination');
      }
    }
  }
  if (p._useDstGroup && !p._dstAddrGrpFound && !p._dstAddrName) add('destination');

  if (!Array.isArray(a.services) || a.services.length === 0) add('service');
  const serviceResolved = service => {
    if (service.found || service._isMerged) return true;
    const notation = String(service.label || '').match(/^(TCP|UDP)\/(\d+)$/i);
    const keys = Array.isArray(service.reuseKeys)
      ? service.reuseKeys
      : notation ? [`${notation[1].toUpperCase()}/${notation[2]}`]
        : service.port ? [`${String(service.proto || '').toUpperCase()}/${service.port}`] : [];
    if (keys.length > 0 && keys.every(key => {
      const decision = p._resolvedServiceKeys?.[key];
      return decision === 'specific'
        || (decision?.startsWith('existing:') && p._serviceReuse?.[key] === decision.slice(9));
    })) return true;
    const autoLabel = service.isNamed ? service.label : `FF_SVC_${service.port}_${service.proto}`;
    const isPortNotation = /^(TCP|UDP)\/\d+$/i.test(service.suggestedName || '');
    return service.suggestedName && !isPortNotation && service.suggestedName !== autoLabel;
  };
  if ((a.services || []).some(service => !serviceResolved(service))) add('service');
  return missing;
}

function isPolicyComplete(p, _debug) {
  const a = p.analysis || {};
  const dbg = msg => { if (_debug) console.log('[complete]', msg, 'dstMode:', p._dstMode, '_use32Dst:', p._use32Dst, '_isMultiDst:', p._isMultiDst, 'dstHosts:', p.dstHosts, '_dstHostsFound:', p._dstHostsFound, '_dstHostNames:', p._dstHostNames, '_multiDstSubnets:', JSON.stringify(p._multiDstSubnets)); };

  if (p._backendIssues?.length && p._backendIssueKind !== 'risk') {
    dbg(`FAIL: ${p._backendIssues.join('; ')}`);
    return false;
  }

  // Interfaces must be explicitly selected
  if (!p._srcintf) { dbg('FAIL: no _srcintf'); return false; }
  if (!p._dstintf) { dbg('FAIL: no _dstintf'); return false; }

  // Helper : un nom auto-généré FF_HOST_... non modifié = incomplet
  const autoHostName = h => `FF_HOST_${h.replace(/\./g, '_')}`;
  const hostNameOk = (h, namesMap) => {
    const n = cleanHostName(h, namesMap?.[h]);
    return n && n !== autoHostName(h);
  };

  // Source addresses / hosts
  // _multiSrcSubnets a la priorité — srcHosts est une liste plate qui peut contenir
  // des hosts dont le subnet a été switché en /24 (useSubnet !== false), il ne faut pas les vérifier
  if (p._multiSrcSubnets?.length) {
    const srcFoundSet = new Set(p._srcHostsFound || []);
    for (const s of p._multiSrcSubnets) {
      if (s.useSubnet !== false) {
        if (!s.addrFound && !s.addrName) { dbg(`FAIL: multiSrc subnet ${s.subnet} no addrName`); return false; }
      } else {
        for (const h of (s.hosts || [])) {
          if (!srcFoundSet.has(h) && !hostNameOk(h, p._srcHostNames)) { dbg(`FAIL: multiSrc host ${h} not found/named`); return false; }
        }
      }
    }
  } else {
    const _srcModeResolved = p._srcMode || (p._use32Src ? 'hosts' : 'subnet');
    if (_srcModeResolved === 'hosts' && (p.srcHosts || []).length > 0) {
      const foundSet = new Set(p._srcHostsFound || []);
      for (const h of (p.srcHosts || [])) {
        if (!foundSet.has(h) && !hostNameOk(h, p._srcHostNames)) { dbg(`FAIL: src host ${h} not found/named`); return false; }
      }
    } else {
      if (!a.srcAddr?.found && !p._srcAddrName) { dbg('FAIL: srcAddr not found/named'); return false; }
    }
  }

  // Source group (addrgrp): if active and not already found, must have a typed name
  if (p._useSrcGroup && !p._srcAddrGrpFound && !p._srcAddrName) { dbg('FAIL: srcGroup missing name'); return false; }

  // Destination addresses / hosts
  // _multiDstSubnets a la priorité — dstHosts peut contenir des hosts dont le subnet
  // a été switché en /24 (useSubnet !== false), il ne faut pas les vérifier
  const _isWanPolicy = p._isWan || p.dstType === 'public';
  if (p._isMultiDst && p._multiDstSubnets?.length && !(_isWanPolicy && p._dstUseAll === true)) {
    const dstFoundSet = new Set(p._dstHostsFound || []);
    for (const s of p._multiDstSubnets) {
      if (s.useSubnet !== false) {
        if (!s.addrFound && !s.addrName) { dbg(`FAIL: multiDst subnet ${s.subnet} no addrName`); return false; }
      } else {
        for (const h of (s.hosts || [])) {
          if (!dstFoundSet.has(h) && !hostNameOk(h, p._dstHostNames)) { dbg(`FAIL: multiDst host ${h} not found/named`); return false; }
        }
      }
    }
  } else if (!p._isMultiDst || !(_isWanPolicy && p._dstUseAll === true)) {
    const _dstModeResolved = p._dstMode || (p._use32Dst ? 'hosts' : 'subnet');
    const isWanSpecific = (p._isWan || p.dstType === 'public') && p._dstUseAll === false;
    if (isWanSpecific && p.dstHosts?.length > 0) {
      const foundSet = new Set(p._dstHostsFound || []);
      for (const h of (p.dstHosts || [])) {
        if (!foundSet.has(h) && !hostNameOk(h, p._dstHostNames)) { dbg(`FAIL: dst host ${h} not found/named (WAN specific)`); return false; }
      }
    } else if (!isWanSpecific) {
      if (_dstModeResolved === 'hosts' && (p.dstHosts || []).length > 0) {
        const foundSet = new Set(p._dstHostsFound || []);
        for (const h of (p.dstHosts || [])) {
          if (!foundSet.has(h) && !hostNameOk(h, p._dstHostNames)) { dbg(`FAIL: dst host ${h} not found/named`); return false; }
        }
      } else if (p.dstType !== 'public') {
        if (!a.dstAddr?.found && !p._dstAddrName) { dbg('FAIL: dstAddr not found/named'); return false; }
      }
    }
  }

  // Destination group (addrgrp)
  if (p._useDstGroup && !p._dstAddrGrpFound && !p._dstAddrName) { dbg('FAIL: dstGroup missing name'); return false; }

  // Services — must be found, merged, or explicitly renamed by user
  // Aligné avec svcCells: orange si pas de customName (= suggestedName identique au label auto)
  if (!Array.isArray(a.services) || a.services.length === 0) { dbg('FAIL: no services'); return false; }
  for (const svc of a.services || []) {
    if (svc.found || svc._isMerged || isCompatibleServiceSelected(p, svc)) continue;
    const isPortNotation = /^(TCP|UDP)\/\d+$/i.test(svc.suggestedName || '');
    const autoLabel = svc.isNamed ? svc.label : `FF_SVC_${svc.port}_${svc.proto}`;
    const hasCustomName = svc.suggestedName && !isPortNotation && svc.suggestedName !== autoLabel;
    if (!hasCustomName) { dbg(`FAIL: svc ${svc.label||svc.name} no custom name (suggested="${svc.suggestedName}" auto="${autoLabel}")`); return false; }
  }

  return true;
}

function syncRowStatus(idx) {
  const p = deployState.analyzed?.[idx];
  if (!p) return;
  const bar = document.querySelector(`.deploy-policy-row[data-idx="${idx}"] .status-bar`);
  if (!bar) return;
  bar.className = `status-bar status-${isPolicyComplete(p) ? 'ok' : 'warn'}`;
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

window.debugPolicy = idx => { const p = deployState.analyzed?.[idx]; if (!p) return console.log('no policy at', idx); isPolicyComplete(p, true); };
window.debugAllIncomplete = () => (deployState.analyzed || []).forEach((p, i) => { if (!isPolicyComplete(p)) isPolicyComplete(p, true); });

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

  // ── change: .deploy-merge-chk ──
  container.addEventListener('change', e => {
    const chk = e.target.closest('.deploy-merge-chk');
    if (!chk || chk.disabled) return;
    const i = +chk.dataset.idx;
    chk.checked ? deployState.mergeSelected.add(i) : deployState.mergeSelected.delete(i);
    _updateMergeSelectionBtn();
  });

  // ── click: .deploy-del-policy (supprimer une policy) ──
  container.addEventListener('click', e => {
    const btn = e.target.closest('.deploy-del-policy');
    if (!btn) return;
    e.stopPropagation();
    _savePolicySnapshot();
    if (btn.dataset.seqMembers) {
      const members = new Set(btn.dataset.seqMembers.split(',').map(Number));
      _removeAnalyzedIndices(members);
    } else {
      _removeAnalyzedIndices(new Set([+btn.dataset.idx]));
    }
    renderDeployPolicies(filterDeployPolicies(), false);
  });

  // ── click: .btn-toggle-policy (enable/disable) ──
  container.addEventListener('click', e => {
    const btn = e.target.closest('.btn-toggle-policy');
    if (!btn) return;
    e.stopPropagation();
    const idx = +btn.dataset.idx;
    const p = deployState.analyzed[idx];
    if (!p) return;
    p._disabled = !p._disabled;
    const badge = btn.querySelector('.policy-status-badge');
    if (badge) {
      badge.textContent = p._disabled ? 'DIS' : 'ENA';
      badge.className = `policy-status-badge ${p._disabled ? 'badge-disabled' : 'badge-enabled'}`;
    }
    btn.title = p._disabled ? 'Policy désactivée — cliquer pour activer' : 'Policy activée — cliquer pour désactiver';
    btn.closest('.deploy-policy-row')?.classList.toggle('policy-disabled-row', !!p._disabled);
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
      if (svc) { svc.suggestedName = e.target.value; syncSvcCell(+idx); }
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

  // ── click: .btn-merge-group (fusionner un groupe spécifique) ──
  container.addEventListener('click', e => {
    const btn = e.target.closest('.btn-merge-group');
    if (!btn) return;
    e.stopPropagation();
    const pair = btn.dataset.mergeGroup;
    if (!pair || !deployState.analyzed) return;
    _savePolicySnapshot();
    const strategy = deployState.mergeStrategy || 'service';
    const pairPols = deployState.analyzed.filter(p => {
      const src = p._srcintf || p.analysis?.srcIface || '';
      const dst = p._dstintf || p.analysis?.dstIface || '';
      return `${src} → ${dst}` === pair;
    });
    const rest     = deployState.analyzed.filter(p => {
      const src = p._srcintf || p.analysis?.srcIface || '';
      const dst = p._dstintf || p.analysis?.dstIface || '';
      return `${src} → ${dst}` !== pair;
    });
    let merged;
    if (strategy === 'max') {
      merged = mergeAnalyzedPolicies(pairPols.map(p => ({ ...p })), 'all');
    } else if (strategy === 'service') {
      merged = mergeByService(pairPols.map(p => ({ ...p })));
    } else if (strategy === 'destination') {
      merged = mergeByDestination(pairPols.map(p => ({ ...p })));
    } else {
      merged = mergeByPolicyId(pairPols.map(p => ({ ...p })));
    }
    deployState.analyzed = [...merged, ...rest].sort((a, b) => (b.sessions || 0) - (a.sessions || 0));
    renderDeployPolicies(filterDeployPolicies(), false);
  });

  // ── click: .intf-pair-header (collapse/expand groups) ──
  container.addEventListener('click', e => {
    if (e.target.closest('.btn-merge-group')) return; // handled above
    const header = e.target.closest('.intf-pair-header');
    if (!header) return;
    e.stopPropagation();
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

function thSort(label, col) {
  const active = deployState.sortCol === col;
  const arrow = active ? (deployState.sortDir === 'asc' ? ' ▲' : ' ▼') : '';
  return `<th class="sortable-th${active ? ' sort-active' : ''}" data-sort="${col}" style="cursor:pointer;user-select:none">${label}${arrow}</th>`;
}

function renderDeployPolicies(analyzed, resetPage = true) {
  // M1: si la vue deploy n'est plus montée (render déclenché après changement de vue),
  // el('deploy-policy-body') est null → on abandonne au lieu de crasher sur .innerHTML.
  const body = el('deploy-policy-body');
  if (!body) return;
  analyzed = analyzed || [];   // garde: liste absente → pas de crash sur .length plus bas
  if (resetPage) deployState.page = 1;

  // In sequence mode, aggregate before pagination
  const viewMode = deployState.viewMode || 'interface-pair';
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

    const mergeChkChecked = !isAgg && deployState.mergeSelected.has(idx);
    const mergeChkAttr = isAgg ? 'class="deploy-merge-chk" disabled' : `class="deploy-merge-chk" data-idx="${idx}" ${mergeChkChecked ? 'checked' : ''}`;

    // Src addr — simplified inline-editable
    const srcAddrCell = _buildSrcAddrCell(p, idx);
    const dstAddrCell = _buildDstAddrCell(p, idx);

    // Services — compact
    const svcCells = _buildSvcCellHtml(p, 3);

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
      const srcIfBadge = srcIfSrc === 'route' ? badgeHtml('route') : srcIfSrc === 'sdwan' ? badgeHtml('sdwan') : srcIfSrc === 'subnet' ? badgeHtml('subnet') : srcIfSrc === 'log' ? badgeHtml('route') : '';
      const dstIfBadge = dstIfSrc === 'route' ? badgeHtml('route') : dstIfSrc === 'sdwan' ? badgeHtml('sdwan') : dstIfSrc === 'subnet' ? badgeHtml('subnet') : '';
      srcIntf = `<span class="mono" style="font-size:10px;color:${p._srcintf ? 'var(--text)' : 'var(--text2)'}">${escHtml(srcLabel)}${srcIfBadge}</span>`;
      dstIntf = `<span class="mono" style="font-size:10px;color:${p._dstintf ? 'var(--text)' : 'var(--text2)'}">${escHtml(dstLabel)}${sameWarn}${dstIfBadge}</span>`;
    }

    const actionBadge = (p._action === 'deny')
      ? `<span class="dir-badge" style="background:var(--danger,#ef4444);color:#fff">DENY</span> `
      : '';
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
    const srcHostCount = (p.srcHosts || []).length;
    const srcModeBadge = srcHostCount > 0 ? ` <span class="dst-count-badge">${srcHostCount}h</span>` : '';

    const backendIssues = p._backendIssues || [];
    const backendIncomplete = p._backendIssueKind === 'incomplete';
    const technicalIssues = p._backendIssueKind === 'risk' ? [] : backendIssues;
    const fieldComplete = p._disabled || isPolicyComplete(p);
    const statusTitle = technicalIssues.join('\n') || (p.analysis?.missingFields || []).join(', ') || '';
    const isHighlighted = !isAgg && idx === deployState._highlightIdx;
    if (isHighlighted) deployState._highlightIdx = null; // consommer une seule fois
    const isScan = isScanPolicy(p);
    const objectState = technicalIssues.length > 0
      ? `<span class="policy-needs-work" title="${escHtml(statusTitle)}">${backendIncomplete ? 'À compléter' : 'Erreur technique'}</span>`
      : fieldComplete
      ? '<span class="policy-ready">Complète</span>'
      : `<span class="policy-needs-work" title="${escHtml(statusTitle)}">À compléter</span>`;
    const interfaceSummary = `<span class="policy-interface-pair">${srcIntf}<span class="policy-interface-arrow">→</span>${dstIntf}</span>`;
    return `
      <tr class="deploy-policy-row ${isAgg ? 'seq-row' : ''} ${p._action === 'deny' ? 'policy-deny-row' : ''} ${p._disabled ? 'policy-disabled-row' : ''} ${isHighlighted ? 'policy-row-flash' : ''} ${isScan ? 'policy-scan-row' : ''}" data-idx="${idx}" ${isAgg ? `data-seq-members="${p._sequenceMembers.join(',')}"` : ''}>
        <td class="policy-controls-cell">
          <input type="checkbox" ${chkAttr} title="Inclure dans le CLI">
          <button class="btn-toggle-policy" data-idx="${idx}" title="${p._disabled ? 'Activer' : 'Désactiver'}"><span class="policy-status-badge ${p._disabled ? 'badge-disabled' : 'badge-enabled'}">${p._disabled ? 'DIS' : 'ENA'}</span></button>
          <input type="checkbox" ${mergeChkAttr} title="Sélectionner pour fusion">
          <button class="btn-del-item deploy-del-policy policy-row-secondary" data-idx="${idx}" ${isAgg ? `data-seq-members="${p._sequenceMembers.join(',')}"` : ''} title="Supprimer">✕</button>
        </td>
        <td class="policy-main-cell"><div class="policy-primary-line">${actionBadge}${dirBadge}${warnBadge}${seqBadge}${isScan ? '<span class="scan-badge">⚠ silencieux</span>' : ''}<span class="policy-primary-value">${srcSubnetText}${srcModeBadge}</span><span class="policy-session-inline">${fmtNum(p.sessions || 0)}</span></div></td>
        <td class="policy-main-cell">${dstTargetCell(p, idx)}</td>
        <td class="svc-cell policy-services-cell" data-svc-idx="${idx}">${svcCells}</td>
        <td class="policy-interfaces-cell">${interfaceSummary}</td>
        <td class="policy-objects-cell"><div class="policy-object-pair">${srcAddrCell}<span class="policy-interface-arrow">→</span>${dstAddrCell}</div></td>
        <td class="policy-state-cell">${objectState}</td>
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
        <td colspan="99"><div class="intf-pair-header-inner">
          <span class="intf-pair-toggle">${collapsed ? '▸' : '▾'}</span>
          <span class="intf-pair-name">${escHtml(pair)}</span>
          <span class="intf-pair-count">${members.length} polic${members.length > 1 ? 'ies' : 'y'}</span>
          ${members.length > 1 ? `<button class="btn-sm btn-merge-group" data-merge-group="${escHtml(pair)}" title="Fusionner ce groupe (stratégie courante)">⚡ Fusionner</button>` : ''}
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
  // body est récupéré et vérifié non-null en tête de fonction (garde M1)
  body.innerHTML = `
    <div style="margin-bottom:8px;font-size:12px;color:var(--text2);display:flex;align-items:center;gap:12px">
      <span>${total} polic${total > 1 ? 'ies' : 'y'} · <strong>${selCount}</strong> sélectionnées${hasMerge ? ' · <span style="color:var(--accent2)">⚡ fusion</span>' : ''}${
        (deployState.warnings || []).length > 0
          ? ` · <span style="color:var(--warn)">⚠ ${deployState.warnings.length} conflit${deployState.warnings.length > 1 ? 's' : ''}</span>`
          : ''
      }</span>
    </div>
    ${paginationBar}
    <div style="overflow-x:auto">
      <table class="deploy-policy-table">
        <thead><tr>
          <th class="col-hdr-chk" title="Inclure toutes les policies"><input type="checkbox" id="chk-all-deploy" title="Tout cocher / décocher"></th>
          ${thSort('Source', 'source')}
          ${thSort('Destination', 'dst')}
          ${thSort('Services', 'services')}
          <th>Interfaces</th>
          <th>Objets FortiGate</th>
          <th>État</th>
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

  // Wire sortable column headers
  document.querySelectorAll('.sortable-th').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (deployState.sortCol === col) {
        deployState.sortDir = deployState.sortDir === 'desc' ? 'asc' : 'desc';
      } else {
        deployState.sortCol = col;
        deployState.sortDir = 'desc';
      }
      deployState.page = 1;
      renderDeployPolicies(filterDeployPolicies(), false);
    });
  });

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

  // Wire select-all — opère sur TOUTES les pages (pas seulement la page courante)
  const chkAll = el('chk-all-deploy');
  if (chkAll) {
    // Tous les indices de la liste filtrée (toutes pages)
    const allIdxs = [];
    for (const p of displayList) {
      if (p._isAggregated && p._sequenceMembers) {
        allIdxs.push(...p._sequenceMembers);
      } else {
        allIdxs.push(policyIndexMap.get(p) ?? -1);
      }
    }
    chkAll.checked = allIdxs.length > 0 && allIdxs.every(i => deployState.selected.has(i));
    chkAll.indeterminate = !chkAll.checked && allIdxs.some(i => deployState.selected.has(i));
    chkAll.addEventListener('change', e => {
      allIdxs.forEach(i => {
        e.target.checked ? deployState.selected.add(i) : deployState.selected.delete(i);
      });
      // Mettre à jour visuellement les checkboxes de la page courante
      document.querySelectorAll('.deploy-chk').forEach(chk => { chk.checked = e.target.checked; });
    });
  }

  // (iface dropdowns are pre-selected via buildIfaceDropdown — no post-render step needed)

  // Wire event delegation on deploy-policy-body (idempotent — only installed once)
  wireDeployTable();

  // Synchronise le bouton "sans réponse" dans deploy-merge-info (toolbar)
  syncNoRcvdInfoBtn();
}

// Synchronise la barre "destination silencieuse"
function syncNoRcvdInfoBtn() {
  if (!deployState.analyzed) return;
  if (deployState._noRcvdCount === undefined) {
    deployState._noRcvdCount = deployState.analyzed.filter(isScanPolicy).length;
  }
  const count = deployState._noRcvdCount;
  const bar = document.getElementById('no-rcvd-bar');
  if (bar) bar.style.display = count === 0 ? 'none' : '';
  if (count > 0) updateNoRcvdToggleBtn();
}

function isNonBlockingPolicyIssue(issue) {
  return ['risk', 'warn'].includes(String(issue?.level || '').toLowerCase());
}

function formatPolicyValidationError(payload) {
  const issues = Array.isArray(payload?.issues) ? payload.issues
    : Array.isArray(payload?.preflight?.issues) ? payload.preflight.issues : [];
  const title = payload?.error || 'Validation backend refusée';
  if (issues.length === 0) return title;
  const prefix = payload?.preflight ? 'À compléter' : 'Erreur technique';
  const blocking = issues.filter(issue => !isNonBlockingPolicyIssue(issue));
  const nonBlocking = issues.filter(isNonBlockingPolicyIssue);
  const sections = [];
  if (blocking.length) sections.push(blocking.map(issue =>
    `• ${issue.msg || issue.code || 'Cause non précisée'}`).join('\n'));
  if (nonBlocking.length) sections.push(`Avertissement non bloquant :\n${nonBlocking.map(issue =>
    `• ${issue.msg || issue.code || 'Risque non précisé'}`).join('\n')}`);
  return `${blocking.length ? prefix : 'Information'} — ${title}\n\n${sections.join('\n\n')}`;
}

function markSelectedPolicyIssues(issues, selectedIndexes, kind = 'security') {
  const blockingIssues = (issues || []).filter(issue => !isNonBlockingPolicyIssue(issue));
  const groups = Array.isArray(selectedIndexes[0])
    ? selectedIndexes : selectedIndexes.map(index => [index]);
  for (const index of groups.flat()) delete deployState.analyzed[index]._backendIssues;
  for (const issue of blockingIssues) {
    const position = String(issue?.msg || '').match(/^Policy #(\d+):/);
    const indexes = position && groups[Number(position[1]) - 1]
      ? groups[Number(position[1]) - 1] : groups.flat();
    const detail = `[${issue?.code || 'VALIDATION'}] ${issue?.msg || 'Cause non précisée'}`;
    for (const index of indexes) {
      const policy = deployState.analyzed[index];
      if (!policy) continue;
      if (!policy._backendIssues) policy._backendIssues = [];
      policy._backendIssueKind = kind;
      if (!policy._backendIssues.includes(detail)) policy._backendIssues.push(detail);
    }
  }
  renderDeployPolicies(filterDeployPolicies(), false);
}

async function generateDeployConf() {
  if (!deployState.analyzed) return;

  try {
    const recovery = await recoverInvalidSpecificServiceState(
      deployState.analyzed,
      'preflight-service-name-conflict',
    );
    if (recovery.applied.length) {
      deployState.generatedCli = null;
      renderDeployPolicies(filterDeployPolicies(), false);
      if (_drawerIdx !== null) populateDrawer(_drawerIdx);
      alert(`Récupération services : ${recovery.applied.length} association(s) invalide(s) retirée(s). Sauvegarde : ${recovery.backupId}`);
    }
  } catch (recoveryError) {
    alert(`Génération annulée — sauvegarde de récupération impossible : ${recoveryError.message}`);
    return;
  }

  const selectedIndexes = [...deployState.selected]
    .filter(index => index >= 0 && index < deployState.analyzed.length)
    .sort((a, b) => a - b);

  if (selectedIndexes.length === 0) { alert('Sélectionnez au moins une policy'); return; }
  const incompleteSelectedIndexes = selectedIndexes
    .filter(index => !isPolicyComplete(deployState.analyzed[index]));
  if (incompleteSelectedIndexes.length > 0) {
    const details = incompleteSelectedIndexes.map(index => {
      const policy = deployState.analyzed[index];
      const fields = policyMissingMandatoryFields(policy);
      if (fields.length > 0) {
        return `Policy #${index + 1} — champ obligatoire manquant :\n${fields.map(field => `  • ${field}`).join('\n')}`;
      }
      const technical = (policy._backendIssues || []).join(', ');
      return `Policy #${index + 1} — erreur technique : ${technical || 'incohérence de génération'}`;
    }).join('\n');
    alert(details);
    return;
  }

  let selectedPolicies;
  let selectedPolicyIndexGroups;
  const selectedCompleteIndexes = selectedIndexes;
  if (deployState.viewMode === 'sequence') {
    // In sequence mode, aggregate selected policies before sending
    const selected = selectedCompleteIndexes.map(index => deployState.analyzed[index]);
    const aggregated = buildSequenceAggregated(selected);
    selectedPolicyIndexGroups = aggregated.map(policy => policy._isAggregated
      ? policy._sequenceMembers : [deployState.analyzed.indexOf(policy)]);
    selectedPolicies = aggregated.map(p => ({
      ...p,
      services:        serializePolicyServiceLabels(p),
      _mergedServices: serializeMergedServiceDecisions(p),
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
      securityProfiles: p._secProfiles || null,
      action:       p._action || null,
      log:          p._log    || null,
      disabled:     p._disabled || false,
    }));
  } else {
    selectedPolicyIndexGroups = selectedCompleteIndexes.map(index => [index]);
    selectedPolicies = selectedCompleteIndexes
      .map(index => deployState.analyzed[index])
      .map(p => ({
        ...p,
        services:        serializePolicyServiceLabels(p),
        _mergedServices: serializeMergedServiceDecisions(p),
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
        securityProfiles: p._secProfiles || null,
        action:       p._action || null,
        log:          p._log    || null,
        disabled:     p._disabled || false,
      }));
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
  const resetGenerateButton = () => {
    if (btn) { btn.disabled = false; btn.textContent = '⬇ Générer config FortiGate'; }
  };

  // Preflight validation
  try {
    const submitPreflight = () => fetch(`/api/deploy/preflight?session=${state.session}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ selectedPolicies, opts }),
    });
    const pfRes = await submitPreflight();
    const pf = await pfRes.json().catch(() => ({}));
    if (!pfRes.ok) {
      const pfIssues = pf.issues || pf.preflight?.issues || [];
      markSelectedPolicyIssues(
        pfIssues,
        selectedPolicyIndexGroups,
        pf.code === 'POLICY_DECISION_INVALID' ? 'security' : 'incomplete',
      );
      alert(formatPolicyValidationError(pf));
      resetGenerateButton();
      return;
    }
    renderDeployPolicies(filterDeployPolicies(), false);
  } catch (err) {
    alert(`Validation backend indisponible — ${err.message}`);
    resetGenerateButton();
    return;
  }

  if (btn) btn.textContent = 'Génération…';

  try {
    // Fetch JSON (not download) to get CLI text for inline preview
    const r = await fetch(`/api/deploy/generate?session=${state.session}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ selectedPolicies, opts }),
    });
    if (!r.ok) {
      const e = await r.json().catch(() => ({}));
      const issues = e.issues || e.preflight?.issues || [];
      markSelectedPolicyIssues(
        issues,
        selectedPolicyIndexGroups,
        e.code === 'POLICY_DECISION_INVALID' ? 'security' : 'incomplete',
      );
      alert(formatPolicyValidationError(e));
      return;
    }
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
      a.href = url; a.download = `fortiflow_deploy_${tsNow()}.conf`; a.click();
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
    resetGenerateButton();
  }
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
loadWsHistory();
