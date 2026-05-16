/* FATV — Forensic Artifact Timeline Visualizer
   Farhan Saifullah & Tayyab Ayub — 2026
   Fixed dashboard version: consistent filtering, working entity/phase/source filters,
   working anomaly clicks, safer rendering, and graceful Plotly handling. */

let filteredEvents = [...EVENTS];
let currentPage = 1;
const PAGE_SIZE = 50;
let activeChainId = null;
let activeSev = null;
let activeSource = null;
let activePhase = null;
let activeEntity = null;
let currentEventId = null;
let plotlyReady = false;

// ── Shared filter helpers ────────────────────────────────────────────────────

function chainForId(chainId) {
  return CHAINS.find(c => c.chain_id === chainId) || null;
}

function eventMatchesChain(e, chainId) {
  if (!chainId) return true;
  if (e.attack_chain_id === chainId) return true;
  const chain = chainForId(chainId);
  return !!(chain && Array.isArray(chain.event_ids) && chain.event_ids.includes(e.event_id));
}

function eventMatchesText(e, q) {
  if (!q) return true;
  const haystack = [
    e.event_id, e.timestamp_human, e.source, e.source_type, e.event_type,
    e.description, e.src_ip, e.dst_ip, e.src_port, e.dst_port, e.protocol,
    e.user, e.hostname, e.kill_chain_phase, e.anomaly_reason,
    ...(e.tags || [])
  ].join(' ').toLowerCase();
  return haystack.includes(q.toLowerCase());
}

function currentSeverityFilter() {
  const selectValue = document.getElementById('sevFilter')?.value || '';
  if (activeSev && activeSev !== 'ALL') return activeSev;
  return selectValue;
}

function currentSourceFilter() {
  const selectValue = document.getElementById('sourceFilter')?.value || '';
  return activeSource || selectValue;
}

function applyCommonFilters(options = {}) {
  const includeTimelineSearch = options.includeTimelineSearch !== false;
  const includeTableSearch = options.includeTableSearch === true;
  const sev = currentSeverityFilter();
  const src = currentSourceFilter();
  const timelineQ = includeTimelineSearch ? (document.getElementById('searchBox')?.value || '').trim().toLowerCase() : '';
  const tableQ = includeTableSearch ? (document.getElementById('tableSearch')?.value || '').trim().toLowerCase() : '';

  return EVENTS.filter(e => {
    if (sev && e.severity !== sev) return false;
    if (src && e.source_type !== src) return false;
    if (activePhase && e.kill_chain_phase !== activePhase) return false;
    if (activeEntity && !(e.src_ip === activeEntity || e.dst_ip === activeEntity || e.user === activeEntity || e.hostname === activeEntity)) return false;
    if (!eventMatchesChain(e, activeChainId)) return false;
    if (timelineQ && !eventMatchesText(e, timelineQ)) return false;
    if (tableQ && !eventMatchesText(e, tableQ)) return false;
    return true;
  });
}

function updateSidebarState() {
  document.querySelectorAll('.sev-item').forEach(el => {
    const sev = el.dataset.sev || 'ALL';
    const isAll = el.id === 'sev-all';
    el.classList.toggle('active', (activeSev && sev === activeSev) || (!activeSev && isAll));
  });

  document.querySelectorAll('.source-pill[data-source]').forEach(el => {
    el.classList.toggle('active', !!activeSource && el.dataset.source === activeSource);
  });

  document.querySelectorAll('.phase-pill[data-phase]').forEach(el => {
    el.classList.toggle('active', !!activePhase && el.dataset.phase === activePhase);
  });
}

function refreshDashboard() {
  updateSidebarState();
  buildTimeline();
  renderTable();
}

// ── Plotly Timeline ──────────────────────────────────────────────────────────

function buildTimeline() {
  const chartDiv = document.getElementById('plotlyChart');
  if (!chartDiv) return;

  if (typeof Plotly === 'undefined') {
    chartDiv.innerHTML = '<div class="empty"><div class="empty-icon">⚠</div><div class="empty-text">Timeline chart library could not load. Check internet connection or include Plotly locally.</div></div>';
    return;
  }

  let evts = applyCommonFilters({ includeTimelineSearch: true, includeTableSearch: false });

  const sourceTypes = [...new Set(evts.map(e => e.source_type))].sort();
  const severities  = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
  const traces = [];

  for (const sev of severities) {
    const subset = evts.filter(e => e.severity === sev);
    if (!subset.length) continue;

    traces.push({
      type: 'scatter',
      mode: 'markers',
      name: sev,
      x: subset.map(e => e.timestamp),
      y: subset.map(e => e.source_type),
      text: subset.map(e =>
        `<b>${escHtml(e.event_type)}</b><br>` +
        `${escHtml((e.description||'').substring(0,120))}<br>` +
        `Src: ${escHtml(e.src_ip||'—')}  →  Dst: ${escHtml(e.dst_ip||'—')}<br>` +
        `${escHtml(e.timestamp_human||'')}` +
        (e.kill_chain_phase ? `<br>Phase: ${escHtml(e.kill_chain_phase)}` : '') +
        (e.is_anomaly ? `<br><b>⚠ ${escHtml(e.anomaly_reason||'Anomaly')}</b>` : '')
      ),
      hovertemplate: '%{text}<extra></extra>',
      customdata: subset.map(e => e.event_id),
      marker: {
        color:   SEV_COLORS[sev] || '#64748b',
        size:    { CRITICAL:16, HIGH:13, MEDIUM:10, LOW:8, INFO:6 }[sev] || 7,
        symbol:  subset.map(e => getSymbol(e.source_type)),
        opacity: 0.9,
        line: {
          width: subset.map(e => e.is_anomaly ? 2 : 0.4),
          color: subset.map(e => e.is_anomaly ? '#ffffff' : 'rgba(255,255,255,0.15)'),
        },
      },
    });
  }

  if (!traces.length) {
    traces.push({ type:'scatter', mode:'markers', x:[], y:[], name:'No data', marker:{color:'#64748b',size:6} });
  }

  const shapes = [];
  if (activeChainId) {
    const chain = chainForId(activeChainId);
    if (chain && chain.start_time && chain.end_time) {
      shapes.push({
        type: 'rect',
        x0: chain.start_time, x1: chain.end_time,
        y0: -0.5, y1: Math.max(sourceTypes.length - 0.5, 0.5),
        fillcolor: 'rgba(0,212,255,0.06)',
        line: { color: 'rgba(0,212,255,0.35)', width: 1, dash: 'dash' },
        layer: 'below',
      });
    }
  }

  const layout = {
    paper_bgcolor: '#0f1f35',
    plot_bgcolor:  '#0a1628',
    font: { family:"'IBM Plex Mono',monospace", color:'#6b8aad', size:11 },
    margin: { t:16, r:16, b:56, l:110 },
    height: 460,
    xaxis: {
      type: 'date', gridcolor: '#1a3050', zerolinecolor: '#1a3050',
      tickfont: { size:10, color:'#6b8aad' }, linecolor: '#1a3050', tickformat: '%H:%M:%S',
    },
    yaxis: {
      gridcolor: '#1a3050', zerolinecolor: '#1a3050',
      tickfont: { size:10, color:'#6b8aad' }, categoryorder: 'category ascending',
    },
    legend: {
      x:1.01, y:1, bgcolor: 'rgba(10,22,40,.92)', bordercolor: '#1a3050',
      borderwidth: 1, font: { size:10 },
    },
    shapes: shapes,
    hovermode: 'closest',
    hoverlabel: {
      bgcolor: '#0f1f35', bordercolor: '#253d5e',
      font: { family:"'IBM Plex Mono',monospace", size:11, color:'#e2eeff' }, align: 'left',
    },
    dragmode: 'pan',
  };

  const config = {
    responsive: true,
    scrollZoom: true,
    displayModeBar: true,
    modeBarButtonsToRemove: ['lasso2d','select2d','toggleSpikelines','autoScale2d'],
    toImageButtonOptions: { format:'png', filename:'fatv_timeline', width:1400, height:500 },
    displaylogo: false,
  };

  if (plotlyReady) {
    Plotly.react('plotlyChart', traces, layout, config);
  } else {
    Plotly.newPlot('plotlyChart', traces, layout, config);
    plotlyReady = true;
  }

  chartDiv.on('plotly_click', function(data) {
    if (!data.points.length) return;
    const eid = data.points[0].customdata;
    if (eid) openDetailById(eid);
  });
}

function getSymbol(sourceType) {
  const map = {
    auth:'circle', network:'diamond', syslog:'square',
    filesystem:'triangle-up', pcap:'star', web:'cross',
    windows:'pentagon', unknown:'circle-open',
  };
  return map[sourceType] || 'circle';
}

// ── Event Table ──────────────────────────────────────────────────────────────

function renderTable() {
  const body = document.getElementById('eventsTableBody');
  if (!body) return;

  const evts = applyCommonFilters({ includeTimelineSearch: true, includeTableSearch: true });
  filteredEvents = evts;

  const cntEl = document.getElementById('visibleCount');
  if (cntEl) cntEl.textContent = evts.length;

  const totalPages = Math.max(1, Math.ceil(evts.length / PAGE_SIZE));
  if (currentPage > totalPages) currentPage = totalPages;
  const start = (currentPage - 1) * PAGE_SIZE;
  const page  = evts.slice(start, start + PAGE_SIZE);

  const piEl = document.getElementById('pageInfo');
  if (piEl) piEl.textContent = `Page ${currentPage} / ${totalPages}`;

  if (!page.length) {
    body.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:24px">No events match the current filters.</td></tr>';
    return;
  }

  body.innerHTML = page.map(e => `
    <tr class="${e.is_anomaly ? 'anomaly' : ''}" onclick="openDetailById('${escAttr(e.event_id)}')">
      <td style="font-size:10px;color:var(--muted);white-space:nowrap">${escHtml(e.timestamp_human||'')}</td>
      <td>
        <span style="display:inline-flex;align-items:center;gap:4px">
          <span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:${escAttr(e.severity_color)};flex-shrink:0"></span>
          <span style="color:${escAttr(e.severity_color)};font-size:10px;font-weight:600">${escHtml(e.severity)}</span>
        </span>
      </td>
      <td><span style="color:${SOURCE_COLORS[e.source_type]||'#94a3b8'};font-size:10px">${escHtml(e.source_type)}</span></td>
      <td style="font-weight:600;color:var(--text)">${escHtml(e.event_type)}</td>
      <td style="color:#7dd3fc">${escHtml(e.src_ip||'—')}</td>
      <td style="color:#7dd3fc">${escHtml(e.dst_ip||'—')}</td>
      <td style="font-size:9px;color:var(--muted)">${escHtml(e.kill_chain_phase||'')}</td>
      <td style="color:var(--muted);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
        ${escHtml((e.description||'').substring(0,110))}
      </td>
    </tr>`).join('');
}

function filterTable() { currentPage = 1; renderTable(); }
function filterTimelineSearch() { currentPage = 1; refreshDashboard(); }
function prevPage()    { if (currentPage > 1) { currentPage--; renderTable(); } }
function nextPage()    {
  const total = Math.ceil(filteredEvents.length / PAGE_SIZE);
  if (currentPage < total) { currentPage++; renderTable(); }
}

// ── Detail Panel ─────────────────────────────────────────────────────────────

function openDetailById(eid) {
  const evt = EVENTS.find(e => e.event_id === eid);
  if (!evt) return;
  currentEventId = eid;

  setText('detailTitle',    evt.event_type);
  setHTML('detailSevBadge',
    `<span style="font-family:var(--mono);font-size:10px;padding:2px 10px;border-radius:4px;
      background:${escAttr(evt.severity_color)}20;color:${escAttr(evt.severity_color)};border:1px solid ${escAttr(evt.severity_color)}40">
      ${escHtml(evt.severity)}
    </span>
    ${evt.is_anomaly ? `<span style="margin-left:8px;font-size:10px;color:#f59e0b">⚠ ANOMALY — ${escHtml(evt.anomaly_reason||'')}</span>` : ''}`
  );
  setText('detailTs',    evt.timestamp_human || evt.timestamp || '—');
  setText('detailSrc',   `${evt.source}  (${evt.source_type})`);
  setText('detailIps',   `${evt.src_ip||'—'}  →  ${evt.dst_ip||'—'}`);
  setText('detailPorts', `${evt.src_port||'—'} → ${evt.dst_port||'—'}  /  ${evt.protocol||'—'}`);
  setText('detailUser',  evt.user || '—');
  setText('detailDesc',  evt.description || '—');
  setText('detailKill',  evt.kill_chain_phase || '—');
  setText('detailRaw',   evt.raw || '(no raw data)');

  const noteEl = document.getElementById('noteInput');
  if (noteEl) noteEl.value = evt.note || '';

  const tagList = document.getElementById('tagList');
  if (tagList) {
    tagList.innerHTML = (evt.tags||[]).map(t =>
      `<span class="tag-chip">${escHtml(t)}</span>`
    ).join('');
  }

  const corrDiv  = document.getElementById('rowCorr');
  const corrList = document.getElementById('corrList');
  if (corrDiv && corrList) {
    const ids = (evt.correlation_ids || []).filter(id => id !== eid).slice(0, 8);
    if (ids.length) {
      corrDiv.style.display = 'block';
      corrList.innerHTML = ids.map(cid => {
        const ce = EVENTS.find(e => e.event_id === cid);
        if (!ce) return '';
        return `<div class="corr-item" onclick="openDetailById('${escAttr(cid)}')">
          <span style="color:${escAttr(ce.severity_color)};font-weight:600">${escHtml(ce.severity)}</span>
          <span style="color:var(--muted);margin:0 6px">·</span>${escHtml(ce.event_type)}
          <span style="color:var(--muted);margin-left:8px;font-size:9px">${escHtml(ce.timestamp_human||'')}</span>
        </div>`;
      }).join('');
    } else {
      corrDiv.style.display = 'none';
    }
  }

  document.getElementById('detailPanel')?.classList.add('open');
  const bg = document.getElementById('detailBg');
  if (bg) bg.style.display = 'block';
}

function closeDetail() {
  document.getElementById('detailPanel')?.classList.remove('open');
  const bg = document.getElementById('detailBg');
  if (bg) bg.style.display = 'none';
  currentEventId = null;
}

async function saveNote() {
  if (!currentEventId) return;
  const note = document.getElementById('noteInput')?.value || '';
  try {
    const resp = await fetch(`/api/note/${currentEventId}`, {
      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({note}),
    });
    if (resp.ok) {
      const evt = EVENTS.find(e => e.event_id === currentEventId);
      if (evt) evt.note = note;
      showToast('✓ Note saved');
    } else {
      showToast('Failed to save note');
    }
  } catch(e) { showToast('Failed to save note'); }
}

async function addTag() {
  if (!currentEventId) return;
  const input = document.getElementById('tagInput');
  const tag = input?.value.trim();
  if (!tag) return;
  try {
    const resp = await fetch(`/api/tag/${currentEventId}`, {
      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({tag}),
    });
    if (resp.ok) {
      const data = await resp.json();
      const evt = EVENTS.find(e => e.event_id === currentEventId);
      if (evt) evt.tags = data.tags;
      const tagList = document.getElementById('tagList');
      if (tagList) {
        tagList.innerHTML = (data.tags||[]).map(t =>
          `<span class="tag-chip">${escHtml(t)}</span>`
        ).join('');
      }
      if (input) input.value = '';
      showToast('✓ Tag added');
    } else {
      showToast('Failed to add tag');
    }
  } catch(e) { showToast('Failed to add tag'); }
}

// ── Filters ──────────────────────────────────────────────────────────────────

function filterBySeverity(sev) {
  activeSev = (sev === 'ALL') ? null : (activeSev === sev ? null : sev);
  const sevSelect = document.getElementById('sevFilter');
  if (sevSelect) sevSelect.value = activeSev || '';
  currentPage = 1;
  refreshDashboard();
}

function filterBySource(src, el) {
  activeSource = (activeSource === src) ? null : src;
  const srcSelect = document.getElementById('sourceFilter');
  if (srcSelect) srcSelect.value = activeSource || '';
  currentPage = 1;
  refreshDashboard();
}

function filterByPhase(phase) {
  activePhase = (activePhase === phase) ? null : phase;
  showPanel('timeline', document.querySelectorAll('.tab')[0]);
  currentPage = 1;
  refreshDashboard();
}

function updateSelectFilters() {
  activeSev = null;
  activeSource = null;
  activeEntity = null;
  activeChainId = null;
  currentPage = 1;
  refreshDashboard();
}

function highlightChain(chainId) {
  activeChainId = (activeChainId === chainId) ? null : chainId;
  activeEntity = null;
  currentPage = 1;
  refreshDashboard();
}

function filterByChainCard(chainId) {
  activeChainId = chainId;
  activeEntity = null;
  currentPage = 1;
  showPanel('evidence', document.querySelectorAll('.tab')[3]);
  refreshDashboard();
}

function filterByEntity(val) {
  activeEntity = val;
  activeChainId = null;
  const tableSearch = document.getElementById('tableSearch');
  if (tableSearch) tableSearch.value = '';
  currentPage = 1;
  showPanel('evidence', document.querySelectorAll('.tab')[3]);
  refreshDashboard();
}

function resetFilters() {
  activeSev = null;
  activeSource = null;
  activePhase = null;
  activeChainId = null;
  activeEntity = null;
  const sevF = document.getElementById('sevFilter');
  const srcF = document.getElementById('sourceFilter');
  const searchBox = document.getElementById('searchBox');
  const tableSearch = document.getElementById('tableSearch');
  if (sevF) sevF.value = '';
  if (srcF) srcF.value = '';
  if (searchBox) searchBox.value = '';
  if (tableSearch) tableSearch.value = '';
  currentPage = 1;
  refreshDashboard();
}

// ── Tab navigation ────────────────────────────────────────────────────────────

function showPanel(name, tabEl) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  const panel = document.getElementById(`panel-${name}`);
  if (panel) panel.classList.add('active');
  if (tabEl) tabEl.classList.add('active');
  if (name === 'timeline') { setTimeout(buildTimeline, 30); }
  if (name === 'evidence') renderTable();
}

// ── Utility ───────────────────────────────────────────────────────────────────

function escHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}

function escAttr(s) {
  return escHtml(s).replace(/`/g,'&#96;');
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
function setHTML(id, val) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = val;
}

function showToast(msg) {
  const t = document.createElement('div');
  t.textContent = msg;
  Object.assign(t.style, {
    position:'fixed', bottom:'24px', right:'24px', zIndex:'9999',
    background:'rgba(0,212,255,.12)', border:'1px solid rgba(0,212,255,.4)',
    color:'#00d4ff', padding:'10px 18px', borderRadius:'8px',
    fontFamily:"'IBM Plex Mono',monospace", fontSize:'12px',
  });
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2500);
}

// ── Init ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function() {
  updateSidebarState();
  setTimeout(function() {
    buildTimeline();
    renderTable();
  }, 100);

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeDetail();
  });
});
