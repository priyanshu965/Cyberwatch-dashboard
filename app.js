/**
 * CYBERWATCH DASHBOARD — app.js
 * Loads data/intel.json and renders the threat intelligence feed.
 * No external dependencies — pure vanilla JavaScript.
 *
 * Loading strategy (in order):
 *  1. Try fetch('data/intel.json')  — works on GitHub Pages & local server
 *  2. Fall back to window.INTEL_DATA — embedded in index.html, works when
 *     opening the file directly (file:// protocol, no server needed)
 *
 * AI Features:
 *  - Cards are expandable — click to reveal the AI analysis panel
 *  - AI panel contains: ai_summary, severity_score, workflow_graph (Mermaid)
 *  - Mermaid diagrams are lazily initialised only when a card expands
 */

// ─── State ───────────────────────────────────────────────────────────────────
let allItems = [];
let filteredItems = [];
let activeFilter = 'all';
let searchQuery = '';

// ─── Mermaid Init ─────────────────────────────────────────────────────────────
// Configure Mermaid once at startup (dark theme to match the dashboard)
if (typeof mermaid !== 'undefined') {
  mermaid.initialize({
    startOnLoad: false,
    theme: 'dark',
    themeVariables: {
      background:       '#111820',
      primaryColor:     '#16202e',
      primaryTextColor: '#c9d8e8',
      primaryBorderColor: '#1e2d3d',
      lineColor:        '#00ffe1',
      secondaryColor:   '#0d1117',
      tertiaryColor:    '#080b0f',
      edgeLabelBackground: '#111820',
      fontFamily:       "'JetBrains Mono', monospace",
      fontSize:         '12px',
    }
  });
}

// ─── Entry Point ─────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initFilters();
  initSearch();
  loadIntelData();
});

// ─── Load Data ────────────────────────────────────────────────────────────────
async function loadIntelData() {
  try {
    let data;

    if (window.location.protocol !== 'file:') {
      const response = await fetch(`data/intel.json?v=${Date.now()}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      data = await response.json();
    } else {
      if (window.INTEL_DATA) {
        data = window.INTEL_DATA;
        const meta = document.getElementById('last-updated');
        if (meta) {
          meta.textContent = '⚠ Preview mode (open via server or GitHub Pages for live data)';
          meta.style.color = '#f5c518';
        }
      } else {
        throw new Error('No data available — place intel.json in the data/ folder and open via a server');
      }
    }

    allItems = data.items || [];

    if (data.last_updated) {
      const date = new Date(data.last_updated);
      const utc  = date.toUTCString();
      const ist  = date.toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata',
        dateStyle: 'medium',
        timeStyle: 'medium'
      });
      document.getElementById('last-updated').textContent =
        `Last updated: ${utc} | IST: ${ist}`;
    }

    renderSidebar();
    renderDailySummary();
    applyFilters();
    showContent();

  } catch (err) {
    console.error('Failed to load intel.json:', err);
    showError();
  }
}

// ─── Filter & Search Logic ────────────────────────────────────────────────────

function applyFilters() {
  if (activeFilter === 'matrix') {
    showMatrixView();
    return;
  }

  filteredItems = allItems.filter(item => {
    const categoryMatch =
      activeFilter === 'all' || item.category === activeFilter;

    const q = searchQuery.toLowerCase();
    const searchMatch =
      !q ||
      (item.title       && item.title.toLowerCase().includes(q))       ||
      (item.description && item.description.toLowerCase().includes(q)) ||
      (item.cve_id      && item.cve_id.toLowerCase().includes(q))      ||
      (item.source      && item.source.toLowerCase().includes(q))      ||
      (item.ai_summary  && item.ai_summary.toLowerCase().includes(q))  ||
      (item.ttps        && item.ttps.some(t =>
        t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)
      ));

    return categoryMatch && searchMatch;
  });

  renderCards();
  updateHeaderStats();
}

// ─── Event Listeners ──────────────────────────────────────────────────────────

function initFilters() {
  document.getElementById('filter-tabs').addEventListener('click', e => {
    const btn = e.target.closest('.filter-btn');
    if (!btn) return;

    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    activeFilter = btn.dataset.filter;
    applyFilters();
  });
}

function initSearch() {
  const input = document.getElementById('search-input');
  let debounceTimer;

  input.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      searchQuery = input.value.trim();
      applyFilters();
    }, 250);
  });
}

// ─── Render Cards ─────────────────────────────────────────────────────────────

function renderCards() {
  const container = document.getElementById('cards-container');
  const noResults = document.getElementById('no-results');
  const feedCount = document.getElementById('feed-count');

  container.innerHTML = '';

  if (filteredItems.length === 0) {
    noResults.style.display = 'block';
    feedCount.textContent   = 'No items found';
    return;
  }

  noResults.style.display = 'none';
  feedCount.textContent = `${filteredItems.length} item${filteredItems.length !== 1 ? 's' : ''} in feed`;

  const sorted = [...filteredItems].sort((a, b) => {
    return new Date(b.published || 0) - new Date(a.published || 0);
  });

  sorted.forEach((item, index) => {
    const card = buildCard(item, index);
    container.appendChild(card);
  });
}

// ─── Build Card ───────────────────────────────────────────────────────────────

function buildCard(item, index) {
  const card = document.createElement('div');

  const isNew =
    item.published &&
    (Date.now() - new Date(item.published)) < (24 * 60 * 60 * 1000);

  card.className = 'intel-card';
  if (isNew) card.classList.add('new-item');

  // Mark AI-enriched cards (have a real ai_summary, not the pending placeholder)
  const hasAI = item.aisummary && item.aisummary !== 'AI analysis pending';
  const providerLabel = (item.ai_provider || 'AI').toUpperCase();
  const modelLabel = item.ai_model || item.ai_provider || 'AI';
  if (hasAI) card.classList.add('ai-enriched');

  card.dataset.category = item.category || 'news';
  card.style.animationDelay = `${index * 0.04}s`;

  const severity = (item.severity || 'medium').toLowerCase();

  const badgeHTML = `<span class="badge ${severity}">${severity.toUpperCase()}</span>`;

  const newBadgeHTML = isNew ? `<span class="new-item-badge">NEW</span>` : '';

  const aiBadgeHTML = hasAI
    ? `<span class="ai-badge" title="AI enriched by ${escapeHTML(providerLabel)}">${escapeHTML(providerLabel)}</span>`
    : '';

  const cveIdHTML = item.cve_id
    ? `<span class="cve-id">${item.cve_id}</span> · `
    : '';

  const descriptionHTML = item.description
    ? `<p class="card-description">${escapeHTML(item.description)}</p>`
    : '';

  const dateStr = item.published ? timeAgo(new Date(item.published)) : '';

  // CVSS score
  const cvssHTML = item.cvss_score
    ? `<span class="meta-tag meta-cvss">CVSS ${item.cvss_score.toFixed(1)}</span>`
    : '';

  // AI severity score tag (shown alongside CVSS)
  const aiScoreHTML = (item.severity_score !== undefined && item.severity_score !== null)
    ? `<span class="meta-tag meta-ai-score" title="AI-assessed severity score">
         ✦ AI&nbsp;${item.severity_score.toFixed(1)}
       </span>`
    : '';

  // TTP pills
  const ttps = item.ttps || [];
  let ttpHTML = '';
  if (ttps.length > 0) {
    const shown  = ttps.slice(0, 4);
    const hidden = ttps.length - shown.length;
    const pills  = shown.map(t =>
      `<span class="ttp-pill" title="${escapeHTML(t.tactic)}: ${escapeHTML(t.name)}"
             onclick="event.stopPropagation();filterByTechnique('${t.id}')"
       >${escapeHTML(t.id)}</span>`
    ).join('');
    const more = hidden > 0
      ? `<span class="ttp-more" title="${ttps.slice(4).map(t => t.id).join(', ')}">+${hidden}</span>`
      : '';
    ttpHTML = `<div class="card-ttps">${pills}${more}</div>`;
  }

  // ── AI Analysis Section (hidden by default, revealed on .expanded) ─────────
  // The Mermaid graph is stored as raw text in a <pre class="mermaid"> block.
  // mermaid.init() is called manually when the card expands to avoid rendering
  // hundreds of invisible diagrams on page load (perf optimisation).
  const graphSource = (item.workflow_graph || '').replace(/\\n/g, '\n');
  const aiSummaryText = item.ai_summary || '';

  const analysisHTML = `
    <div class="analysis-section" id="analysis-${index}">
      <div class="analysis-header">
        <span class="analysis-label">AI THREAT ANALYSIS</span>
        <span class="analysis-model">${escapeHTML(modelLabel)}</span>
      </div>
      <p class="analysis-summary">${escapeHTML(aiSummaryText)}</p>
      <div class="analysis-graph-wrap">
        <div class="analysis-graph-label">ATTACK FLOW</div>
        <div class="mermaid-container" id="mermaid-${index}">
          <pre class="mermaid">${escapeHTML(graphSource)}</pre>
        </div>
      </div>
    </div>
  `;

  // ── Expand hint (only shown if AI data exists) ─────────────────────────────
  const expandHintHTML = `
    <div class="card-expand-hint">
      ${hasAI ? '▼ EXPAND FOR AI ANALYSIS' : '▼ EXPAND'}
    </div>`;

  card.innerHTML = `
    <div class="card-top">
      <p class="card-title">
        ${item.url
          ? `<a href="${escapeHTML(item.url)}" target="_blank" rel="noopener">${escapeHTML(item.title)}</a>`
          : escapeHTML(item.title)
        }
        ${newBadgeHTML}
        ${aiBadgeHTML}
      </p>
      ${badgeHTML}
    </div>
    ${descriptionHTML}
    <div class="card-meta">
      ${cveIdHTML}
      <span class="meta-tag meta-source">${escapeHTML(item.source || 'unknown')}</span>
      <span class="meta-tag meta-cat">${escapeHTML(item.category || 'general')}</span>
      ${cvssHTML}
      ${aiScoreHTML}
      <span class="meta-date">${dateStr}</span>
    </div>
    ${ttpHTML}
    ${analysisHTML}
    ${expandHintHTML}
  `;

  // ── Card click → toggle expanded state & lazy-init Mermaid ────────────────
  card.addEventListener('click', e => {
    // Don't expand/collapse when clicking links, TTP pills, or the analysis text itself
    if (e.target.closest('a') || e.target.closest('.ttp-pill') || e.target.closest('.ttp-more')) {
      return;
    }

    const wasExpanded = card.classList.contains('expanded');
    card.classList.toggle('expanded');

    // Lazy-render the Mermaid diagram the first time this card is expanded
    if (!wasExpanded && typeof mermaid !== 'undefined') {
      const container = card.querySelector(`#mermaid-${index}`);
      if (container && !container.dataset.rendered) {
        container.dataset.rendered = 'true';
        // Un-escape the graph source for Mermaid rendering
        const pre = container.querySelector('pre.mermaid');
        if (pre) {
          pre.textContent = graphSource;  // raw text, Mermaid needs unescaped content
          try {
            mermaid.init(undefined, pre);
          } catch (err) {
            console.warn('Mermaid render failed:', err);
            container.innerHTML = `<p class="mermaid-error">Graph unavailable</p>`;
          }
        }
      }
    }
  });

  return card;
}

// ─── Render Sidebar ───────────────────────────────────────────────────────────

function renderSidebar() {
  renderSeverityBars();
  renderSourceList();
  renderCategoryList();
}

function renderSeverityBars() {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };

  allItems.forEach(item => {
    const s = (item.severity || '').toLowerCase();
    if (counts.hasOwnProperty(s)) counts[s]++;
  });

  const max = Math.max(...Object.values(counts), 1);

  Object.entries(counts).forEach(([sev, count]) => {
    document.getElementById(`bar-${sev}`).style.width = `${(count / max) * 100}%`;
    document.getElementById(`sev-count-${sev}`).textContent = count;
  });
}

function renderSourceList() {
  const sourceCounts = {};

  allItems.forEach(item => {
    const src = item.source || 'unknown';
    sourceCounts[src] = (sourceCounts[src] || 0) + 1;
  });

  const sorted = Object.entries(sourceCounts).sort((a, b) => b[1] - a[1]);

  document.getElementById('source-list').innerHTML = sorted.map(([name, count]) => `
    <div class="source-item">
      <span class="source-name">${escapeHTML(name)}</span>
      <span class="source-badge">${count}</span>
    </div>
  `).join('');
}

function renderCategoryList() {
  const catCounts = {};

  allItems.forEach(item => {
    const cat = item.category || 'general';
    catCounts[cat] = (catCounts[cat] || 0) + 1;
  });

  document.getElementById('cat-list').innerHTML = Object.entries(catCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([cat, count]) => `
      <div class="cat-item" onclick="filterByCategory('${cat}')">
        <span class="cat-name">${escapeHTML(cat)}</span>
        <span class="cat-count">${count}</span>
      </div>
    `).join('');
}

window.filterByCategory = function(cat) {
  activeFilter = cat;
  document.querySelectorAll('.filter-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.filter === cat);
  });
  applyFilters();
};

// ─── Header Stats ─────────────────────────────────────────────────────────────

function updateHeaderStats() {
  const critical = filteredItems.filter(
    i => (i.severity || '').toLowerCase() === 'critical'
  ).length;
  const high = filteredItems.filter(
    i => (i.severity || '').toLowerCase() === 'high'
  ).length;

  document.getElementById('count-critical').textContent = critical;
  document.getElementById('count-high').textContent     = high;
  document.getElementById('count-total').textContent    = filteredItems.length;
}

// ─── UI State Transitions ─────────────────────────────────────────────────────

function showContent() {
  document.getElementById('loading-state').style.display   = 'none';
  document.getElementById('error-state').style.display     = 'none';
  document.getElementById('matrix-view').style.display     = 'none';
  document.getElementById('cards-container').style.display = 'flex';
}

function showError() {
  document.getElementById('loading-state').style.display = 'none';
  document.getElementById('error-state').style.display   = 'block';
}

function showMatrixView() {
  document.getElementById('loading-state').style.display   = 'none';
  document.getElementById('error-state').style.display     = 'none';
  document.getElementById('cards-container').style.display = 'none';
  document.getElementById('no-results').style.display      = 'none';
  document.getElementById('matrix-view').style.display     = 'block';
  renderMatrixGrid();

  document.getElementById('feed-count').textContent =
    'MITRE ATT&CK Coverage Map — click any technique to filter feed';
}

// ─── Utility: Time Ago ────────────────────────────────────────────────────────

function timeAgo(date) {
  const now  = new Date();
  const diff = now - date;
  const mins  = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days  = Math.floor(diff / 86400000);

  if (isNaN(diff)) return '';
  if (mins  <  1)  return 'just now';
  if (mins  < 60)  return `${mins}m ago`;
  if (hours < 24)  return `${hours}h ago`;
  if (days  <  7)  return `${days}d ago`;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

// ─── Utility: Escape HTML ─────────────────────────────────────────────────────

function escapeHTML(str) {
  if (!str) return '';
  return str
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#039;');
}

// ─── Daily Summary Bar ────────────────────────────────────────────────────────

function renderDailySummary() {
  const bar   = document.getElementById('daily-summary');
  const stats = document.getElementById('summary-stats');
  const top   = document.getElementById('summary-top-threat');

  if (!bar || !stats) return;

  const critical   = allItems.filter(i => i.severity === 'critical').length;
  const high       = allItems.filter(i => i.severity === 'high').length;
  const medium     = allItems.filter(i => i.severity === 'medium').length;
  const newItems   = allItems.filter(i =>
    i.published && (Date.now() - new Date(i.published)) < 86400000
  ).length;
  const incidents  = allItems.filter(i => i.category === 'incident').length;
  const cves       = allItems.filter(i => i.category === 'cve').length;
  const advisories = allItems.filter(i => i.category === 'advisory').length;
  const aiEnriched = allItems.filter(i =>
    i.ai_summary && i.ai_summary !== 'AI analysis pending'
  ).length;

  stats.innerHTML = `
    <span class="summary-stat">
      <span class="summary-stat-val c">${critical}</span>
      <span class="summary-stat-lbl">CRITICAL</span>
    </span>
    <span class="summary-stat">
      <span class="summary-stat-val h">${high}</span>
      <span class="summary-stat-lbl">HIGH</span>
    </span>
    <span class="summary-stat">
      <span class="summary-stat-val m">${medium}</span>
      <span class="summary-stat-lbl">MEDIUM</span>
    </span>
    <span class="summary-divider">·</span>
    <span class="summary-stat">
      <span class="summary-stat-val n">${cves}</span>
      <span class="summary-stat-lbl">CVEs</span>
    </span>
    <span class="summary-stat">
      <span class="summary-stat-val n">${incidents}</span>
      <span class="summary-stat-lbl">INCIDENTS</span>
    </span>
    <span class="summary-stat">
      <span class="summary-stat-val n">${advisories}</span>
      <span class="summary-stat-lbl">ADVISORIES</span>
    </span>
    <span class="summary-divider">·</span>
    <span class="summary-stat">
      <span class="summary-stat-val" style="color:var(--accent-cyan)">${newItems}</span>
      <span class="summary-stat-lbl">NEW TODAY</span>
    </span>
    <span class="summary-stat">
      <span class="summary-stat-val" style="color:#a78bfa">${aiEnriched}</span>
      <span class="summary-stat-lbl">AI ENRICHED</span>
    </span>
  `;

  const topThreat = allItems.find(i => i.severity === 'critical') ||
                    allItems.find(i => i.severity === 'high');
  if (top && topThreat) {
    top.innerHTML = `🔴 Top threat: <strong>${escapeHTML(topThreat.title.substring(0, 80))}${topThreat.title.length > 80 ? '…' : ''}</strong>`;
  }

  bar.style.display = 'block';
}

// ─── Mobile Sidebar Toggle ────────────────────────────────────────────────────

window.toggleMobileSidebar = function() {
  const sidebar = document.querySelector('.sidebar');
  const label   = document.getElementById('toggle-label');
  if (!sidebar) return;

  const isOpen = sidebar.classList.toggle('mobile-open');
  label.textContent = isOpen ? '▲ HIDE STATS' : '▼ SHOW STATS';
};

// ─── MITRE ATT&CK Matrix ─────────────────────────────────────────────────────

const TACTIC_ORDER = [
  { id: "TA0043", name: "Reconnaissance" },
  { id: "TA0042", name: "Resource Dev" },
  { id: "TA0001", name: "Initial Access" },
  { id: "TA0002", name: "Execution" },
  { id: "TA0003", name: "Persistence" },
  { id: "TA0004", name: "Privilege Esc" },
  { id: "TA0005", name: "Defense Evasion" },
  { id: "TA0006", name: "Credential Access" },
  { id: "TA0007", name: "Discovery" },
  { id: "TA0008", name: "Lateral Movement" },
  { id: "TA0009", name: "Collection" },
  { id: "TA0011", name: "Command & Control" },
  { id: "TA0010", name: "Exfiltration" },
  { id: "TA0040", name: "Impact" },
];

function renderMatrixGrid() {
  const grid = document.getElementById('matrix-grid');
  if (!grid) return;

  const tacticMap = {};
  TACTIC_ORDER.forEach(t => { tacticMap[t.id] = {}; });

  allItems.forEach(item => {
    (item.ttps || []).forEach(ttp => {
      if (!tacticMap[ttp.tactic_id]) tacticMap[ttp.tactic_id] = {};
      if (!tacticMap[ttp.tactic_id][ttp.id]) {
        tacticMap[ttp.tactic_id][ttp.id] = { name: ttp.name, count: 0, items: [] };
      }
      tacticMap[ttp.tactic_id][ttp.id].count++;
      tacticMap[ttp.tactic_id][ttp.id].items.push(item.title);
    });
  });

  grid.innerHTML = TACTIC_ORDER.map(tactic => {
    const techniques  = tacticMap[tactic.id] || {};
    const techEntries = Object.entries(techniques).sort((a, b) => b[1].count - a[1].count);

    const cells = techEntries.map(([techId, data]) => {
      const intensity = data.count >= 3 ? 'high' : data.count >= 1 ? 'med' : '';
      const tooltip   = `${data.count} item${data.count !== 1 ? 's' : ''}: ${data.items.slice(0, 2).join(' | ')}${data.items.length > 2 ? '...' : ''}`;
      return `
        <div class="tech-cell active-${intensity}"
             title="${escapeHTML(tooltip)}"
             onclick="filterByTechnique('${techId}')">
          <span class="tech-id">${escapeHTML(techId)}</span>
          <span class="tech-name">${escapeHTML(data.name)}</span>
          <span class="tech-count">${data.count}</span>
        </div>`;
    }).join('');

    const totalCount = techEntries.reduce((s, [, d]) => s + d.count, 0);

    return `
      <div class="tactic-col">
        <div class="tactic-header">
          <span class="tactic-name">${escapeHTML(tactic.name)}</span>
          <span class="tactic-count">${techEntries.length > 0 ? totalCount : '—'}</span>
        </div>
        <div class="tactic-cells">
          ${cells || `<div class="tech-cell inactive"><span class="tech-name">No hits</span></div>`}
        </div>
      </div>`;
  }).join('');
}

window.filterByTechnique = function(techId) {
  activeFilter = 'all';
  document.querySelectorAll('.filter-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.filter === 'all');
  });

  searchQuery = techId;
  const searchInput = document.getElementById('search-input');
  if (searchInput) searchInput.value = techId;

  showContent();
  applyFilters();
};
