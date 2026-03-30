let allItems = [];
let filteredItems = [];
let activeFilter = 'all';
let searchQuery = '';

document.addEventListener('DOMContentLoaded', () => {
  initFilters();
  initSearch();
  initRefresh();
  loadIntelData();
});

async function loadIntelData(force = false) {
  try {
    let data;

    if (window.location.protocol !== 'file:') {
      const url = force
        ? `data/intel.json?v=${Date.now()}`
        : 'data/intel.json';

      const response = await fetch(url);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      data = await response.json();
    } else {
      if (window.INTEL_DATA) {
        data = window.INTEL_DATA;
      } else {
        throw new Error("No local data");
      }
    }

    allItems = data.items || [];

    if (data.last_updated) {
      const date = new Date(data.last_updated);

      const utc = date.toUTCString();

      const ist = date.toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata',
        dateStyle: 'medium',
        timeStyle: 'medium'
      });

      document.getElementById('last-updated').textContent =
        `Last updated: ${utc} | IST: ${ist}`;
    }

    renderSidebar();
    applyFilters();
    showContent();

  } catch (err) {
    console.error(err);
    showError();
  }
}

function initRefresh() {
  const btn = document.getElementById('refresh-btn');
  if (!btn) return;

  btn.addEventListener('click', () => {
    btn.textContent = "Loading...";
    loadIntelData(true).finally(() => {
      btn.textContent = "⟳ Refresh";
    });
  });
}

function applyFilters() {
  filteredItems = allItems.filter(item => {
    const categoryMatch =
      activeFilter === 'all' || item.category === activeFilter;

    const q = searchQuery.toLowerCase();

    const searchMatch =
      !q ||
      (item.title && item.title.toLowerCase().includes(q)) ||
      (item.description && item.description.toLowerCase().includes(q)) ||
      (item.cve_id && item.cve_id.toLowerCase().includes(q)) ||
      (item.source && item.source.toLowerCase().includes(q));

    return categoryMatch && searchMatch;
  });

  renderCards();
  updateHeaderStats();
}

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