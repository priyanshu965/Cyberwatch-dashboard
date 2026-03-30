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

    const url = force
      ? `data/intel.json?v=${Date.now()}`
      : 'data/intel.json';

    const response = await fetch(url);

    if (!response.ok) {
      throw new Error("Failed to fetch JSON");
    }

    data = await response.json();

    allItems = data.items || [];

    // ✅ FIX: stop infinite loading
    document.getElementById("loading-state").style.display = "none";
    document.getElementById("cards-container").style.display = "block";

    // ✅ TIME (UTC + IST)
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

    renderCards();
  } catch (err) {
    console.error(err);

    document.getElementById("loading-state").style.display = "none";
    document.getElementById("error-state").style.display = "block";
  }
}

// 🔄 Refresh button
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

// 🔍 Search
function initSearch() {
  const input = document.getElementById('search-input');

  input.addEventListener('input', () => {
    searchQuery = input.value.toLowerCase();
    applyFilters();
  });
}

// 🔘 Filters
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

// 🧠 Filter logic
function applyFilters() {
  filteredItems = allItems.filter(item => {
    const matchCategory =
      activeFilter === 'all' || item.category === activeFilter;

    const matchSearch =
      !searchQuery ||
      item.title.toLowerCase().includes(searchQuery) ||
      (item.description && item.description.toLowerCase().includes(searchQuery));

    return matchCategory && matchSearch;
  });

  renderCards();
}

// 🧱 Render cards
function renderCards() {
  const container = document.getElementById('cards-container');
  container.innerHTML = "";

  const list = filteredItems.length ? filteredItems : allItems;

  list.forEach(item => {
    container.innerHTML += `
      <div class="intel-card">
        <p><a href="${item.url}" target="_blank">${item.title}</a></p>
        <p>${item.description || ""}</p>
        <small>${item.source} | ${item.category}</small>
      </div>
    `;
  });
}