async function loadData(force = false) {
  const url = force
    ? `data/intel.json?v=${Date.now()}`
    : 'data/intel.json';

  const res = await fetch(url);
  const data = await res.json();

  const date = new Date(data.last_updated);

  const utc = date.toUTCString();
  const ist = date.toLocaleString('en-IN', {
    timeZone: 'Asia/Kolkata',
    dateStyle: 'medium',
    timeStyle: 'medium'
  });

  document.getElementById("lastUpdated").innerText =
    `Last Updated: ${utc} | IST: ${ist}`;

  render("news", data.items.filter(i => i.category !== "cve"));
  render("cves", data.items.filter(i => i.category === "cve"));
}

function render(id, items) {
  const container = document.getElementById(id);
  container.innerHTML = `<h2>${id.toUpperCase()}</h2>`;

  items.slice(0, 20).forEach(item => {
    container.innerHTML += `
      <div class="card">
        <a href="${item.url}" target="_blank">${item.title}</a>
        <p>${item.description || ""}</p>
        <small>${item.source} | ${item.category}</small>
      </div>
    `;
  });
}

document.getElementById("refresh-btn").onclick = () => loadData(true);

loadData();
