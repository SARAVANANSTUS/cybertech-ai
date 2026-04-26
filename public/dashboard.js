console.log("Dashboard JS loaded");

const isLoggedIn = localStorage.getItem("isLoggedIn");

if (!isLoggedIn) {
  alert("Please login first");
  window.location.href = "main.html";
}

const navHome = document.getElementById("navHome");
const navScan = document.getElementById("navScan");
const navHistory = document.getElementById("navHistory");
const navReports = document.getElementById("navReports");

const homeDisplay = document.getElementById("homeDisplay");
const scanDisplay = document.getElementById("scanDisplay");
const scanHistory = document.getElementById("scanHistory");
const scanReports = document.getElementById("scanReports");

const logoutBtn = document.getElementById("logOutBtn");
const scanForm = document.getElementById("scanForm");
const startScanBtn = document.getElementById("startScanBtn");
const activeScansContainer = document.getElementById("activeScans");

function hideAllSections() {
  homeDisplay.classList.add("display-container");
  scanDisplay.classList.add("display-container");
  scanHistory.classList.add("display-container");
  scanReports.classList.add("display-container");
}

function removeActiveClasses() {
  navHome.classList.remove("active");
  navScan.classList.remove("active");
  navHistory.classList.remove("active");
  navReports.classList.remove("active");
}


hideAllSections();
removeActiveClasses();

homeDisplay.classList.remove("display-container");
navHome.classList.add("active");

navHome.addEventListener("click", () => {
  hideAllSections();
  removeActiveClasses();

  homeDisplay.classList.remove("display-container");
  navHome.classList.add("active");
});

navScan.addEventListener("click", () => {
  hideAllSections();
  removeActiveClasses();

  scanDisplay.classList.remove("display-container");
  navScan.classList.add("active");
});

navHistory.addEventListener("click", () => {
  hideAllSections();
  removeActiveClasses();

  scanHistory.classList.remove("display-container");
  navHistory.classList.add("active");

  loadScanHistory();
});

navReports.addEventListener("click", () => {
  hideAllSections();
  removeActiveClasses();

  scanReports.classList.remove("display-container");
  navReports.classList.add("active");

  loadReports(); // IMPORTANT
});


function toggleSidebar() {
  document.getElementById("sidebar").classList.toggle("collapsed");
}

logoutBtn.addEventListener("click", () => {
  localStorage.removeItem("isLoggedIn");
  window.location.href = "main.html";
});

async function loadActiveScans() {
  try {
    const response = await fetch("/active-scans");
    const scans = await response.json();

    activeScansContainer.innerHTML = "";

    if (scans.length === 0) {
      activeScansContainer.innerHTML =
        "<p class='empty-text'>No active scans</p>";
      return;
    }

    scans.forEach(scan => {
      const scanCard = document.createElement("div");
      scanCard.className = "scan-card";

      scanCard.innerHTML = `
        <div class="scan-header">
          <strong>${scan.scan_name}</strong>
          <span>${scan.progress}%</span>
        </div>
        <div class="progress-bar">
          <div class="progress-fill" style="width: ${scan.progress}%"></div>
        </div>
      `;

      activeScansContainer.appendChild(scanCard);
    });
  } catch (err) {
    console.error("Failed to load active scans", err);
  }
}

loadActiveScans();
setInterval(loadActiveScans, 3000);

async function loadScanHistory() {
  try {
    const response = await fetch("/scan-history");
    const scans = await response.json();

    const historyRows = document.getElementById("historyRows");
    historyRows.innerHTML = "";

    scans.forEach(scan => {
      const row = document.createElement("div");
      row.className = "history-row";

      const date = new Date(scan.created_at);
      const dateStr = date.toISOString().split("T")[0];
      const timeStr = date.toTimeString().slice(0, 5);

      row.innerHTML = `
        <strong>${scan.scan_name}</strong>
        <span>${dateStr}</span>
        <span>${timeStr}</span>
        <span class="status">${scan.status}</span>
        <span class="delete-btn" data-id="${scan.id}"><i class="fas fa-trash"></i> Delete</span>
      `;

      historyRows.appendChild(row);
    });
    document.querySelectorAll(".delete-btn").forEach(btn => {
      btn.addEventListener("click", async () => {
        const scanId = btn.getAttribute("data-id");

        if (!confirm("Delete this scan history?")) return;

        await deleteScan(scanId);
        loadScanHistory();
      });
    });

  } catch (err) {
    console.error("Failed to load scan history", err);
  }
}

async function deleteScan(scanId) {
  try {
    const response = await fetch(`/scan-history/${scanId}`, {
      method: "DELETE"
    });

    if (!response.ok) {
      alert("Failed to delete scan");
    }
  } catch (err) {
    console.error("Delete error", err);
  }
}


scanForm.addEventListener("submit", async event => {
  event.preventDefault();

  const reportName = document.getElementById("reportName").value;
  const url = document.getElementById("url").value;

  const tools = Array.from(
    document.querySelectorAll('input[name="tools"]:checked')
  ).map(cb => cb.value);

  if (!reportName || !url || tools.length === 0) {
    alert("Please fill all fields and select at least one tool");
    return;
  }

  try {
    const response = await fetch("/start-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        reportName,
        url,
        tools
      })
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.message);

    alert("Scan started successfully");
    scanForm.reset();

  } catch (err) {
    console.error(err);
    alert("Failed to start scan");
  }
});

async function loadTotalScans() {
  const res = await fetch("/scan-count");
  const data = await res.json();

  document.querySelector(".single-scan-container .heading").textContent =
    data.total;
}

async function loadReports() {

  try {

    const response = await fetch("/report-history");
    const reports = await response.json();

    const container = document.getElementById("reportRows");
    container.innerHTML = "";

    reports.forEach(r => {

      const row = document.createElement("div");
      row.className = "history-row";

      const date = new Date(r.created_at);
      const dateStr = date.toISOString().split("T")[0];
      const timeStr = date.toTimeString().slice(0, 5);

      row.innerHTML = `
        <strong>${r.scan_name}</strong>
        <span>${dateStr}</span>
        <span>${timeStr}</span>
        <span>
          <a href="/download-report/${r.id}" class="download-btn">
            <i class="fas fa-download"></i> Download
          </a>
        </span>
      `;

      container.appendChild(row);

    });

  } catch (err) {

    console.error("Failed to load reports", err);

  }
}

loadTotalScans();
setInterval(loadTotalScans, 5000);

async function loadTotalReports() {

  const res = await fetch("/report-history");

  const data = await res.json();

  document.querySelector(".report-container .heading")
    .textContent = data.length;
}

loadTotalReports();
setInterval(loadTotalReports, 5000);