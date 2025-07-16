const apiBase = "http://localhost:5000";
let moduleList = [];
let agentList = [];
let executionChain = [];

// === INIT ===
document.addEventListener("DOMContentLoaded", () => {
  fetchModules();
  fetchAgents();
  setupWebSocket();
  setupSearchFilter();
});

// === FETCH MODULES ===
async function fetchModules() {
  const res = await fetch(`${apiBase}/api/modules`);
  const data = await res.json();
  moduleList = data;
  populateModules(data);
  populateCategories(data);
}

// === FETCH AGENTS ===
async function fetchAgents() {
  const res = await fetch(`${apiBase}/api/agents`);
  const data = await res.json();
  agentList = data;
  const selector = document.getElementById("agentSelector");
  data.forEach(a => {
    const opt = document.createElement("option");
    opt.value = a.id;
    opt.textContent = a.id;
    selector.appendChild(opt);
  });
}

// === POPULATE MODULES ===
function populateModules(data) {
  const ul = document.getElementById("moduleList");
  ul.innerHTML = "";
  data.forEach(mod => {
    const li = document.createElement("li");
    li.textContent = mod.name;
    li.draggable = true;
    li.dataset.file = mod.file;
    li.dataset.category = mod.category;
    li.addEventListener("dragstart", e => {
      e.dataTransfer.setData("text/plain", JSON.stringify(mod));
    });
    ul.appendChild(li);
  });
}

// === POPULATE CATEGORIES ===
function populateCategories(data) {
  const unique = [...new Set(data.map(m => m.category))];
  const sel = document.getElementById("categoryFilter");
  unique.forEach(cat => {
    const opt = document.createElement("option");
    opt.value = cat;
    opt.textContent = cat;
    sel.appendChild(opt);
  });
  sel.addEventListener("change", () => {
    filterModules();
  });
}

// === FILTER MODULES ===
function setupSearchFilter() {
  document.getElementById("searchBox").addEventListener("input", filterModules);
}

function filterModules() {
  const q = document.getElementById("searchBox").value.toLowerCase();
  const c = document.getElementById("categoryFilter").value;
  const list = document.getElementById("moduleList").children;
  for (let item of list) {
    const match = item.textContent.toLowerCase().includes(q);
    const categoryMatch = c === "All" || item.dataset.category === c;
    item.style.display = match && categoryMatch ? "" : "none";
  }
}

// === DROP ZONE ===
document.getElementById("chainList").addEventListener("dragover", e => {
  e.preventDefault();
});
document.getElementById("chainList").addEventListener("drop", e => {
  e.preventDefault();
  const mod = JSON.parse(e.dataTransfer.getData("text/plain"));
  executionChain.push(mod);
  const li = document.createElement("li");
  li.textContent = mod.name;
  li.dataset.file = mod.file;
  document.getElementById("chainList").appendChild(li);
  updateCopilotSuggestions();
});

// === EXECUTION ===
async function runChain() {
  if (executionChain.length === 0) return;
  await fetch(`${apiBase}/api/chain`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chain: executionChain })
  });
}

async function exportChain() {
  const zip = new JSZip();
  const chainMeta = {
    exported: new Date().toISOString(),
    agent: document.getElementById("agentSelector").value,
    modules: executionChain
  };
  zip.file("chain_metadata.json", JSON.stringify(chainMeta, null, 2));
  const blob = await zip.generateAsync({ type: "blob" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "chain_export.zip";
  link.click();
}

function clearChain() {
  executionChain = [];
  document.getElementById("chainList").innerHTML = "";
  updateCopilotSuggestions();
}

// === WEBSOCKET ===
function setupWebSocket() {
  const socket = new WebSocket("ws://localhost:5000/socket.io/?EIO=4&transport=websocket");

  socket.onopen = () => logToConsole("[WebSocket] Connected.");
  socket.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data.split("42")[1]);
      if (data[0] === "console_output") {
        logToConsole(data[1].line);
        updateMetricsChart(data[1].line);
      }
    } catch {}
  };
}

// === CONSOLE ===
function logToConsole(msg) {
  const consoleEl = document.getElementById("consoleOutput");
  consoleEl.textContent += msg + "\n";
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

// === COPILOT ===
function updateCopilotSuggestions() {
  const copilot = document.getElementById("copilotList");
  copilot.innerHTML = "";
  const last = executionChain[executionChain.length - 1];
  if (!last) return;

  const keywords = {
    "firmware": ["Firmware Timeline Builder", "Firmware Persistent Implant"],
    "gnss": ["GNSS Spoofer", "GNSS Spoof Guard"],
    "ota": ["OTA Firmware Injector", "OTA Packet Analyzer"],
    "telemetry": ["Telemetry Guardian", "Threat Classifier"],
    "c2": ["SATCOM C2 Hijacker", "Payload Launcher"]
  };

  for (let k in keywords) {
    if (last.name.toLowerCase().includes(k)) {
      keywords[k].forEach(s => {
        const li = document.createElement("li");
        li.textContent = s;
        copilot.appendChild(li);
      });
    }
  }
}

// === AUDIT VIEWER ===
async function loadAuditTrail() {
  const res = await fetch("../logs/audit_trail.jsonl");
  const text = await res.text();
  const audit = document.getElementById("auditViewer");
  audit.innerHTML = "";
  text.trim().split("\n").forEach(line => {
    try {
      const data = JSON.parse(line);
      const li = document.createElement("li");
      li.textContent = `[${new Date(data.timestamp * 1000).toISOString()}] ${data.module} (${data.agent})`;
      audit.appendChild(li);
    } catch {}
  });
}
loadAuditTrail();

// === METRICS ===
const ctx = document.getElementById("metricsChart").getContext("2d");
const chart = new Chart(ctx, {
  type: "bar",
  data: {
    labels: [],
    datasets: [{
      label: "Module Runs",
      data: [],
      backgroundColor: "lime"
    }]
  },
  options: {
    scales: {
      y: {
        beginAtZero: true
      }
    }
  }
});

function updateMetricsChart(line) {
  const match = line.match(/\[\*\] Running (.+)/);
  if (!match) return;
  const name = match[1];
  const i = chart.data.labels.indexOf(name);
  if (i >= 0) {
    chart.data.datasets[0].data[i]++;
  } else {
    chart.data.labels.push(name);
    chart.data.datasets[0].data.push(1);
  }
  chart.update();
}
