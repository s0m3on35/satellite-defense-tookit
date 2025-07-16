let moduleList = [];
let agentList = [];
let chain = [];

const moduleListEl = document.getElementById("moduleList");
const chainListEl = document.getElementById("chainList");
const consoleOutput = document.getElementById("consoleOutput");
const agentSelector = document.getElementById("agentSelector");
const categoryFilter = document.getElementById("categoryFilter");
const searchBox = document.getElementById("searchBox");
const configOverlay = document.getElementById("configOverlay");
const configEditor = document.getElementById("configEditor");
const configModuleTitle = document.getElementById("configModuleTitle");
const metricsCanvas = document.getElementById("metricsChart");
const auditLogEl = document.getElementById("auditLogContent");

let metricsChart;

document.addEventListener("DOMContentLoaded", () => {
  fetchModules();
  fetchAgents();
  initWebSocket();
  initializeOnboarding();
  document.getElementById("exportBtn").addEventListener("click", exportDashboardState);
});

function initializeOnboarding() {
  const onboarding = document.getElementById("onboarding");
  setTimeout(() => {
    onboarding.classList.add("fade-out");
    setTimeout(() => onboarding.style.display = "none", 1200);
  }, 2000);
}

function fetchModules() {
  fetch("/api/modules")
    .then(res => res.json())
    .then(data => {
      moduleList = data;
      populateModules();
      populateCategories();
    });
}

function fetchAgents() {
  fetch("/api/agents")
    .then(res => res.json())
    .then(data => {
      agentList = data;
      agentList.forEach(agent => {
        const option = document.createElement("option");
        option.value = agent.id;
        option.textContent = agent.id;
        agentSelector.appendChild(option);
      });
    });
}

function populateModules() {
  moduleListEl.innerHTML = "";
  const query = searchBox.value.toLowerCase();
  const selectedCategory = categoryFilter.value;
  const filtered = moduleList.filter(mod =>
    (selectedCategory === "All" || mod.category === selectedCategory) &&
    mod.name.toLowerCase().includes(query)
  );

  filtered.forEach(mod => {
    const li = document.createElement("li");
    li.textContent = `[${mod.category}] ${mod.name}`;
    li.draggable = true;
    li.dataset.module = JSON.stringify(mod);
    li.addEventListener("dragstart", e => {
      e.dataTransfer.setData("text/plain", JSON.stringify(mod));
    });
    li.addEventListener("dblclick", () => showModuleConfig(mod));
    moduleListEl.appendChild(li);
  });
}

function populateCategories() {
  const cats = Array.from(new Set(moduleList.map(m => m.category))).sort();
  cats.forEach(cat => {
    const opt = document.createElement("option");
    opt.value = cat;
    opt.textContent = cat;
    categoryFilter.appendChild(opt);
  });
}

searchBox.addEventListener("input", populateModules);
categoryFilter.addEventListener("change", populateModules);

chainListEl.addEventListener("dragover", e => e.preventDefault());
chainListEl.addEventListener("drop", e => {
  e.preventDefault();
  const mod = JSON.parse(e.dataTransfer.getData("text/plain"));
  chain.push(mod);
  renderChain();
});

function renderChain() {
  chainListEl.innerHTML = "";
  chain.forEach((mod, index) => {
    const li = document.createElement("li");
    li.textContent = `[${mod.category}] ${mod.name}`;
    const remove = document.createElement("button");
    remove.textContent = "x";
    remove.onclick = () => {
      chain.splice(index, 1);
      renderChain();
    };
    li.appendChild(remove);
    chainListEl.appendChild(li);
  });
}

function runChain() {
  if (!chain.length) return;
  fetch("/api/chain", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chain })
  });
}

function clearChain() {
  chain = [];
  renderChain();
}

function exportDashboardState() {
  const state = {
    agent: agentSelector.value,
    chain,
    timestamp: new Date().toISOString()
  };
  const blob = new Blob([JSON.stringify(state, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.download = "dashboard_state.json";
  link.href = url;
  link.click();
}

function showModuleConfig(mod) {
  configOverlay.style.display = "block";
  configModuleTitle.textContent = mod.name;
  configEditor.value = JSON.stringify(mod, null, 2);
}

function closeConfigOverlay() {
  configOverlay.style.display = "none";
}

document.getElementById("closeConfigOverlay").onclick = closeConfigOverlay;

function initWebSocket() {
  const socket = new WebSocket("ws://" + window.location.hostname + ":5000/socket.io/?EIO=4&transport=websocket");

  socket.onopen = () => logOutput("[WebSocket] Connected");
  socket.onmessage = event => {
    const data = parseSocketMessage(event.data);
    if (data && data.type === "console_output" && data.data) {
      logOutput(data.data.line);
      updateMetrics(data.data.line);
      updateAuditLog(data.data.line);
    }
  };
}

function parseSocketMessage(raw) {
  const match = raw.match(/\d+{(.+)}/);
  if (match && match[1]) {
    try {
      return { type: "console_output", data: JSON.parse(`{${match[1]}}`) };
    } catch (e) {
      return null;
    }
  }
  return null;
}

function logOutput(text) {
  consoleOutput.textContent += text + "\n";
  consoleOutput.scrollTop = consoleOutput.scrollHeight;
}

function updateMetrics(line) {
  if (!metricsChart) {
    metricsChart = new Chart(metricsCanvas.getContext("2d"), {
      type: "bar",
      data: {
        labels: [],
        datasets: [{
          label: "Execution Logs",
          data: [],
          backgroundColor: "lime"
        }]
      },
      options: {
        responsive: true,
        scales: { y: { beginAtZero: true } }
      }
    });
  }

  const label = line.split(" ")[0];
  const idx = metricsChart.data.labels.indexOf(label);
  if (idx >= 0) {
    metricsChart.data.datasets[0].data[idx]++;
  } else {
    metricsChart.data.labels.push(label);
    metricsChart.data.datasets[0].data.push(1);
  }
  metricsChart.update();
}

function updateAuditLog(line) {
  const el = document.createElement("div");
  el.textContent = `[${new Date().toLocaleTimeString()}] ${line}`;
  auditLogEl.appendChild(el);
}
