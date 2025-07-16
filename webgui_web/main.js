// === DOM elements ===
const moduleListEl = document.getElementById("moduleList");
const chainListEl = document.getElementById("chainList");
const progressBar = document.getElementById("progressBar");
const consoleOutput = document.getElementById("consoleOutput");
const categoryFilter = document.getElementById("categoryFilter");
const agentSelector = document.getElementById("agentSelector");
const searchBox = document.getElementById("searchBox");

// === State ===
let allModules = [];
let chainModules = [];

// === Init ===
document.addEventListener("DOMContentLoaded", () => {
  fetchAgents();
  fetchModules();
  setupSearchFilter();
  setupDragAndDrop();
});

// === Fetch agents from backend ===
function fetchAgents() {
  fetch("http://localhost:5000/api/agents")
    .then(res => res.json())
    .then(data => {
      data.forEach(agent => {
        const opt = document.createElement("option");
        opt.value = agent.id || agent;
        opt.textContent = agent.id || agent;
        agentSelector.appendChild(opt);
      });
    })
    .catch(() => {
      const fallback = ["default"];
      fallback.forEach(agent => {
        const opt = document.createElement("option");
        opt.value = agent;
        opt.textContent = agent;
        agentSelector.appendChild(opt);
      });
    });
}

// === Fetch modules from backend ===
function fetchModules() {
  fetch("http://localhost:5000/api/modules")
    .then(res => res.json())
    .then(data => {
      allModules = data;
      updateCategoryFilter();
      renderModuleList();
    });
}

// === Populate category dropdown ===
function updateCategoryFilter() {
  const unique = new Set(allModules.map(m => m.category));
  unique.forEach(cat => {
    const opt = document.createElement("option");
    opt.value = cat;
    opt.textContent = cat;
    categoryFilter.appendChild(opt);
  });
  categoryFilter.addEventListener("change", renderModuleList);
}

// === Search filter setup ===
function setupSearchFilter() {
  searchBox.addEventListener("input", renderModuleList);
}

// === Filter and render modules ===
function renderModuleList() {
  const query = searchBox.value.toLowerCase();
  const selectedCat = categoryFilter.value;

  moduleListEl.innerHTML = "";

  allModules
    .filter(m =>
      (selectedCat === "All" || m.category === selectedCat) &&
      m.name.toLowerCase().includes(query)
    )
    .forEach(mod => {
      const li = document.createElement("li");
      li.textContent = mod.name;
      li.draggable = true;
      li.dataset.name = mod.name;
      li.dataset.file = mod.file;
      li.addEventListener("dragstart", e => {
        e.dataTransfer.setData("text/plain", JSON.stringify(mod));
      });
      moduleListEl.appendChild(li);
    });
}

// === Drag-and-drop setup ===
function setupDragAndDrop() {
  chainListEl.addEventListener("dragover", e => e.preventDefault());

  chainListEl.addEventListener("drop", e => {
    e.preventDefault();
    const mod = JSON.parse(e.dataTransfer.getData("text/plain"));
    const li = document.createElement("li");
    li.textContent = mod.name;
    li.dataset.name = mod.name;
    li.dataset.file = mod.file;
    chainListEl.appendChild(li);
    chainModules.push(mod);
  });
}

// === Run execution chain live ===
function runChain() {
  const sequence = Array.from(chainListEl.querySelectorAll("li")).map(li => ({
    name: li.dataset.name,
    file: li.dataset.file
  }));

  if (!sequence.length) {
    logOutput("No modules selected.");
    return;
  }

  progressBar.value = 0;
  logOutput("Executing module chain...");

  fetch("http://localhost:5000/api/chain", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chain: sequence })
  })
    .then(res => res.json())
    .then(results => {
      results.forEach(entry => {
        if (entry.output) {
          logOutput(`[â] ${entry.module}: ${entry.output}`);
        } else {
          logOutput(`[â] ${entry.module}: ${entry.error}`);
        }
      });
      progressBar.value = 100;
    })
    .catch(err => {
      logOutput("Execution error: " + err.message);
    });
}

// === Clear chain list ===
function clearChain() {
  chainModules = [];
  chainListEl.innerHTML = "";
  progressBar.value = 0;
  logOutput("Chain cleared.");
}

// === Export chain to JSON ===
function exportChain() {
  const sequence = Array.from(chainListEl.querySelectorAll("li")).map(li => ({
    name: li.dataset.name,
    file: li.dataset.file
  }));
  const blob = new Blob([JSON.stringify(sequence, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "execution_chain.json";
  a.click();
  URL.revokeObjectURL(url);
}

// === Log output to terminal area ===
function logOutput(msg) {
  const ts = new Date().toLocaleTimeString();
  consoleOutput.textContent += `[${ts}] ${msg}\n`;
  consoleOutput.scrollTop = consoleOutput.scrollHeight;
}
