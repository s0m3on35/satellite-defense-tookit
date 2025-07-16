// === DOM elements ===
const moduleListEl = document.getElementById("moduleList");
const chainListEl = document.getElementById("chainList");
const progressBar = document.getElementById("progressBar");
const consoleOutput = document.getElementById("consoleOutput");
const categoryFilter = document.getElementById("categoryFilter");
const agentSelector = document.getElementById("agentSelector");
const searchBox = document.getElementById("searchBox");

// === State ===
let allModules = []; // will be populated with { name, category }
let chainModules = [];

// === Init ===
document.addEventListener("DOMContentLoaded", () => {
  loadAgents();
  loadModules();
  setupSearchFilter();
  setupDragAndDrop();
});

// === Load Agents ===
function loadAgents() {
  // Placeholder for backend call
  const agents = ["default", "satellite-001", "telemetry-agent"];
  agents.forEach(agent => {
    const opt = document.createElement("option");
    opt.value = agent;
    opt.textContent = agent;
    agentSelector.appendChild(opt);
  });
}

// === Load Modules (simulated or backend-ready) ===
function loadModules() {
  // Simulated example
  allModules = [
    { name: "GNSS Spoofer", category: "Attacks" },
    { name: "Firmware Integrity Watcher", category: "Defense" },
    { name: "Copilot Engine", category: "AI" },
    { name: "Telemetry Guardian", category: "Defense" },
    { name: "OTA Firmware Injector", category: "Attacks" },
    { name: "Threat Classifier", category: "AI" }
  ];

  updateCategoryFilter();
  renderModuleList();
}

// === Render Category Dropdown ===
function updateCategoryFilter() {
  const uniqueCategories = new Set(allModules.map(m => m.category));
  uniqueCategories.forEach(cat => {
    const opt = document.createElement("option");
    opt.value = cat;
    opt.textContent = cat;
    categoryFilter.appendChild(opt);
  });

  categoryFilter.addEventListener("change", renderModuleList);
}

// === Search Filter Setup ===
function setupSearchFilter() {
  searchBox.addEventListener("input", renderModuleList);
}

// === Filter + Render Modules ===
function renderModuleList() {
  const query = searchBox.value.toLowerCase();
  const selectedCategory = categoryFilter.value;

  moduleListEl.innerHTML = "";

  allModules
    .filter(mod =>
      (selectedCategory === "All" || mod.category === selectedCategory) &&
      mod.name.toLowerCase().includes(query)
    )
    .forEach(mod => {
      const li = document.createElement("li");
      li.textContent = mod.name;
      li.draggable = true;
      li.dataset.name = mod.name;
      li.addEventListener("dragstart", e => {
        e.dataTransfer.setData("text/plain", mod.name);
      });
      moduleListEl.appendChild(li);
    });
}

// === Drag and Drop Setup ===
function setupDragAndDrop() {
  chainListEl.addEventListener("dragover", e => e.preventDefault());

  chainListEl.addEventListener("drop", e => {
    e.preventDefault();
    const moduleName = e.dataTransfer.getData("text/plain");
    if (moduleName) {
      const li = document.createElement("li");
      li.textContent = moduleName;
      li.dataset.name = moduleName;
      chainListEl.appendChild(li);
      chainModules.push(moduleName);
    }
  });
}

// === Run Chain ===
function runChain() {
  const items = chainListEl.querySelectorAll("li");
  const sequence = Array.from(items).map(i => i.dataset.name);
  if (sequence.length === 0) {
    logOutput("No modules selected.");
    return;
  }

  progressBar.value = 0;
  logOutput("Executing module chain: " + sequence.join(" -> "));

  let i = 0;
  function next() {
    if (i >= sequence.length) {
      progressBar.value = 100;
      logOutput("Execution complete.");
      suggestNext(sequence[sequence.length - 1]); // Copilot stub
      return;
    }
    const mod = sequence[i++];
    logOutput(`[+] Running: ${mod}`);
    progressBar.value = Math.floor((i / sequence.length) * 100);

    // Optionally: fetch('/api/run', { method: 'POST', body: JSON.stringify({ module: mod }) })

    setTimeout(next, 1200); // Simulated delay
  }

  next();
}

// === Clear Chain ===
function clearChain() {
  chainModules = [];
  chainListEl.innerHTML = "";
  progressBar.value = 0;
  logOutput("Chain cleared.");
}

// === Export Chain ===
function exportChain() {
  const sequence = Array.from(chainListEl.querySelectorAll("li")).map(li => li.dataset.name);
  const blob = new Blob([JSON.stringify(sequence, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "execution_chain.json";
  a.click();
  URL.revokeObjectURL(url);
}

// === Console Logging ===
function logOutput(message) {
  const ts = new Date().toLocaleTimeString();
  consoleOutput.textContent += `[${ts}] ${message}\n`;
  consoleOutput.scrollTop = consoleOutput.scrollHeight;
}

// === Copilot Stub ===
function suggestNext(lastModule) {
  const suggestions = allModules
    .filter(m => m.name !== lastModule && m.category === "AI")
    .map(m => m.name);
  if (suggestions.length) {
    logOutput(`Copilot suggestion: Next module may be "${suggestions[0]}"`);
  }
}
