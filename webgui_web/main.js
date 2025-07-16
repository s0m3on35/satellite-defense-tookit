// File: /webgui_web/main.js

const moduleList = document.getElementById("moduleList");
const agentSelector = document.getElementById("agentSelector");
const categoryFilter = document.getElementById("categoryFilter");
const searchBox = document.getElementById("searchBox");
const chainList = document.getElementById("chainList");
const consoleOutput = document.getElementById("consoleOutput");
const progressBar = document.getElementById("progressBar");

let allModules = [];
let chain = [];

// === Load modules from backend ===
async function loadModules() {
  const res = await fetch("/api/modules");
  const modules = await res.json();
  allModules = modules;
  populateCategories(modules);
  renderModules(modules);
}

// === Load agents ===
async function loadAgents() {
  const res = await fetch("/api/agents");
  const agents = await res.json();
  agentSelector.innerHTML = "";
  agents.forEach(agent => {
    const option = document.createElement("option");
    option.value = agent.id;
    option.textContent = agent.id;
    agentSelector.appendChild(option);
  });
}

// === Populate category dropdown ===
function populateCategories(modules) {
  const categories = new Set(modules.map(m => m.category));
  categoryFilter.innerHTML = `<option value="All">All</option>`;
  categories.forEach(cat => {
    const opt = document.createElement("option");
    opt.value = cat;
    opt.textContent = cat;
    categoryFilter.appendChild(opt);
  });
}

// === Render module list based on filter/search ===
function renderModules(modules) {
  const search = searchBox.value.toLowerCase();
  const filter = categoryFilter.value;
  moduleList.innerHTML = "";
  modules.forEach(mod => {
    if ((filter === "All" || mod.category === filter) && mod.name.toLowerCase().includes(search)) {
      const li = document.createElement("li");
      li.textContent = `${mod.name} (${mod.category})`;
      li.classList.add("module-item");
      li.dataset.file = mod.file;
      li.draggable = true;

      li.addEventListener("dragstart", e => {
        e.dataTransfer.setData("module", JSON.stringify(mod));
      });

      li.addEventListener("dblclick", () => runModule(mod));
      moduleList.appendChild(li);
    }
  });
}

// === Drag/drop to chain ===
chainList.addEventListener("dragover", e => e.preventDefault());
chainList.addEventListener("drop", e => {
  e.preventDefault();
  const mod = JSON.parse(e.dataTransfer.getData("module"));
  chain.push(mod);
  const li = document.createElement("li");
  li.textContent = mod.name;
  li.classList.add("chain-item");
  li.dataset.file = mod.file;
  chainList.appendChild(li);
});

// === Run single module ===
function runModule(mod) {
  printToConsole(`> Running: ${mod.name}`);
  progressBar.value = 0;
  fetch("/api/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ file: mod.file })
  });
}

// === Run full chain ===
function runChain() {
  if (!chain.length) return;
  printToConsole("> Executing chain...");
  progressBar.value = 0;
  fetch("/api/chain", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chain: chain.map(mod => ({ file: mod.file })) })
  });
}

// === Export chain to JSON ===
function exportChain() {
  const blob = new Blob([JSON.stringify(chain, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "module_chain.json";
  a.click();
  URL.revokeObjectURL(url);
}

// === Clear chain UI + array ===
function clearChain() {
  chain = [];
  chainList.innerHTML = "";
  printToConsole("> Cleared execution chain.");
}

// === WebSocket console output ===
const ws = new WebSocket(`ws://${location.hostname}:5000/ws`);
ws.onmessage = event => {
  const { line } = JSON.parse(event.data);
  printToConsole(line);
};
ws.onopen = () => printToConsole("[✓] WebSocket connected");
ws.onerror = () => printToConsole("[x] WebSocket connection failed");

// === Print to console output area ===
function printToConsole(msg) {
  const span = document.createElement("div");
  span.textContent = msg;
  consoleOutput.appendChild(span);
  consoleOutput.scrollTop = consoleOutput.scrollHeight;
  progressBar.value = Math.min(progressBar.value + 5, 100);
}

// === Bind input events ===
searchBox.addEventListener("input", () => renderModules(allModules));
categoryFilter.addEventListener("change", () => renderModules(allModules));

// === Init ===
window.onload = () => {
  loadModules();
  loadAgents();
  printToConsole("> GUI ready.");
};
